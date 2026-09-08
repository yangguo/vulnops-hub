"""Outbox orchestration: evidence events -> exposures -> (policy-gated) cases.

Consumes undelivered rows from outbox_events, dispatches by event_type to a
handler that queries intelligence for advisories, evaluates matches, and
upserts exposures. Deterministic/confirmed matches create remediation cases
through CaseService when CASE_AUTO_CREATE_ENABLED. Each handler commits its
own transaction; the outbox row is marked delivered only after success.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy.orm import Session

from vulnops.cases.models import CaseExposure, CaseStatus, RemediationCase
from vulnops.cases.service import CaseService
from vulnops.config import get_settings
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.intelligence.osv import OSVAdapter
from vulnops.matching.models import Exposure, MatchEvidence
from vulnops.matching.service import MatchingService
from vulnops.risk.policy import PolicyInput, RiskPolicyEngine
from vulnops.sbom.models import ComponentOccurrence
from vulnops.sbom.parser import ParsedComponent

logger = logging.getLogger("vulnops.workers.orchestration")

_CASE_CLASSES = ("confirmed", "deterministic")


def claim_events(session: Session, batch_size: int, max_attempts: int) -> list[OutboxEvent]:
    """Return undelivered outbox rows under the attempt cap, oldest first."""

    rows = (
        session.query(OutboxEvent)
        .filter(OutboxEvent.delivered_at.is_(None), OutboxEvent.attempts < max_attempts)
        .order_by(OutboxEvent.created_at)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .all()
    )
    return list(rows)


def complete_event(session: Session, event: OutboxEvent) -> None:
    event.delivered_at = datetime.now(UTC)
    session.commit()


def fail_event(session: Session, event: OutboxEvent) -> None:
    session.rollback()
    stored = session.get(OutboxEvent, event.id)
    stored.attempts = (stored.attempts or 0) + 1
    session.commit()


def upsert_exposure(session: Session, **kwargs: Any) -> tuple[Exposure, bool]:
    """Idempotently create or refresh one exposure keyed by org+vuln+context."""

    organization_id = kwargs["organization_id"]
    vulnerability_id = kwargs["vulnerability_id"]
    detection_context = kwargs["detection_context"]
    component_occurrence_id = kwargs.get("component_occurrence_id")

    query = session.query(Exposure).filter(
        Exposure.organization_id == organization_id,
        Exposure.vulnerability_id == vulnerability_id,
        Exposure.detection_context == detection_context,
    )
    if component_occurrence_id is None:
        query = query.filter(Exposure.component_occurrence_id.is_(None))
    else:
        query = query.filter(Exposure.component_occurrence_id == component_occurrence_id)
    existing = query.first()

    match_class = kwargs["match_class"]
    state = (
        "not_affected"
        if match_class == "not_affected"
        else ("active" if match_class in _CASE_CLASSES else "candidate")
    )

    if existing is not None:
        existing.last_observed_at = datetime.now(UTC)
        existing.match_class = match_class
        existing.confidence = kwargs["confidence"]
        existing.state = state
        if kwargs.get("matched_rules"):
            existing.matched_rules = kwargs["matched_rules"]
        if kwargs.get("priority"):
            existing.priority = kwargs["priority"]
        if kwargs.get("policy_version"):
            existing.policy_version = kwargs["policy_version"]
        exposure = existing
        created = False
    else:
        exposure = Exposure(
            id=f"exp_{uuid.uuid4().hex[:12]}",
            organization_id=organization_id,
            component_occurrence_id=component_occurrence_id,
            asset_id=kwargs.get("asset_id"),
            vulnerability_id=vulnerability_id,
            detection_context=detection_context,
            match_class=match_class,
            confidence=kwargs["confidence"],
            state=state,
            matched_rules=kwargs.get("matched_rules"),
            evidence_refs=kwargs.get("evidence_refs"),
            limitations=kwargs.get("limitations"),
            matcher_version=kwargs.get("matcher_version"),
            priority=kwargs.get("priority"),
            policy_version=kwargs.get("policy_version"),
        )
        session.add(exposure)
        session.flush()
        created = True

    evidence_ref = kwargs.get("evidence_ref")
    if evidence_ref:
        seen = (
            session.query(MatchEvidence)
            .filter(
                MatchEvidence.exposure_id == exposure.id,
                MatchEvidence.evidence_ref == evidence_ref,
            )
            .first()
        )
        if seen is None:
            session.add(
                MatchEvidence(
                    id=f"mev_{uuid.uuid4().hex[:12]}",
                    exposure_id=exposure.id,
                    vulnerability_id=vulnerability_id,
                    evidence_ref=evidence_ref,
                    matcher_version=kwargs.get("matcher_version"),
                )
            )
            session.flush()
    return exposure, created


def _advisory_from_record(record: Any) -> dict[str, Any]:
    """Convert an AdvisoryRecord's affected_ranges into matcher OSV shape."""

    affected: list[dict[str, Any]] = []
    for rng in record.affected_ranges or []:
        events: list[dict[str, str]] = []
        if rng.get("introduced"):
            events.append({"introduced": rng["introduced"]})
        if rng.get("fixed"):
            events.append({"fixed": rng["fixed"]})
        if not events:
            continue
        affected.append(
            {
                "package": {"ecosystem": rng.get("ecosystem"), "purl": rng.get("purl")},
                "ranges": [{"type": rng.get("type") or "ECOSYSTEM", "events": events}],
            }
        )
    return {"id": record.vulnerability_id, "affected": affected}


def _component_from_occurrence(occurrence: Any) -> ParsedComponent:
    return ParsedComponent(
        raw_name=occurrence.raw_name,
        raw_version=occurrence.raw_version,
        purl=occurrence.purl,
        ecosystem=occurrence.ecosystem,
        normalized_name=occurrence.normalized_name,
        cpe=occurrence.cpe,
        version_scheme=occurrence.version_scheme,
    )


class OutboxOrchestrator:
    """Consume evidence outbox events and materialize exposures/cases."""

    def __init__(self, session_factory, osv=None, kev=None, epss=None, settings=None):
        self.session_factory = session_factory
        self.osv = osv or OSVAdapter()
        self.kev = kev
        self.epss = epss
        self.settings = settings or get_settings()
        self.matcher = MatchingService()
        self.policy = RiskPolicyEngine()

    # -- dispatch ----------------------------------------------------------

    _HANDLERS: ClassVar[dict[str, str]] = {
        "vulnops.sbom.processed.v1": "_handle_sbom_processed",
    }

    def process_event(self, session: Session, event: OutboxEvent) -> str | None:
        name = self._HANDLERS.get(event.event_type)
        if name is None:
            logger.warning("no handler for event_type=%s; marking delivered", event.event_type)
            complete_event(session, event)
            return None
        handler: Any = getattr(self, name)
        try:
            summary = handler(session, event)
        except Exception:
            fail_event(session, event)
            raise
        complete_event(session, event)
        return summary

    def run_once(self) -> int:
        session = self.session_factory()
        try:
            # Handlers may emit follow-up outbox rows (e.g. case.created via
            # CaseService); keep claiming until the queue is drained so one
            # invocation leaves nothing undelivered behind. Only events handled
            # by a registered handler count toward the delivered total.
            delivered = 0
            while True:
                events = claim_events(
                    session,
                    batch_size=self.settings.orchestrator_batch_size,
                    max_attempts=self.settings.orchestrator_max_attempts,
                )
                if not events:
                    break
                for event in events:
                    summary = self.process_event(session, event)
                    if summary is not None:
                        delivered += 1
            return delivered
        finally:
            session.close()

    def run_forever(self, max_iterations: int | None = None) -> None:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            try:
                count = self.run_once()
                if count:
                    logger.info("orchestrator delivered %d event(s)", count)
            except Exception:
                logger.exception("orchestrator loop error; backing off")
            time.sleep(self.settings.orchestrator_poll_interval_seconds)

    # -- priority ----------------------------------------------------------

    def _priority_for(self, vulnerability_id: str, match_class: str, confidence: float):
        kev = bool(self.kev is not None and self.kev.is_kev(vulnerability_id))
        epss_score = 0.0
        epss_percentile = None
        if self.epss is not None:
            try:
                rec = self.epss.get_scores([vulnerability_id]).get(vulnerability_id)
                if rec is not None:
                    epss_score = float(rec.epss_score or 0.0)
                    epss_percentile = rec.epss_percentile
            except Exception as exc:  # enrichment is best-effort, never blocking
                logger.warning("EPSS lookup failed for %s: %s", vulnerability_id, exc)
        result = self.policy.evaluate(
            PolicyInput(
                vulnerability_id=vulnerability_id,
                kev=kev,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                match_confidence=confidence,
                match_class=match_class,
            )
        )
        priority = result.priority
        if priority == "P4" and match_class in _CASE_CLASSES:
            # Un-enriched inputs (no CVSS/EPSS) score below the policy's P3
            # band; case-generating matches never sit in the bottom bin.
            priority = "P3"
        return priority, result.policy_version, kev

    # -- case creation -----------------------------------------------------

    def _maybe_create_case(self, session: Session, exposure: Exposure, component_label: str):
        if not self.settings.case_auto_create_enabled:
            return None
        if exposure.match_class not in _CASE_CLASSES:
            return None
        existing = (
            session.query(RemediationCase)
            .join(CaseExposure, CaseExposure.case_id == RemediationCase.id)
            .filter(
                CaseExposure.exposure_id == exposure.id,
                RemediationCase.status != CaseStatus.CLOSED,
            )
            .first()
        )
        if existing is not None:
            return None
        # create_case commits the case row (with its exposures JSON list) and
        # the CaseExposure link in separate transactions; a crash between them
        # leaves no link row to join on. The JSON list commits atomically with
        # the case row, so also treat any non-closed org case whose exposures
        # list already contains this exposure as already linked (per-org case
        # sets are small at this scale).
        org_cases = (
            session.query(RemediationCase)
            .filter(
                RemediationCase.organization_id == exposure.organization_id,
                RemediationCase.status != CaseStatus.CLOSED,
            )
            .all()
        )
        if any(exposure.id in (rc.exposures or []) for rc in org_cases):
            return None
        case = CaseService(session).create_case(
            organization_id=exposure.organization_id,
            title=f"Remediate {exposure.vulnerability_id} in {component_label}",
            owner_team=self.settings.default_case_owner_team,
            priority=exposure.priority or "P2",
            exposures=[exposure.id],
            policy_version=exposure.policy_version,
        )
        session.add(
            CaseExposure(id=f"cx_{uuid.uuid4().hex[:12]}", case_id=case.id, exposure_id=exposure.id)
        )
        session.commit()
        return case

    # -- handlers ----------------------------------------------------------

    def _handle_sbom_processed(self, session: Session, event: OutboxEvent) -> str:
        payload = event.payload or {}
        sbom_id = payload["sbom_id"]
        organization_id = payload.get("organization_id") or "default"

        occurrences = session.query(ComponentOccurrence).filter_by(sbom_id=sbom_id).all()
        ordered = [o for o in occurrences if o.purl and o.raw_version]
        query_components = [{"purl": o.purl, "version": o.raw_version} for o in ordered]
        records = self.osv.lookup_batch(query_components) if query_components else []

        by_index: dict[int, list[Any]] = {}
        for rec in records:
            by_index.setdefault(rec.retrieval_metadata.get("query_index", -1), []).append(rec)

        exposure_count = 0
        for idx, occurrence in enumerate(ordered):
            for rec in by_index.get(idx, []):
                advisory = _advisory_from_record(rec)
                component = _component_from_occurrence(occurrence)
                result = self.matcher.evaluate(component, advisory)
                priority, policy_version, _kev = self._priority_for(
                    rec.vulnerability_id, result.match_class, result.confidence
                )
                exposure, _created = upsert_exposure(
                    session,
                    organization_id=organization_id,
                    vulnerability_id=rec.vulnerability_id,
                    match_class=result.match_class,
                    confidence=result.confidence,
                    detection_context=f"sbom:{sbom_id}",
                    component_occurrence_id=occurrence.id,
                    asset_id=occurrence.asset_id,
                    matched_rules=result.matched_rules,
                    evidence_refs=[event.id],
                    limitations=result.limitations,
                    matcher_version=result.matcher_version,
                    priority=priority,
                    policy_version=policy_version,
                    evidence_ref=event.id,
                )
                session.commit()
                self._maybe_create_case(
                    session, exposure, occurrence.normalized_name or occurrence.raw_name
                )
                exposure_count += 1
        return f"sbom={sbom_id} exposures={exposure_count}"
