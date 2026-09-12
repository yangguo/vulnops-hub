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
from vulnops.db.models.audit_event import AuditEvent
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


def fail_event(session: Session, event: OutboxEvent, max_attempts: int) -> None:
    """Roll back, count one attempt, and flag poison when the cap is reached."""

    session.rollback()
    stored = session.get(OutboxEvent, event.id)
    stored.attempts = (stored.attempts or 0) + 1
    session.commit()
    if stored.attempts >= max_attempts:
        logger.error(
            "outbox event %s (%s) dead-lettered after %d attempts",
            stored.id,
            stored.event_type,
            stored.attempts,
        )


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
    return {
        "id": record.vulnerability_id,
        "aliases": list(record.aliases or []),
        "affected": affected,
    }


def _osv_record_matches_cve(record: Any, cve: str) -> bool:
    """True when the OSV record id or aliases includes the Wazuh-reported CVE."""

    target = cve.upper()
    if str(record.vulnerability_id).upper() == target:
        return True
    return any(str(alias).upper() == target for alias in record.aliases or [])


def _select_osv_record_for_cve(records: list[Any], cve: str) -> Any | None:
    """Return the first OSV record whose id or aliases includes ``cve``."""

    for record in records:
        if _osv_record_matches_cve(record, cve):
            return record
    return None


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


def _component_from_fields(
    *, raw_name: str, raw_version: str | None, purl: str | None
) -> ParsedComponent:
    ecosystem = None
    if purl and purl.startswith("pkg:"):
        ecosystem = purl[4:].split("/")[0].lower()
    return ParsedComponent(
        raw_name=raw_name,
        raw_version=raw_version,
        purl=purl,
        ecosystem=ecosystem,
        normalized_name=raw_name,
        cpe=None,
        version_scheme=ecosystem,
    )


class OutboxOrchestrator:
    """Consume evidence outbox events and materialize exposures/cases."""

    def __init__(self, session_factory, osv=None, kev=None, epss=None, vex=None, settings=None):
        self.session_factory = session_factory
        self.osv = osv or OSVAdapter()
        self.kev = kev
        self.epss = epss
        self.vex = vex
        self.settings = settings or get_settings()
        self.matcher = MatchingService()
        self.policy = RiskPolicyEngine()
        self._last_kev_refresh_monotonic = 0.0

    # -- dispatch ----------------------------------------------------------

    _HANDLERS: ClassVar[dict[str, str]] = {
        "vulnops.sbom.processed.v1": "_handle_sbom_processed",
        "vulnops.evidence.defectdojo.ingested.v1": "_handle_defectdojo_ingested",
        "vulnops.evidence.wazuh.ingested.v1": "_handle_wazuh_ingested",
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
            fail_event(session, event, self.settings.orchestrator_max_attempts)
            raise
        complete_event(session, event)
        return summary

    def run_once(self) -> int:
        session = self.session_factory()
        try:
            # Handlers may emit follow-up outbox rows (e.g. case.created via
            # CaseService); keep claiming until the queue is drained so one
            # invocation leaves nothing undelivered behind. Only events handled
            # by a registered handler count toward the delivered total. A failed
            # event stops claiming until the next poll so its retry cadence is
            # the poll interval instead of burning attempts in one tight drain.
            delivered = 0
            while True:
                events = claim_events(
                    session,
                    batch_size=self.settings.orchestrator_batch_size,
                    max_attempts=self.settings.orchestrator_max_attempts,
                )
                if not events:
                    break
                stop_claiming = False
                for event in events:
                    try:
                        summary = self.process_event(session, event)
                    except Exception:
                        # fail_event already rolled back and counted the attempt.
                        logger.exception(
                            "outbox event %s failed; deferring remaining events to next poll",
                            event.id,
                        )
                        stop_claiming = True
                        break
                    if summary is not None:
                        delivered += 1
                if stop_claiming:
                    break
            return delivered
        finally:
            session.close()

    def _is_kev(self, vulnerability_id: str, session: Session | None = None) -> bool:
        if self.kev is None:
            return False
        try:
            return bool(self.kev.is_kev(vulnerability_id, session=session))
        except TypeError:
            return bool(self.kev.is_kev(vulnerability_id))

    def _maybe_refresh_kev_catalog(self) -> None:
        if self.kev is None:
            return
        interval = self.settings.kev_refresh_interval_seconds
        now = time.monotonic()
        if now - self._last_kev_refresh_monotonic < interval:
            return
        from vulnops.intelligence.persistence import refresh_kev_catalog

        session = self.session_factory()
        try:
            refresh_kev_catalog(session, self.kev)
            session.commit()
            self._last_kev_refresh_monotonic = now
            logger.info("KEV catalog refreshed and persisted")
        except Exception as exc:
            session.rollback()
            try:
                from vulnops.intelligence.persistence import upsert_source_health

                upsert_source_health(session, self.kev.get_health())
                session.commit()
            except Exception:
                session.rollback()
            logger.warning("KEV catalog refresh failed: %s", exc)
        finally:
            session.close()

    def _persist_advisories(self, handler_session: Session, records: list[Any]) -> None:
        """Best-effort intel cache write on an isolated session (never poisons handler txn)."""

        if not records:
            return
        cache_session = self.session_factory()
        owns_cache_session = cache_session is not handler_session
        try:
            from vulnops.intelligence.persistence import upsert_advisory_records

            upsert_advisory_records(cache_session, records)
            cache_session.flush()
            cache_session.commit()
        except Exception as exc:
            cache_session.rollback()
            logger.warning(
                "intel cache persist failed for %d record(s); matching continues: %s",
                len(records),
                exc,
            )
        finally:
            if owns_cache_session:
                cache_session.close()

    def run_forever(self, max_iterations: int | None = None) -> None:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            self._maybe_refresh_kev_catalog()
            try:
                count = self.run_once()
                if count:
                    logger.info("orchestrator delivered %d event(s)", count)
            except Exception:
                logger.exception("orchestrator loop error; backing off")
            time.sleep(self.settings.orchestrator_poll_interval_seconds)

    # -- priority ----------------------------------------------------------

    def _priority_for(
        self,
        vulnerability_id: str,
        match_class: str,
        confidence: float,
        session: Session | None = None,
    ):
        kev = self._is_kev(vulnerability_id, session=session)
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

    def _vex_status_for(self, vulnerability_id: str) -> str | None:
        """Best-effort VEX lookup; failures degrade to no VEX input."""

        if self.vex is None:
            return None
        try:
            return self.vex.get_status(vulnerability_id)
        except Exception as exc:
            logger.warning("VEX lookup failed for %s: %s", vulnerability_id, exc)
            return None

    # -- case creation -----------------------------------------------------

    def _maybe_create_case(
        self,
        session: Session,
        exposure: Exposure,
        component_label: str,
        external_ticket_id: str | None = None,
        ticket_provenance: str | None = None,
    ):
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
        case = CaseService(session, settings=self.settings).create_case(
            organization_id=exposure.organization_id,
            title=f"Remediate {exposure.vulnerability_id} in {component_label}",
            # Let CaseService resolve inventory ownership at creation time;
            # passing a pre-resolved non-default team would make that snapshot
            # look like an explicit override.
            owner_team=self.settings.default_case_owner_team,
            priority=exposure.priority or "P2",
            exposures=[exposure.id],
            policy_version=exposure.policy_version,
            asset_id=exposure.asset_id,
        )
        session.add(
            CaseExposure(id=f"cx_{uuid.uuid4().hex[:12]}", case_id=case.id, exposure_id=exposure.id)
        )
        if external_ticket_id:
            case.external_ticket_id = external_ticket_id
            session.add(
                AuditEvent(
                    id=f"aud_{uuid.uuid4().hex[:12]}",
                    actor="orchestration",
                    action="case.external_ticket.linked",
                    subject_type="case",
                    subject_id=case.id,
                    reason=ticket_provenance or "external ticket linked",
                    organization_id=exposure.organization_id,
                )
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
        self._persist_advisories(session, records)

        by_index: dict[int, list[Any]] = {}
        for rec in records:
            by_index.setdefault(rec.retrieval_metadata.get("query_index", -1), []).append(rec)

        exposure_count = 0
        for idx, occurrence in enumerate(ordered):
            for rec in by_index.get(idx, []):
                advisory = _advisory_from_record(rec)
                component = _component_from_occurrence(occurrence)
                vex_status = self._vex_status_for(rec.vulnerability_id)
                result = self.matcher.evaluate(component, advisory, vex_status=vex_status)
                priority, policy_version, _kev = self._priority_for(
                    rec.vulnerability_id, result.match_class, result.confidence, session=session
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

    def _handle_defectdojo_ingested(self, session: Session, event: OutboxEvent) -> str:
        payload = event.payload or {}
        finding_id = str(payload.get("finding_id"))
        mapping_status = (payload.get("mapping") or {}).get("status")
        if mapping_status == "ambiguous":
            return f"dojo={finding_id} skipped-ambiguous"

        cve = payload.get("cve")
        if not cve or cve == "unknown":
            return f"dojo={finding_id} skipped-no-cve"

        organization_id = payload.get("organization_id") or "default"
        purl = payload.get("purl")
        component_name = payload.get("component_name") or "unknown"
        component_version = payload.get("component_version")
        verified = bool(payload.get("verified"))
        scan_metadata = payload.get("scan_metadata") or {}
        scanner = payload.get("scanner") or scan_metadata.get("scanner")
        scan_type = payload.get("scan_type") or scan_metadata.get("scan_type")

        advisory: dict[str, Any] = {"id": cve, "affected": []}
        if purl:
            records = self.osv.lookup_batch([{"purl": purl, "version": component_version}])
            self._persist_advisories(session, records)
            if records:
                advisory = _advisory_from_record(records[0])
                advisory["id"] = advisory.get("id") or cve

        component = _component_from_fields(
            raw_name=component_name, raw_version=component_version, purl=purl
        )
        scanner_evidence = None
        if verified:
            scanner_evidence = {"scanner_confirmed": True, "finding_id": finding_id}
            if scanner:
                scanner_evidence["scanner"] = scanner
            if scan_type:
                scanner_evidence["scan_type"] = scan_type
        vex_status = self._vex_status_for(cve) if not verified else None
        result = self.matcher.evaluate(
            component, advisory, scanner_evidence=scanner_evidence, vex_status=vex_status
        )
        priority, policy_version, _kev = self._priority_for(
            cve, result.match_class, result.confidence, session=session
        )
        exposure, _created = upsert_exposure(
            session,
            organization_id=organization_id,
            vulnerability_id=cve,
            match_class=result.match_class,
            confidence=result.confidence,
            detection_context=f"defectdojo:{finding_id}",
            component_occurrence_id=None,
            asset_id=(payload.get("mapping") or {}).get("asset_id"),
            matched_rules=result.matched_rules,
            evidence_refs=[event.id],
            limitations=result.limitations,
            matcher_version=result.matcher_version,
            priority=priority,
            policy_version=policy_version,
            evidence_ref=event.id,
        )
        session.commit()
        if purl:
            jira_key = payload.get("jira_key")
            self._maybe_create_case(
                session,
                exposure,
                component_name,
                external_ticket_id=jira_key,
                ticket_provenance=f"jira via defectdojo finding {finding_id}" if jira_key else None,
            )
        return f"dojo={finding_id} match={result.match_class}"

    def _handle_wazuh_ingested(self, session: Session, event: OutboxEvent) -> str:
        payload = event.payload or {}
        agent_id = str(payload.get("agent_id") or "unknown")
        cve = payload.get("cve")
        if not cve or cve == "unknown":
            return f"wazuh={agent_id} no-cve"
        organization_id = payload.get("organization_id") or "default"
        package = payload.get("package") or {}
        purl = package.get("purl")
        component_name = package.get("name") or "unknown"
        component_version = package.get("version")
        purl_derivation = payload.get("purl_derivation") or {}

        advisory: dict[str, Any] = {"id": cve, "affected": []}
        osv_cve_bound = False
        if purl:
            records = self.osv.lookup_batch([{"purl": purl, "version": component_version}])
            self._persist_advisories(session, records)
            bound = _select_osv_record_for_cve(records, cve)
            if bound is not None:
                advisory = _advisory_from_record(bound)
                advisory["id"] = advisory.get("id") or cve
                osv_cve_bound = True

        component = _component_from_fields(
            raw_name=component_name, raw_version=component_version, purl=purl
        )
        vex_status = self._vex_status_for(cve)
        result = self.matcher.evaluate(component, advisory, vex_status=vex_status)
        limitations = list(result.limitations)
        if not purl:
            limitations.append("package inventory without purl; review required")
        elif purl_derivation.get("status") == "derived":
            limitations.append("purl derived from Wazuh package metadata (best-effort)")
        if purl and not osv_cve_bound:
            limitations.append(
                "osv lookup did not confirm the Wazuh CVE; package-version match alone is insufficient"
            )
            if result.match_class in _CASE_CLASSES:
                result = result.__class__(
                    match_class="candidate",
                    confidence=min(result.confidence, 0.4),
                    should_create_case=False,
                    case_id=None,
                    matched_rules=["wazuh.osv-cve-unbound"],
                    limitations=limitations,
                    matcher_version=result.matcher_version,
                    explanation=result.explanation,
                )

        priority, policy_version, _kev = self._priority_for(
            cve, result.match_class, result.confidence, session=session
        )
        exposure, _created = upsert_exposure(
            session,
            organization_id=organization_id,
            vulnerability_id=cve,
            match_class=result.match_class,
            confidence=result.confidence,
            detection_context=f"wazuh:{agent_id}",
            component_occurrence_id=None,
            asset_id=(payload.get("mapping") or {}).get("asset_id"),
            matched_rules=result.matched_rules,
            evidence_refs=[event.id],
            limitations=limitations,
            matcher_version=result.matcher_version,
            priority=priority,
            policy_version=policy_version,
            evidence_ref=event.id,
        )
        session.commit()
        if purl and osv_cve_bound:
            self._maybe_create_case(session, exposure, component_name)
        return f"wazuh={agent_id} match={result.match_class} exposure={exposure.id}"


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    from vulnops.db import get_engine, get_sessionmaker
    from vulnops.intelligence.epss import EPSSAdapter
    from vulnops.intelligence.kev import KEVAdapter

    settings = get_settings()
    engine = get_engine()
    kev = KEVAdapter()
    kev_loaded = False
    session = get_sessionmaker(engine)()
    try:
        from vulnops.intelligence.persistence import refresh_kev_catalog

        refresh_kev_catalog(session, kev)
        session.commit()
        kev_loaded = True
        logger.info("KEV catalog loaded and persisted")
    except Exception as exc:
        session.rollback()
        logger.warning("KEV catalog unavailable at startup: %s", exc)
    finally:
        session.close()

    orchestrator = OutboxOrchestrator(
        session_factory=lambda: get_sessionmaker(engine)(),
        kev=kev,
        epss=EPSSAdapter(),
        settings=settings,
    )
    if kev_loaded:
        orchestrator._last_kev_refresh_monotonic = time.monotonic()
    orchestrator.run_forever()


if __name__ == "__main__":
    main()
