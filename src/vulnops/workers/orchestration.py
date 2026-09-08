"""Outbox orchestration: evidence events -> exposures -> (policy-gated) cases.

Consumes undelivered rows from outbox_events, dispatches by event_type to a
handler that queries intelligence for advisories, evaluates matches, and
upserts exposures. Deterministic/confirmed matches create remediation cases
through CaseService when CASE_AUTO_CREATE_ENABLED. Each handler commits its
own transaction; the outbox row is marked delivered only after success.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.matching.models import Exposure, MatchEvidence

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
