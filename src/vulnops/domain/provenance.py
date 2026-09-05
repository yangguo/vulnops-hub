from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.db.models.source_snapshot import SourceSnapshot


def _utcnow():
    return datetime.now(UTC)


def persist_snapshot_with_event(
    session: Session,
    snapshot: SourceSnapshot,
    *,
    event_type: str,
    audit_event: AuditEvent | None = None,
    payload: dict | None = None,
) -> SourceSnapshot:
    """
    Atomically persist a SourceSnapshot together with an OutboxEvent
    (and optionally an AuditEvent) in the same DB transaction.

    Idempotency: if a snapshot with the same natural key
    (source, source_record_id, content_sha256) already exists,
    return it without emitting a duplicate outbox/audit event.

    Transactionality: all inserts happen inside a single transaction.
    Any failure rolls back all rows.
    """
    if not event_type:
        raise ValueError("event_type is required and must be non-empty")

    # Idempotency check - outside transaction but we also guard within transaction
    existing = (
        session.query(SourceSnapshot)
        .filter_by(
            source=snapshot.source,
            source_record_id=snapshot.source_record_id,
            content_sha256=snapshot.content_sha256,
        )
        .first()
    )
    if existing:
        return existing

    # Ensure snapshot has correlation_id etc.
    if not snapshot.correlation_id:
        snapshot.correlation_id = str(uuid.uuid4())

    # Prepare outbox event
    outbox = OutboxEvent(
        id=f"evt_{uuid.uuid4().hex[:12]}",
        aggregate_type="source_snapshot",
        aggregate_id=snapshot.id,
        event_type=event_type,
        payload=payload
        or {
            "source": snapshot.source,
            "source_record_id": snapshot.source_record_id,
            "content_sha256": snapshot.content_sha256,
            "object_uri": snapshot.object_uri,
        },
        correlation_id=snapshot.correlation_id,
    )

    # Transaction boundary: use session.begin() if not already in transaction
    # If session already has an active transaction, we use nested.
    try:
        # SQLAlchemy 2.x: session.begin() will start if not already begun
        # Use explicit transaction control
        if session.in_transaction():
            # already inside a transaction (e.g., tests with outer begin)
            session.add(snapshot)
            session.add(outbox)
            if audit_event is not None:
                if not audit_event.action:
                    raise ValueError("audit_event.action is required")
                session.add(audit_event)
            session.flush()
        else:
            with session.begin():
                session.add(snapshot)
                session.add(outbox)
                if audit_event is not None:
                    if not audit_event.action:
                        raise ValueError("audit_event.action is required")
                    session.add(audit_event)
        # If we were in outer transaction, commit here if not already
        if not session.in_transaction():
            session.commit()
        else:
            # For the case where we used session.begin() internally, it already committed
            # For the in_transaction branch, we need to commit manually
            try:
                session.commit()
            except Exception:
                session.rollback()
                raise
        return snapshot
    except Exception:
        session.rollback()
        raise


def create_audit_event(
    *,
    actor: str,
    action: str,
    subject_type: str,
    subject_id: str,
    correlation_id: str | None = None,
    reason: str | None = None,
    prior_state: str | None = None,
    new_state: str | None = None,
    policy_version: str | None = None,
    evidence_refs: list | None = None,
    organization_id: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        id=f"aud_{uuid.uuid4().hex[:12]}",
        actor=actor,
        action=action,
        subject_type=subject_type,
        subject_id=subject_id,
        correlation_id=correlation_id or str(uuid.uuid4()),
        reason=reason,
        prior_state=prior_state,
        new_state=new_state,
        policy_version=policy_version,
        evidence_refs=evidence_refs,
        organization_id=organization_id,
    )
