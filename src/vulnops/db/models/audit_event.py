from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from vulnops.db import Base


def _utcnow():
    return datetime.now(UTC)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_correlation", "correlation_id"),
        Index("ix_audit_subject", "subject_type", "subject_id"),
        Index("ix_audit_time", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)

    prior_state: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_state: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    evidence_refs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    organization_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # ``legacy_request`` preserves provenance for rows written before the
    # authenticated actor boundary.  New HTTP workflow events set the
    # authenticated claim metadata explicitly.
    actor_provenance: Mapped[str] = mapped_column(
        String(32), nullable=False, default="legacy_request"
    )
    actor_principal_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    actor_roles: Mapped[list | None] = mapped_column(JSON, nullable=True)
    actor_scopes: Mapped[list | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
