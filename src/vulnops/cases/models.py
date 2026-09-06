from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from vulnops.db import Base


def _utcnow():
    return datetime.now(UTC)


class CaseStatus:
    NEW = "new"
    TRIAGE = "triage"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    AWAITING_VERIFICATION = "awaiting_verification"
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"
    NOT_APPLICABLE = "not_applicable"
    REOPENED = "reopened"


# Allowed transitions map per docs/data-model.md:135
ALLOWED_TRANSITIONS = {
    CaseStatus.NEW: [CaseStatus.TRIAGE],
    CaseStatus.TRIAGE: [CaseStatus.ASSIGNED, CaseStatus.NOT_APPLICABLE, CaseStatus.RISK_ACCEPTED],
    CaseStatus.ASSIGNED: [CaseStatus.IN_PROGRESS, CaseStatus.TRIAGE],
    CaseStatus.IN_PROGRESS: [CaseStatus.AWAITING_VERIFICATION, CaseStatus.TRIAGE],
    CaseStatus.AWAITING_VERIFICATION: [CaseStatus.CLOSED, CaseStatus.IN_PROGRESS],
    CaseStatus.RISK_ACCEPTED: [CaseStatus.TRIAGE],
    CaseStatus.NOT_APPLICABLE: [CaseStatus.TRIAGE],
    CaseStatus.CLOSED: [CaseStatus.REOPENED],
    CaseStatus.REOPENED: [CaseStatus.TRIAGE],
}


PRIORITY_SLA_DAYS = {
    "P0": 1,
    "P1": 3,
    "P2": 7,
    "P3": 30,
    "P4": 90,
}


class RemediationCase(Base):
    __tablename__ = "remediation_cases"
    __table_args__ = (
        Index("ix_case_org", "organization_id"),
        Index("ix_case_status", "status"),
        Index("ix_case_priority", "priority"),
        Index("ix_case_owner", "owner_team"),
        Index("ix_case_due", "due_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_team: Mapped[str] = mapped_column(String(128), nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=CaseStatus.NEW)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # for If-Match
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    closure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_ticket_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exposures: Mapped[list | None] = mapped_column(JSON, nullable=True)  # list of exposure ids
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class CaseExposure(Base):
    __tablename__ = "case_exposures"
    __table_args__ = (
        Index("ix_case_exposure_case", "case_id"),
        Index("ix_case_exposure_exposure", "exposure_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("remediation_cases.id"), nullable=False
    )
    exposure_id: Mapped[str] = mapped_column(String(64), nullable=False)


class SlaClock(Base):
    __tablename__ = "sla_clocks"
    __table_args__ = (Index("ix_sla_case", "case_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("remediation_cases.id"), nullable=False
    )
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    breached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class RiskDecision(Base):
    __tablename__ = "risk_decisions"
    __table_args__ = (
        Index("ix_risk_case", "case_id"),
        Index("ix_risk_status", "status"),
        Index("ix_risk_expiry", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("remediation_cases.id"), nullable=False
    )
    type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # risk_accepted, false_positive, not_affected etc.
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )  # pending, approved, revoked, expired
    scope_exposure_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_by_provenance: Mapped[str] = mapped_column(
        String(32), nullable=False, default="legacy_request"
    )
    approver: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approver_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approver_provenance: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approver_principal_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class Verification(Base):
    __tablename__ = "verifications"
    __table_args__ = (Index("ix_verif_case", "case_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("remediation_cases.id"), nullable=False
    )
    method: Mapped[str] = mapped_column(String(64), nullable=False)
    asserted_result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    coverage: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # closed|insufficient_evidence|requires_approval etc.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
