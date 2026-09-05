from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Index, Float, JSON, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from vulnops.db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Exposure(Base):
    __tablename__ = "exposures"
    __table_args__ = (
        Index("ix_exposure_org", "organization_id"),
        Index("ix_exposure_asset", "asset_id"),
        Index("ix_exposure_vuln", "vulnerability_id"),
        Index("ix_exposure_state", "state"),
        Index("ix_exposure_priority", "priority"),
        Index("ix_exposure_match_class", "match_class"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    component_occurrence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_context: Mapped[str | None] = mapped_column(String(64), nullable=True)

    match_class: Mapped[str] = mapped_column(String(32), nullable=False)  # confirmed|deterministic|corroborated|candidate|not_affected|superseded
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority: Mapped[str | None] = mapped_column(String(16), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="active")  # candidate|active|under_review|not_affected|remediated|superseded

    matched_rules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence_refs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    limitations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    matcher_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class MatchEvidence(Base):
    __tablename__ = "match_evidence"
    __table_args__ = (
        Index("ix_match_evidence_exposure", "exposure_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    exposure_id: Mapped[str] = mapped_column(String(64), ForeignKey("exposures.id"), nullable=False)
    component_purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    matcher_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
