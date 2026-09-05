from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Index, Text, Float, JSON, UniqueConstraint, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulnops.db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_published", "published_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # CVE-ID or internal
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    aliases: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class VulnerabilityAlias(Base):
    __tablename__ = "vulnerability_aliases"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "alias", name="uq_vuln_alias"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    alias: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AffectedRange(Base):
    __tablename__ = "affected_ranges"
    __table_args__ = (
        Index("ix_range_vuln", "vulnerability_id"),
        Index("ix_range_ecosystem", "ecosystem"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    ecosystem: Mapped[str | None] = mapped_column(String(64), nullable=True)
    purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    introduced: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fixed: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_affected: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class AdvisoryAssertion(Base):
    __tablename__ = "advisory_assertions"
    __table_args__ = (
        Index("ix_advisory_vuln", "vulnerability_id"),
        Index("ix_advisory_source", "source"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_snapshot_id: Mapped[str] = mapped_column(String(64), ForeignKey("source_snapshots.id"), nullable=True)
    content: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    kev: Mapped[bool | None] = mapped_column(nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    vex_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)


class SourceStatus(Base):
    __tablename__ = "source_statuses"
    __table_args__ = (
        UniqueConstraint("source", "scope", name="uq_source_scope"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="global")
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False, default="fresh")  # fresh|stale|degraded|unknown
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)
