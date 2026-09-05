from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from vulnops.db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class SourceSnapshot(Base):
    __tablename__ = "source_snapshots"
    __table_args__ = (
        UniqueConstraint("source", "source_record_id", "content_sha256", name="uq_snapshot_natural_key"),
        Index("ix_snapshot_source", "source"),
        Index("ix_snapshot_retrieved", "retrieved_at"),
        Index("ix_snapshot_correlation", "correlation_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., osv, kev, defectdojo
    source_record_id: Mapped[str] = mapped_column(String(256), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # retrieval metadata
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    provider_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)

    # provenance
    schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    adapter_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    object_uri: Mapped[str] = mapped_column(Text, nullable=False)
    validation_state: Mapped[str] = mapped_column(String(32), nullable=False, default="valid")  # valid|invalid|pending
    validation_errors: Mapped[str | None] = mapped_column(Text, nullable=True)

    # scope
    organization_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
