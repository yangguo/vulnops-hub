from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulnops.db import Base


def _utcnow():
    return datetime.now(UTC)


class SbomDocument(Base):
    __tablename__ = "sbom_documents"
    __table_args__ = (
        UniqueConstraint("content_sha256", "organization_id", name="uq_sbom_digest_org"),
        Index("ix_sbom_org", "organization_id"),
        Index("ix_sbom_serial", "serial_number"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    serial_number: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    format: Mapped[str] = mapped_column(String(32), nullable=False)  # cyclonedx, spdx
    spec_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_size: Mapped[int] = mapped_column(Integer, nullable=False)
    object_uri: Mapped[str] = mapped_column(Text, nullable=False)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_state: Mapped[str] = mapped_column(String(32), nullable=False, default="valid")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (
        Index("ix_component_purl", "purl"),
        Index("ix_component_ecosystem", "ecosystem"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(64), nullable=True)
    normalized_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    raw_name: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cpe: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class ComponentOccurrence(Base):
    __tablename__ = "component_occurrences"
    __table_args__ = (
        Index("ix_occurrence_sbom", "sbom_id"),
        Index("ix_occurrence_component", "component_id"),
        Index("ix_occurrence_purl", "purl"),
        Index("ix_occurrence_asset", "asset_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sbom_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("sbom_documents.id"), nullable=False
    )
    component_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("components.id"), nullable=True
    )
    asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(64), nullable=True)
    normalized_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    raw_name: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cpe: Mapped[str | None] = mapped_column(Text, nullable=True)
    version_scheme: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # evidence
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="sbom")
    evidence_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    dependency_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    sbom: Mapped[SbomDocument] = relationship()
    component: Mapped[Component | None] = relationship()
