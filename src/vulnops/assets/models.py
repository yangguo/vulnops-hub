from __future__ import annotations

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Index, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulnops.db import Base


def _utcnow():
    return datetime.now(timezone.utc)


def _gen_id(prefix: str = "alias"):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_asset_org", "organization_id"),
        Index("ix_asset_type", "type"),
        Index("ix_asset_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False, default="host")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    data_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    internet_exposure: Mapped[str | None] = mapped_column(String(32), nullable=True)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    business_service_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    aliases: Mapped[list["AssetAlias"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class AssetAlias(Base):
    __tablename__ = "asset_aliases"
    __table_args__ = (
        Index("ix_alias_namespace_value", "namespace", "value"),
        Index("ix_alias_org", "organization_id"),
        Index("ix_alias_asset", "asset_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: _gen_id("alias"))
    asset_id: Mapped[str] = mapped_column(String(64), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    namespace: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    asset: Mapped[Asset] = relationship(back_populates="aliases")
