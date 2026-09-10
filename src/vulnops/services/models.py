from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnops.db import Base


def _utcnow():
    return datetime.now(UTC)


def _gen_id() -> str:
    return f"svc_{uuid.uuid4().hex[:12]}"


class BusinessService(Base):
    """An organization-owned business service used for asset ownership."""

    __tablename__ = "business_services"
    __table_args__ = (
        Index("ix_business_service_org", "organization_id"),
        Index("ix_business_service_org_name", "organization_id", "name"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_gen_id)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_team: Mapped[str] = mapped_column(String(128), nullable=False)
    criticality: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
