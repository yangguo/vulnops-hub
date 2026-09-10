from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column

from vulnops.db import Base


def _utcnow():
    return datetime.now(UTC)


def _gen_id() -> str:
    return f"svc_{uuid.uuid4().hex[:12]}"


def normalize_business_service_name(name: str) -> str:
    """Return the case-insensitive identity key for a business-service name."""

    return name.strip().casefold()


class BusinessService(Base):
    """An organization-owned service with a case-insensitive org-scoped name.

    ``name_normalized`` is the persisted identity key.  The ORM listener keeps
    it synchronized with the display name so the database can enforce the
    identity even when two requests race to create the same service.
    """

    __tablename__ = "business_services"
    __table_args__ = (
        Index("ix_business_service_org", "organization_id"),
        UniqueConstraint("organization_id", "name", name="uq_business_service_org_name"),
        UniqueConstraint(
            "organization_id",
            "name_normalized",
            name="uq_business_service_org_name_normalized",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_gen_id)
    organization_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_team: Mapped[str] = mapped_column(String(128), nullable=False)
    criticality: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


@event.listens_for(BusinessService, "before_insert")
@event.listens_for(BusinessService, "before_update")
def _sync_business_service_name_normalized(_mapper, _connection, target: BusinessService) -> None:
    target.name_normalized = normalize_business_service_name(target.name)
