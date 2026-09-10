from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnops.assets.models import Asset
from vulnops.config import get_settings
from vulnops.services.models import BusinessService

OwnerSource = Literal["asset", "service", "default", "explicit"]


@dataclass(frozen=True, slots=True)
class ResolvedOwner:
    """An owner team together with the source that established ownership."""

    owner_team: str
    source: OwnerSource

    @property
    def team(self) -> str:
        """Short alias for callers that refer to the team rather than the field."""

        return self.owner_team


def _default_owner_team(default_owner_team: str | None) -> str:
    default = (default_owner_team or get_settings().default_case_owner_team or "unassigned").strip()
    return default or "unassigned"


def resolve_case_owner(
    session: Session,
    *,
    organization_id: str,
    asset_id: str | None = None,
    default_owner_team: str | None = None,
) -> ResolvedOwner:
    """Resolve an owner and preserve whether it came from inventory or fallback.

    Asset and service lookups are organization-scoped so a stale or malformed
    cross-organization reference cannot influence case assignment.  The
    configured default is a fallback source, not a string sentinel: a real
    asset or service owner whose display name happens to equal the default is
    still considered owned.
    """

    default = _default_owner_team(default_owner_team)
    if not asset_id:
        return ResolvedOwner(default, "default")

    asset = session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == organization_id,
        )
    )
    if asset is None:
        return ResolvedOwner(default, "default")

    owner = (asset.owner or "").strip()
    if owner:
        return ResolvedOwner(owner, "asset")

    if asset.business_service_id:
        service = session.scalar(
            select(BusinessService).where(
                BusinessService.id == asset.business_service_id,
                BusinessService.organization_id == organization_id,
            )
        )
        service_owner = (service.owner_team if service else "").strip()
        if service_owner:
            return ResolvedOwner(service_owner, "service")

    return ResolvedOwner(default, "default")


def resolve_case_owner_team(
    session: Session,
    *,
    organization_id: str,
    asset_id: str | None = None,
    default_owner_team: str | None = None,
) -> str:
    """Return only the team for legacy callers that do not need provenance."""

    return resolve_case_owner(
        session,
        organization_id=organization_id,
        asset_id=asset_id,
        default_owner_team=default_owner_team,
    ).owner_team
