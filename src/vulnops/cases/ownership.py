from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnops.assets.models import Asset
from vulnops.config import get_settings
from vulnops.services.models import BusinessService


def resolve_case_owner_team(
    session: Session,
    *,
    organization_id: str,
    asset_id: str | None = None,
    default_owner_team: str | None = None,
) -> str:
    """Resolve a case owner from asset ownership, service ownership, or default.

    Asset and service lookups are organization-scoped so a stale or malformed
    cross-organization reference cannot influence case assignment.
    ``default_owner_team`` is injectable for workers and tests; callers that do
    not provide it use the configured default.
    """

    default = default_owner_team or get_settings().default_case_owner_team
    if not asset_id:
        return default

    asset = session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == organization_id,
        )
    )
    if asset is None:
        return default

    owner = (asset.owner or "").strip()
    if owner:
        return owner

    if asset.business_service_id:
        service = session.scalar(
            select(BusinessService).where(
                BusinessService.id == asset.business_service_id,
                BusinessService.organization_id == organization_id,
            )
        )
        service_owner = (service.owner_team if service else "").strip()
        if service_owner:
            return service_owner

    return default
