from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.api.schemas import ProblemDetails
from vulnops.assets.models import Asset
from vulnops.assets.reconciliation import AssetService
from vulnops.auth.dependencies import require_capability

router = APIRouter(
    tags=["assets"],
    responses={
        401: {"model": ProblemDetails, "description": "Authentication required"},
        403: {"model": ProblemDetails, "description": "Insufficient permission"},
    },
)

_VALID_CRITICALITY = {"critical", "high", "medium", "low"}
_VALID_EXPOSURE = {"external", "internal", "unknown"}


@router.post(
    "/organizations/{org_id}/assets/import",
    dependencies=[Depends(require_capability("asset:write"))],
)
async def import_assets(org_id: str, request: Request, db: Session = Depends(get_db)) -> dict:
    """Import a CSV asset inventory (CMDB export).

    Header row required; recognized columns: hostname (required identity),
    name, criticality, environment, owner, internet_exposure, type.
    Existing assets are matched by hostname alias and updated in place;
    unknown hostnames create assets with a hostname alias; ambiguous alias
    collisions are skipped for review, never merged.
    """
    body = (await request.body()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(body))
    if not reader.fieldnames:
        return {"created": 0, "updated": 0, "skipped": 0, "skipped_details": [], "total": 0}
    fieldnames = [f.strip().lower() for f in reader.fieldnames]
    reader.fieldnames = fieldnames
    if "hostname" not in fieldnames:
        return {
            "created": 0,
            "updated": 0,
            "skipped": 0,
            "skipped_details": [{"row": 1, "reason": "missing required 'hostname' column"}],
            "total": 0,
        }

    service = AssetService(db)
    created = updated = skipped = 0
    skipped_details: list[dict] = []
    total = 0
    for row_number, row in enumerate(reader, start=2):  # header is row 1
        hostname = (row.get("hostname") or "").strip()
        if not hostname:
            skipped += 1
            skipped_details.append({"row": row_number, "reason": "empty hostname"})
            continue
        total += 1
        criticality = (row.get("criticality") or "medium").strip().lower()
        if criticality not in _VALID_CRITICALITY:
            criticality = "medium"
        internet_exposure = (row.get("internet_exposure") or "").strip().lower()
        if internet_exposure not in _VALID_EXPOSURE:
            internet_exposure = None
        environment = (row.get("environment") or "").strip() or None
        owner = (row.get("owner") or "").strip() or None
        asset_type = (row.get("type") or "host").strip() or "host"

        result = service.reconcile_alias("hostname", hostname, organization_id=org_id)
        if result.status == "ambiguous":
            skipped += 1
            skipped_details.append(
                {"row": row_number, "reason": result.reason, "hostname": hostname}
            )
            continue
        if result.status == "resolved":
            asset = db.get(Asset, result.asset_id)
            asset.criticality = criticality
            asset.environment = environment or asset.environment
            asset.owner = owner or asset.owner
            asset.internet_exposure = internet_exposure or asset.internet_exposure
            updated += 1
        else:
            asset = service.create_asset(
                name=(row.get("name") or "").strip() or hostname,
                type=asset_type,
                organization_id=org_id,
                criticality=criticality,
                environment=environment,
            )
            asset.owner = owner
            asset.internet_exposure = internet_exposure
            service.add_alias(asset.id, "hostname", hostname, org_id)
            created += 1
    db.commit()
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "skipped_details": skipped_details[:20],
        "total": total,
    }
