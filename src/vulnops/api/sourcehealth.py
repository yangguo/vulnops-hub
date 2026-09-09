from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.api.schemas import ProblemDetails, SourceHealthResponse
from vulnops.auth.dependencies import require_capability
from vulnops.intelligence.models import SourceStatus

router = APIRouter(
    tags=["source-health"],
    responses={
        401: {"model": ProblemDetails, "description": "Authentication required"},
        403: {"model": ProblemDetails, "description": "Insufficient permission"},
    },
)


def _serialize(status: SourceStatus) -> dict:
    return {
        "source": status.source,
        "scope": status.scope,
        "freshness": status.freshness,
        "cursor": status.cursor,
        "last_success_at": status.last_success_at.isoformat() if status.last_success_at else None,
        "last_checked_at": status.last_checked_at.isoformat() if status.last_checked_at else None,
        "last_error": status.last_error,
        "enabled": status.enabled,
    }


@router.get(
    "/organizations/{org_id}/source-health",
    dependencies=[Depends(require_capability("case:read"))],
)
async def source_health(
    org_id: str, db: Session = Depends(get_db)
) -> SourceHealthResponse:
    """Operational visibility for source freshness (global scope, read-only)."""

    rows = db.query(SourceStatus).filter_by(enabled=True).order_by(SourceStatus.source).all()
    items = [_serialize(s) for s in rows]
    degraded = [i["source"] for i in items if i["freshness"] in ("stale", "degraded")]
    return SourceHealthResponse(items=items, total=len(items), degraded_sources=degraded)
