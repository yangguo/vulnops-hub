from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.api.schemas import (
    ProblemDetails,
    ExposureItem,
    ExposureListResponse,
    ExposureReviewResponse,
)
from vulnops.auth.dependencies import get_principal, require_capability
from vulnops.auth.models import Principal
from vulnops.db.models.audit_event import AuditEvent
from vulnops.matching.models import Exposure

router = APIRouter(
    tags=["exposures"],
    responses={
        401: {"model": ProblemDetails, "description": "Authentication required"},
        403: {"model": ProblemDetails, "description": "Insufficient permission"},
    },
)


@router.get(
    "/organizations/{org_id}/exposures",
    dependencies=[Depends(require_capability("case:read"))],
)
async def list_exposures(
    org_id: str,
    state: str = Query(default="candidate"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> ExposureListResponse:
    del principal  # org scoping is enforced by the query itself
    query = db.query(Exposure).filter(Exposure.organization_id == org_id, Exposure.state == state)
    total = query.count()
    rows = (
        query.order_by(Exposure.priority.asc(), Exposure.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return ExposureListResponse(
        items=[_serialize(e) for e in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/organizations/{org_id}/exposures/{exposure_id}/review",
    dependencies=[Depends(require_capability("risk:request"))],
)
async def review_exposure(
    org_id: str,
    exposure_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> ExposureReviewResponse:
    body = await request.json()
    decision = str(body.get("decision") or "").strip()
    reason = str(body.get("reason") or "").strip()
    if decision not in ("confirmed", "not_affected"):
        return _problem(422, "invalid_decision", "decision must be confirmed or not_affected")
    if not reason:
        return _problem(422, "invalid_decision", "reason is required for a review decision")

    exposure = (
        db.query(Exposure)
        .filter(
            Exposure.id == exposure_id,
            Exposure.organization_id == org_id,
        )
        .first()
    )
    if exposure is None:
        return _problem(404, "resource_not_found", "exposure not found")
    if exposure.state not in ("candidate", "under_review"):
        return _problem(422, "invalid_state", f"exposure state {exposure.state} is not reviewable")

    exposure.state = "active" if decision == "confirmed" else "not_affected"
    exposure.match_class = "confirmed" if decision == "confirmed" else "not_affected"
    db.add(
        AuditEvent(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            actor=principal.subject,
            action="exposure.reviewed",
            subject_type="exposure",
            subject_id=exposure.id,
            new_state=exposure.state,
            reason=reason,
            organization_id=org_id,
        )
    )
    db.commit()
    return ExposureReviewResponse(
        id=exposure.id, state=exposure.state, match_class=exposure.match_class
    )


def _serialize(e: Exposure) -> ExposureItem:
    return ExposureItem(
        id=e.id,
        vulnerability_id=e.vulnerability_id,
        match_class=e.match_class,
        confidence=e.confidence,
        state=e.state,
        priority=e.priority,
        detection_context=e.detection_context,
        component_occurrence_id=e.component_occurrence_id,
        asset_id=e.asset_id,
        first_observed_at=e.first_observed_at.isoformat() if e.first_observed_at else None,
        last_observed_at=e.last_observed_at.isoformat() if e.last_observed_at else None,
    )


def _problem(status: int, code: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "type": f"https://hub.example/problems/{code}",
            "title": code.replace("_", " ").title(),
            "status": status,
            "code": code,
            "detail": detail,
        },
    )
