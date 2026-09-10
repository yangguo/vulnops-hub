from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.api.schemas import (
    BusinessServiceCreateRequest,
    BusinessServiceListResponse,
    BusinessServiceResponse,
    ProblemDetails,
    json_request_body,
    validate_request_body,
)
from vulnops.auth.dependencies import (
    AuthorizationError,
    authorize_capability,
    require_any_capability,
    require_capability,
    require_organization,
)
from vulnops.auth.models import Principal
from vulnops.services.models import BusinessService, normalize_business_service_name

router = APIRouter(
    tags=["services"],
    responses={
        401: {"model": ProblemDetails, "description": "Authentication required"},
        403: {"model": ProblemDetails, "description": "Insufficient permission"},
        409: {"model": ProblemDetails, "description": "Business service name conflict"},
    },
)


def _serialize_service(service: BusinessService) -> dict:
    return {
        "id": service.id,
        "organization_id": service.organization_id,
        "name": service.name,
        "owner_team": service.owner_team,
        "criticality": service.criticality,
        "created_at": service.created_at.isoformat(),
        "updated_at": service.updated_at.isoformat(),
    }


def _duplicate_service_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "type": "https://hub.example/problems/business-service-conflict",
            "title": "Business Service Conflict",
            "status": status.HTTP_409_CONFLICT,
            "code": "business_service_conflict",
            "detail": "A business service with this name already exists in the organization.",
        },
    )


@router.post(
    "/organizations/{org_id}/services",
    response_model=BusinessServiceResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra=json_request_body(BusinessServiceCreateRequest),
    dependencies=[Depends(require_any_capability("asset:write", "case:write"))],
)
async def create_business_service(
    org_id: str, request: Request, db: Session = Depends(get_db)
) -> dict:
    payload = validate_request_body(
        BusinessServiceCreateRequest,
        await request.json(),
        code="invalid_request_body",
    )
    normalized_name = normalize_business_service_name(payload.name)
    if (
        db.scalar(
            select(BusinessService.id).where(
                BusinessService.organization_id == org_id,
                BusinessService.name_normalized == normalized_name,
            )
        )
        is not None
    ):
        raise _duplicate_service_error()

    service = BusinessService(
        organization_id=org_id,
        name=payload.name,
        owner_team=payload.owner_team,
        criticality=payload.criticality,
    )
    db.add(service)
    try:
        db.commit()
    except IntegrityError:
        # The pre-check gives a useful fast path; the constraint handles races
        # between concurrent creators and legacy callers that bypass the API.
        db.rollback()
        raise _duplicate_service_error() from None
    db.refresh(service)
    return _serialize_service(service)


@router.get(
    "/organizations/{org_id}/services",
    response_model=BusinessServiceListResponse,
    dependencies=[Depends(require_capability("case:read"))],
)
async def list_business_services(org_id: str, db: Session = Depends(get_db)) -> dict:
    stmt = (
        select(BusinessService)
        .where(BusinessService.organization_id == org_id)
        .order_by(BusinessService.name.asc(), BusinessService.id.asc())
    )
    items = list(db.scalars(stmt).all())
    return {"items": [_serialize_service(service) for service in items], "total": len(items)}


@router.get(
    "/organizations/{org_id}/services/{service_id}",
    response_model=BusinessServiceResponse,
)
async def get_business_service(
    org_id: str,
    service_id: str,
    request: Request,
    principal: Principal = Depends(require_organization),
    db: Session = Depends(get_db),
) -> dict:
    # Authorize before resolving the row so a principal without case:read
    # cannot distinguish an existing service from a missing one.
    authorize_capability(request, principal, "case:read")
    service = db.scalar(
        select(BusinessService).where(
            BusinessService.id == service_id,
            BusinessService.organization_id == org_id,
        )
    )
    if service is None:
        raise AuthorizationError("resource_not_found")
    return _serialize_service(service)
