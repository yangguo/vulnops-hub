from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.api.schemas import (
    AllowedTransitionsResponse,
    CaseCreateRequest,
    CaseCreateResponse,
    CaseDetailResponse,
    CaseListResponse,
    ProblemDetails,
    RiskApprovalRequest,
    RiskApprovalResponse,
    RiskDecisionCreateResponse,
    RiskDecisionRequest,
    RiskDecisionsResponse,
    TransitionRequest,
    TransitionResponse,
    VerificationsResponse,
    VerificationSubmitResponse,
    json_request_body,
    validate_request_body,
)
from vulnops.auth.dependencies import (
    AuthorizationError,
    authorize_capability,
    get_principal,
    require_capability,
    require_organization,
)
from vulnops.auth.models import Principal
from vulnops.cases.models import ALLOWED_TRANSITIONS, RemediationCase
from vulnops.cases.service import CaseService

router = APIRouter(
    tags=["cases"],
    responses={
        401: {"model": ProblemDetails, "description": "Authentication required"},
        403: {"model": ProblemDetails, "description": "Insufficient permission"},
    },
)


_CLIENT_IDENTITY_FIELDS = frozenset(
    {
        "actor",
        "actor_id",
        "actorId",
        "actor_role",
        "actorRole",
        "requested_by",
        "requestedBy",
        "requestedById",
        "requested_by_id",
        "requested_by_role",
        "requestedByRole",
        "requester",
        "requesterId",
        "requester_id",
        "requester_role",
        "requesterRole",
        "approver",
        "approverId",
        "approver_id",
        "approved_by",
        "approvedBy",
        "approvedById",
        "approved_by_id",
        "approver_role",
        "approverRole",
        "approved_by_role",
        "approvedByRole",
    }
)


def _reject_client_identity_fields(data: object) -> dict:
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=422,
            detail={
                "type": "https://hub.example/problems/invalid-request-body",
                "title": "Invalid Request Body",
                "status": 422,
                "code": "invalid_request_body",
                "detail": "request body must be a JSON object",
            },
        )
    supplied = sorted(_CLIENT_IDENTITY_FIELDS.intersection(data))
    if supplied:
        raise HTTPException(
            status_code=422,
            detail={
                "type": "https://hub.example/problems/identity-fields-forbidden",
                "title": "Identity Fields Forbidden",
                "status": 422,
                "code": "identity_fields_forbidden",
                "detail": "workflow actor identity is derived from the authenticated principal",
                "fields": supplied,
            },
        )
    return data


def _risk_problem(detail: str, *, code: str = "invalid_risk_decision") -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "type": f"https://hub.example/problems/{code}",
            "title": "Invalid Risk Decision"
            if code == "invalid_risk_decision"
            else "Invalid Risk Approval",
            "status": 422,
            "code": code,
            "detail": detail,
        },
    )


def _serialize_case(case: RemediationCase) -> dict:
    return {
        "id": case.id,
        "case_key": case.case_key,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "owner_team": case.owner_team,
        "assignee": case.assignee,
        "organization_id": case.organization_id,
        "policy_version": case.policy_version,
        "version": case.version,
        "etag": f'"{case.version}"',
        "due_at": case.due_at.isoformat() if case.due_at else None,
        "exposures": case.exposures,
        "sla_breached": case.sla_breached,
        "closure_reason": case.closure_reason,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }


def _serialize_risk_decision(d) -> dict:
    return {
        "id": d.id,
        "case_id": d.case_id,
        "type": d.type,
        "status": d.status,
        "scope_exposure_ids": d.scope_exposure_ids or [],
        "reason": d.reason,
        "compensating_controls": d.compensating_controls or [],
        "evidence_ids": d.evidence_ids or [],
        "requested_by": d.requested_by,
        "approver": d.approver,
        "approver_role": d.approver_role,
        "expires_at": d.expires_at.isoformat() if d.expires_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _serialize_verification(v) -> dict:
    return {
        "id": v.id,
        "case_id": v.case_id,
        "method": v.method,
        "asserted_result": v.asserted_result,
        "evidence_ids": v.evidence_ids or [],
        "coverage": v.coverage or {},
        "status": v.status,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }


def _parse_if_match(if_match: str | None) -> int | None:
    if not if_match:
        return None
    # Expected format: "123" or W/"123" or case-version-123 or etag
    original = if_match
    val = if_match.strip().strip('"').strip("'")
    # Try to handle W/ prefix
    if val.startswith("W/"):
        val = val[2:].strip().strip('"')
    # If contains etag like case-version-12, extract number
    if "case-version-" in val:
        try:
            return int(val.split("case-version-")[1])
        except Exception:
            raise ValueError(f"invalid If-Match value: {original}")
    # If just quoted version
    try:
        return int(val)
    except Exception:
        # If header was present but not parseable, treat as invalid -> conflict
        raise ValueError(f"invalid If-Match value: {original}")


@router.post(
    "/organizations/{org_id}/cases",
    response_model=CaseCreateResponse,
    openapi_extra=json_request_body(CaseCreateRequest),
    dependencies=[Depends(require_capability("case:write"))],
)
async def create_case(org_id: str, request: Request, db: Session = Depends(get_db)):
    data = _reject_client_identity_fields(await request.json())
    payload = validate_request_body(CaseCreateRequest, data, code="invalid_request_body")

    svc = CaseService(db)
    case = svc.create_case(
        organization_id=org_id,
        title=payload.title,
        owner_team=payload.owner_team,
        priority=payload.priority,
        exposures=payload.exposures,
        policy_version=payload.policy_version,
        assignee=payload.assignee,
    )
    return {
        "id": case.id,
        "case_key": case.case_key,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "owner_team": case.owner_team,
        "organization_id": case.organization_id,
        "version": case.version,
        "etag": f'"{case.version}"',
        "due_at": case.due_at.isoformat() if case.due_at else None,
    }


@router.get(
    "/organizations/{org_id}/cases",
    response_model=CaseListResponse,
    dependencies=[Depends(require_capability("case:read"))],
)
async def list_cases(
    org_id: str,
    status: str | None = None,
    priority: str | None = None,
    owner_team: str | None = None,
    assignee: str | None = None,
    sla_breached: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(
        default="-created_at", pattern=r"^-?(created_at|updated_at|due_at|priority)$"
    ),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    items, total = svc.list_cases(
        organization_id=org_id,
        status=status,
        priority=priority,
        owner_team=owner_team,
        assignee=assignee,
        sla_breached=sla_breached,
        page=page,
        page_size=page_size,
        sort=sort,
    )
    return {
        "items": [_serialize_case(c) for c in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get(
    "/organizations/{org_id}/cases/{case_id}",
    response_model=CaseDetailResponse,
    dependencies=[Depends(require_organization)],
)
async def get_case(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise AuthorizationError("resource_not_found")
    if case.organization_id != org_id:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "case:read")
    return _serialize_case(case)


@router.get(
    "/organizations/{org_id}/cases/{case_id}/allowed-transitions",
    response_model=AllowedTransitionsResponse,
    dependencies=[Depends(require_organization)],
)
async def allowed_transitions(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise AuthorizationError("resource_not_found")
    if case.organization_id != org_id:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "case:read")
    allowed = ALLOWED_TRANSITIONS.get(case.status, [])
    return {"case_id": case_id, "status": case.status, "allowed": allowed, "current": case.status}


@router.post(
    "/organizations/{org_id}/cases/{case_id}/transitions",
    response_model=TransitionResponse,
    openapi_extra=json_request_body(TransitionRequest),
    dependencies=[Depends(require_organization)],
)
async def transition_case(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    if_match: str | None = Header(default=None, alias="If-Match"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise AuthorizationError("resource_not_found")
    except ValueError:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "case:write")

    data = _reject_client_identity_fields(await request.json())
    payload = validate_request_body(TransitionRequest, data, code="invalid_request_body")
    target = payload.target
    reason = payload.reason
    extra = {}

    try:
        expected_version = _parse_if_match(if_match)
    except ValueError as ve:
        raise HTTPException(
            status_code=412,
            detail={
                "type": "https://hub.example/problems/precondition-failed",
                "title": "Precondition Failed",
                "status": 412,
                "code": "precondition_failed",
                "detail": str(ve),
            },
        )

    try:
        updated = svc.transition(
            case_id,
            target,
            actor=principal.subject,
            reason=reason,
            extra=extra,
            expected_version=expected_version,
            actor_provenance="authenticated_claim",
            actor_principal_type=principal.principal_type.value,
            actor_roles=principal.roles,
            actor_scopes=principal.scopes,
            request_id=getattr(request.state, "request_id", None),
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    except ValueError as ve:
        msg = str(ve).lower()
        if "conflict" in msg or "version" in msg:
            raise HTTPException(
                status_code=412,
                detail={
                    "type": "https://hub.example/problems/conflict",
                    "title": "Precondition Failed",
                    "status": 412,
                    "code": "conflict",
                    "detail": str(ve),
                },
            )
        if "not allowed" in msg:
            raise HTTPException(
                status_code=422,
                detail={
                    "type": "https://hub.example/problems/invalid-transition",
                    "title": "Invalid Transition",
                    "status": 422,
                    "code": "invalid_transition",
                    "detail": str(ve),
                },
            )
        raise HTTPException(status_code=422, detail=str(ve))

    return {
        "id": updated.id,
        "status": updated.status,
        "version": updated.version,
        "etag": f'"{updated.version}"',
    }


@router.post(
    "/organizations/{org_id}/cases/{case_id}/risk-decisions",
    response_model=RiskDecisionCreateResponse,
    openapi_extra=json_request_body(RiskDecisionRequest),
    dependencies=[Depends(require_organization)],
)
async def create_risk_decision(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    if_match: str | None = Header(default=None, alias="If-Match"),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise AuthorizationError("resource_not_found")
    except ValueError:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "risk:request")

    data = _reject_client_identity_fields(await request.json())
    payload = validate_request_body(RiskDecisionRequest, data, code="invalid_risk_decision")
    type_ = payload.type
    reason = payload.reason
    scope = payload.scope
    compensating = payload.compensating_controls
    evidence_ids = payload.evidence_ids
    expires_at = payload.expires_at

    # Handle If-Match if provided - check version
    if if_match:
        expected = _parse_if_match(if_match)
        if expected is not None and case.version != expected:
            raise HTTPException(status_code=412, detail="Precondition Failed: version mismatch")

    try:
        decision = svc.create_risk_decision(
            case_id,
            type=type_,
            reason=reason,
            expires_at=expires_at,
            compensating_controls=compensating,
            evidence_ids=evidence_ids,
            requested_by=principal.subject,
            actor=principal.subject,
            scope=scope,
            actor_provenance="authenticated_claim",
            actor_principal_type=principal.principal_type.value,
            actor_roles=principal.roles,
            actor_scopes=principal.scopes,
            request_id=getattr(request.state, "request_id", None),
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    except ValueError as ve:
        raise _risk_problem(str(ve))

    return {
        "id": decision.id,
        "type": decision.type,
        "status": decision.status,
        "reason": decision.reason,
        "expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
        "case_status": svc.get_case(case_id).status,
    }


@router.post(
    "/organizations/{org_id}/cases/{case_id}/risk-decisions/{decision_id}/approval",
    response_model=RiskApprovalResponse,
    openapi_extra=json_request_body(RiskApprovalRequest),
    dependencies=[Depends(require_organization)],
)
async def approve_risk_decision(
    org_id: str,
    case_id: str,
    decision_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise AuthorizationError("resource_not_found")
        decision = svc.get_risk_decision(decision_id)
        if decision.case_id != case_id:
            raise AuthorizationError("resource_not_found")
    except ValueError:
        raise AuthorizationError("resource_not_found")

    authorize_capability(request, principal, "risk:approve")
    data = _reject_client_identity_fields(await request.json())
    payload = validate_request_body(RiskApprovalRequest, data, code="invalid_risk_approval")
    outcome = payload.outcome
    reason = payload.reason

    try:
        decision = svc.approve_risk_decision(
            decision.id,
            outcome=outcome,
            reason=reason,
            actor=principal.subject,
            actor_principal_type=principal.principal_type.value,
            actor_roles=principal.roles,
            actor_capabilities=principal.capabilities,
            actor_provenance="authenticated_claim",
            actor_scopes=principal.scopes,
            request_id=getattr(request.state, "request_id", None),
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    except ValueError as ve:
        if "risk decision conflict" in str(ve).lower():
            raise HTTPException(
                status_code=409,
                detail={
                    "type": "https://hub.example/problems/risk-decision-conflict",
                    "title": "Risk Decision Conflict",
                    "status": 409,
                    "code": "risk_decision_conflict",
                    "detail": str(ve),
                },
            )
        raise _risk_problem(str(ve), code="invalid_risk_approval")

    return {
        "id": decision.id,
        "case_id": decision.case_id,
        "type": decision.type,
        "status": decision.status,
        "approver": decision.approver,
        "approver_role": decision.approver_role,
        "decided_at": decision.decided_at.isoformat() if decision.decided_at else None,
        "case_status": svc.get_case(case_id).status,
    }


@router.get(
    "/organizations/{org_id}/cases/{case_id}/risk-decisions",
    response_model=RiskDecisionsResponse,
    dependencies=[Depends(require_organization)],
)
async def list_risk_decisions(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise AuthorizationError("resource_not_found")
    if case.organization_id != org_id:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "case:read")
    decisions = svc.list_risk_decisions(case_id)
    return {"items": [_serialize_risk_decision(d) for d in decisions]}


@router.get(
    "/organizations/{org_id}/cases/{case_id}/verifications",
    response_model=VerificationsResponse,
    dependencies=[Depends(require_organization)],
)
async def list_verifications(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise AuthorizationError("resource_not_found")
    if case.organization_id != org_id:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "case:read")
    verifications = svc.list_verifications(case_id)
    return {"items": [_serialize_verification(v) for v in verifications]}


@router.post(
    "/organizations/{org_id}/cases/{case_id}/verifications",
    response_model=VerificationSubmitResponse,
    dependencies=[Depends(require_organization)],
)
async def submit_verification(
    org_id: str,
    case_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise AuthorizationError("resource_not_found")
    except ValueError:
        raise AuthorizationError("resource_not_found")
    authorize_capability(request, principal, "verification:write")

    data = _reject_client_identity_fields(await request.json())
    method = data.get("method") or data.get("type") or "unknown"
    evidence_ids = (
        data.get("evidence_ids") or data.get("evidenceIds") or data.get("evidence_ids") or []
    )
    coverage = data.get("coverage")
    asserted = data.get("asserted_result") or data.get("assertedResult")

    try:
        verification = svc.verify(
            case_id,
            method=method,
            evidence_ids=evidence_ids,
            coverage=coverage,
            actor=principal.subject,
            asserted_result=asserted,
            actor_provenance="authenticated_claim",
            actor_principal_type=principal.principal_type.value,
            actor_roles=principal.roles,
            actor_scopes=principal.scopes,
            request_id=getattr(request.state, "request_id", None),
            correlation_id=getattr(request.state, "correlation_id", None),
        )
    except ValueError as ve:
        msg = str(ve).lower()
        if "not allowed" in msg:
            raise HTTPException(
                status_code=422,
                detail={
                    "type": "https://hub.example/problems/invalid-transition",
                    "title": "Invalid Transition",
                    "status": 422,
                    "code": "invalid_transition",
                    "detail": str(ve),
                },
            )
        raise HTTPException(status_code=422, detail=str(ve))

    # Map to problem details if insufficient
    if verification.status == "insufficient_evidence":
        # Return 200 with status, but also ensure case not closed
        # For stricter API, could be 422; we support both
        return {
            "id": verification.id,
            "status": verification.status,
            "case_status": svc.get_case(case_id).status,
            "coverage": coverage,
        }
    if verification.status == "requires_approval":
        return {
            "id": verification.id,
            "status": verification.status,
            "case_status": svc.get_case(case_id).status,
        }

    return {
        "id": verification.id,
        "status": verification.status,
        "case_status": svc.get_case(case_id).status,
    }
