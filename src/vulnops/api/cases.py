from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.cases.models import ALLOWED_TRANSITIONS, RemediationCase
from vulnops.cases.service import CaseService

router = APIRouter(tags=["cases"])


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
        "exposures": case.exposures or [],
        "sla_breached": case.sla_breached,
        "closure_reason": case.closure_reason,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
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


@router.post("/organizations/{org_id}/cases")
async def create_case(org_id: str, request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    title = data.get("title") or data.get("name") or "Untitled case"
    owner_team = data.get("owner_team") or data.get("owner") or "unassigned"
    priority = data.get("priority", "P2")
    exposures = data.get("exposures") or data.get("exposure_ids") or []
    policy_version = data.get("policy_version")
    assignee = data.get("assignee")

    svc = CaseService(db)
    case = svc.create_case(
        organization_id=org_id,
        title=title,
        owner_team=owner_team,
        priority=priority,
        exposures=exposures,
        policy_version=policy_version,
        assignee=assignee,
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


@router.get("/organizations/{org_id}/cases")
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


@router.get("/organizations/{org_id}/cases/{case_id}")
async def get_case(org_id: str, case_id: str, db: Session = Depends(get_db)):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Case not found")
    return _serialize_case(case)


@router.get("/organizations/{org_id}/cases/{case_id}/allowed-transitions")
async def allowed_transitions(org_id: str, case_id: str, db: Session = Depends(get_db)):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")
    allowed = ALLOWED_TRANSITIONS.get(case.status, [])
    return {"case_id": case_id, "status": case.status, "allowed": allowed, "current": case.status}


@router.post("/organizations/{org_id}/cases/{case_id}/transitions")
async def transition_case(
    org_id: str,
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
    if_match: str | None = Header(default=None, alias="If-Match"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    data = await request.json()
    target = data.get("target") or data.get("to") or data.get("next_status")
    if not target:
        raise HTTPException(status_code=400, detail="target required")
    reason = data.get("reason")
    actor = data.get("actor") or data.get("requested_by") or "api"
    extra = {k: v for k, v in data.items() if k not in ("target", "reason", "actor")}

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
    svc = CaseService(db)
    try:
        # Verify org match
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise HTTPException(status_code=404, detail="Case not found")
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        updated = svc.transition(
            case_id,
            target,
            actor=actor,
            reason=reason,
            extra=extra,
            expected_version=expected_version,
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


@router.post("/organizations/{org_id}/cases/{case_id}/risk-decisions")
async def create_risk_decision(
    org_id: str,
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
    if_match: str | None = Header(default=None, alias="If-Match"),
):
    data = await request.json()
    type_ = data.get("type")
    reason = data.get("reason") or "no reason"
    scope = data.get("scope")
    compensating = data.get("compensating_controls") or data.get("compensatingControls")
    evidence_ids = data.get("evidence_ids") or data.get("evidenceIds") or []
    requested_by = (
        data.get("requested_by") or data.get("requestedBy") or data.get("requester") or "unknown"
    )
    approver = data.get("approver") or data.get("approved_by")
    approver_role = data.get("approver_role") or data.get("approverRole")
    expires_at_str = data.get("expires_at") or data.get("expiresAt")
    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            expires_at = None

    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise HTTPException(status_code=404, detail="Case not found")
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")

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
            requested_by=requested_by,
            approver=approver,
            approver_role=approver_role,
            actor=requested_by,
            scope=scope,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=422,
            detail={
                "type": "https://hub.example/problems/invalid-transition",
                "title": "Invalid Risk Decision",
                "status": 422,
                "code": "invalid_transition",
                "detail": str(ve),
            },
        )

    return {
        "id": decision.id,
        "type": decision.type,
        "status": decision.status,
        "reason": decision.reason,
        "expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
        "case_status": svc.get_case(case_id).status,
    }


@router.post("/organizations/{org_id}/cases/{case_id}/verifications")
async def submit_verification(
    org_id: str,
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    data = await request.json()
    method = data.get("method") or data.get("type") or "unknown"
    evidence_ids = (
        data.get("evidence_ids") or data.get("evidenceIds") or data.get("evidence_ids") or []
    )
    coverage = data.get("coverage")
    asserted = data.get("asserted_result") or data.get("assertedResult")

    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
        if case.organization_id != org_id:
            raise HTTPException(status_code=404, detail="Case not found")
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        verification = svc.verify(
            case_id,
            method=method,
            evidence_ids=evidence_ids,
            coverage=coverage,
            actor=data.get("actor") or "api",
            asserted_result=asserted,
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
