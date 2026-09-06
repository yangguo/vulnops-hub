"""Response models for the case read endpoints.

These exist so FastAPI emits typed response schemas into openapi/openapi.yaml;
the frontend console generates its TypeScript client from that file.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ProblemDetails(BaseModel):
    """Stable error envelope shared by authenticated API operations."""

    type: str
    title: str
    status: int
    code: str
    detail: str
    correlation_id: str | None = None
    fields: list[str] | None = None


class TransitionRequest(BaseModel):
    """Actor-free case transition request contract."""

    model_config = ConfigDict(extra="forbid")

    target: str | None = None
    to: str | None = None
    next_status: str | None = None
    reason: str | None = None


class RiskDecisionRequest(BaseModel):
    """Actor-free risk decision request contract."""

    model_config = ConfigDict(extra="forbid")

    type: str | None = None
    reason: str | None = None
    scope: dict[str, Any] | None = None
    compensating_controls: list[str] | None = None
    evidence_ids: list[str] | None = None
    expires_at: str | None = None


class RiskApprovalRequest(BaseModel):
    """Actor-free risk approval contract; identity comes from the token."""

    model_config = ConfigDict(extra="forbid")

    outcome: str | None = None
    decision: str | None = None
    reason: str | None = None


def json_request_body(model: type[BaseModel]) -> dict[str, Any]:
    """Build request-body metadata without validating before resource checks.

    The workflow routes intentionally parse raw JSON inside the endpoint so
    organization/resource authorization runs before body validation.  FastAPI
    still needs a typed OpenAPI contract, which is supplied from the same
    Pydantic models without adding a pre-endpoint body dependency.
    """

    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }


class TransitionResponse(BaseModel):
    id: str
    status: str
    version: int
    etag: str


class RiskDecisionCreateResponse(BaseModel):
    id: str
    type: str
    status: str
    reason: str
    expires_at: str | None = None
    case_status: str


class RiskApprovalResponse(BaseModel):
    id: str
    case_id: str
    type: str
    status: str
    approver: str | None = None
    approver_role: str | None = None
    decided_at: str | None = None
    case_status: str


class CaseDetailResponse(BaseModel):
    id: str
    case_key: str
    title: str
    status: str
    priority: str
    owner_team: str
    assignee: str | None = None
    organization_id: str
    policy_version: str | None = None
    version: int
    etag: str
    due_at: str | None = None
    exposures: list[str] | None = None
    sla_breached: bool
    closure_reason: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class CaseListResponse(BaseModel):
    items: list[CaseDetailResponse]
    total: int
    page: int
    page_size: int


class RiskDecisionResponse(BaseModel):
    id: str
    case_id: str
    type: str
    status: str
    scope_exposure_ids: list[str] | None = None
    reason: str
    compensating_controls: list[str] | None = None
    evidence_ids: list[str] | None = None
    requested_by: str
    approver: str | None = None
    approver_role: str | None = None
    expires_at: str | None = None
    created_at: str | None = None


class RiskDecisionsResponse(BaseModel):
    items: list[RiskDecisionResponse]


class VerificationResponse(BaseModel):
    id: str
    case_id: str
    method: str
    asserted_result: str | None = None
    evidence_ids: list[str] | None = None
    coverage: dict[str, Any] | None = None
    status: str
    created_at: str | None = None


class VerificationsResponse(BaseModel):
    items: list[VerificationResponse]
