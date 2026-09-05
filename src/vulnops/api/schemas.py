"""Response models for the case read endpoints.

These exist so FastAPI emits typed response schemas into openapi/openapi.yaml;
the frontend console generates its TypeScript client from that file.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


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
