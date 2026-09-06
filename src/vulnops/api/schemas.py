"""Response models for the case read endpoints.

These exist so FastAPI emits typed response schemas into openapi/openapi.yaml;
the frontend console generates its TypeScript client from that file.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, TypeVar

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

RequestModel = TypeVar("RequestModel", bound=BaseModel)


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

    target: str = Field(
        min_length=1,
        validation_alias=AliasChoices("target", "to", "next_status"),
    )
    reason: str | None = None


class RiskDecisionRequest(BaseModel):
    """Actor-free risk decision request contract."""

    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "risk_accepted",
        "waiver",
        "compensating_control",
        "false_positive",
        "not_affected",
    ]
    reason: str = Field(min_length=1)
    scope: dict[str, Any] | None = None
    compensating_controls: list[str] | None = Field(
        default=None,
        validation_alias=AliasChoices("compensating_controls", "compensatingControls"),
    )
    evidence_ids: list[str] = Field(
        min_length=1,
        validation_alias=AliasChoices("evidence_ids", "evidenceIds"),
    )
    expires_at: datetime = Field(
        description="Timezone-aware timestamp in the future; final future validation is domain-owned.",
        validation_alias=AliasChoices("expires_at", "expiresAt"),
    )

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, value: object) -> object:
        supported = {
            "risk_accepted",
            "waiver",
            "compensating_control",
            "false_positive",
            "not_affected",
        }
        if value not in supported:
            raise ValueError("unsupported risk decision type")
        return value

    @field_validator("reason", mode="before")
    @classmethod
    def validate_reason(cls, value: object) -> object:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("risk decision reason is required")
        return value

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def validate_evidence_ids(cls, value: object) -> object:
        if not isinstance(value, list) or not value:
            raise ValueError("risk decision evidence_ids must contain at least one item")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError("risk decision evidence_ids must contain only nonblank strings")
        return value

    @field_validator("expires_at", mode="before")
    @classmethod
    def validate_expires_at(cls, value: object) -> object:
        if value is None:
            raise ValueError("risk decision expires_at is required")
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError("risk decision expires_at must be an ISO-8601 timestamp") from exc
        if not isinstance(value, datetime):
            raise ValueError("risk decision expires_at must be an ISO-8601 timestamp")
        try:
            offset = value.utcoffset()
        except (OverflowError, RuntimeError, TypeError, ValueError) as exc:
            raise ValueError("risk decision expires_at must be timezone-aware") from exc
        if value.tzinfo is None or offset is None:
            raise ValueError("risk decision expires_at must be timezone-aware")
        return value


class RiskApprovalRequest(BaseModel):
    """Actor-free risk approval contract; identity comes from the token."""

    model_config = ConfigDict(extra="forbid")

    outcome: Literal["approve", "reject"] = Field(
        validation_alias=AliasChoices("outcome", "decision")
    )
    reason: str = Field(min_length=1)

    @field_validator("outcome", mode="before")
    @classmethod
    def validate_outcome(cls, value: object) -> object:
        if not isinstance(value, str) or value.strip().lower() not in {"approve", "reject"}:
            raise ValueError("risk decision outcome must be approve or reject")
        return value.strip().lower()

    @field_validator("reason", mode="before")
    @classmethod
    def validate_reason(cls, value: object) -> object:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("approval reason is required")
        return value


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


def validate_request_body(
    model: type[RequestModel], data: dict[str, Any], *, code: str
) -> RequestModel:
    """Validate after authorization while preserving stable problem details."""

    from fastapi import HTTPException
    from pydantic import ValidationError

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        errors = exc.errors()
        fields = sorted({str(error["loc"][0]) for error in errors if error.get("loc")})
        extra_fields = sorted(
            {
                str(error["loc"][0])
                for error in errors
                if error.get("type") == "extra_forbidden" and error.get("loc")
            }
        )
        if extra_fields:
            detail = "request body contains unsupported fields"
            error_code = "invalid_request_body"
            error_fields = extra_fields
        else:
            error = errors[0]
            context = error.get("ctx") or {}
            custom_error = context.get("error")
            detail = (
                str(custom_error)
                if custom_error is not None
                else _missing_field_detail(model, error)
            )
            error_code = code
            error_fields = fields or None
        title = {
            "invalid_request_body": "Invalid Request Body",
            "invalid_risk_decision": "Invalid Risk Decision",
            "invalid_risk_approval": "Invalid Risk Approval",
        }.get(error_code, "Invalid Request Body")
        raise HTTPException(
            status_code=422,
            detail={
                "type": f"https://hub.example/problems/{error_code}",
                "title": title,
                "status": 422,
                "code": error_code,
                "detail": detail,
                **({"fields": error_fields} if error_fields else {}),
            },
        ) from exc


def _missing_field_detail(model: type[BaseModel], error: dict[str, Any]) -> str:
    field = str(error.get("loc", ("request",))[0])
    if model is TransitionRequest and field == "target":
        return "target required"
    if model is RiskDecisionRequest:
        return {
            "type": "unsupported risk decision type",
            "reason": "risk decision reason is required",
            "evidence_ids": "risk decision evidence_ids must contain at least one item",
            "expires_at": "risk decision expires_at is required",
        }.get(field, "invalid risk decision request")
    if model is RiskApprovalRequest:
        return {
            "outcome": "outcome required",
            "reason": "approval reason required",
        }.get(field, "invalid risk approval request")
    return "invalid request body"


class TransitionResponse(BaseModel):
    id: str
    status: str
    version: int
    etag: str


class CaseCreateResponse(BaseModel):
    id: str
    case_key: str
    title: str
    status: str
    priority: str
    owner_team: str
    organization_id: str
    version: int
    etag: str
    due_at: str | None = None


class AllowedTransitionsResponse(BaseModel):
    case_id: str
    status: str
    allowed: list[str]
    current: str


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


class VerificationSubmitResponse(BaseModel):
    id: str
    status: str
    case_status: str
    coverage: dict[str, Any] | None = None


class SbomSubmitResponse(BaseModel):
    id: str
    sbom_id: str
    submission_id: str
    content_sha256: str
    content_hash: str
    digest: str
    status: str
    received_at: str


class SbomResponse(BaseModel):
    id: str
    organization_id: str
    format: str
    spec_version: str | None = None
    content_sha256: str
    object_uri: str
    created_at: str


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
