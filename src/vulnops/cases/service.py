from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from vulnops.cases.models import (
    ALLOWED_TRANSITIONS,
    CaseStatus,
    RemediationCase,
    RiskDecision,
    SlaClock,
    Verification,
)
from vulnops.cases.sla import calculate_due_date
from vulnops.cases.verification import evaluate_coverage
from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.outbox_event import OutboxEvent


def _utcnow():
    return datetime.now(UTC)


def _ensure_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _gen_case_key():
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"


_LEGACY_PROVENANCE = "legacy_request"
_AUTHENTICATED_PROVENANCE = "authenticated_claim"
_APPROVER_ROLE_ORDER = ("risk_approver", "security_lead", "policy_admin", "admin")
_SUPPORTED_RISK_DECISION_TYPES = frozenset(
    {"risk_accepted", "waiver", "compensating_control", "false_positive", "not_affected"}
)


def _actor_audit_fields(
    *,
    actor_provenance: str,
    actor_principal_type: str | None,
    actor_roles: Iterable[str] | None,
    actor_scopes: Iterable[str] | None,
) -> dict[str, Any]:
    if actor_provenance not in {_LEGACY_PROVENANCE, _AUTHENTICATED_PROVENANCE}:
        raise ValueError("actor provenance must be legacy_request or authenticated_claim")
    return {
        "actor_provenance": actor_provenance,
        "actor_principal_type": actor_principal_type,
        "actor_roles": sorted({role for role in (actor_roles or ()) if role}),
        "actor_scopes": sorted({scope for scope in (actor_scopes or ()) if scope}),
    }


def _approval_role(actor_roles: Iterable[str] | None) -> str | None:
    normalized = {role.strip().lower() for role in (actor_roles or ()) if role.strip()}
    return next((role for role in _APPROVER_ROLE_ORDER if role in normalized), None)


def _trace_payload(
    *,
    actor_fields: dict[str, Any],
    actor: str,
    organization_id: str,
    request_id: str | None,
    correlation_id: str,
) -> dict[str, Any]:
    principal_type = actor_fields["actor_principal_type"]
    roles = actor_fields["actor_roles"]
    scopes = actor_fields["actor_scopes"]
    return {
        "actor": actor,
        "actor_subject": actor,
        "organization_id": organization_id,
        "request_id": request_id,
        "correlation_id": correlation_id,
        "principal_type": principal_type,
        "roles": roles,
        "scopes": scopes,
        "actor_principal_type": principal_type,
        "actor_roles": roles,
        "actor_scopes": scopes,
    }


def _validate_evidence_ids(evidence_ids: Any) -> None:
    if not isinstance(evidence_ids, list) or not evidence_ids:
        raise ValueError("risk decision evidence_ids must contain at least one item")
    if any(not isinstance(item, str) or not item.strip() for item in evidence_ids):
        raise ValueError("risk decision evidence_ids must contain only nonblank strings")


def _validate_risk_decision_request(
    *,
    type: Any,
    reason: Any,
    evidence_ids: Any,
    expires_at: Any,
) -> None:
    if type not in _SUPPORTED_RISK_DECISION_TYPES:
        raise ValueError("unsupported risk decision type")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("risk decision reason is required")
    _validate_evidence_ids(evidence_ids)
    if expires_at is None:
        raise ValueError("risk decision expires_at is required")
    if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
        raise ValueError("risk decision expires_at must be timezone-aware")
    if expires_at.utcoffset() is None:
        raise ValueError("risk decision expires_at must be timezone-aware")
    if expires_at <= _utcnow():
        raise ValueError("risk decision expires_at must be in the future")


def _validate_risk_decision_expiry(expires_at: Any) -> None:
    """Validate the expiry again immediately before an approval mutation.

    SQLite's timezone-aware datetime adapter returns persisted values as naive
    UTC datetimes.  Normalize that storage representation before applying the
    same future-time check used for a newly submitted request.
    """

    if expires_at is None:
        raise ValueError("risk decision expires_at is required")
    if not isinstance(expires_at, datetime):
        raise ValueError("risk decision expires_at must be timezone-aware")
    effective_expiry = _ensure_aware(expires_at)
    if effective_expiry is None or effective_expiry.utcoffset() is None:
        raise ValueError("risk decision expires_at must be timezone-aware")
    if effective_expiry <= _utcnow():
        raise ValueError("risk decision expires_at must be in the future")


class CaseService:
    def __init__(self, session: Session):
        self.session = session

    def create_case(
        self,
        organization_id: str,
        title: str,
        owner_team: str,
        priority: str = "P2",
        exposures: list[str] | None = None,
        policy_version: str | None = None,
        assignee: str | None = None,
    ) -> RemediationCase:
        case_id = f"case_{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        due = calculate_due_date(priority, now)
        case = RemediationCase(
            id=case_id,
            case_key=_gen_case_key(),
            title=title,
            organization_id=organization_id,
            owner_team=owner_team,
            assignee=assignee,
            priority=priority,
            policy_version=policy_version,
            status=CaseStatus.NEW,
            version=1,
            due_at=due,
            exposures=exposures or [],
        )
        try:
            self.session.add(case)
            # SLA clock
            clock = SlaClock(
                id=f"sla_{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                phase="remediation",
                due_at=due,
            )
            self.session.add(clock)
            audit = AuditEvent(
                id=f"aud_{uuid.uuid4().hex[:12]}",
                actor="system",
                action="case.created",
                subject_type="case",
                subject_id=case_id,
                correlation_id=str(uuid.uuid4()),
                new_state=CaseStatus.NEW,
                reason="case created",
                organization_id=organization_id,
            )
            self.session.add(audit)
            outbox = OutboxEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                aggregate_type="case",
                aggregate_id=case_id,
                event_type="vulnops.case.created.v1",
                payload={"case_id": case_id, "priority": priority, "exposures": exposures or []},
                correlation_id=audit.correlation_id,
            )
            self.session.add(outbox)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        # Refresh to get committed state
        self.session.refresh(case)
        return case

    def get_case(self, case_id: str) -> RemediationCase:
        case = self.session.get(RemediationCase, case_id)
        if not case:
            raise ValueError(f"case {case_id} not found")
        return case

    def list_cases(
        self,
        organization_id: str,
        *,
        status: str | None = None,
        priority: str | None = None,
        owner_team: str | None = None,
        assignee: str | None = None,
        sla_breached: bool | None = None,
        page: int = 1,
        page_size: int = 20,
        sort: str = "-created_at",
    ) -> tuple[list[RemediationCase], int]:
        stmt = select(RemediationCase).where(RemediationCase.organization_id == organization_id)
        if status:
            stmt = stmt.where(RemediationCase.status == status)
        if priority:
            stmt = stmt.where(RemediationCase.priority == priority)
        if owner_team:
            stmt = stmt.where(RemediationCase.owner_team == owner_team)
        if assignee:
            stmt = stmt.where(RemediationCase.assignee == assignee)
        if sla_breached is not None:
            stmt = stmt.where(RemediationCase.sla_breached == sla_breached)

        total = self.session.scalar(select(func.count()).select_from(stmt.subquery())) or 0

        desc = sort.startswith("-")
        order_col = getattr(RemediationCase, sort.lstrip("-"))
        stmt = stmt.order_by(
            order_col.desc() if desc else order_col.asc(), RemediationCase.id.desc()
        )
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.scalars(stmt).all())
        return items, total

    def list_risk_decisions(self, case_id: str) -> list[RiskDecision]:
        stmt = (
            select(RiskDecision)
            .where(RiskDecision.case_id == case_id)
            .order_by(RiskDecision.created_at.desc(), RiskDecision.id.desc())
        )
        return list(self.session.scalars(stmt).all())

    def list_verifications(self, case_id: str) -> list[Verification]:
        stmt = (
            select(Verification)
            .where(Verification.case_id == case_id)
            .order_by(Verification.created_at.desc(), Verification.id.desc())
        )
        return list(self.session.scalars(stmt).all())

    def transition(
        self,
        case_id: str,
        target: str,
        actor: str,
        reason: str | None = None,
        extra: dict | None = None,
        expected_version: int | None = None,
        actor_provenance: str = _LEGACY_PROVENANCE,
        actor_principal_type: str | None = None,
        actor_roles: Iterable[str] | None = None,
        actor_scopes: Iterable[str] | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> RemediationCase:
        case = self.get_case(case_id)

        allowed = ALLOWED_TRANSITIONS.get(case.status, [])
        if target not in allowed:
            raise ValueError(f"transition {case.status} -> {target} not allowed")

        prior = case.status
        now = _utcnow()
        # SLA breach evaluation
        sla_breached = case.sla_breached
        if case.due_at:
            due_aware = _ensure_aware(case.due_at)
            if due_aware and now > due_aware:
                sla_breached = True

        new_assignee = extra.get("assignee") if extra and "assignee" in extra else case.assignee
        actor_fields = _actor_audit_fields(
            actor_provenance=actor_provenance,
            actor_principal_type=actor_principal_type,
            actor_roles=actor_roles,
            actor_scopes=actor_scopes,
        )
        event_correlation_id = correlation_id or str(uuid.uuid4())
        audit = AuditEvent(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            actor=actor,
            action="case.transitioned",
            subject_type="case",
            subject_id=case_id,
            correlation_id=event_correlation_id,
            request_id=request_id,
            prior_state=prior,
            new_state=target,
            reason=reason or f"{prior}->{target}",
            organization_id=case.organization_id,
            **actor_fields,
        )
        outbox = OutboxEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            aggregate_type="case",
            aggregate_id=case_id,
            event_type="vulnops.case.transitioned.v1",
            payload={
                "from": prior,
                "to": target,
                "reason": reason,
                "evidence_ids": extra.get("evidence_ids") if extra else None,
                **_trace_payload(
                    actor_fields=actor_fields,
                    actor=actor,
                    organization_id=case.organization_id,
                    request_id=request_id,
                    correlation_id=event_correlation_id,
                ),
            },
            correlation_id=audit.correlation_id,
        )
        try:
            if expected_version is not None:
                # Atomic compare-and-swap: enforce version in the UPDATE
                # predicate so concurrent writers cannot both succeed.
                stmt = (
                    update(RemediationCase)
                    .where(
                        RemediationCase.id == case_id, RemediationCase.version == expected_version
                    )
                    .values(
                        status=target,
                        version=expected_version + 1,
                        assignee=new_assignee,
                        updated_at=now,
                        sla_breached=sla_breached,
                    )
                )
                result = self.session.execute(stmt)
                if result.rowcount == 0:
                    self.session.rollback()
                    current = self.get_case(case_id)
                    raise ValueError(
                        f"conflict: expected version {expected_version} but current is {current.version}"
                    )
                self.session.add(audit)
                self.session.add(outbox)
                self.session.commit()
            else:
                case.status = target
                case.version += 1
                case.assignee = new_assignee
                case.updated_at = now
                case.sla_breached = sla_breached
                self.session.add(audit)
                self.session.add(outbox)
                self.session.commit()
        except ValueError:
            raise
        except Exception:
            self.session.rollback()
            raise
        # Expire cached state so callers see the committed version.
        self.session.expire_all()
        return self.get_case(case_id)

    def verify(
        self,
        case_id: str,
        method: str,
        evidence_ids: list[str],
        coverage: dict[str, Any] | None = None,
        actor: str = "system",
        asserted_result: str | None = None,
        actor_provenance: str = _LEGACY_PROVENANCE,
        actor_principal_type: str | None = None,
        actor_roles: Iterable[str] | None = None,
        actor_scopes: Iterable[str] | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> Verification:
        case = self.get_case(case_id)
        if case.status != CaseStatus.AWAITING_VERIFICATION:
            raise ValueError(
                f"verification not allowed from state {case.status} -> closed: "
                "case must be in awaiting_verification"
            )

        can_close, reason = evaluate_coverage(method, coverage)

        ver_id = f"ver_{uuid.uuid4().hex[:12]}"
        if can_close:
            status = "closed"
            case.status = CaseStatus.CLOSED
            case.version += 1
            case.closure_reason = reason
            case.updated_at = _utcnow()
            audit_action = "verification.completed"
            outbox_type = "vulnops.verification.completed.v1"
        else:
            # Determine if requires approval vs insufficient
            if method == "manual_attestation":
                status = "requires_approval"
                audit_action = "verification.requires_approval"
                outbox_type = "vulnops.verification.requires_approval.v1"
            else:
                status = "insufficient_evidence"
                audit_action = "verification.failed"
                outbox_type = "vulnops.verification.failed.v1"

        verification = Verification(
            id=ver_id,
            case_id=case_id,
            method=method,
            asserted_result=asserted_result,
            evidence_ids=evidence_ids,
            coverage=coverage,
            status=status,
        )
        self.session.add(verification)

        actor_fields = _actor_audit_fields(
            actor_provenance=actor_provenance,
            actor_principal_type=actor_principal_type,
            actor_roles=actor_roles,
            actor_scopes=actor_scopes,
        )
        event_correlation_id = correlation_id or str(uuid.uuid4())
        audit = AuditEvent(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            actor=actor,
            action=audit_action,
            subject_type="case",
            subject_id=case_id,
            correlation_id=event_correlation_id,
            request_id=request_id,
            reason=reason,
            organization_id=case.organization_id,
            **actor_fields,
        )
        outbox = OutboxEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            aggregate_type="case",
            aggregate_id=case_id,
            event_type=outbox_type,
            payload={
                "method": method,
                "evidence_ids": evidence_ids,
                "coverage": coverage,
                "status": status,
                "reason": reason,
                **_trace_payload(
                    actor_fields=actor_fields,
                    actor=actor,
                    organization_id=case.organization_id,
                    request_id=request_id,
                    correlation_id=event_correlation_id,
                ),
            },
            correlation_id=audit.correlation_id,
        )
        self.session.add(audit)
        self.session.add(outbox)
        self.session.commit()
        self.session.refresh(case)
        return verification

    def get_risk_decision(self, decision_id: str) -> RiskDecision:
        decision = self.session.get(RiskDecision, decision_id)
        if not decision:
            raise ValueError(f"decision {decision_id} not found")
        return decision

    def create_risk_decision(
        self,
        case_id: str,
        type: str,
        reason: str,
        expires_at: datetime | None = None,
        compensating_controls: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        requested_by: str = "unknown",
        approver: str | None = None,
        approver_role: str | None = None,
        actor: str = "system",
        scope: dict | None = None,
        actor_provenance: str = _LEGACY_PROVENANCE,
        actor_principal_type: str | None = None,
        actor_roles: Iterable[str] | None = None,
        actor_scopes: Iterable[str] | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> RiskDecision:
        """Create a pending decision request.

        Approval identity is deliberately not accepted as part of this
        operation.  The retained parameters make the breaking transition
        explicit for direct domain callers and fail closed instead of silently
        turning a request into an approval.
        """

        if approver is not None or approver_role is not None:
            raise ValueError("risk decision approval must use approve_risk_decision")
        if actor != requested_by:
            raise ValueError("risk request actor must match requested_by")
        _validate_risk_decision_request(
            type=type,
            reason=reason,
            evidence_ids=evidence_ids,
            expires_at=expires_at,
        )
        actor_fields = _actor_audit_fields(
            actor_provenance=actor_provenance,
            actor_principal_type=actor_principal_type,
            actor_roles=actor_roles,
            actor_scopes=actor_scopes,
        )
        case = self.get_case(case_id)
        event_correlation_id = correlation_id or str(uuid.uuid4())
        decision = RiskDecision(
            id=f"rdec_{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            type=type,
            status="pending_approval",
            scope_exposure_ids=(scope or {}).get("exposure_ids") if scope else None,
            reason=reason,
            compensating_controls=compensating_controls,
            evidence_ids=evidence_ids,
            requested_by=requested_by,
            requested_by_provenance=actor_provenance,
            approver=None,
            approver_role=None,
            expires_at=expires_at,
        )
        audit = AuditEvent(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            actor=actor,
            action="risk.decision.requested",
            subject_type="risk_decision",
            subject_id=decision.id,
            correlation_id=event_correlation_id,
            request_id=request_id,
            reason=reason,
            organization_id=case.organization_id,
            **actor_fields,
        )
        outbox = OutboxEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            aggregate_type="risk_decision",
            aggregate_id=decision.id,
            event_type="vulnops.risk-decision.requested.v1",
            payload={
                "decision_id": decision.id,
                "case_id": case_id,
                "type": type,
                "expires_at": expires_at.isoformat(),
                **_trace_payload(
                    actor_fields=actor_fields,
                    actor=actor,
                    organization_id=case.organization_id,
                    request_id=request_id,
                    correlation_id=event_correlation_id,
                ),
            },
            correlation_id=audit.correlation_id,
        )
        try:
            self.session.add(decision)
            self.session.add(audit)
            self.session.add(outbox)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        self.session.refresh(decision)
        self.session.refresh(case)
        return decision

    def approve_risk_decision(
        self,
        decision_id: str,
        *,
        outcome: str,
        reason: str,
        actor: str,
        actor_principal_type: str,
        actor_roles: Iterable[str] | None = None,
        actor_capabilities: Iterable[str] | None = None,
        actor_provenance: str = _AUTHENTICATED_PROVENANCE,
        actor_scopes: Iterable[str] | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> RiskDecision:
        """Apply an authenticated human approval or rejection to a request."""

        decision = self.get_risk_decision(decision_id)
        if decision.status != "pending_approval":
            raise ValueError("risk decision conflict: decision is no longer pending approval")
        if actor_principal_type != "human":
            raise ValueError("service principals cannot approve risk decisions")
        capabilities = {capability.strip().lower() for capability in (actor_capabilities or ())}
        if "risk:approve" not in capabilities:
            raise ValueError("actor lacks risk:approve capability")
        if actor == decision.requested_by:
            raise ValueError("self-approval is not allowed")
        if not isinstance(outcome, str):
            raise ValueError("risk decision outcome must be approve or reject")
        normalized_outcome = outcome.strip().lower()
        if normalized_outcome not in {"approve", "reject"}:
            raise ValueError("risk decision outcome must be approve or reject")
        if not reason or not reason.strip():
            raise ValueError("approval reason is required")

        actor_fields = _actor_audit_fields(
            actor_provenance=actor_provenance,
            actor_principal_type=actor_principal_type,
            actor_roles=actor_roles,
            actor_scopes=actor_scopes,
        )
        role = _approval_role(actor_roles)
        if role is None:
            raise ValueError("actor must carry an approver role")

        case = self.get_case(decision.case_id)
        now = _utcnow()

        target_state_map = {
            "risk_accepted": CaseStatus.RISK_ACCEPTED,
            "waiver": CaseStatus.RISK_ACCEPTED,
            "compensating_control": CaseStatus.RISK_ACCEPTED,
            "false_positive": CaseStatus.NOT_APPLICABLE,
            "not_affected": CaseStatus.NOT_APPLICABLE,
        }
        audit_action_map = {
            "risk_accepted": "risk.accepted",
            "waiver": "risk.waiver.accepted",
            "compensating_control": "risk.compensating_control.accepted",
            "false_positive": "risk.false_positive.accepted",
            "not_affected": "risk.not_affected.accepted",
        }
        prior = case.status
        if normalized_outcome == "approve":
            if decision.type not in _SUPPORTED_RISK_DECISION_TYPES:
                raise ValueError("unsupported risk decision type")
            if not isinstance(decision.reason, str) or not decision.reason.strip():
                raise ValueError("risk decision reason is required")
            _validate_evidence_ids(decision.evidence_ids)
            _validate_risk_decision_expiry(decision.expires_at)
            target_state = target_state_map[decision.type]
            audit_action = audit_action_map.get(decision.type, "risk.accepted")
            outbox_type = "vulnops.risk-decision.accepted.v1"
            next_status = "approved"
        else:
            audit_action = "risk.decision.rejected"
            outbox_type = "vulnops.risk-decision.rejected.v1"
            next_status = "rejected"

        event_correlation_id = correlation_id or str(uuid.uuid4())
        # The conditional UPDATE is the linearization point for an approval.
        # Every contender may validate the same pending snapshot, but exactly
        # one transaction can claim the row and create its audit/outbox pair.
        try:
            decision_update = self.session.execute(
                update(RiskDecision)
                .where(
                    RiskDecision.id == decision.id,
                    RiskDecision.status == "pending_approval",
                )
                .values(
                    status=next_status,
                    approver=actor,
                    approver_role=role,
                    approver_provenance=actor_provenance,
                    approver_principal_type=actor_principal_type,
                    decided_at=now,
                    updated_at=now,
                )
            )
            if decision_update.rowcount != 1:
                raise ValueError("risk decision conflict: decision is no longer pending approval")

            if normalized_outcome == "approve":
                if target_state not in ALLOWED_TRANSITIONS.get(prior, []):
                    raise ValueError(
                        f"transition {prior} -> {target_state} not allowed for decision type {decision.type}"
                    )
                case.status = target_state
                case.version += 1
                case.updated_at = now

            audit = AuditEvent(
                id=f"aud_{uuid.uuid4().hex[:12]}",
                actor=actor,
                action=audit_action,
                subject_type="risk_decision",
                subject_id=decision.id,
                correlation_id=event_correlation_id,
                request_id=request_id,
                prior_state=prior if normalized_outcome == "approve" else None,
                new_state=target_state if normalized_outcome == "approve" else None,
                reason=reason,
                organization_id=case.organization_id,
                **actor_fields,
            )
            payload = {
                "decision_id": decision.id,
                "case_id": case.id,
                "type": decision.type,
                "outcome": normalized_outcome,
                "approver": actor,
                "approver_role": role,
                "decided_at": now.isoformat(),
                **_trace_payload(
                    actor_fields=actor_fields,
                    actor=actor,
                    organization_id=case.organization_id,
                    request_id=request_id,
                    correlation_id=event_correlation_id,
                ),
            }
            if normalized_outcome == "approve":
                payload["expires_at"] = (
                    decision.expires_at.isoformat() if decision.expires_at else None
                )

            outbox = OutboxEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                aggregate_type="risk_decision",
                aggregate_id=decision.id,
                event_type=outbox_type,
                payload=payload,
                correlation_id=audit.correlation_id,
            )
            self.session.add(audit)
            self.session.add(outbox)
            self.session.commit()
        except ValueError:
            self.session.rollback()
            raise
        except Exception:
            self.session.rollback()
            raise
        self.session.expire_all()
        return self.get_risk_decision(decision_id)

    def revoke_decision(self, decision_id: str, actor: str, reason: str):
        decision = self.session.get(RiskDecision, decision_id)
        if not decision:
            raise ValueError("decision not found")
        decision.status = "revoked"
        decision.updated_at = _utcnow()
        case = self.get_case(decision.case_id)
        prior = case.status
        case.status = CaseStatus.TRIAGE
        case.version += 1
        audit = AuditEvent(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            actor=actor,
            action="risk.decision.revoked",
            subject_type="case",
            subject_id=case.id,
            correlation_id=str(uuid.uuid4()),
            prior_state=prior,
            new_state=CaseStatus.TRIAGE,
            reason=reason,
            organization_id=case.organization_id,
        )
        outbox = OutboxEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            aggregate_type="case",
            aggregate_id=case.id,
            event_type="vulnops.risk-decision.revoked.v1",
            payload={"decision_id": decision_id, "reason": reason},
            correlation_id=audit.correlation_id,
        )
        self.session.add(audit)
        self.session.add(outbox)
        self.session.commit()

    def process_expirations(self, now: datetime | None = None) -> int:
        now = now or _utcnow()
        now_aware = _ensure_aware(now)
        # Fetch all approved with expiry, then filter in python to handle tz naive/aware mismatch
        all_pending = (
            self.session.execute(
                select(RiskDecision).where(
                    RiskDecision.status == "approved", RiskDecision.expires_at != None
                )
            )
            .scalars()
            .all()
        )
        decisions = []
        for d in all_pending:
            exp = _ensure_aware(d.expires_at)
            if exp is not None and now_aware is not None and exp <= now_aware:
                decisions.append(d)
        count = 0
        for dec in decisions:
            dec.status = "expired"
            case = self.get_case(dec.case_id)
            if case.status == CaseStatus.RISK_ACCEPTED:
                prior = case.status
                case.status = CaseStatus.TRIAGE
                case.version += 1
                audit = AuditEvent(
                    id=f"aud_{uuid.uuid4().hex[:12]}",
                    actor="system",
                    action="risk-decision.expired",
                    subject_type="case",
                    subject_id=case.id,
                    correlation_id=str(uuid.uuid4()),
                    prior_state=prior,
                    new_state=CaseStatus.TRIAGE,
                    reason="risk acceptance expired",
                    organization_id=case.organization_id,
                )
                outbox = OutboxEvent(
                    id=f"evt_{uuid.uuid4().hex[:12]}",
                    aggregate_type="case",
                    aggregate_id=case.id,
                    event_type="vulnops.risk-decision.expired.v1",
                    payload={"decision_id": dec.id, "expired_at": now.isoformat()},
                    correlation_id=audit.correlation_id,
                )
                self.session.add(audit)
                self.session.add(outbox)
            count += 1
        self.session.commit()
        return count

    def reopen_on_evidence(
        self, case_id: str, evidence_id: str, reason: str = "new confirming evidence"
    ):
        case = self.get_case(case_id)
        if case.status != CaseStatus.CLOSED:
            # Only reopen closed cases per spec
            # But for test we allow closed -> reopened
            if case.status == CaseStatus.CLOSED:
                pass
            else:
                raise ValueError("only closed cases can be reopened via evidence")
        prior = case.status
        case.status = CaseStatus.REOPENED
        case.version += 1
        audit = AuditEvent(
            id=f"aud_{uuid.uuid4().hex[:12]}",
            actor="system",
            action="exposure.reopened",
            subject_type="case",
            subject_id=case_id,
            correlation_id=str(uuid.uuid4()),
            prior_state=prior,
            new_state=CaseStatus.REOPENED,
            reason=reason,
            organization_id=case.organization_id,
        )
        outbox = OutboxEvent(
            id=f"evt_{uuid.uuid4().hex[:12]}",
            aggregate_type="case",
            aggregate_id=case_id,
            event_type="vulnops.exposure.reopened.v1",
            payload={"evidence_id": evidence_id, "reason": reason},
            correlation_id=audit.correlation_id,
        )
        self.session.add(audit)
        self.session.add(outbox)
        self.session.commit()
        return case
