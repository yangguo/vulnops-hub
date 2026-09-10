"""Case owner resolution and high-priority ownership escalation tests."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import vulnops.assets.models
import vulnops.cases.models
import vulnops.db.models.audit_event
import vulnops.db.models.outbox_event
import vulnops.matching.models
import vulnops.services.models  # noqa: F401
from vulnops.assets.models import Asset
from vulnops.cases.ownership import resolve_case_owner, resolve_case_owner_team
from vulnops.cases.service import CaseService
from vulnops.config import Settings
from vulnops.db import Base
from vulnops.db.models.audit_event import AuditEvent
from vulnops.matching.models import Exposure
from vulnops.services.models import BusinessService


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        yield session


def _service_and_asset(db: Session) -> Asset:
    db.add(
        BusinessService(
            id="svc-billing",
            organization_id="org-ownership",
            name="Billing",
            owner_team="billing-platform",
        )
    )
    asset = Asset(
        id="asset-billing",
        organization_id="org-ownership",
        name="billing-01",
        business_service_id="svc-billing",
    )
    db.add(asset)
    db.commit()
    return asset


def test_owner_resolution_prefers_asset_then_service_then_default(db):
    asset = _service_and_asset(db)
    resolved = resolve_case_owner(
        db,
        organization_id="org-ownership",
        asset_id=asset.id,
        default_owner_team="unassigned",
    )
    assert resolved.owner_team == "billing-platform"
    assert resolved.source == "service"
    assert (
        resolve_case_owner_team(
            db,
            organization_id="org-ownership",
            asset_id=asset.id,
            default_owner_team="unassigned",
        )
        == "billing-platform"
    )

    asset.owner = "asset-oncall"
    db.commit()
    assert (
        resolve_case_owner_team(
            db,
            organization_id="org-ownership",
            asset_id=asset.id,
            default_owner_team="unassigned",
        )
        == "asset-oncall"
    )

    asset.owner = None
    db.query(BusinessService).filter_by(id="svc-billing").one().owner_team = ""
    db.commit()
    assert (
        resolve_case_owner_team(
            db,
            organization_id="org-ownership",
            asset_id=asset.id,
            default_owner_team="unassigned",
        )
        == "unassigned"
    )


def test_case_service_applies_owner_resolution_for_default_manual_create(db):
    asset = _service_and_asset(db)
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )
    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title="Billing exposure",
        owner_team="unassigned",
        priority="P1",
        asset_id=asset.id,
    )
    assert case.owner_team == "billing-platform"
    assert case.ownership_escalated is False


def test_case_service_resolves_owner_from_manual_exposure_scope(db):
    asset = _service_and_asset(db)
    db.add(
        Exposure(
            id="exp-manual-owner",
            organization_id="org-ownership",
            asset_id=asset.id,
            vulnerability_id="CVE-2026-0001",
            match_class="confirmed",
            confidence=1.0,
            state="active",
        )
    )
    db.commit()
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )
    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title="Exposure-scoped ownership",
        owner_team="unassigned",
        priority="P1",
        exposures=["exp-manual-owner"],
    )
    assert case.owner_team == "billing-platform"


def test_unassigned_high_priority_case_is_flagged_and_audited(db):
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )
    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title="Unowned critical exposure",
        owner_team="unassigned",
        priority="P0",
    )
    assert case.ownership_escalated is True
    audit = (
        db.query(AuditEvent)
        .filter_by(
            action="case.ownership.unassigned_high_priority",
            subject_id=case.id,
        )
        .one()
    )
    assert audit.organization_id == "org-ownership"
    assert audit.new_state == "unassigned"
    assert "P0" in (audit.reason or "")


@pytest.mark.parametrize("priority", ["P0", "P1"])
def test_real_asset_owner_named_like_default_is_not_escalated(db, priority):
    asset = _service_and_asset(db)
    asset.owner = "Unassigned"
    db.commit()
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )

    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title=f"Intentionally default-named owner {priority}",
        owner_team="unassigned",
        priority=priority,
        asset_id=asset.id,
    )

    assert case.owner_team == "Unassigned"
    assert case.ownership_escalated is False
    assert (
        db.query(AuditEvent)
        .filter_by(action="case.ownership.unassigned_high_priority", subject_id=case.id)
        .count()
        == 0
    )


def test_non_default_explicit_unassigned_sentinel_is_not_escalated(db):
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="triage-queue",
    )

    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title="Explicit legacy sentinel",
        owner_team="unassigned",
        priority="P0",
    )

    assert case.owner_team == "unassigned"
    assert case.ownership_escalated is False
    assert db.query(AuditEvent).filter_by(subject_id=case.id).count() == 1


@pytest.mark.parametrize("priority", ["P0", "P1"])
def test_true_default_fallback_escalates_for_high_priority(db, priority):
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )

    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title=f"Unowned {priority} exposure",
        owner_team="unassigned",
        priority=priority,
    )

    assert case.ownership_escalated is True
    assert (
        db.query(AuditEvent)
        .filter_by(action="case.ownership.unassigned_high_priority", subject_id=case.id)
        .count()
        == 1
    )


def test_unassigned_p2_does_not_escalate_or_audit(db):
    settings = Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )

    case = CaseService(db, settings=settings).create_case(
        organization_id="org-ownership",
        title="Unowned P2 exposure",
        owner_team="unassigned",
        priority="P2",
    )

    assert case.ownership_escalated is False
    assert (
        db.query(AuditEvent)
        .filter_by(action="case.ownership.unassigned_high_priority", subject_id=case.id)
        .count()
        == 0
    )


def _asset_with_owner(db: Session, asset_id: str, owner: str | None) -> Asset:
    asset = Asset(
        id=asset_id,
        organization_id="org-ownership",
        name=asset_id,
        owner=owner,
    )
    db.add(asset)
    return asset


def _exposure_for_asset(db: Session, exposure_id: str, asset_id: str) -> None:
    db.add(
        Exposure(
            id=exposure_id,
            organization_id="org-ownership",
            asset_id=asset_id,
            vulnerability_id=f"CVE-{exposure_id}",
            match_class="confirmed",
            confidence=1.0,
            state="active",
        )
    )


def _ownership_settings() -> Settings:
    return Settings(
        _env_file=None,
        oidc_issuer_url="https://issuer.example",
        oidc_audience="vulnops-api",
        default_case_owner_team="unassigned",
    )


def test_multi_exposure_owner_resolution_is_order_independent(db):
    _asset_with_owner(db, "asset-owner-a", "team-a")
    _asset_with_owner(db, "asset-owner-b", "TEAM-A")
    _exposure_for_asset(db, "exp-owner-a", "asset-owner-a")
    _exposure_for_asset(db, "exp-owner-b", "asset-owner-b")
    db.commit()
    svc = CaseService(db, settings=_ownership_settings())

    first = svc.create_case(
        organization_id="org-ownership",
        title="Ordered exposures",
        owner_team="unassigned",
        priority="P1",
        exposures=["exp-owner-a", "exp-owner-b"],
    )
    second = svc.create_case(
        organization_id="org-ownership",
        title="Reversed exposures",
        owner_team="unassigned",
        priority="P1",
        exposures=["exp-owner-b", "exp-owner-a"],
    )

    assert first.owner_team == "TEAM-A"
    assert second.owner_team == "TEAM-A"
    assert first.ownership_escalated is False
    assert second.ownership_escalated is False


def test_conflicting_multi_exposure_owners_are_rejected(db):
    _asset_with_owner(db, "asset-conflict-a", "team-a")
    _asset_with_owner(db, "asset-conflict-b", "team-b")
    _exposure_for_asset(db, "exp-conflict-a", "asset-conflict-a")
    _exposure_for_asset(db, "exp-conflict-b", "asset-conflict-b")
    db.commit()

    with pytest.raises(ValueError, match="^conflicting exposure owners$"):
        CaseService(db, settings=_ownership_settings()).create_case(
            organization_id="org-ownership",
            title="Conflicting exposures",
            owner_team="unassigned",
            priority="P1",
            exposures=["exp-conflict-b", "exp-conflict-a"],
        )
    assert db.query(AuditEvent).filter_by(action="case.created").count() == 0


def test_mixed_owned_and_unowned_multi_exposure_is_rejected(db):
    _asset_with_owner(db, "asset-mixed-owned", "team-a")
    _asset_with_owner(db, "asset-mixed-unowned", None)
    _exposure_for_asset(db, "exp-mixed-owned", "asset-mixed-owned")
    _exposure_for_asset(db, "exp-mixed-unowned", "asset-mixed-unowned")
    db.commit()

    with pytest.raises(ValueError, match="^conflicting exposure owners$"):
        CaseService(db, settings=_ownership_settings()).create_case(
            organization_id="org-ownership",
            title="Mixed ownership exposures",
            owner_team="unassigned",
            priority="P0",
            exposures=["exp-mixed-owned", "exp-mixed-unowned"],
        )


def test_all_default_multi_exposure_case_escalates(db):
    _asset_with_owner(db, "asset-default-a", None)
    _asset_with_owner(db, "asset-default-b", None)
    _exposure_for_asset(db, "exp-default-a", "asset-default-a")
    _exposure_for_asset(db, "exp-default-b", "asset-default-b")
    db.commit()

    case = CaseService(db, settings=_ownership_settings()).create_case(
        organization_id="org-ownership",
        title="All default exposures",
        owner_team="unassigned",
        priority="P1",
        exposures=["exp-default-b", "exp-default-a"],
    )

    assert case.owner_team == "unassigned"
    assert case.ownership_escalated is True
