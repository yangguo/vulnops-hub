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
from vulnops.cases.ownership import resolve_case_owner_team
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
