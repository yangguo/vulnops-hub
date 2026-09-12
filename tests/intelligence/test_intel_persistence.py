"""Intel table upserts and KEV refresh persistence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

import vulnops.intelligence.models  # noqa: F401
from vulnops.db import Base
from vulnops.intelligence.contracts import AdvisoryRecord
from vulnops.intelligence.kev import KEVAdapter
from vulnops.intelligence.models import (
    AdvisoryAssertion,
    AffectedRange,
    SourceStatus,
    Vulnerability,
    VulnerabilityAlias,
)
from vulnops.intelligence.persistence import (
    is_kev_persisted,
    refresh_kev_catalog,
    upsert_advisory_records,
)

KEV_FIXTURE = Path(__file__).parent.parent / "fixtures" / "intelligence" / "kev_catalog.json"


@pytest.fixture()
def db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


def _osv_record() -> AdvisoryRecord:
    return AdvisoryRecord(
        vulnerability_id="CVE-2026-9999",
        source="osv",
        retrieved_at=datetime.now(UTC),
        source_url="https://api.osv.dev/v1/query",
        description="Test advisory",
        aliases=["GHSA-xxxx"],
        affected_ranges=[
            {
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/urllib3",
                "introduced": "0",
                "fixed": "2.0.0",
            }
        ],
        content={"id": "CVE-2026-9999"},
    )


def test_upsert_advisory_records_idempotent(db):
    rec = _osv_record()
    assert upsert_advisory_records(db, [rec]) == 1
    db.commit()

    assert db.query(Vulnerability).count() == 1
    assert db.query(VulnerabilityAlias).count() == 1
    assert db.query(AffectedRange).count() == 1
    assert db.query(AdvisoryAssertion).count() == 1

    rec.description = "Updated description"
    assert upsert_advisory_records(db, [rec]) == 1
    db.commit()

    assert db.query(Vulnerability).count() == 1
    assert db.query(VulnerabilityAlias).count() == 1
    assert db.query(AffectedRange).count() == 1
    assert db.query(AdvisoryAssertion).count() == 1
    assert db.get(Vulnerability, "CVE-2026-9999").description == "Updated description"


def test_kev_refresh_persists_catalog_and_health(db):
    data = json.loads(KEV_FIXTURE.read_text())
    adapter = KEVAdapter()
    count = refresh_kev_catalog(db, adapter, raw_fixture=data)
    db.commit()

    assert count == len(data["vulnerabilities"])
    assert db.query(AdvisoryAssertion).filter_by(source="kev", kev=True).count() == count
    assert is_kev_persisted(db, "CVE-2026-12345") is True
    assert adapter.is_kev("CVE-2026-12345", session=db) is True

    status = db.query(SourceStatus).filter_by(source="kev").one()
    assert status.freshness == "fresh"
    assert status.last_success_at is not None

    first_assertions = db.query(func.count(AdvisoryAssertion.id)).scalar()
    refresh_kev_catalog(db, adapter, raw_fixture=data)
    db.commit()
    second_assertions = db.query(func.count(AdvisoryAssertion.id)).scalar()
    assert first_assertions == second_assertions


def test_kev_loaded_catalog_overrides_stale_persisted_assertion(db):
    """After CISA drops a CVE, in-memory catalog negatives win over DB kev=true."""

    data = json.loads(KEV_FIXTURE.read_text())
    adapter = KEVAdapter()
    adapter.fetch_catalog(raw_fixture=data)
    dropped_cve = "CVE-2026-DROPPED"
    db.add(
        AdvisoryAssertion(
            id="adv_kev_dropped_manual",
            vulnerability_id=dropped_cve,
            source="kev",
            kev=True,
            content={"cveID": dropped_cve},
        )
    )
    db.commit()

    assert is_kev_persisted(db, dropped_cve) is True
    assert dropped_cve not in adapter._catalog
    assert adapter.is_kev(dropped_cve, session=db) is False


def test_kev_adapter_apply_delegates_to_persistence(db):
    adapter = KEVAdapter()
    adapter.fetch_catalog(raw_fixture=json.loads(KEV_FIXTURE.read_text()))
    rec = adapter.get_record("CVE-2026-12345")
    assert rec is not None
    assert adapter.apply([rec], db) == 1
    db.commit()
    assert is_kev_persisted(db, "CVE-2026-12345")
