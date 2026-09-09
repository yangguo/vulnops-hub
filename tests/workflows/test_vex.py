"""VEX client unit tests plus orchestrator VEX integration tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulnops.intelligence.models
import vulnops.matching.models
import vulnops.workers.orchestration  # noqa: F401
from vulnops.config import Settings
from vulnops.db import Base
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.intelligence.osv import OSVAdapter
from vulnops.intelligence.vex import VexClient
from vulnops.workers.orchestration import OutboxOrchestrator, claim_events


def _settings(**overrides) -> Settings:
    defaults: dict = {
        "oidc_issuer_url": "http://127.0.0.1:8082/realms/vulnops",
        "oidc_audience": "vulnops-api",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _outbox(event_type: str, payload: dict) -> OutboxEvent:
    return OutboxEvent(
        id=f"evt_{uuid.uuid4().hex[:12]}",
        aggregate_type="test",
        aggregate_id="agg-1",
        event_type=event_type,
        payload=payload,
        created_at=datetime.now(UTC),
    )


def _occurrence(purl: str = "pkg:pypi/urllib3@1.26.17"):
    from vulnops.sbom.models import ComponentOccurrence

    name = purl.split("/")[-1].split("@")[0]
    return ComponentOccurrence(
        id=f"occ_{uuid.uuid4().hex[:8]}",
        sbom_id="sbom_1",
        purl=purl,
        ecosystem="pypi",
        normalized_name=name,
        raw_name=name,
        raw_version=purl.split("@")[-1],
        version_scheme="pypi",
    )


def _osv_fixture_for(purl_base: str, cve: str, fixed: str) -> dict:
    return {
        "results": [
            {
                "vulns": [
                    {
                        "id": cve,
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "purl": purl_base},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }


class _FixtureOSV:
    def lookup_batch(self, components, **kwargs):
        return OSVAdapter().lookup_batch(
            components,
            raw_fixture=_osv_fixture_for("pkg:pypi/urllib3", "CVE-2026-1234", "1.26.19"),
        )


@pytest.fixture()
def db():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _FakeClient:
    def __init__(self, payload=None, error=False):
        self._payload = payload
        self._error = error
        self.closed = False
        self.requested: list[str] = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        if self._error:
            raise RuntimeError("network down")
        return _Resp(self._payload)

    def close(self):
        self.closed = True


def test_vex_status_affected_wins_over_not_affected():
    client = _FakeClient(
        {
            "statements": [
                {"status": "not_affected", "source": "vendor-a"},
                {"status": "affected", "source": "vendor-b"},
            ]
        }
    )
    assert VexClient("http://vl", http_client=client).get_status("CVE-2026-1") == "affected"
    assert client.requested == ["http://vl/api/vex/CVE-2026-1"]


def test_vex_status_not_affected_when_only_suppression():
    client = _FakeClient({"statements": [{"status": "not_affected", "source": "vendor"}]})
    assert VexClient("http://vl", http_client=client).get_status("CVE-2026-1") == "not_affected"


def test_vex_status_none_when_no_statements_or_unknown():
    assert VexClient("http://vl", http_client=_FakeClient({})).get_status("CVE-2026-1") is None
    assert (
        VexClient(
            "http://vl", http_client=_FakeClient({"statements": [{"status": "under_review"}]})
        ).get_status("CVE-2026-1")
        is None
    )


def test_vex_network_error_raises_for_caller_to_degrade():
    with pytest.raises(RuntimeError):
        VexClient("http://vl", http_client=_FakeClient(error=True)).get_status("CVE-2026-1")


def _orch(db, vex):
    return OutboxOrchestrator(
        session_factory=lambda: db, osv=_FixtureOSV(), vex=vex, settings=_settings()
    )


def test_orchestrator_vex_not_affected_suppresses_case(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure

    class _VexStub:
        def get_status(self, cve_id):
            return "not_affected" if cve_id == "CVE-2026-1234" else None

    db.add(_occurrence())
    db.add(
        _outbox(
            "vulnops.sbom.processed.v1",
            {"sbom_id": "sbom_1", "organization_id": "org-demo", "component_count": 1},
        )
    )
    db.commit()

    orch = _orch(db, _VexStub())
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.state == "not_affected"
    assert db.query(RemediationCase).count() == 0


def test_orchestrator_vex_lookup_failure_does_not_block_matching(db):
    from vulnops.matching.models import Exposure

    class _BrokenVex:
        def get_status(self, cve_id):
            raise RuntimeError("network down")

    db.add(_occurrence())
    db.add(
        _outbox(
            "vulnops.sbom.processed.v1",
            {"sbom_id": "sbom_1", "organization_id": "org-demo", "component_count": 1},
        )
    )
    db.commit()

    orch = _orch(db, _BrokenVex())
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "deterministic"
    assert ev.delivered_at is not None
