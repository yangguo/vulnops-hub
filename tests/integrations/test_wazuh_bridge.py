import json
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.integrations.wazuh import WazuhBridge

FIXTURE = Path(__file__).parent.parent / "fixtures" / "wazuh" / "event.json"


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.db.models.source_snapshot  # noqa
    import vulnops.db.models.audit_event  # noqa
    import vulnops.db.models.outbox_event  # noqa
    import vulnops.assets.models  # noqa
    Base.metadata.create_all(bind=eng)
    return eng


def test_wazuh_import_preserves_agent_and_package_identity():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = WazuhBridge(session)

    raw = json.loads(FIXTURE.read_text())
    result = bridge.ingest_event(raw, organization_id="org1")

    assert result.source_snapshot.source == "wazuh"
    assert result.source_snapshot.source_record_id == "001" or "CVE-2026-12345" in result.source_snapshot.source_record_id
    # Preserve Wazuh agent id
    assert result.agent_id == "001"
    # Preserve package purl and version
    assert result.package_purl == "pkg:deb/debian/openssl@3.0.2?arch=x86_64"
    assert result.package_version == "3.0.2"
    # Evidence captured
    assert result.evidence_ref is not None
    session.close()


def test_wazuh_replay_is_idempotent():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = WazuhBridge(session)

    raw = json.loads(FIXTURE.read_text())
    r1 = bridge.ingest_event(raw, organization_id="org1")
    r2 = bridge.ingest_event(raw, organization_id="org1")

    assert r1.source_snapshot.id == r2.source_snapshot.id
    cnt = session.execute(text("SELECT COUNT(*) FROM source_snapshots WHERE source='wazuh'")).scalar()
    assert cnt == 1
    session.close()


def test_wazuh_treats_status_as_evidence_not_case_state():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = WazuhBridge(session)

    raw = json.loads(FIXTURE.read_text())
    result = bridge.ingest_event(raw, organization_id="org1")

    # Wazuh status is evidence, not overall case state - bridge should not directly mutate Case
    assert result.should_update_case is False
    assert result.case_id is None
    session.close()


def test_wazuh_captures_scope_and_completeness():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = WazuhBridge(session)

    raw = json.loads(FIXTURE.read_text())
    result = bridge.ingest_event(raw, organization_id="org1")

    assert result.scan_metadata["scope_status"] == "complete"
    assert "agent" in result.scan_metadata or result.agent_id is not None
    session.close()
