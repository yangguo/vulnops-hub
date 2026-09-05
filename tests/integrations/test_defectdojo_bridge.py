import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.integrations.defectdojo import DefectDojoBridge

FIXTURE = Path(__file__).parent.parent / "fixtures" / "defectdojo" / "finding.json"


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.db.models.source_snapshot  # noqa
    import vulnops.db.models.audit_event
    import vulnops.db.models.outbox_event
    import vulnops.assets.models
    import vulnops.cases.models  # noqa

    Base.metadata.create_all(bind=eng)
    return eng


def test_defectdojo_import_creates_evidence_and_exposure():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = DefectDojoBridge(session)

    raw = json.loads(FIXTURE.read_text())
    result = bridge.ingest_finding(raw, organization_id="org1")

    # Should retain original source IDs and URL
    assert result.source_snapshot is not None
    assert result.source_snapshot.source == "defectdojo"
    assert result.source_snapshot.source_record_id == "123456"
    assert (
        "dojo.example" in result.source_snapshot.object_uri
        or "123456" in result.source_snapshot.source_record_id
    )
    # Evidence should be created
    assert result.evidence_ref is not None
    # Should produce exposure or evidence mapping, not directly case via scanner evidence
    # For confirmed scanner evidence, should create deterministic/confirmed exposure
    assert result.exposure is not None or result.evidence_ref is not None
    # Scan completeness should be captured
    assert result.scan_metadata["scope_status"] == "complete"
    session.close()


def test_defectdojo_replay_is_idempotent():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = DefectDojoBridge(session)

    raw = json.loads(FIXTURE.read_text())
    r1 = bridge.ingest_finding(raw, organization_id="org1")
    r2 = bridge.ingest_finding(raw, organization_id="org1")

    # Second ingest with same natural key should be idempotent, no duplicate case/event
    assert r1.source_snapshot.id == r2.source_snapshot.id
    # Count rows: should be 1 source_snapshot, 1 exposure
    from sqlalchemy import text

    cnt_snap = session.execute(
        text("SELECT COUNT(*) FROM source_snapshots WHERE source='defectdojo'")
    ).scalar()
    assert cnt_snap == 1
    session.close()


def test_defectdojo_conflicting_asset_hints_creates_reconciliation_work():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()

    # Create two assets with same hostname to cause collision
    from vulnops.assets.models import Asset, AssetAlias

    a1 = Asset(
        id="ast_01",
        name="api-01-a",
        type="host",
        status="active",
        criticality="high",
        organization_id="org1",
    )
    a2 = Asset(
        id="ast_02",
        name="api-01-b",
        type="host",
        status="active",
        criticality="high",
        organization_id="org1",
    )
    session.add_all([a1, a2])
    session.commit()
    session.add_all(
        [
            AssetAlias(
                asset_id="ast_01",
                namespace="hostname",
                value="payments-api-3",
                organization_id="org1",
            ),
            AssetAlias(
                asset_id="ast_02",
                namespace="hostname",
                value="payments-api-3",
                organization_id="org1",
            ),
        ]
    )
    session.commit()

    bridge = DefectDojoBridge(session)
    raw = json.loads(FIXTURE.read_text())
    # Ensure asset_hints contains ambiguous hostname
    result = bridge.ingest_finding(raw, organization_id="org1")

    # Should detect ambiguous mapping
    assert result.mapping.status == "ambiguous"
    assert result.mapping.reason is not None
    # Should not arbitrarily select an asset
    assert result.mapped_asset_id is None
    session.close()


def test_defectdojo_does_not_create_case_directly_from_missing_evidence():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    bridge = DefectDojoBridge(session)

    # Payload without scanner_confirmed or purl should be candidate, not auto case
    raw = {
        "id": 999999,
        "title": "Candidate finding",
        "cve": "CVE-2026-99999",
        "component_name": "unknown",
        "asset_hints": [{"namespace": "hostname", "value": "unknown-host"}],
        "scan_run": {"scope_status": "complete"},
    }
    result = bridge.ingest_finding(raw, organization_id="org1")
    # Candidate should not auto-create case
    assert result.should_create_case is False
    assert result.case_id is None
    session.close()
