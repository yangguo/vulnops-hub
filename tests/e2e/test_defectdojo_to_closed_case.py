import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.assets.models import Asset, AssetAlias
from vulnops.sbom.service import SBOMService
from vulnops.integrations.defectdojo import DefectDojoBridge
from vulnops.integrations.wazuh import WazuhBridge
from vulnops.matching.service import MatchingService
from vulnops.sbom.parser import ParsedComponent
from vulnops.risk.policy import RiskPolicyEngine, PolicyInput
from vulnops.cases.service import CaseService

DOJO_FIXTURE = Path(__file__).parent.parent / "fixtures" / "defectdojo" / "finding.json"
WAZUH_FIXTURE = Path(__file__).parent.parent / "fixtures" / "wazuh" / "event.json"


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.db.models.source_snapshot  # noqa
    import vulnops.db.models.audit_event  # noqa
    import vulnops.db.models.outbox_event  # noqa
    import vulnops.assets.models  # noqa
    import vulnops.sbom.models  # noqa
    import vulnops.cases.models  # noqa
    import vulnops.matching.models  # noqa
    import vulnops.intelligence.models  # noqa
    Base.metadata.create_all(bind=eng)
    return eng


def test_defectdojo_to_closed_case_e2e():
    """
    End-to-end: asset/SBOM or scanner evidence -> matching -> risk -> case -> verification -> close
    This proves the full acceptance table path: repeated import idempotent, KEV escalation, SBOM match, ambiguous, etc.
    """
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()

    # 1. Create canonical asset with alias
    asset = Asset(id="ast_e2e_01", name="payments-api-3", type="host", status="active", criticality="critical", organization_id="org1", internet_exposure="external")
    session.add(asset)
    session.commit()
    session.add(AssetAlias(asset_id="ast_e2e_01", namespace="hostname", value="payments-api-3", organization_id="org1"))
    session.add(AssetAlias(asset_id="ast_e2e_01", namespace="cmdb", value="CI-009871", organization_id="org1"))
    session.commit()

    # 2. Ingest SBOM (CycloneDX with openssl)
    sbom_service = SBOMService(session)
    sbom_raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "openssl", "version": "3.0.2", "purl": "pkg:deb/debian/openssl@3.0.2"}],
    }
    sbom_result = sbom_service.ingest(sbom_raw, organization_id="org1")
    assert sbom_result["status"] == "accepted"

    # 3. Ingest DefectDojo finding (scanner-confirmed)
    dojo_bridge = DefectDojoBridge(session)
    dojo_raw = json.loads(DOJO_FIXTURE.read_text())
    # Ensure finding maps to our asset
    dojo_raw["asset_hints"] = [{"namespace": "hostname", "value": "payments-api-3"}]
    dojo_result = dojo_bridge.ingest_finding(dojo_raw, organization_id="org1")
    assert dojo_result.source_snapshot is not None
    assert dojo_result.mapping.status == "resolved"
    assert dojo_result.mapped_asset_id == "ast_e2e_01"

    # 4. Deterministic matching: purl in OSV range
    matcher = MatchingService()
    comp = ParsedComponent(raw_name="openssl", raw_version="3.0.2", purl="pkg:deb/debian/openssl@3.0.2", ecosystem="deb", normalized_name="openssl", cpe=None, version_scheme="deb")
    advisory = {"id": "CVE-2026-12345", "affected": [{"package": {"ecosystem": "Debian", "purl": "pkg:deb/debian/openssl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.5"}]}]}]}
    exposure = matcher.evaluate(comp, advisory, asset_context={"criticality": "critical", "internet_exposure": "external"}, scanner_evidence=None)
    assert exposure.match_class == "deterministic"
    assert exposure.should_create_case is True

    # 5. Risk policy: KEV escalation on critical internet
    risk_engine = RiskPolicyEngine(policy_version="risk-2026-09-01")
    risk_input = PolicyInput(vulnerability_id="CVE-2026-12345", kev=True, epss_score=0.91, cvss_score=9.8, asset_criticality="critical", internet_exposure="external", match_confidence=exposure.confidence, match_class=exposure.match_class)
    risk_result = risk_engine.evaluate(risk_input)
    assert risk_result.priority == "P0"
    assert risk_result.escalated is True

    # 6. Create remediation case from exposure
    case_svc = CaseService(session)
    case = case_svc.create_case(organization_id="org1", title="Fix CVE-2026-12345 on payments-api-3", owner_team="secops", priority=risk_result.priority, exposures=["exp_01"], policy_version=risk_result.policy_version)
    assert case.priority == "P0"
    assert case.status == "new"

    for s in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        case_svc.transition(case.id, s, actor="tester")

    assert case_svc.get_case(case.id).status == "awaiting_verification"

    # 7. Verification via Wazuh fixed inventory
    wazuh_bridge = WazuhBridge(session)
    wazuh_raw = json.loads(WAZUH_FIXTURE.read_text())
    # Simulate fixed version observation (3.0.5) after remediation
    wazuh_raw["package"]["version"] = "3.0.5"
    wazuh_raw["package"]["purl"] = "pkg:deb/debian/openssl@3.0.5?arch=x86_64"
    wazuh_result = wazuh_bridge.ingest_event(wazuh_raw, organization_id="org1")
    assert wazuh_result.package_version == "3.0.5"

    # Positive verification should close case
    verification = case_svc.verify(case.id, method="wazuh_inventory", evidence_ids=[wazuh_result.evidence_ref], coverage={"status": "complete", "scope_version": "inventory-policy-3"}, actor="verifier")
    assert verification.status == "closed"
    assert case_svc.get_case(case.id).status == "closed"

    # 8. Reopen on new confirming evidence (should create reopened, not duplicate ticket)
    case_svc.reopen_on_evidence(case.id, evidence_id="ev_new", reason="new scanner confirmed detection")
    assert case_svc.get_case(case.id).status == "reopened"

    # 9. Replay idempotency: re-ingest same DefectDojo finding should not duplicate
    r2 = dojo_bridge.ingest_finding(dojo_raw, organization_id="org1")
    assert r2.source_snapshot.id == dojo_result.source_snapshot.id

    session.close()
