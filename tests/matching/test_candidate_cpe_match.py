import pytest
from vulnops.matching.service import MatchingService
from vulnops.sbom.parser import ParsedComponent


def test_cpe_name_only_is_candidate_not_case():
    svc = MatchingService()
    # Component with only CPE, no purl - e.g., commercial product scanner output
    component = ParsedComponent(
        raw_name="openssl",
        raw_version="3.0.2",
        purl=None,
        ecosystem=None,
        normalized_name="openssl",
        cpe="cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
        version_scheme="generic",
    )
    advisory = {
        "id": "CVE-2026-99999",
        "affected": [
            {
                "package": {"ecosystem": "CPE", "name": "openssl"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.5"}]}],
            }
        ],
    }
    exposure = svc.evaluate(
        component=component,
        advisory=advisory,
        asset_context={},
        scanner_evidence=None,
    )
    assert exposure.match_class == "candidate"
    assert exposure.case_id is None
    assert exposure.should_create_case is False
    assert "cpe" in str(exposure.matched_rules).lower() or "candidate" in exposure.match_class


def test_corroborated_cpe_with_second_signal_is_triaged():
    svc = MatchingService()
    component = ParsedComponent(
        raw_name="openssl",
        raw_version="3.0.2",
        purl=None,
        ecosystem=None,
        normalized_name="openssl",
        cpe="cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
        version_scheme="generic",
    )
    advisory = {
        "id": "CVE-2026-99999",
        "affected": [{"package": {"name": "openssl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.5"}]}]}],
    }
    # Second independent signal - e.g., Wazuh inventory confirms same package
    exposure = svc.evaluate(
        component=component,
        advisory=advisory,
        asset_context={"second_signal": True},
        scanner_evidence=None,
    )
    # With corroboration, may be corroborated but still not deterministic -> triage by default
    assert exposure.match_class in ("corroborated", "candidate")
    assert exposure.should_create_case is False


def test_scanner_confirmed_overrides_cpe_candidate():
    svc = MatchingService()
    component = ParsedComponent(
        raw_name="openssl",
        raw_version="3.0.2",
        purl="pkg:deb/debian/openssl@3.0.2",
        ecosystem="deb",
        normalized_name="openssl",
        cpe="cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
        version_scheme="deb",
    )
    advisory = {"id": "CVE-2026-99999"}
    scanner_evidence = {
        "source": "defectdojo",
        "finding_id": "123456",
        "scanner_confirmed": True,
        "asset_mapping": "payments-api-3",
    }
    exposure = svc.evaluate(
        component=component,
        advisory=advisory,
        asset_context={},
        scanner_evidence=scanner_evidence,
    )
    assert exposure.match_class == "confirmed"
    assert exposure.confidence >= 0.95
    # Confirmed should allow case creation subject to policy
    assert exposure.should_create_case is True
