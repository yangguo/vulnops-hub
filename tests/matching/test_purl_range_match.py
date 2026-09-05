import pytest
from vulnops.matching.versioning import is_version_in_range
from vulnops.matching.service import MatchingService
from vulnops.sbom.parser import ParsedComponent


def test_purl_in_osv_range_creates_deterministic_exposure():
    svc = MatchingService()
    component = ParsedComponent(
        raw_name="urllib3",
        raw_version="1.26.18",
        purl="pkg:pypi/urllib3@1.26.18",
        ecosystem="pypi",
        normalized_name="urllib3",
        cpe=None,
        version_scheme="pypi",
    )
    # OSV range: introduced 0, fixed 1.26.19 -> 1.26.18 is vulnerable
    advisory = {
        "id": "CVE-2026-12345",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "purl": "pkg:pypi/urllib3"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.19"}]}],
            }
        ],
    }
    exposure = svc.evaluate(
        component=component,
        advisory=advisory,
        asset_context={"criticality": "high", "internet_exposure": "external"},
        scanner_evidence=None,
    )
    assert exposure.match_class == "deterministic"
    assert exposure.confidence >= 0.9
    assert exposure.case_id is not None or exposure.should_create_case is True
    # Evidence should include purl-range rule
    assert "osv.purl-range" in exposure.matched_rules or "purl-range" in str(exposure.matched_rules)


def test_purl_outside_range_not_vulnerable():
    svc = MatchingService()
    component = ParsedComponent(
        raw_name="urllib3",
        raw_version="1.26.19",
        purl="pkg:pypi/urllib3@1.26.19",
        ecosystem="pypi",
        normalized_name="urllib3",
        cpe=None,
        version_scheme="pypi",
    )
    advisory = {
        "id": "CVE-2026-12345",
        "affected": [
            {
                "package": {"ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.19"}]}],
            }
        ],
    }
    exposure = svc.evaluate(
        component=component,
        advisory=advisory,
        asset_context={},
        scanner_evidence=None,
    )
    assert exposure.match_class in ("not_affected", "candidate", "none")
    assert exposure.should_create_case is False


def test_version_in_range_helper():
    assert is_version_in_range("1.26.18", "0", "1.26.19") is True
    assert is_version_in_range("1.26.19", "0", "1.26.19") is False
    assert is_version_in_range("0", "0", "1.26.19") is True
    assert is_version_in_range("2.0.0", "0", "1.26.19") is False


def test_unsupported_version_scheme_produces_candidate():
    svc = MatchingService()
    component = ParsedComponent(
        raw_name="weirdpkg",
        raw_version="1.0.0-unknown-scheme",
        purl="pkg:unknown/weirdpkg@1.0.0-unknown-scheme",
        ecosystem="unknown",
        normalized_name="weirdpkg",
        cpe=None,
        version_scheme="unknown",
    )
    advisory = {
        "id": "CVE-2026-99999",
        "affected": [
            {
                "package": {"ecosystem": "unknown"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }
    exposure = svc.evaluate(
        component=component,
        advisory=advisory,
        asset_context={},
        scanner_evidence=None,
    )
    # Unsupported scheme should not be deterministic, must be candidate or unsupported
    assert exposure.match_class in ("candidate", "unsupported", "not_affected")
