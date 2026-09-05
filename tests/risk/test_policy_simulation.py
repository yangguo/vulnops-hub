import pytest
from vulnops.risk.policy import RiskPolicyEngine, PolicyInput
from vulnops.risk.simulation import PolicySimulator


def test_policy_simulation_dry_run():
    engine = RiskPolicyEngine(policy_version="risk-2026-09-01")
    simulator = PolicySimulator(engine)

    inputs = [
        PolicyInput("CVE-2026-12345", kev=True, epss_score=0.91, cvss_score=9.8, asset_criticality="critical", internet_exposure="external", match_confidence=0.99, match_class="deterministic"),
        PolicyInput("CVE-2026-99999", kev=False, epss_score=0.1, cvss_score=5.0, asset_criticality="low", internet_exposure="internal", match_confidence=0.9, match_class="deterministic"),
        PolicyInput("CVE-2026-00001", kev=False, epss_score=0.5, cvss_score=7.5, asset_criticality="medium", internet_exposure="internal", match_confidence=0.4, match_class="candidate"),
    ]
    results = simulator.simulate(inputs)
    assert len(results) == 3
    assert results[0].priority == "P0"
    assert results[1].priority in ("P2", "P3", "P4")
    # Candidate should not be P0
    assert results[2].priority != "P0" or results[2].priority == "P4"


def test_policy_change_produces_new_version_and_audit():
    engine_v1 = RiskPolicyEngine(policy_version="risk-2026-09-01")
    engine_v2 = RiskPolicyEngine(policy_version="risk-2026-10-01")
    inp = PolicyInput("CVE-2026-12345", kev=True, epss_score=0.91, cvss_score=9.8, asset_criticality="critical", internet_exposure="external", match_confidence=0.99, match_class="deterministic")
    r1 = engine_v1.evaluate(inp)
    r2 = engine_v2.evaluate(inp)
    assert r1.policy_version != r2.policy_version
    assert r1.priority == r2.priority  # same logic but version differs
    # Version should be recorded for audit
    assert r2.policy_version == "risk-2026-10-01"


def test_explainable_factors_present():
    engine = RiskPolicyEngine(policy_version="risk-2026-09-01")
    inp = PolicyInput("CVE-2026-12345", kev=True, epss_score=0.91, cvss_score=9.8, asset_criticality="critical", internet_exposure="external", match_confidence=0.93, match_class="deterministic")
    result = engine.evaluate(inp)
    # Every factor must be visible for audit
    assert result.factors is not None
    assert "kev" in result.factors
    assert "cvss" in result.factors
    assert "epss" in result.factors
    assert "asset_criticality" in result.factors
    assert "match_confidence" in result.factors
    assert result.explanation is not None
    assert len(result.explanation) > 0
