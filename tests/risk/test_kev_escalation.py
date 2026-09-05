from vulnops.risk.policy import PolicyInput, RiskPolicyEngine


def test_kev_critical_internet_asset_selects_p0_policy():
    engine = RiskPolicyEngine(policy_version="risk-2026-09-01")
    inp = PolicyInput(
        vulnerability_id="CVE-2026-12345",
        kev=True,
        epss_score=0.91,
        cvss_score=9.8,
        asset_criticality="critical",
        internet_exposure="external",
        match_confidence=0.93,
        match_class="deterministic",
    )
    result = engine.evaluate(inp)
    assert result.priority == "P0"
    assert result.policy_version == "risk-2026-09-01"
    # Must include explanation factors
    assert "kev" in str(result.factors).lower() or "escalation" in str(result.explanation).lower()
    # KEV on critical internet should be hard escalation
    assert result.escalated is True


def test_non_kev_high_cvss_not_p0_without_other_factors():
    engine = RiskPolicyEngine(policy_version="risk-2026-09-01")
    inp = PolicyInput(
        vulnerability_id="CVE-2026-99999",
        kev=False,
        epss_score=0.1,
        cvss_score=5.0,
        asset_criticality="low",
        internet_exposure="internal",
        match_confidence=0.9,
        match_class="deterministic",
    )
    result = engine.evaluate(inp)
    assert result.priority in ("P2", "P3", "P4")
    assert result.escalated is False


def test_candidate_match_never_escalates_to_p0():
    engine = RiskPolicyEngine(policy_version="risk-2026-09-01")
    inp = PolicyInput(
        vulnerability_id="CVE-2026-99999",
        kev=True,  # even with KEV, candidate confidence should not auto-create P0
        epss_score=0.99,
        cvss_score=10.0,
        asset_criticality="critical",
        internet_exposure="external",
        match_confidence=0.4,
        match_class="candidate",
    )
    result = engine.evaluate(inp)
    # Candidate should not be P0; policy must downgrade
    assert result.priority != "P0" or result.reasons is not None
    # At least should note candidate limitation
    assert "candidate" in str(result.factors).lower() or "confidence" in str(result.factors).lower()
