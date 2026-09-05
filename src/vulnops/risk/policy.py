from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class PolicyInput:
    vulnerability_id: str
    kev: bool = False
    epss_score: float = 0.0
    epss_percentile: float | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    asset_criticality: str = "medium"  # critical|high|medium|low
    internet_exposure: str = "internal"  # external|internal|unknown
    match_confidence: float = 0.9
    match_class: str = "deterministic"  # confirmed|deterministic|corroborated|candidate|not_affected
    age_days: int | None = None
    data_sensitivity: str | None = None


@dataclass
class PolicyResult:
    priority: Literal["P0", "P1", "P2", "P3", "P4"]
    policy_version: str
    escalated: bool
    factors: dict
    explanation: str
    reasons: list[str] = field(default_factory=list)
    score: float | None = None


class RiskPolicyEngine:
    """
    Versioned transparent risk policy engine per docs/modules.md:6
    Supports hard escalation rules + score contributions + explainability
    """

    def __init__(self, policy_version: str = "risk-2026-09-01"):
        self.policy_version = policy_version

    def evaluate(self, inp: PolicyInput) -> PolicyResult:
        factors: dict = {}
        reasons: list[str] = []
        escalated = False

        # Capture all inputs for audit
        factors["kev"] = inp.kev
        factors["epss"] = inp.epss_score
        factors["epss_percentile"] = inp.epss_percentile
        factors["cvss"] = inp.cvss_score
        factors["cvss_vector"] = inp.cvss_vector
        factors["asset_criticality"] = inp.asset_criticality
        factors["internet_exposure"] = inp.internet_exposure
        factors["match_confidence"] = inp.match_confidence
        factors["match_class"] = inp.match_class

        # Hard escalation rules first (per arch 3.4)
        # Example: applicable CISA KEV on internet-facing critical service
        if inp.kev and inp.asset_criticality == "critical" and inp.internet_exposure == "external" and inp.match_class in ("deterministic", "confirmed"):
            if inp.match_confidence >= 0.7:
                explanation = f"Hard escalation: KEV {inp.vulnerability_id} on critical internet-facing asset with {inp.match_class} confidence {inp.match_confidence}"
                factors["hard_escalation"] = "kev_critical_internet"
                return PolicyResult(
                    priority="P0",
                    policy_version=self.policy_version,
                    escalated=True,
                    factors=factors,
                    explanation=explanation,
                    reasons=["kev_escalation"],
                    score=100,
                )

        # Also escalate if confirmed + KEV + high EPSS
        if inp.kev and inp.match_class == "confirmed" and (inp.epss_score or 0) > 0.5:
            factors["hard_escalation"] = "kev_confirmed_high_epss"
            return PolicyResult(
                priority="P0",
                policy_version=self.policy_version,
                escalated=True,
                factors=factors,
                explanation=f"Escalation: confirmed KEV with EPSS {inp.epss_score}",
                reasons=["kev_confirmed"],
                score=95,
            )

        # Candidate matches must not escalate to P0 - downgrade
        if inp.match_class == "candidate":
            factors["candidate_limitation"] = "candidate matches require review, cannot be P0"
            # Calculate base score but cap at P2+
            base = self._calculate_score(inp)
            # Downgrade: even with high CVSS, keep at P3/P4
            if base >= 70:
                priority = "P2"
            elif base >= 40:
                priority = "P3"
            else:
                priority = "P4"
            explanation = f"Candidate match (confidence {inp.match_confidence}) - triage required, base score {base:.1f} -> {priority}"
            return PolicyResult(
                priority=priority,  # type: ignore
                policy_version=self.policy_version,
                escalated=False,
                factors=factors,
                explanation=explanation,
                reasons=["candidate_requires_review"],
                score=base,
            )

        # Normal scoring path: weighted impact + exploitability + asset context + confidence
        score = self._calculate_score(inp)

        # Map score to priority bands
        if score >= 90:
            priority = "P0"
        elif score >= 70:
            priority = "P1"
        elif score >= 40:
            priority = "P2"
        elif score >= 20:
            priority = "P3"
        else:
            priority = "P4"

        # Confidence adjustment: low confidence downgrades
        if inp.match_confidence < 0.5 and priority in ("P0", "P1"):
            # Downgrade one tier
            downgrade_map = {"P0": "P1", "P1": "P2"}
            new_priority = downgrade_map.get(priority, priority)
            reasons.append(f"confidence_adjustment {inp.match_confidence} downgrades {priority}->{new_priority}")
            priority = new_priority  # type: ignore

        explanation = f"Score {score:.1f} -> {priority} (CVSS {inp.cvss_score}, EPSS {inp.epss_score}, criticality {inp.asset_criticality}, exposure {inp.internet_exposure}, confidence {inp.match_confidence})"

        return PolicyResult(
            priority=priority,  # type: ignore
            policy_version=self.policy_version,
            escalated=escalated,
            factors=factors,
            explanation=explanation,
            reasons=reasons,
            score=score,
        )

    def _calculate_score(self, inp: PolicyInput) -> float:
        # Weighted formula: illustrative only per modules.md
        # priority = escalations first otherwise weighted_impact + weighted_exploitability + asset_context + confidence_adjustment
        cvss = inp.cvss_score or 0
        epss = inp.epss_score or 0

        # Impact: CVSS weighted
        weighted_impact = cvss * 5  # 0-50

        # Exploitability: EPSS percentile or score
        weighted_exploitability = epss * 20  # 0-20
        if inp.epss_percentile:
            weighted_exploitability += inp.epss_percentile * 5

        # Asset context
        criticality_weights = {"critical": 20, "high": 15, "medium": 10, "low": 5, "unknown": 5}
        exposure_weights = {"external": 10, "internal": 2, "unknown": 5}
        weighted_asset = criticality_weights.get(inp.asset_criticality, 5) + exposure_weights.get(inp.internet_exposure, 2)

        # Confidence adjustment
        confidence_adj = (inp.match_confidence - 0.5) * 10  # -5 to +5

        total = weighted_impact + weighted_exploitability + weighted_asset + confidence_adj
        # Clamp 0-100
        return max(0, min(100, total))
