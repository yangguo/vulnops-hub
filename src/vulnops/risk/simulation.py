from __future__ import annotations

from typing import List

from vulnops.risk.policy import PolicyInput, PolicyResult, RiskPolicyEngine


class PolicySimulator:
    """
    Simulate policy against historical exposure sample before activation.
    Per modules.md:6 policy simulation must be testable.
    """

    def __init__(self, engine: RiskPolicyEngine):
        self.engine = engine

    def simulate(self, inputs: List[PolicyInput]) -> List[PolicyResult]:
        return [self.engine.evaluate(inp) for inp in inputs]

    def compare(self, old_engine: RiskPolicyEngine, new_engine: RiskPolicyEngine, inputs: List[PolicyInput]) -> dict:
        old_results = [old_engine.evaluate(i) for i in inputs]
        new_results = [new_engine.evaluate(i) for i in inputs]
        changes = []
        for idx, (old, new) in enumerate(zip(old_results, new_results)):
            if old.priority != new.priority:
                changes.append({"index": idx, "from": old.priority, "to": new.priority, "vuln": inputs[idx].vulnerability_id})
        return {
            "old_version": old_engine.policy_version,
            "new_version": new_engine.policy_version,
            "total": len(inputs),
            "changed": len(changes),
            "changes": changes,
        }
