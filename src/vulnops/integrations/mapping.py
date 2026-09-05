from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from vulnops.assets.reconciliation import AssetService, ReconciliationResult


@dataclass
class MappingResult:
    status: str  # resolved|ambiguous|not_found|candidate
    asset_id: str | None
    reason: str


class AssetMapper:
    """
    Maps external identifiers (DefectDojo product/service, Wazuh agent, etc.)
    to canonical Assets via AssetService reconciliation.
    Never arbitrarily selects an asset on collision.
    """

    def __init__(self, session: Session):
        self.session = session
        self.service = AssetService(session)

    def map_hints(self, hints: list[dict], organization_id: str) -> MappingResult:
        if not hints:
            return MappingResult(status="not_found", asset_id=None, reason="no hints")

        # Try each hint in order, return first resolved
        # If any hint is ambiguous, return ambiguous immediately (requires review)
        for hint in hints:
            ns = hint.get("namespace")
            val = hint.get("value")
            if not ns or not val:
                continue
            result = self.service.reconcile_alias(ns, val, organization_id=organization_id)
            if result.status == "ambiguous":
                return MappingResult(status="ambiguous", asset_id=None, reason=result.reason)
            if result.status == "resolved":
                return MappingResult(status="resolved", asset_id=result.asset_id, reason=result.reason)

        # No resolved, check if any candidate/not_found?
        return MappingResult(status="not_found", asset_id=None, reason="no resolvable alias")

    def map_defectdojo(self, finding: dict, organization_id: str) -> MappingResult:
        hints = list(finding.get("asset_hints") or [])
        # Also synthesize hints from product/service/host fields (without mutating original)
        if finding.get("host") and not any(h["value"] == finding["host"] for h in hints):
            hints.append({"namespace": "hostname", "value": finding["host"]})
        if finding.get("service") and not any(h["value"] == finding["service"] for h in hints):
            hints.append({"namespace": "service", "value": finding["service"]})
        return self.map_hints(hints, organization_id)

    def map_wazuh(self, event: dict, organization_id: str) -> MappingResult:
        hints = list(event.get("asset_hints") or [])
        agent = event.get("agent", {})
        if agent.get("id"):
            hints.append({"namespace": "wazuh", "value": agent["id"]})
        if agent.get("name"):
            hints.append({"namespace": "hostname", "value": agent["name"]})
        return self.map_hints(hints, organization_id)
