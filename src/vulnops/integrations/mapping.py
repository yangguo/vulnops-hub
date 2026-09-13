from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from vulnops.assets.reconciliation import AssetService


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
                return MappingResult(
                    status="resolved", asset_id=result.asset_id, reason=result.reason
                )

        # No resolved, check if any candidate/not_found?
        return MappingResult(status="not_found", asset_id=None, reason="no resolvable alias")

    def map_defectdojo(self, finding: dict, organization_id: str) -> MappingResult:
        hints = list(finding.get("asset_hints") or [])
        # DefectDojo v2 exposes scanner-specific metadata through the
        # read-only ``finding_meta`` list rather than flattening values onto
        # the finding.  Normalize the host/service aliases here so a real
        # API response follows the same join contract as Hub fixtures.
        metadata = self._metadata_map(finding.get("finding_meta"))
        host = finding.get("host") or metadata.get("host") or metadata.get("hostname")
        service = finding.get("service") or metadata.get("service")
        # Also synthesize hints from product/service/host fields (without mutating original)
        if host and not any(h.get("value") == host for h in hints):
            hints.append({"namespace": "hostname", "value": host})
        if service and not any(h.get("value") == service for h in hints):
            hints.append({"namespace": "service", "value": service})
        return self.map_hints(hints, organization_id)

    @staticmethod
    def _metadata_map(raw: object) -> dict[str, str]:
        """Return safe, case-insensitive name/value pairs from DD metadata."""

        if not isinstance(raw, list):
            return {}
        values: dict[str, str] = {}
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and isinstance(value, str) and value.strip():
                values[name.strip().lower()] = value.strip()
        return values

    def map_wazuh(self, event: dict, organization_id: str) -> MappingResult:
        hints = list(event.get("asset_hints") or [])
        agent = event.get("agent", {})
        if agent.get("id"):
            hints.append({"namespace": "wazuh", "value": agent["id"]})
        if agent.get("name"):
            hints.append({"namespace": "hostname", "value": agent["name"]})
        return self.map_hints(hints, organization_id)
