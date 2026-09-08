from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from vulnops.intelligence.contracts import AdvisoryRecord, IntelligenceAdapter, SourceHealth

logger = logging.getLogger("vulnops.intelligence.osv")


def _strip_purl_version(purl: str) -> str:
    """
    Drop the version qualifier from a purl for OSV package queries.

    OSV rejects a version-qualified purl combined with a version param, so the
    query carries the bare package purl plus a separate version field. Cut at
    the first `@` in the final `/`-segment only, after splitting off any query
    or fragment, so namespace purls survive:
    pkg:pypi/urllib3@1.26.17 -> pkg:pypi/urllib3
    pkg:rpm/fedora/curl@7.0-1 -> pkg:rpm/fedora/curl
    """
    base = purl
    for sep in ("?", "#"):
        base = base.split(sep, 1)[0]
    last_sep = base.rfind("/")
    segment = base[last_sep + 1 :]
    at = segment.find("@")
    if at == -1:
        return base
    return base[: last_sep + 1 + at]


class OSVAdapter(IntelligenceAdapter):
    """
    Direct OSV adapter for purl/ecosystem/version-range queries.
    Live path uses https://api.osv.dev/v1/query, one call per component.
    Stores only fields needed for matching, with source provenance.
    """

    source = "osv"
    base_url = "https://api.osv.dev"

    def __init__(self, session=None, http_client=None):
        self.session = session
        self.http_client = http_client  # For testing injection
        self._status = SourceHealth(
            source=self.source, last_success_at=None, last_checked_at=None, freshness="unknown"
        )

    def discover(self, config: dict, cursor: str | None):
        # Not used for batch query; batch is on-demand matching path
        return []

    def validate(self, raw: dict):
        if not isinstance(raw, dict) or "results" not in raw:
            return False, "missing results"
        return True, None

    def normalize(self, validated: dict, retrieved_at: datetime, source_url: str) -> AdvisoryRecord:
        raise NotImplementedError("Use lookup_batch for OSV")

    def apply(self, records: list[AdvisoryRecord], session):
        # Persist to DB - for now just count; real implementation would upsert Vulnerability etc.
        # Must not delete existing assertions on failure; caller handles health
        return len(records)

    def checkpoint(self, result):
        return None, self._status

    @staticmethod
    def _component_query(component: dict) -> dict[str, Any] | None:
        """Build one /v1/query payload; None when the component is unqueryable."""
        purl = component.get("purl")
        if purl:
            return {"package": {"purl": _strip_purl_version(purl)}}
        if component.get("ecosystem") and component.get("name"):
            return {
                "package": {
                    "ecosystem": component["ecosystem"],
                    "name": component["name"],
                }
            }
        return None

    def lookup_batch(
        self,
        components: list[dict],
        retrieved_at: datetime | None = None,
        source_url: str | None = None,
        raw_fixture: dict | None = None,
    ) -> list[AdvisoryRecord]:
        """
        Query OSV for a batch of components.
        components: list of {"purl": str, "version": str} or similar
        Live path: one POST {base}/v1/query per component, sending the
        version-stripped purl plus a separate version field. OSV 400s on a
        version-qualified purl combined with a version param, and
        /v1/querybatch returns {id, modified} stubs without affected ranges.
        A per-component HTTP error is logged and that component skipped (its
        result slot stays empty so query_index keeps matching the component
        index); the call raises only when every component failed, so the
        orchestrator's fail_event path can retry the event.
        For tests, pass raw_fixture ({"results": [...]}-shaped) to bypass HTTP
        and directly parse.
        Returns normalized AdvisoryRecords with provenance.
        """
        now = retrieved_at or datetime.now(UTC)
        url = source_url or f"{self.base_url}/v1/query"

        had_failures = False
        if raw_fixture is not None:
            raw = raw_fixture
        else:
            # One request per component; SBOM component counts are small.
            client = self.http_client
            owns_client = client is None
            if owns_client:
                client = httpx.Client(timeout=10)
            results: list[dict[str, Any]] = []
            attempted = 0
            failures = 0
            last_error: Exception | None = None
            try:
                for idx, component in enumerate(components):
                    query = self._component_query(component)
                    if query is None:
                        results.append({"vulns": []})
                        continue
                    attempted += 1
                    if component.get("version"):
                        query["version"] = component["version"]
                    try:
                        resp = client.post(f"{self.base_url}/v1/query", json=query)
                        resp.raise_for_status()
                        payload = resp.json()
                        results.append(payload if isinstance(payload, dict) else {"vulns": []})
                    except Exception as e:
                        # Mark stale but do NOT delete existing advisory
                        # assertions; other components still get their queries.
                        had_failures = True
                        failures += 1
                        last_error = e
                        self._status.last_checked_at = now
                        self._status.freshness = "stale"
                        self._status.error = str(e)[:512]
                        logger.warning(
                            "OSV query failed for component %s (purl=%s): %s",
                            idx,
                            component.get("purl"),
                            e,
                        )
                        results.append({"vulns": []})
            finally:
                if owns_client:
                    client.close()
            if attempted and failures == attempted and last_error is not None:
                raise last_error
            raw = {"results": results}

        is_valid, err = self.validate(raw)
        if not is_valid:
            self._status.last_checked_at = now
            self._status.freshness = "degraded"
            self._status.error = err
            raise ValueError(f"invalid OSV response: {err}")

        records: list[AdvisoryRecord] = []
        for idx, result in enumerate(raw.get("results", [])):
            vulns = result.get("vulns") or []
            for vuln in vulns:
                vuln_id = (
                    vuln.get("id")
                    or vuln.get("aliases", [None])[0]
                    or f"OSV-{uuid.uuid4().hex[:8]}"
                )
                # Extract affected ranges
                affected = []
                for aff in vuln.get("affected", []):
                    pkg = aff.get("package", {})
                    ecosystem = pkg.get("ecosystem")
                    purl = pkg.get("purl")
                    for rng in aff.get("ranges", []):
                        rtype = rng.get("type")
                        events = rng.get("events", [])
                        introduced = None
                        fixed = None
                        for ev in events:
                            if "introduced" in ev:
                                introduced = ev["introduced"]
                            if "fixed" in ev:
                                fixed = ev["fixed"]
                        affected.append(
                            {
                                "ecosystem": ecosystem,
                                "purl": purl,
                                "type": rtype,
                                "introduced": introduced,
                                "fixed": fixed,
                            }
                        )
                rec = AdvisoryRecord(
                    vulnerability_id=vuln_id,
                    source=self.source,
                    retrieved_at=now,
                    source_url=url,
                    content=vuln,
                    description=vuln.get("summary") or vuln.get("details"),
                    aliases=vuln.get("aliases", []),
                    affected_ranges=affected,
                    references=[r.get("url") for r in vuln.get("references", []) if r.get("url")],
                    retrieval_metadata={"query_index": idx},
                )
                records.append(rec)

        if not had_failures:
            # Full success (or fixture path) is fresh; partial failures already
            # set stale above and must not be overwritten.
            self._status.last_success_at = now
            self._status.last_checked_at = now
            self._status.freshness = "fresh"
        return records

    def get_health(self) -> SourceHealth:
        return self._status
