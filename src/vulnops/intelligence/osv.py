from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from vulnops.intelligence.contracts import AdvisoryRecord, IntelligenceAdapter, SourceHealth
from vulnops.intelligence.models import SourceStatus
from vulnops.config import get_settings


class OSVAdapter(IntelligenceAdapter):
    """
    Direct OSV adapter for purl/ecosystem/version-range queries.
    Uses https://api.osv.dev/v1/querybatch
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
        For tests, pass raw_fixture to bypass HTTP and directly parse.
        Returns normalized AdvisoryRecords with provenance.
        """
        now = retrieved_at or datetime.now(timezone.utc)
        url = source_url or f"{self.base_url}/v1/querybatch"
        settings = get_settings()

        if raw_fixture is not None:
            raw = raw_fixture
        else:
            # Build query payload
            queries = []
            for c in components:
                q: dict[str, Any] = {}
                if c.get("purl"):
                    q["package"] = {"purl": c["purl"]}
                elif c.get("ecosystem") and c.get("name"):
                    q["package"] = {"ecosystem": c["ecosystem"], "name": c["name"]}
                else:
                    continue
                if c.get("version"):
                    q["version"] = c["version"]
                queries.append(q)
            payload = {"queries": queries}
            try:
                client = self.http_client or httpx.Client(timeout=10)
                resp = client.post(f"{self.base_url}/v1/querybatch", json=payload)
                resp.raise_for_status()
                raw = resp.json()
                self._status.last_success_at = now
                self._status.last_checked_at = now
                self._status.freshness = "fresh"
                self._status.error = None
            except Exception as e:
                # Mark stale/degraded but do NOT delete existing advisory assertions
                self._status.last_checked_at = now
                self._status.freshness = "stale"
                self._status.error = str(e)[:512]
                # Re-raise? For now return empty and let caller handle health
                raise

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
                vuln_id = vuln.get("id") or vuln.get("aliases", [None])[0] or f"OSV-{uuid.uuid4().hex[:8]}"
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
                )
                records.append(rec)

        self._status.last_success_at = now
        self._status.last_checked_at = now
        self._status.freshness = "fresh"
        return records

    def get_health(self) -> SourceHealth:
        return self._status
