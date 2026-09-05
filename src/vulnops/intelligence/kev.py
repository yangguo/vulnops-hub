from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx

from vulnops.intelligence.contracts import AdvisoryRecord, IntelligenceAdapter, SourceHealth


class KEVAdapter(IntelligenceAdapter):
    source = "kev"
    base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, http_client=None):
        self.http_client = http_client
        self._catalog: dict[str, dict] | None = None
        self._status = SourceHealth(source=self.source, last_success_at=None, last_checked_at=None, freshness="unknown")

    def discover(self, config: dict, cursor: str | None):
        return []

    def validate(self, raw: dict):
        if not isinstance(raw, dict) or "vulnerabilities" not in raw:
            return False, "missing vulnerabilities"
        return True, None

    def normalize(self, validated: dict, retrieved_at: datetime, source_url: str) -> AdvisoryRecord:
        raise NotImplementedError

    def apply(self, records: list[AdvisoryRecord], session):
        return len(records)

    def checkpoint(self, result):
        return None, self._status

    def fetch_catalog(self, raw_fixture: dict | None = None, source_url: str | None = None) -> dict:
        now = datetime.now(timezone.utc)
        url = source_url or self.base_url
        if raw_fixture is not None:
            raw = raw_fixture
        else:
            try:
                client = self.http_client or httpx.Client(timeout=10)
                resp = client.get(url)
                resp.raise_for_status()
                raw = resp.json()
            except Exception as e:
                self._status.last_checked_at = now
                self._status.freshness = "stale"
                self._status.error = str(e)[:512]
                raise
        is_valid, err = self.validate(raw)
        if not is_valid:
            self._status.last_checked_at = now
            self._status.freshness = "degraded"
            self._status.error = err
            raise ValueError(err)
        # Build catalog dict
        self._catalog = {v["cveID"]: v for v in raw.get("vulnerabilities", []) if "cveID" in v}
        self._status.last_success_at = now
        self._status.last_checked_at = now
        self._status.freshness = "fresh"
        self._status.error = None
        return raw

    def is_kev(self, cve_id: str) -> bool:
        if self._catalog is None:
            # Try fetch? For tests, catalog must be loaded via fetch_catalog with fixture
            return False
        return cve_id in self._catalog

    def get_record(self, cve_id: str, retrieved_at: datetime | None = None, source_url: str | None = None) -> AdvisoryRecord | None:
        if self._catalog is None or cve_id not in self._catalog:
            return None
        entry = self._catalog[cve_id]
        now = retrieved_at or datetime.now(timezone.utc)
        return AdvisoryRecord(
            vulnerability_id=cve_id,
            source=self.source,
            retrieved_at=now,
            source_url=source_url or self.base_url,
            kev=True,
            kev_due_date=entry.get("dueDate"),
            content=entry,
            description=entry.get("shortDescription"),
        )

    def get_health(self) -> SourceHealth:
        return self._status
