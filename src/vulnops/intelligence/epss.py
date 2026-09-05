from __future__ import annotations

from datetime import UTC, datetime

import httpx

from vulnops.intelligence.contracts import AdvisoryRecord, IntelligenceAdapter, SourceHealth


class EPSSAdapter(IntelligenceAdapter):
    source = "epss"
    base_url = "https://api.first.org/data/v1/epss"

    def __init__(self, http_client=None):
        self.http_client = http_client
        self._status = SourceHealth(
            source=self.source, last_success_at=None, last_checked_at=None, freshness="unknown"
        )

    def discover(self, config: dict, cursor: str | None):
        return []

    def validate(self, raw: dict):
        if not isinstance(raw, dict) or raw.get("status") != "OK":
            return False, "invalid EPSS response"
        if "data" not in raw:
            return False, "missing data"
        return True, None

    def normalize(self, validated: dict, retrieved_at: datetime, source_url: str) -> AdvisoryRecord:
        raise NotImplementedError

    def apply(self, records: list[AdvisoryRecord], session):
        return len(records)

    def checkpoint(self, result):
        return None, self._status

    def get_scores(
        self,
        cve_ids: list[str],
        raw_fixture: dict | None = None,
        retrieved_at: datetime | None = None,
        source_url: str | None = None,
    ) -> dict[str, AdvisoryRecord]:
        now = retrieved_at or datetime.now(UTC)
        url = source_url or f"{self.base_url}?cve={','.join(cve_ids)}"
        if raw_fixture is not None:
            raw = raw_fixture
        else:
            try:
                client = self.http_client or httpx.Client(timeout=10)
                resp = client.get(f"{self.base_url}?cve={','.join(cve_ids)}")
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

        result: dict[str, AdvisoryRecord] = {}
        for entry in raw.get("data", []):
            cve = entry.get("cve")
            if not cve:
                continue
            try:
                score = float(entry.get("epss", 0))
                percentile = float(entry.get("percentile", 0))
            except Exception:
                score = 0.0
                percentile = 0.0
            rec = AdvisoryRecord(
                vulnerability_id=cve,
                source=self.source,
                retrieved_at=now,
                source_url=url,
                epss_score=score,
                epss_percentile=percentile,
                content=entry,
            )
            result[cve] = rec

        self._status.last_success_at = now
        self._status.last_checked_at = now
        self._status.freshness = "fresh"
        self._status.error = None
        return result

    def get_health(self) -> SourceHealth:
        return self._status
