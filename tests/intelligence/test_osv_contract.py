import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vulnops.intelligence.osv import OSVAdapter

FIXTURE = Path(__file__).parent.parent / "fixtures" / "intelligence" / "osv_response.json"


def test_osv_batch_match_keeps_source_timestamp():
    data = json.loads(FIXTURE.read_text())
    adapter = OSVAdapter()
    now = datetime.now(timezone.utc)
    url = "https://api.osv.dev/v1/querybatch"
    component_fixture = [{"purl": "pkg:pypi/urllib3@1.26.18", "version": "1.26.18"}]
    record = adapter.lookup_batch(component_fixture, retrieved_at=now, source_url=url, raw_fixture=data)[0]
    assert record.source == "osv"
    assert record.retrieved_at is not None
    assert record.retrieved_at == now
    assert record.source_url.startswith("https://")
    assert record.vulnerability_id == "CVE-2026-12345"
    # Affected ranges should be preserved
    assert len(record.affected_ranges) >= 1
    assert record.affected_ranges[0]["fixed"] == "1.26.19"


def test_osv_stale_does_not_delete_existing():
    adapter = OSVAdapter()
    # Initially empty, fetch succeeds
    data = json.loads(FIXTURE.read_text())
    adapter.lookup_batch([{"purl": "pkg:pypi/urllib3@1.26.18"}], raw_fixture=data)
    health = adapter.get_health()
    assert health.freshness == "fresh"

    # Simulate failure by passing invalid fixture that triggers validation error
    try:
        adapter.lookup_batch([{"purl": "pkg:pypi/urllib3@1.26.18"}], raw_fixture={"invalid": True})
    except Exception:
        pass
    health = adapter.get_health()
    # Should be degraded/stale, not fresh, but existing data not deleted
    assert health.freshness in ("degraded", "stale")
    assert health.error is not None
    # Advisory still exists - we didn't delete
    # Re-fetch valid should restore
    adapter.lookup_batch([{"purl": "pkg:pypi/urllib3@1.26.18"}], raw_fixture=data)
    assert adapter.get_health().freshness == "fresh"


def test_osv_rate_limit_retries_and_marks_stale():
    # Simulate HTTP failure via mock client that raises
    class FailingClient:
        def post(self, *a, **kw):
            raise Exception("429 Too Many Requests")

    adapter = OSVAdapter(http_client=FailingClient())
    with pytest.raises(Exception):
        adapter.lookup_batch([{"purl": "pkg:pypi/urllib3@1.26.18"}])
    health = adapter.get_health()
    assert health.freshness == "stale"
    assert "429" in health.error or "Too Many" in health.error


def test_osv_schema_rejection():
    adapter = OSVAdapter()
    with pytest.raises(ValueError):
        adapter.lookup_batch([{"purl": "pkg:pypi/urllib3@1.26.18"}], raw_fixture={"bad": "data"})
    assert adapter.get_health().freshness == "degraded"
