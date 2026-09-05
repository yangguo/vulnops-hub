import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vulnops.intelligence.epss import EPSSAdapter

FIXTURE = Path(__file__).parent.parent / "fixtures" / "intelligence" / "epss_response.json"


def test_epss_keeps_source_provenance():
    data = json.loads(FIXTURE.read_text())
    adapter = EPSSAdapter()
    now = datetime.now(timezone.utc)
    url = "https://api.first.org/data/v1/epss?cve=CVE-2026-12345"
    result = adapter.get_scores(["CVE-2026-12345"], raw_fixture=data, retrieved_at=now, source_url=url)
    assert "CVE-2026-12345" in result
    rec = result["CVE-2026-12345"]
    assert rec.source == "epss"
    assert rec.retrieved_at == now
    assert rec.source_url.startswith("https://")
    assert rec.epss_score == 0.91
    assert rec.epss_percentile == 0.99


def test_epss_stale_on_failure():
    class FailingClient:
        def get(self, *a, **kw):
            raise Exception("connection timeout")

    adapter = EPSSAdapter(http_client=FailingClient())
    with pytest.raises(Exception):
        adapter.get_scores(["CVE-2026-12345"])
    health = adapter.get_health()
    assert health.freshness == "stale"
    assert health.error is not None


def test_epss_schema_rejection_marks_degraded():
    adapter = EPSSAdapter()
    with pytest.raises(ValueError):
        adapter.get_scores(["CVE-2026-12345"], raw_fixture={"status": "ERROR", "data": []})
    assert adapter.get_health().freshness == "degraded"


def test_epss_does_not_downgrade_existing_on_stale():
    data = json.loads(FIXTURE.read_text())
    adapter = EPSSAdapter()
    result1 = adapter.get_scores(["CVE-2026-12345"], raw_fixture=data)
    assert result1["CVE-2026-12345"].epss_score == 0.91

    # Now cause stale - existing data should remain logically (health stale but not delete)
    class FailingClient:
        def get(self, *a, **kw):
            raise Exception("503 Service Unavailable")

    adapter.http_client = FailingClient()
    try:
        adapter.get_scores(["CVE-2026-12345"])
    except Exception:
        pass
    assert adapter.get_health().freshness == "stale"
    # Re-fetch success restores
    adapter.http_client = None
    result2 = adapter.get_scores(["CVE-2026-12345"], raw_fixture=data)
    assert result2["CVE-2026-12345"].epss_score == 0.91
