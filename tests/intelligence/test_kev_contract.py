import json
from pathlib import Path

import pytest

from vulnops.intelligence.kev import KEVAdapter

FIXTURE = Path(__file__).parent.parent / "fixtures" / "intelligence" / "kev_catalog.json"


def test_kev_parses_catalog_and_retains_source():
    data = json.loads(FIXTURE.read_text())
    adapter = KEVAdapter()
    adapter.fetch_catalog(raw_fixture=data, source_url="https://www.cisa.gov/known_exploited_vulnerabilities.json")
    assert adapter.is_kev("CVE-2026-12345") is True
    assert adapter.is_kev("CVE-1999-0001") is False
    rec = adapter.get_record("CVE-2026-12345")
    assert rec is not None
    assert rec.kev is True
    assert rec.source == "kev"
    assert rec.source_url.startswith("https://")


def test_kev_stale_does_not_delete():
    data = json.loads(FIXTURE.read_text())
    adapter = KEVAdapter()
    adapter.fetch_catalog(raw_fixture=data)
    assert adapter.is_kev("CVE-2026-12345")

    class FailingClient:
        def get(self, *a, **kw):
            raise Exception("network error")

    adapter.http_client = FailingClient()
    with pytest.raises(Exception):
        adapter.fetch_catalog()

    health = adapter.get_health()
    assert health.freshness == "stale"
    # Existing catalog still retained - is_kev still true (not deleted)
    assert adapter.is_kev("CVE-2026-12345") is True


def test_kev_schema_rejection():
    adapter = KEVAdapter()
    with pytest.raises(ValueError):
        adapter.fetch_catalog(raw_fixture={"bad": "data"})
    assert adapter.get_health().freshness == "degraded"
