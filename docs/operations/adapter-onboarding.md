# Adapter Onboarding Checklist

> **Status:** Reusable acceptance template. Unchecked boxes are requirements
> for each adapter review, not a claim that all current adapters are incomplete.

Every new adapter must prove:

- [ ] Source snapshot capture and content digest (SHA-256)
- [ ] Idempotent replay (same natural key returns original, no duplicate events)
- [ ] Cursor/checkpoint behavior (persist cursor only after durable processing)
- [ ] Rate-limit / error / staleness handling (health `stale`/`degraded`, no silent downgrade)
- [ ] Identity-mapping conflict handling (ambiguous aliases produce review work, not arbitrary merges)
- [ ] No direct mutation of Case workflow (only observations/evidence; matching decides)
- [ ] Sanitized fixtures and contract tests (recorded non-secret provider responses)
- [ ] Operational owner and runbook entry

## Contract

```python
discover(config, cursor) -> source records
validate(raw) -> validated record | rejection
normalize(validated) -> canonical observations + evidence refs
apply(observations) -> idempotent domain commands
checkpoint(result) -> next cursor and health
```

## Adapter Implementations

| Adapter | Source URL | Record Digest | Freshness Policy |
| --- | --- | --- | --- |
| OSV | https://api.osv.dev/v1/querybatch | content_sha256 | 1h |
| KEV | https://www.cisa.gov/.../known_exploited_vulnerabilities.json | catalog SHA | 24h |
| EPSS | https://api.first.org/data/v1/epss | response SHA | 24h |
| Vulnerability-Lookup | https://vulnerability.circl.lu/api/cve/{id} | payload SHA | 1h |
| DefectDojo | $DEFECTDOJO_BASE_URL/api/v2/findings | finding id + digest | 5m |
| Wazuh | $WAZUH_BASE_URL/manager/status | agent id + event digest | 5m |

## Security Requirements

- Validate TLS and provider identity
- Obey documented API terms, rate limits, cache headers, pagination
- Egress via allowlisted proxy
- Secrets only via secret manager, never in logs/events/snapshots
- Payload validation, size limits, archive-bomb protection

## Example Fixture

Place recorded response under `tests/fixtures/<adapter>/`:

```json
{
  "id": "CVE-2026-12345",
  "content": "...",
  "retrieved_at": "2026-09-05T10:00:00Z"
}
```

Then implement contract test:

```python
def test_osv_batch_match_keeps_source_timestamp(osv_adapter, fixture_http):
    record = osv_adapter.lookup_batch([component_fixture])[0]
    assert record.source == "osv"
    assert record.retrieved_at is not None
```
