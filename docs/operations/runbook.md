# VulnOps Hub Operations Runbook

## Health Signals

- API readiness: `GET /health/ready` — checks DB connectivity.
- Liveness: `GET /health/live` — always 200 when process alive.
- Metrics: queue depth, job latency, retry rate, dead-letter count.
- Adapter health: last success, cursor lag, source freshness, parse rejection rate.
- Matching: throughput, candidate rate, ambiguity rate.

## Common Alerts

### Source stale beyond policy threshold

- Check: `GET /api/v1/sources` or `SourceStatus` table.
- Action: inspect adapter logs, verify egress proxy allowlist, check rate limits, replay from last cursor.
- A stale feed never downgrades existing exposures — it only blocks automatic closure if policy requires fresh intelligence.

### High-priority case SLA breach

- Query: `SELECT * FROM remediation_cases WHERE priority='P0' AND sla_breached=true`
- Action: escalate to owner_team, verify case assignment and due_at.
- SLA breaches create `vulnops.sla.breached.v1` events.

### Queue depth above threshold

- Check Valkey/Redis: `LLEN vulnops:queue` or metrics.
- Action: scale workers, check dead-letter, replay failed jobs via source snapshots.

### Backup restore drill overdue

- See `backup-restore.md`.

## Upgrade Procedure

1. Run `alembic upgrade head --sql` to preview migration.
2. Test on staging clone with anonymized fixtures.
3. Deploy API with `readinessProbe` gating.
4. No migration may silently convert candidate to confirmed — re-evaluation records matcher version.

## Troubleshooting

- **500 on SBOM upload**: check `validation_state` in `source_snapshots`, inspect `validation_errors`.
- **Case not progressing**: check allowed transitions via `GET /cases/{id}/allowed-transitions`.
- **Verification insufficient**: check coverage payload — incomplete scans never close cases.
