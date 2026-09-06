# Backup and Restore

> **Status:** Target procedure, not a completed recovery drill. Commands must be
> validated against the selected staging topology before being cited as release
> evidence. The replay CLI and legal-hold enforcement described below are not
> implemented in the current preview.

## PostgreSQL

- Enable point-in-time recovery (PITR) for production.
- Daily base backup + WAL archiving.
- Test restore to isolated environment at defined cadence, including object-store consistency checks.

```bash
# Backup
pg_dump -Fc -h $POSTGRES_HOST -U vulnops vulnops > backup.dump
# Restore
pg_restore -h $POSTGRES_HOST -U vulnops -d vulnops --clean backup.dump
# Verify
psql -c "SELECT count(*) FROM source_snapshots;"
```

## Object Storage (MinIO/S3)

- Raw scanner reports, SBOMs, advisory payloads reside in private bucket `vulnops-snapshots`.
- Each object has content SHA-256, source snapshot ID, retention policy.
- Versioning enabled on bucket.

```bash
# Sync bucket
aws s3 sync s3://vulnops-snapshots s3://vulnops-snapshots-backup --endpoint-url http://minio:9000
# Verify digest consistency
psql -c "SELECT content_sha256, object_uri FROM source_snapshots LIMIT 5;"
aws s3api head-object --bucket vulnops-snapshots --key sbom/<digest>.json --query ContentSHA256
```

## Recovery Procedure

1. Restore database to selected point (PITR).
2. Restore/version corresponding object-store bucket.
3. Rehydrate adapter cursor state (`source_statuses` table).
4. Verify source snapshot digest consistency (`sha256sum` of stored objects vs DB).
5. After the replay CLI is implemented, re-run projections safely from the
   selected source snapshot. Do not use the previously proposed
   `--replay --from-snapshot` flags until they exist in `--help` and tests.
6. Confirm no external ticket action is re-emitted without outbox deduplication (check `outbox_events` delivered_at).
7. Run full E2E fixture: `uv run pytest tests/e2e -q`.

## Retention and Legal Hold

- Raw payloads may be deleted per retention policy, but a minimal hash/provenance record remains for audit.
- A future legal-hold flag on `sbom_documents` and `source_snapshots` must
  prevent deletion; the current schema does not enforce this yet.
