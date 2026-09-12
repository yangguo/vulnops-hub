# Backup and Restore

> **Status:** PostgreSQL and local `./storage` drills are rehearsed on the staging
> topology (see [integrated staging evidence](integrated-staging.md)). MinIO/S3
> wiring is implemented and covered by moto-backed tests plus an optional live
> smoke script; a **certified production** bucket sync + PITR drill remains
> operator-owned.

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

- Raw scanner reports, SBOMs, and advisory payloads live in private bucket
  `vulnops-snapshots` (or your configured `OBJECT_STORAGE_BUCKET`).
- Each SBOM object key is `sbom/<organization_id>/<content_sha256>.json`; the
  object metadata field `content-sha256` duplicates the digest for head-object checks.
- Enable bucket versioning in production.

Configuration and topology options are documented in
[object-storage.md](object-storage.md).

### Host-run staging with MinIO

```bash
docker compose up -d postgres valkey minio
set -a && source deploy/env/host-staging-object-storage.env && set +a
uv run python scripts/object_storage_smoke.py
```

### Bucket sync (disaster copy)

```bash
aws s3 sync s3://vulnops-snapshots s3://vulnops-snapshots-backup \
  --endpoint-url "${OBJECT_STORAGE_ENDPOINT}"
```

### Digest consistency (database ↔ object store)

For each SBOM snapshot row, the stored object must hash to `content_sha256`:

```bash
# Sample URIs from the database
psql -c "SELECT content_sha256, object_uri FROM source_snapshots WHERE source='sbom' LIMIT 5;"

# Option A — AWS CLI (MinIO endpoint)
aws s3api get-object \
  --bucket vulnops-snapshots \
  --key "sbom/<org>/<digest>.json" \
  /tmp/sbom.json \
  --endpoint-url "${OBJECT_STORAGE_ENDPOINT}"
sha256sum /tmp/sbom.json

# Option B — in-repo helper (uses configured OBJECT_STORAGE_*)
uv run python - <<'PY'
from vulnops.config import get_settings
from vulnops.object_storage.object_store import verify_sbom_object_digest

uri = "s3://vulnops-snapshots/sbom/<org>/<digest>.json"
digest = "<digest>"
print(verify_sbom_object_digest(uri, digest, get_settings()))
PY
```

When `OBJECT_STORAGE_*` is unset, objects exist only under `./storage/sbom/...`;
verify with `sha256sum storage/sbom/<org>/<digest>.json`.

## Recovery Procedure

1. Restore database to selected point (PITR).
2. Restore/version corresponding object-store bucket.
3. Rehydrate adapter cursor state (`source_statuses` table).
4. Verify source snapshot digest consistency (`sha256sum` or `verify_sbom_object_digest` per row).
5. After the replay CLI is implemented, re-run projections safely from the
   selected source snapshot. Do not use the previously proposed
   `--replay --from-snapshot` flags until they exist in `--help` and tests.
6. Confirm no external ticket action is re-emitted without outbox deduplication (check `outbox_events` delivered_at).
7. Run full E2E fixture: `uv run pytest tests/e2e -q`.

## Retention and Legal Hold

- Raw payloads may be deleted per retention policy, but a minimal hash/provenance record remains for audit.
- A future legal-hold flag on `sbom_documents` and `source_snapshots` must
  prevent deletion; the current schema does not enforce this yet.
