# Object storage (MinIO / S3)

Raw SBOM evidence is stored under keys `sbom/<organization_id>/<content_sha256>.json`
in the configured bucket. Database rows (`source_snapshots`, `sbom_documents`) record
the canonical `s3://` URI and the content SHA-256 digest.

## Configuration

| Variable | Purpose |
| --- | --- |
| `OBJECT_STORAGE_ENDPOINT` | S3 API base URL (e.g. `http://127.0.0.1:9000` for host-run staging, `http://minio:9000` in compose) |
| `OBJECT_STORAGE_BUCKET` | Bucket name (default `vulnops-snapshots`) |
| `OBJECT_STORAGE_ACCESS_KEY` / `OBJECT_STORAGE_SECRET_KEY` | Credentials |
| `OBJECT_STORAGE_REGION` | Region name (default `us-east-1`) |
| `OBJECT_STORAGE_FORCE_PATH_STYLE` | `true` for MinIO (default) |
| `OBJECT_STORAGE_LOCAL_MIRROR` | When `true`, also write `./storage/...` while S3 is configured |

When **endpoint and credentials are unset**, ingestion writes only to `./storage`
(local MVP path). When they are set, the API/worker upload to S3/MinIO via boto3;
the bucket is created on first write if it does not exist.

## Topology

| Topology | How to enable |
| --- | --- |
| Full compose (`api` / `worker` / `orchestrator`) | Root `docker-compose.yml` already sets `OBJECT_STORAGE_*` and depends on `minio` |
| Host-run API + backing services | `docker compose up -d postgres valkey minio` and export `OBJECT_STORAGE_*` to `http://127.0.0.1:9000` (see [integrated staging](integrated-staging.md)) |
| SQLite / unit tests | No object storage env → local `./storage` only |

Copy `deploy/env/host-staging-object-storage.env` into your shell before starting
host-run workers when you want MinIO populated during staging drills.

## Smoke test (live MinIO)

With MinIO listening on loopback:

```bash
set -a && source deploy/env/host-staging-object-storage.env && set +a
uv run python scripts/object_storage_smoke.py
```

## Automated tests (no Docker)

`tests/object_storage/test_object_store.py` uses **moto** to assert put/get/digest and
SBOM ingestion without a live MinIO process.
