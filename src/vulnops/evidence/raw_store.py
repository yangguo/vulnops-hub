"""Local backing store for immutable raw evidence bytes.

Production deployments map the logical ``s3://`` URIs recorded on
``source_snapshots`` and SBOM documents to object storage. In development and
CI the bytes live under ``./storage`` so digest verification and authorized
API retrieval stay testable without MinIO.
"""

from __future__ import annotations

import os

from vulnops.config import get_settings


def sbom_object_uri(bucket: str, organization_id: str, digest: str) -> str:
    return f"s3://{bucket}/sbom/{organization_id}/{digest}.json"


def sbom_local_path(organization_id: str, digest: str) -> str:
    return os.path.join("storage", "sbom", organization_id, f"{digest}.json")


def evidence_local_path(organization_id: str, digest: str) -> str:
    return os.path.join("storage", "evidence", organization_id, f"{digest}.json")


def _write_idempotent(path: str, raw_bytes: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "wb") as handle:
            handle.write(raw_bytes)


def persist_sbom_bytes(raw_bytes: bytes, organization_id: str, digest: str) -> str:
    """Persist SBOM bytes and return the logical object URI."""

    settings = get_settings()
    _write_idempotent(sbom_local_path(organization_id, digest), raw_bytes)
    return sbom_object_uri(settings.object_storage_bucket, organization_id, digest)


def persist_evidence_bytes(raw_bytes: bytes, organization_id: str, digest: str) -> None:
    """Persist adapter/scanner snapshot bytes keyed by content digest."""

    _write_idempotent(evidence_local_path(organization_id, digest), raw_bytes)


def read_raw_bytes(organization_id: str, digest: str) -> bytes | None:
    """Return stored bytes for an organization/digest pair when present locally."""

    for path in (
        sbom_local_path(organization_id, digest),
        evidence_local_path(organization_id, digest),
    ):
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                return handle.read()
    return None
