"""Storage bridge for immutable raw evidence bytes.

SBOM payloads use configured S3/MinIO storage with the local content-addressed
store as the unconfigured fallback. Scanner-adapter payloads remain node-local
under ``./storage/evidence`` in this pilot implementation.
"""

from __future__ import annotations

import os

from vulnops.config import get_settings
from vulnops.object_storage.object_store import (
    get_object_bytes,
    object_uri,
    persist_sbom_raw_bytes,
    sbom_object_key,
    sha256_hex,
    validate_organization_id,
)


def sbom_object_uri(bucket: str, organization_id: str, digest: str) -> str:
    return object_uri(bucket, sbom_object_key(organization_id, digest))


def sbom_local_path(organization_id: str, digest: str) -> str:
    return os.path.join("storage", sbom_object_key(organization_id, digest))


def evidence_local_path(organization_id: str, digest: str) -> str:
    return os.path.join(
        "storage", "evidence", validate_organization_id(organization_id), f"{digest}.json"
    )


def _write_idempotent(path: str, raw_bytes: bytes, digest: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            existing = handle.read()
        if sha256_hex(existing) != digest:
            raise RuntimeError("existing local evidence digest mismatch")
        return
    with open(path, "wb") as handle:
        handle.write(raw_bytes)


def persist_sbom_bytes(raw_bytes: bytes, organization_id: str, digest: str) -> str:
    """Persist SBOM bytes and return the logical object URI."""

    settings = get_settings()
    return persist_sbom_raw_bytes(
        raw_bytes,
        settings.object_storage_bucket,
        organization_id,
        digest,
        settings,
    )


def persist_evidence_bytes(raw_bytes: bytes, organization_id: str, digest: str) -> None:
    """Persist adapter/scanner snapshot bytes keyed by content digest."""

    if sha256_hex(raw_bytes) != digest:
        raise ValueError("digest does not match raw evidence content")
    _write_idempotent(evidence_local_path(organization_id, digest), raw_bytes, digest)


def read_raw_bytes(
    organization_id: str,
    digest: str,
    object_uri_value: str | None = None,
) -> bytes | None:
    """Return stored bytes from configured object storage or the local evidence store."""

    validate_organization_id(organization_id)
    if object_uri_value and object_uri_value.startswith("s3://"):
        try:
            return get_object_bytes(object_uri_value)
        except FileNotFoundError:
            pass

    for path in (
        sbom_local_path(organization_id, digest),
        evidence_local_path(organization_id, digest),
    ):
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                return handle.read()
    return None
