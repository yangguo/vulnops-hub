"""S3-compatible object storage for immutable raw evidence."""

from vulnops.object_storage.object_store import (
    clear_s3_client_cache,
    get_object_bytes,
    is_object_storage_configured,
    persist_sbom_raw_bytes,
    sbom_object_key,
    sha256_hex,
    verify_sbom_object_digest,
)

__all__ = [
    "clear_s3_client_cache",
    "get_object_bytes",
    "is_object_storage_configured",
    "persist_sbom_raw_bytes",
    "sbom_object_key",
    "sha256_hex",
    "verify_sbom_object_digest",
]
