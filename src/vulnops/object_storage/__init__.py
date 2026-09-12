"""S3-compatible object storage for immutable raw evidence."""

from vulnops.object_storage.object_store import (
    ObjectStorageConfigurationError,
    clear_s3_client_cache,
    ensure_bucket,
    get_object_bytes,
    is_object_storage_configured,
    object_storage_config_state,
    persist_sbom_raw_bytes,
    require_complete_object_storage_config,
    sbom_object_key,
    sha256_hex,
    verify_sbom_object_digest,
)

__all__ = [
    "ObjectStorageConfigurationError",
    "clear_s3_client_cache",
    "ensure_bucket",
    "get_object_bytes",
    "is_object_storage_configured",
    "object_storage_config_state",
    "persist_sbom_raw_bytes",
    "require_complete_object_storage_config",
    "sbom_object_key",
    "sha256_hex",
    "verify_sbom_object_digest",
]
