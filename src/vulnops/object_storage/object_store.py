from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from vulnops.config import Settings, get_settings

CONTENT_SHA256_METADATA_KEY = "content-sha256"


class ObjectStorageConfigurationError(RuntimeError):
    """Raised when OBJECT_STORAGE_* is only partially set."""


def object_storage_config_state(settings: Settings | None = None) -> str:
    """Return ``disabled``, ``enabled``, or ``partial`` for object storage env."""
    cfg = settings or get_settings()
    has_endpoint = bool(cfg.object_storage_endpoint and str(cfg.object_storage_endpoint).strip())
    has_keys = bool(cfg.object_storage_access_key and cfg.object_storage_secret_key)
    if has_endpoint and has_keys:
        return "enabled"
    if has_endpoint or has_keys:
        return "partial"
    return "disabled"


def require_complete_object_storage_config(settings: Settings | None = None) -> None:
    if object_storage_config_state(settings) == "partial":
        raise ObjectStorageConfigurationError(
            "OBJECT_STORAGE_ENDPOINT, ACCESS_KEY, and SECRET_KEY must all be set "
            "together or left unset; partial configuration is not allowed"
        )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sbom_object_key(organization_id: str, digest: str) -> str:
    return f"sbom/{organization_id}/{digest}.json"


def object_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def is_object_storage_configured(settings: Settings | None = None) -> bool:
    return object_storage_config_state(settings) == "enabled"


def _local_sbom_path(organization_id: str, digest: str) -> str:
    return os.path.join("storage", "sbom", organization_id, f"{digest}.json")


def _write_local_sbom(raw_bytes: bytes, organization_id: str, digest: str) -> None:
    local_path = _local_sbom_path(organization_id, digest)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    if not os.path.exists(local_path):
        with open(local_path, "wb") as f:
            f.write(raw_bytes)


@lru_cache(maxsize=1)
def _boto3_client(
    endpoint: str,
    access_key: str,
    secret_key: str,
    region: str,
    force_path_style: bool,
) -> Any:
    import boto3
    from botocore.config import Config

    addressing = "path" if force_path_style else "auto"
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
        config=Config(s3={"addressing_style": addressing}),
    )


def clear_s3_client_cache() -> None:
    _boto3_client.cache_clear()


def get_s3_client(settings: Settings | None = None) -> Any:
    cfg = settings or get_settings()
    if not is_object_storage_configured(cfg):
        raise RuntimeError("object storage is not configured")
    return _boto3_client(
        cfg.object_storage_endpoint or "",
        cfg.object_storage_access_key or "",
        cfg.object_storage_secret_key or "",
        cfg.object_storage_region,
        cfg.object_storage_force_path_style,
    )


def _head_bucket_indicates_missing(exc: ClientError) -> bool:
    code = str(exc.response.get("Error", {}).get("Code", ""))
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    if code in ("404", "NoSuchBucket", "NotFound"):
        return True
    return status == 404


def ensure_bucket(client: Any, bucket: str, region: str) -> None:
    """Ensure ``bucket`` exists; never create on HeadBucket denial (e.g. IAM 403)."""
    try:
        client.head_bucket(Bucket=bucket)
        return
    except ClientError as exc:
        if not _head_bucket_indicates_missing(exc):
            raise

    create_params: dict[str, Any] = {"Bucket": bucket}
    if region != "us-east-1":
        create_params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        client.create_bucket(**create_params)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            return
        raise


def put_sbom_object(
    raw_bytes: bytes,
    bucket: str,
    organization_id: str,
    digest: str,
    settings: Settings | None = None,
) -> str:
    """Store SBOM bytes in S3/MinIO when configured; always mirror locally if enabled."""
    cfg = settings or get_settings()
    require_complete_object_storage_config(cfg)
    key = sbom_object_key(organization_id, digest)
    uri = object_uri(bucket, key)

    if is_object_storage_configured(cfg):
        client = get_s3_client(cfg)
        ensure_bucket(client, bucket, cfg.object_storage_region)
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=raw_bytes,
            ContentType="application/json",
            Metadata={CONTENT_SHA256_METADATA_KEY: digest},
        )

    if not is_object_storage_configured(cfg) or cfg.object_storage_local_mirror:
        _write_local_sbom(raw_bytes, organization_id, digest)

    return uri


def persist_sbom_raw_bytes(
    raw_bytes: bytes,
    bucket: str,
    organization_id: str,
    digest: str,
    settings: Settings | None = None,
) -> str:
    """Persist raw SBOM bytes and return the canonical ``s3://`` object URI."""
    expected = sha256_hex(raw_bytes)
    if digest != expected:
        raise ValueError("digest does not match raw_bytes content")
    return put_sbom_object(raw_bytes, bucket, organization_id, digest, settings=settings)


def parse_object_uri(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.lstrip("/"):
        raise ValueError(f"unsupported object URI: {uri}")
    return parsed.netloc, parsed.path.lstrip("/")


def get_object_bytes(
    object_uri_value: str,
    settings: Settings | None = None,
) -> bytes:
    cfg = settings or get_settings()
    bucket, key = parse_object_uri(object_uri_value)
    require_complete_object_storage_config(cfg)
    if is_object_storage_configured(cfg):
        client = get_s3_client(cfg)
        response = client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    if key.startswith("sbom/"):
        parts = key.split("/")
        if len(parts) == 3:
            _, organization_id, filename = parts
            digest = filename.removesuffix(".json")
            local_path = _local_sbom_path(organization_id, digest)
            if os.path.exists(local_path):
                with open(local_path, "rb") as f:
                    return f.read()

    raise FileNotFoundError(object_uri_value)


def verify_sbom_object_digest(
    object_uri_value: str,
    expected_digest: str,
    settings: Settings | None = None,
) -> bool:
    data = get_object_bytes(object_uri_value, settings=settings)
    return sha256_hex(data) == expected_digest
