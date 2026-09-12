"""Object storage put/get/digest checks (moto-backed; no live MinIO required)."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.config import get_settings
from vulnops.db import Base
from vulnops.object_storage.object_store import (
    ObjectStorageConfigurationError,
    clear_s3_client_cache,
    ensure_bucket,
    get_object_bytes,
    persist_sbom_raw_bytes,
    sbom_object_key,
    verify_sbom_object_digest,
)
from vulnops.sbom.service import SBOMService


@pytest.fixture
def moto_s3_env(monkeypatch):
    monkeypatch.setenv("OBJECT_STORAGE_ENDPOINT", "https://s3.amazonaws.com")
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "vulnops-snapshots")
    monkeypatch.setenv("OBJECT_STORAGE_ACCESS_KEY", "testing")
    monkeypatch.setenv("OBJECT_STORAGE_SECRET_KEY", "testing")
    monkeypatch.setenv("OBJECT_STORAGE_REGION", "us-east-1")
    monkeypatch.setenv("OBJECT_STORAGE_LOCAL_MIRROR", "false")
    get_settings.cache_clear()
    clear_s3_client_cache()
    yield
    get_settings.cache_clear()
    clear_s3_client_cache()


@mock_aws
def test_persist_and_verify_digest_round_trip(moto_s3_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    raw = b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}'
    digest = hashlib.sha256(raw).hexdigest()
    settings = get_settings()

    uri = persist_sbom_raw_bytes(raw, settings.object_storage_bucket, "org1", digest, settings)
    assert uri == f"s3://vulnops-snapshots/{sbom_object_key('org1', digest)}"
    assert not (tmp_path / "storage").exists()

    fetched = get_object_bytes(uri, settings)
    assert fetched == raw
    assert verify_sbom_object_digest(uri, digest, settings)

    s3 = boto3.client("s3", region_name="us-east-1")
    meta = s3.head_object(Bucket="vulnops-snapshots", Key=sbom_object_key("org1", digest))
    assert meta["Metadata"]["content-sha256"] == digest


@mock_aws
def test_sbom_ingest_writes_to_configured_bucket(moto_s3_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    session = sessionmaker(bind=eng)()

    raw_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "demo", "version": "1.0.0"}],
    }
    svc = SBOMService(session)
    result = svc.ingest(raw_doc, organization_id="org-demo")
    digest = result["content_sha256"]
    settings = get_settings()

    s3 = boto3.client("s3", region_name="us-east-1")
    key = sbom_object_key("org-demo", digest)
    body = s3.get_object(Bucket=settings.object_storage_bucket, Key=key)["Body"].read()
    expected = json.dumps(raw_doc, sort_keys=True, separators=(",", ":")).encode()
    assert body == expected
    assert not (tmp_path / "storage").exists()
    session.close()


def test_local_fallback_without_object_storage(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OBJECT_STORAGE_ENDPOINT", raising=False)
    monkeypatch.delenv("OBJECT_STORAGE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("OBJECT_STORAGE_SECRET_KEY", raising=False)
    get_settings.cache_clear()
    clear_s3_client_cache()

    raw = b'{"a":1}'
    digest = hashlib.sha256(raw).hexdigest()
    settings = get_settings()
    uri = persist_sbom_raw_bytes(raw, settings.object_storage_bucket, "org1", digest, settings)
    local = tmp_path / "storage" / "sbom" / "org1" / f"{digest}.json"
    assert local.exists()
    assert get_object_bytes(uri, settings) == raw
    get_settings.cache_clear()
    clear_s3_client_cache()


_PARTIAL_ENV_CASES: list[tuple[dict[str, str | None], str]] = [
    ({"OBJECT_STORAGE_ENDPOINT": "http://127.0.0.1:9000"}, "endpoint only"),
    ({"OBJECT_STORAGE_ACCESS_KEY": "access"}, "access key only"),
    ({"OBJECT_STORAGE_SECRET_KEY": "secret"}, "secret key only"),
    (
        {
            "OBJECT_STORAGE_ENDPOINT": "http://127.0.0.1:9000",
            "OBJECT_STORAGE_ACCESS_KEY": "access",
        },
        "endpoint + access",
    ),
    (
        {
            "OBJECT_STORAGE_ENDPOINT": "http://127.0.0.1:9000",
            "OBJECT_STORAGE_SECRET_KEY": "secret",
        },
        "endpoint + secret",
    ),
    (
        {
            "OBJECT_STORAGE_ACCESS_KEY": "access",
            "OBJECT_STORAGE_SECRET_KEY": "secret",
        },
        "access + secret without endpoint",
    ),
    (
        {
            "OBJECT_STORAGE_ENDPOINT": "http://127.0.0.1:9000",
            "OBJECT_STORAGE_ACCESS_KEY": " ",
            "OBJECT_STORAGE_SECRET_KEY": "secret",
        },
        "endpoint + whitespace access",
    ),
    (
        {
            "OBJECT_STORAGE_ENDPOINT": "http://127.0.0.1:9000",
            "OBJECT_STORAGE_ACCESS_KEY": "access",
            "OBJECT_STORAGE_SECRET_KEY": "  ",
        },
        "endpoint + whitespace secret",
    ),
    (
        {
            "OBJECT_STORAGE_ENDPOINT": "  ",
            "OBJECT_STORAGE_ACCESS_KEY": "access",
            "OBJECT_STORAGE_SECRET_KEY": "secret",
        },
        "whitespace endpoint with keys",
    ),
]


@pytest.mark.parametrize(
    "env_overrides",
    [overrides for overrides, _ in _PARTIAL_ENV_CASES],
    ids=[label for _, label in _PARTIAL_ENV_CASES],
)
def test_partial_object_storage_config_fails_closed(monkeypatch, tmp_path, env_overrides):
    monkeypatch.chdir(tmp_path)
    for var in (
        "OBJECT_STORAGE_ENDPOINT",
        "OBJECT_STORAGE_ACCESS_KEY",
        "OBJECT_STORAGE_SECRET_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    for var, value in env_overrides.items():
        if value is None:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, value)
    get_settings.cache_clear()
    clear_s3_client_cache()

    raw = b'{"a":1}'
    digest = hashlib.sha256(raw).hexdigest()
    settings = get_settings()
    with pytest.raises(ObjectStorageConfigurationError):
        persist_sbom_raw_bytes(raw, settings.object_storage_bucket, "org1", digest, settings)
    assert not (tmp_path / "storage").exists()
    get_settings.cache_clear()
    clear_s3_client_cache()


@pytest.mark.parametrize(
    "env_overrides",
    [
        {"OBJECT_STORAGE_ENDPOINT": "   "},
        {"OBJECT_STORAGE_ACCESS_KEY": "  \t "},
        {"OBJECT_STORAGE_SECRET_KEY": " \n "},
    ],
    ids=["whitespace endpoint", "whitespace access", "whitespace secret"],
)
def test_whitespace_only_fields_count_as_disabled(monkeypatch, tmp_path, env_overrides):
    monkeypatch.chdir(tmp_path)
    for var in (
        "OBJECT_STORAGE_ENDPOINT",
        "OBJECT_STORAGE_ACCESS_KEY",
        "OBJECT_STORAGE_SECRET_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    for var, value in env_overrides.items():
        monkeypatch.setenv(var, value)
    get_settings.cache_clear()
    clear_s3_client_cache()

    raw = b'{"a":1}'
    digest = hashlib.sha256(raw).hexdigest()
    settings = get_settings()
    uri = persist_sbom_raw_bytes(raw, settings.object_storage_bucket, "org1", digest, settings)
    assert uri.startswith("s3://")
    assert (tmp_path / "storage" / "sbom" / "org1" / f"{digest}.json").exists()
    get_settings.cache_clear()
    clear_s3_client_cache()


def test_partial_config_raises_before_returning_s3_uri(monkeypatch, tmp_path):
    """Partial config must not return an s3:// URI (regression: keys-only was disabled)."""
    monkeypatch.chdir(tmp_path)
    for var in (
        "OBJECT_STORAGE_ENDPOINT",
        "OBJECT_STORAGE_ACCESS_KEY",
        "OBJECT_STORAGE_SECRET_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OBJECT_STORAGE_ACCESS_KEY", "only-access")
    get_settings.cache_clear()
    clear_s3_client_cache()

    raw = b'{"a":1}'
    digest = hashlib.sha256(raw).hexdigest()
    settings = get_settings()
    with pytest.raises(ObjectStorageConfigurationError):
        uri = persist_sbom_raw_bytes(raw, settings.object_storage_bucket, "org1", digest, settings)
        pytest.fail(f"unexpected uri {uri}")
    get_settings.cache_clear()
    clear_s3_client_cache()


def test_persist_rejects_digest_mismatch():
    raw = b'{"a":1}'
    digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="digest does not match"):
        persist_sbom_raw_bytes(raw, "bucket", "org1", digest + "0")


@mock_aws
def test_ensure_bucket_creates_on_missing_us_east_1(moto_s3_env):
    client = boto3.client("s3", region_name="us-east-1")
    ensure_bucket(client, "new-bucket-us", "us-east-1")
    client.head_bucket(Bucket="new-bucket-us")


@mock_aws
def test_ensure_bucket_creates_with_location_constraint_eu_west_1(monkeypatch):
    monkeypatch.setenv("OBJECT_STORAGE_REGION", "eu-west-1")
    get_settings.cache_clear()
    client = boto3.client("s3", region_name="eu-west-1")
    ensure_bucket(client, "new-bucket-eu", "eu-west-1")
    client.head_bucket(Bucket="new-bucket-eu")
    get_settings.cache_clear()


@mock_aws
def test_ensure_bucket_treats_already_owned_as_success(moto_s3_env):
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="owned-bucket")
    ensure_bucket(client, "owned-bucket", "us-east-1")


def test_ensure_bucket_create_already_owned_by_you_is_success():
    client = MagicMock()
    client.head_bucket.side_effect = ClientError(
        {
            "Error": {"Code": "404", "Message": "Not Found"},
            "ResponseMetadata": {"HTTPStatusCode": 404},
        },
        "HeadBucket",
    )
    client.create_bucket.side_effect = ClientError(
        {"Error": {"Code": "BucketAlreadyOwnedByYou", "Message": "Owned"}},
        "CreateBucket",
    )
    ensure_bucket(client, "race-bucket", "us-east-1")


def test_ensure_bucket_does_not_create_on_head_forbidden():
    client = MagicMock()
    client.head_bucket.side_effect = ClientError(
        {
            "Error": {"Code": "403", "Message": "Forbidden"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        "HeadBucket",
    )
    with pytest.raises(ClientError):
        ensure_bucket(client, "denied-bucket", "us-east-1")
    client.create_bucket.assert_not_called()


@mock_aws
def test_verify_digest_mismatch_returns_false(moto_s3_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    raw = b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}'
    digest = hashlib.sha256(raw).hexdigest()
    settings = get_settings()
    uri = persist_sbom_raw_bytes(raw, settings.object_storage_bucket, "org1", digest, settings)
    assert verify_sbom_object_digest(uri, "0" * 64, settings) is False
