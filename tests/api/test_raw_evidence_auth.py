from __future__ import annotations

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from moto import mock_aws
from sqlalchemy import select

from vulnops.config import get_settings
from vulnops.db.models.source_snapshot import SourceSnapshot
from vulnops.main import create_app
from vulnops.object_storage.object_store import clear_s3_client_cache


class ClaimsVerifier:
    def __init__(self, claims: dict) -> None:
        self.claims = claims

    def verify_token(self, token: str) -> dict:
        assert token == "test-token"
        return dict(self.claims)


def _claims(
    *,
    organization_ids: list[str],
    roles: list[str] | None = None,
    scopes: str | list[str] | None = None,
    permissions: list[str] | None = None,
    subject: str = "test-user",
) -> dict:
    payload = {
        "sub": subject,
        "principal_type": "service" if scopes is not None else "human",
        "organizations": organization_ids,
        "roles": roles or [],
        "scope": scopes or "",
    }
    if permissions:
        payload["permissions"] = permissions
    return payload


def _client(monkeypatch: pytest.MonkeyPatch, claims: dict) -> TestClient:
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()
    app = create_app()
    app.state.oidc_verifier = ClaimsVerifier(claims)
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-token"}


def _submit_sbom(client: TestClient, organization_id: str) -> dict:
    response = client.post(
        f"/api/v1/organizations/{organization_id}/sboms",
        json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "raw-evidence-fixture",
                    "version": "1.0.0",
                    "purl": f"pkg:pypi/raw-evidence-fixture@{uuid4().hex}",
                }
            ],
        },
        headers=_headers(),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _problem(response, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["code"] == code


def test_unauthenticated_sbom_raw_is_rejected(monkeypatch: pytest.MonkeyPatch):
    client = _client(monkeypatch, _claims(organization_ids=["acme"], roles=["admin"]))
    submitted = _submit_sbom(client, "acme")
    anon = TestClient(create_app())
    response = anon.get(
        f"/api/v1/organizations/acme/sboms/{submitted['id']}/raw",
    )
    _problem(response, 401, "authentication_required")


def test_viewer_can_read_sbom_metadata_without_storage_uri(monkeypatch: pytest.MonkeyPatch):
    admin = _client(monkeypatch, _claims(organization_ids=["acme"], roles=["admin"]))
    submitted = _submit_sbom(admin, "acme")

    viewer = _client(monkeypatch, _claims(organization_ids=["acme"], roles=["viewer"]))
    response = viewer.get(
        f"/api/v1/organizations/acme/sboms/{submitted['id']}",
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["content_sha256"]
    assert "object_uri" not in body


def test_viewer_cannot_download_sbom_raw(monkeypatch: pytest.MonkeyPatch):
    admin = _client(monkeypatch, _claims(organization_ids=["acme"], roles=["admin"]))
    submitted = _submit_sbom(admin, "acme")

    viewer = _client(monkeypatch, _claims(organization_ids=["acme"], roles=["viewer"]))
    response = viewer.get(
        f"/api/v1/organizations/acme/sboms/{submitted['id']}/raw",
        headers=_headers(),
    )
    _problem(response, 403, "insufficient_permission")


def test_raw_read_permission_can_download_sbom_bytes(monkeypatch: pytest.MonkeyPatch):
    organization_id = f"org-raw-{uuid4().hex[:8]}"
    writer = _client(
        monkeypatch,
        _claims(organization_ids=[organization_id], scopes="sbom:write", subject="ci-writer"),
    )
    submitted = _submit_sbom(writer, organization_id)

    reader = _client(
        monkeypatch,
        _claims(
            organization_ids=[organization_id],
            scopes="evidence:raw:read",
            subject="ci-reader",
        ),
    )
    response = reader.get(
        f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}/raw",
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    payload = json.loads(response.content)
    assert payload["bomFormat"] == "CycloneDX"
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].startswith("attachment;")


@mock_aws
def test_raw_read_downloads_sbom_from_s3_without_local_mirror(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OBJECT_STORAGE_ENDPOINT", "https://s3.amazonaws.com")
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "vulnops-snapshots")
    monkeypatch.setenv("OBJECT_STORAGE_ACCESS_KEY", "testing")
    monkeypatch.setenv("OBJECT_STORAGE_SECRET_KEY", "testing")
    monkeypatch.setenv("OBJECT_STORAGE_REGION", "us-east-1")
    monkeypatch.setenv("OBJECT_STORAGE_LOCAL_MIRROR", "false")
    get_settings.cache_clear()
    clear_s3_client_cache()
    try:
        organization_id = f"org-s3-{uuid4().hex[:8]}"
        writer = _client(
            monkeypatch,
            _claims(organization_ids=[organization_id], scopes="sbom:write"),
        )
        submitted = _submit_sbom(writer, organization_id)
        assert not (tmp_path / "storage").exists()

        reader = _client(
            monkeypatch,
            _claims(organization_ids=[organization_id], scopes="evidence:raw:read"),
        )
        response = reader.get(
            f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}/raw",
            headers=_headers(),
        )
        assert response.status_code == 200, response.text
        assert json.loads(response.content)["bomFormat"] == "CycloneDX"
    finally:
        get_settings.cache_clear()
        clear_s3_client_cache()


def test_human_permission_can_download_sbom_raw(monkeypatch: pytest.MonkeyPatch):
    organization_id = f"org-human-{uuid4().hex[:8]}"
    admin = _client(
        monkeypatch,
        _claims(organization_ids=[organization_id], roles=["admin"], subject="admin"),
    )
    submitted = _submit_sbom(admin, organization_id)

    reader = _client(
        monkeypatch,
        _claims(
            organization_ids=[organization_id],
            roles=["viewer"],
            permissions=["evidence:raw:read"],
            subject="evidence-reader",
        ),
    )
    meta = reader.get(
        f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}",
        headers=_headers(),
    )
    assert meta.status_code == 200
    assert meta.json().get("object_uri")

    response = reader.get(
        f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}/raw",
        headers=_headers(),
    )
    assert response.status_code == 200


def test_cross_org_sbom_raw_returns_not_found(monkeypatch: pytest.MonkeyPatch):
    org_a = f"org-a-{uuid4().hex[:6]}"
    org_b = f"org-b-{uuid4().hex[:6]}"
    admin_a = _client(monkeypatch, _claims(organization_ids=[org_a], roles=["admin"]))
    submitted = _submit_sbom(admin_a, org_a)

    reader_b = _client(
        monkeypatch,
        _claims(
            organization_ids=[org_b],
            permissions=["evidence:raw:read"],
            roles=["admin"],
        ),
    )
    response = reader_b.get(
        f"/api/v1/organizations/{org_b}/sboms/{submitted['id']}/raw",
        headers=_headers(),
    )
    _problem(response, 404, "resource_not_found")


def test_auditor_reads_snapshot_metadata_without_raw_uri(monkeypatch: pytest.MonkeyPatch):
    organization_id = f"org-prov-{uuid4().hex[:6]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    _submit_sbom(admin, organization_id)

    from vulnops.api import deps

    db = next(deps.get_db())
    snapshot = (
        db.execute(select(SourceSnapshot).where(SourceSnapshot.organization_id == organization_id))
        .scalars()
        .first()
    )
    assert snapshot is not None

    auditor = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["auditor"]))
    response = auditor.get(
        f"/api/v1/organizations/{organization_id}/source-snapshots/{snapshot.id}",
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    assert "object_uri" not in response.json()


def test_auditor_cannot_download_snapshot_raw(monkeypatch: pytest.MonkeyPatch):
    organization_id = f"org-aud-{uuid4().hex[:6]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    _submit_sbom(admin, organization_id)

    from vulnops.api import deps

    db = next(deps.get_db())
    snapshot = (
        db.execute(select(SourceSnapshot).where(SourceSnapshot.organization_id == organization_id))
        .scalars()
        .first()
    )
    assert snapshot is not None

    auditor = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["auditor"]))
    response = auditor.get(
        f"/api/v1/organizations/{organization_id}/source-snapshots/{snapshot.id}/raw",
        headers=_headers(),
    )
    _problem(response, 403, "insufficient_permission")
