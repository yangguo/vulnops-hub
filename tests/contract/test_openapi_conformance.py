import pathlib
import yaml
import pytest
from fastapi.testclient import TestClient

from vulnops.main import create_app


def test_openapi_exists_and_valid():
    path = pathlib.Path("openapi/openapi.yaml")
    assert path.exists(), "openapi.yaml must exist"
    data = yaml.safe_load(path.read_text())
    assert data["openapi"].startswith("3.")
    assert "paths" in data
    # Check required endpoints per MVP acceptance
    paths = data["paths"]
    assert "/api/v1/organizations/{org_id}/sboms" in paths
    assert "/api/v1/organizations/{org_id}/cases/{case_id}/transitions" in paths
    assert "/api/v1/organizations/{org_id}/cases/{case_id}/verifications" in paths
    assert "/health/live" in paths
    assert "/health/ready" in paths
    # Check health operation
    assert "get" in paths["/health/live"]
    # Check sbom post has requestBody
    sbom_post = paths["/api/v1/organizations/{org_id}/sboms"]["post"]
    assert "requestBody" in sbom_post or "parameters" in sbom_post


def test_sbom_ingestion_conforms_to_openapi():
    app = create_app()
    client = TestClient(app)
    # Valid CycloneDX should be accepted per OpenAPI
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "test", "version": "1.0.0", "purl": "pkg:pypi/test@1.0.0"}],
    }
    resp = client.post("/api/v1/organizations/acme/sboms", json=bom)
    assert resp.status_code in (200, 201, 202)
    data = resp.json()
    # Response should contain expected fields per openapi
    assert "content_sha256" in data or "content_hash" in data or "id" in data


def test_case_transition_conforms_to_openapi():
    app = create_app()
    client = TestClient(app)
    # Create case then transition
    resp = client.post("/api/v1/organizations/acme/cases", json={"title": "test", "owner_team": "t1", "priority": "P2"})
    case_id = resp.json()["id"]
    resp = client.get(f"/api/v1/organizations/acme/cases/{case_id}/allowed-transitions")
    assert resp.status_code == 200
    assert "allowed" in resp.json()

    resp = client.post(f"/api/v1/organizations/acme/cases/{case_id}/transitions", json={"target": "triage", "reason": "triage", "actor": "analyst"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "triage"

    # Invalid transition should be 422 with problem details
    resp = client.post(f"/api/v1/organizations/acme/cases/{case_id}/transitions", json={"target": "closed", "reason": "bad", "actor": "analyst"})
    assert resp.status_code == 422
    assert "detail" in resp.json()
