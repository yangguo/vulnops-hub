from fastapi.testclient import TestClient

from vulnops.main import create_app


def _get_test_app():
    # Use file-based sqlite for API integration so that app's engine and test share?
    # For now, app uses default sqlite:///./vulnops.db ; we clear tables before test
    app = create_app()
    return app


def test_submit_cyclonedx_sbom_accepted():
    app = _get_test_app()
    client = TestClient(app)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "myapp", "version": "1.0.0"}},
        "components": [
            {
                "type": "library",
                "name": "urllib3",
                "version": "1.26.18",
                "purl": "pkg:pypi/urllib3@1.26.18",
            }
        ],
    }
    resp = client.post(
        "/api/v1/organizations/acme/sboms",
        json=bom,
        headers={"Idempotency-Key": "test-123"},
    )
    # Should be 200 or 201 accepted
    assert resp.status_code in (200, 201, 202)
    data = resp.json()
    assert "id" in data or "sbom_id" in data or "submission_id" in data
    # Must include content hash
    assert "content_sha256" in data or "content_hash" in data or "digest" in data


def test_duplicate_sbom_upload_is_idempotent():
    app = _get_test_app()
    client = TestClient(app)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "left-pad",
                "version": "1.3.0",
                "purl": "pkg:npm/left-pad@1.3.0",
            }
        ],
    }
    headers = {"Idempotency-Key": "dup-key-001", "Content-Type": "application/json"}

    r1 = client.post("/api/v1/organizations/acme/sboms", json=bom, headers=headers)
    r2 = client.post("/api/v1/organizations/acme/sboms", json=bom, headers=headers)
    assert r1.status_code in (200, 201, 202)
    assert r2.status_code in (200, 201, 202)
    # Should return same id/digest, not create duplicate
    assert r1.json().get("content_sha256") == r2.json().get("content_sha256") or r1.json().get(
        "id"
    ) == r2.json().get("id")


def test_malformed_sbom_returns_422():
    app = _get_test_app()
    client = TestClient(app)
    bad = {"not": "a sbom"}
    resp = client.post("/api/v1/organizations/acme/sboms", json=bad)
    assert resp.status_code in (400, 422)


def test_spdx_sbom_accepted():
    app = _get_test_app()
    client = TestClient(app)
    bom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "example",
        "documentNamespace": "https://example.com/spdx/1",
        "creationInfo": {"created": "2026-09-05T10:00:00Z", "creators": ["Tool: test"]},
        "packages": [
            {
                "name": "openssl",
                "SPDXID": "SPDXRef-Package-openssl",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "verificationCode": "NOASSERTION",
                "versionInfo": "3.0.2",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:deb/debian/openssl@3.0.2",
                    }
                ],
            }
        ],
    }
    resp = client.post("/api/v1/organizations/acme/sboms", json=bom)
    assert resp.status_code in (200, 201, 202)
