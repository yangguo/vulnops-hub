import pathlib

import yaml
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
        "components": [
            {"type": "library", "name": "test", "version": "1.0.0", "purl": "pkg:pypi/test@1.0.0"}
        ],
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
    resp = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "test", "owner_team": "t1", "priority": "P2"},
    )
    case_id = resp.json()["id"]
    resp = client.get(f"/api/v1/organizations/acme/cases/{case_id}/allowed-transitions")
    assert resp.status_code == 200
    assert "allowed" in resp.json()

    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "triage", "reason": "triage"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "triage"

    # Invalid transition should be 422 with problem details
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "closed", "reason": "bad"},
    )
    assert resp.status_code == 422
    assert "detail" in resp.json()


def test_authenticated_operations_publish_bearer_security_and_problem_schemas():
    schema = create_app().openapi()
    schemes = schema["components"]["securitySchemes"]
    bearer = schemes["BearerAuth"]
    assert bearer["type"] == "http"
    assert bearer["scheme"] == "bearer"
    assert bearer["bearerFormat"] == "JWT"

    problem_ref = "#/components/schemas/ProblemDetails"
    for path, path_item in schema["paths"].items():
        if not path.startswith("/api/v1/"):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            assert operation["security"] == [{"BearerAuth": []}], (method, path)
            for status in ("401", "403"):
                response = operation["responses"][status]
                assert response["content"]["application/json"]["schema"]["$ref"] == problem_ref

    for path in ("/health/live", "/health/ready"):
        operation = schema["paths"][path]["get"]
        assert "security" not in operation
        assert "401" not in operation["responses"]
        assert "403" not in operation["responses"]

    # Compatibility health alias is intentionally hidden from the contract
    # and remains public, like the canonical health probes.
    assert "/api/v1/health" not in schema["paths"]
    assert TestClient(create_app()).get("/api/v1/health").status_code == 200


def test_authenticated_contract_publishes_actor_free_workflow_requests():
    schema = create_app().openapi()
    paths = schema["paths"]
    approval_path = (
        "/api/v1/organizations/{org_id}/cases/{case_id}/risk-decisions/{decision_id}/approval"
    )
    assert approval_path in paths

    transition_body = paths["/api/v1/organizations/{org_id}/cases/{case_id}/transitions"]["post"][
        "requestBody"
    ]["content"]["application/json"]["schema"]
    risk_request_body = paths["/api/v1/organizations/{org_id}/cases/{case_id}/risk-decisions"][
        "post"
    ]["requestBody"]["content"]["application/json"]["schema"]
    approval_body = paths[approval_path]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]

    def resolve(body):
        ref = body.get("$ref")
        if ref:
            _, _, name = ref.rpartition("/")
            return schema["components"]["schemas"][name]
        return body

    transition_body = resolve(transition_body)
    risk_request_body = resolve(risk_request_body)
    approval_body = resolve(approval_body)

    forbidden = {
        "actor",
        "actor_id",
        "actorId",
        "requested_by",
        "requestedBy",
        "approver",
        "approverId",
        "approver_role",
        "approverRole",
    }
    for body in (transition_body, risk_request_body, approval_body):
        assert forbidden.isdisjoint(body.get("properties", {}))
        assert body["additionalProperties"] is False

    assert transition_body["required"] == ["target"]
    assert "target" in transition_body["properties"]
    assert "to" not in transition_body["properties"]
    assert "next_status" not in transition_body["properties"]
    assert risk_request_body["required"] == ["type", "reason", "evidence_ids", "expires_at"]
    assert "type" in risk_request_body["properties"]
    assert risk_request_body["properties"]["type"]["enum"] == [
        "risk_accepted",
        "waiver",
        "compensating_control",
        "false_positive",
        "not_affected",
    ]
    assert approval_body["required"] == ["outcome", "reason"]
    assert "outcome" in approval_body["properties"]
    assert "decision" not in approval_body["properties"]


def test_case_create_contract_rejects_unsafe_shapes():
    schema = create_app().openapi()
    body = schema["paths"]["/api/v1/organizations/{org_id}/cases"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]
    assert body["additionalProperties"] is False
    assert body["required"] == ["title", "owner_team", "priority"]
    assert set(body["properties"]) == {
        "title",
        "owner_team",
        "priority",
        "exposures",
        "policy_version",
        "assignee",
    }
    assert "name" not in body["properties"]
    assert "owner" not in body["properties"]
    assert "exposure_ids" not in body["properties"]
    assert body["properties"]["exposures"] == {
        "items": {"type": "string"},
        "type": "array",
        "title": "Exposures",
    }


def test_checked_in_openapi_matches_runtime_schema():
    checked_in = yaml.safe_load(pathlib.Path("openapi/openapi.yaml").read_text())
    assert checked_in == create_app().openapi()


def test_bounded_console_responses_are_typed():
    schema = create_app().openapi()
    expected = {
        ("/api/v1/organizations/{org_id}/cases/{case_id}", "get", "200", "CaseDetailResponse"),
        (
            "/api/v1/organizations/{org_id}/cases/{case_id}/allowed-transitions",
            "get",
            "200",
            "AllowedTransitionsResponse",
        ),
        (
            "/api/v1/organizations/{org_id}/cases/{case_id}/verifications",
            "post",
            "200",
            "VerificationSubmitResponse",
        ),
        ("/api/v1/organizations/{org_id}/sboms", "post", "201", "SbomSubmitResponse"),
        ("/api/v1/organizations/{org_id}/sboms/{sbom_id}", "get", "200", "SbomResponse"),
    }
    for path, method, status, name in expected:
        response = schema["paths"][path][method]["responses"][status]
        assert response["content"]["application/json"]["schema"] == {
            "$ref": f"#/components/schemas/{name}"
        }
