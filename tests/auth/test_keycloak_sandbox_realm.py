"""Sandbox Keycloak realm invariants used by the live acceptance workflow."""

import json
from pathlib import Path

REALM_PATH = Path(__file__).resolve().parents[2] / "deploy/keycloak/vulnops-realm.json"


def test_sandbox_realm_issues_explicit_raw_evidence_permission_claim():
    realm = json.loads(REALM_PATH.read_text(encoding="utf-8"))
    scope = next(scope for scope in realm["clientScopes"] if scope["name"] == "vulnops-claims")
    assert any(
        mapper["config"].get("user.attribute") == "permissions"
        and mapper["config"].get("claim.name") == "permissions"
        and mapper["config"].get("access.token.claim") == "true"
        for mapper in scope["protocolMappers"]
    )

    users = {user["username"]: user for user in realm["users"]}
    assert users["raw-evidence-demo"]["attributes"]["permissions"] == ["evidence:raw:read"]
