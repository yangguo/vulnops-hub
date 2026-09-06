from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnops.auth.models import Principal, PrincipalType
from vulnops.config import Settings


def test_human_principal_normalizes_claim_values_and_is_immutable():
    principal = Principal(
        subject=" alice ",
        principal_type=PrincipalType.HUMAN,
        organization_ids=[" org-a ", "org-a", "org-b"],
        roles=[" Viewer ", "OWNER", "viewer"],
        scopes=[" profile ", "profile"],
    )

    assert principal.subject == "alice"
    assert principal.principal_type is PrincipalType.HUMAN
    assert principal.organization_ids == frozenset({"org-a", "org-b"})
    assert principal.roles == frozenset({"viewer", "owner"})
    assert principal.scopes == frozenset({"profile"})

    with pytest.raises(ValidationError):
        principal.subject = "mallory"
    with pytest.raises(AttributeError):
        principal.roles.add("admin")


def test_service_principal_exposes_named_scopes_and_type():
    principal = Principal(
        subject="ci-release",
        principal_type="service",
        organization_ids="org-a",
        roles="service",
        scopes="sbom:write evidence:write",
    )

    assert principal.principal_type is PrincipalType.SERVICE
    assert principal.is_service
    assert not principal.is_human
    assert principal.has_scope("sbom:write")
    assert principal.has_scope("evidence:write")
    assert principal.has_capability("sbom:write")
    assert not principal.has_scope("risk:approve")
    assert not principal.has_capability("risk:approve")


def test_principal_checks_organization_membership_and_roles_case_insensitively():
    principal = Principal(
        subject="auditor",
        principal_type="human",
        organization_ids=["org-a"],
        roles=["AUDITOR"],
    )

    assert principal.has_organization("org-a")
    assert not principal.has_organization("org-b")
    assert principal.has_role("auditor")
    assert principal.has_role(" AUDITOR ")
    assert principal.has_capability("risk:read")
    assert not principal.has_role("owner")


@pytest.mark.parametrize(
    ("role", "expected_capabilities"),
    [
        ("viewer", {"case:read", "sbom:read"}),
        (
            "owner",
            {
                "case:read",
                "sbom:read",
                "case:write",
                "risk:request",
                "verification:write",
            },
        ),
        (
            "auditor",
            {
                "case:read",
                "audit:read",
                "provenance:read",
                "risk:read",
                "verification:read",
            },
        ),
        ("risk_approver", {"case:read", "sbom:read", "risk:approve"}),
        (
            "security_lead",
            {
                "case:read",
                "sbom:read",
                "case:write",
                "risk:request",
                "verification:write",
                "risk:approve",
            },
        ),
        (
            "admin",
            {
                "case:read",
                "sbom:read",
                "case:write",
                "risk:request",
                "verification:write",
                "risk:approve",
                "audit:read",
                "provenance:read",
                "risk:read",
                "verification:read",
                "sbom:write",
            },
        ),
    ],
)
def test_human_role_capability_matrix_is_literal(role, expected_capabilities):
    principal = Principal(subject="user", principal_type="human", roles=[role])

    assert principal.capabilities == frozenset(expected_capabilities)


def test_service_principal_never_derives_role_capabilities_or_human_approval():
    principal = Principal(
        subject="ci",
        principal_type="service",
        roles=["admin"],
        scopes=["sbom:write", "case:read", "risk:approve"],
    )

    assert principal.capabilities == frozenset()
    assert principal.has_capability("sbom:write")
    assert not principal.has_capability("case:read")
    assert not principal.has_capability("risk:approve")


def test_principal_accepts_explicit_permissions_without_granting_them_to_services():
    human = Principal(
        subject="evidence-reader",
        principal_type="human",
        permissions=[" evidence:raw:read "],
    )
    service = Principal(
        subject="ci",
        principal_type="service",
        scopes=["evidence:raw:read"],
        permissions=["case:read"],
    )

    assert human.has_permission("evidence:raw:read")
    assert human.has_capability("evidence:raw:read")
    assert service.has_permission("case:read")
    assert not service.has_capability("case:read")
    assert service.has_capability("evidence:raw:read")


def test_principal_rejects_empty_subject():
    with pytest.raises(ValidationError):
        Principal(subject=" ", principal_type="human")


def test_auth_settings_define_oidc_algorithms_claims_and_test_bypass():
    settings = Settings(_env_file=None)

    assert settings.oidc_allowed_algorithms == ("RS256",)
    assert settings.oidc_organization_claim == "organizations"
    assert settings.oidc_role_claim == "roles"
    assert settings.oidc_service_scope_claim == "scope"
    assert settings.auth_test_bypass_enabled is False
    assert settings.oidc_algorithms == settings.oidc_allowed_algorithms
    assert settings.oidc_org_claim == settings.oidc_organization_claim
    assert settings.oidc_scope_claim == settings.oidc_service_scope_claim


def test_auth_settings_parse_space_separated_algorithms_from_environment(monkeypatch):
    monkeypatch.setenv("OIDC_ALLOWED_ALGORITHMS", "RS256 ES384")

    settings = Settings(_env_file=None)

    assert settings.oidc_allowed_algorithms == ("RS256", "ES384")


def test_auth_settings_parse_json_algorithms_from_environment(monkeypatch):
    monkeypatch.setenv("OIDC_ALLOWED_ALGORITHMS", '["RS256", "ES384"]')

    settings = Settings(_env_file=None)

    assert settings.oidc_allowed_algorithms == ("RS256", "ES384")
