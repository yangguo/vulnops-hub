"""Production IdP scaffolding invariants for docs and deploy templates."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from vulnops.auth.dependencies import AuthenticationConfigurationError, validate_auth_configuration
from vulnops.config import Settings, get_settings
from vulnops.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]

PRODUCTION_ENV_EXAMPLES = (
    REPO_ROOT / "deploy/.env.production.example",
    REPO_ROOT / "deploy/env/production-idp.example.env",
)

HELM_PRODUCTION_OVERLAY = REPO_ROOT / "deploy/helm/vulnops-hub/values-production-idp.example.yaml"
HELM_DEFAULT_VALUES = REPO_ROOT / "deploy/helm/vulnops-hub/values.yaml"
PRODUCTION_IDP_DOC = REPO_ROOT / "docs/operations/production-idp-integration.md"


def _production_settings(**overrides: object) -> Settings:
    base = {
        "environment": "production",
        "auth_test_bypass_enabled": False,
        "oidc_allow_insecure_loopback": False,
        "oidc_issuer_url": "https://issuer.example/realms/vulnops",
        "oidc_audience": "vulnops-api",
    }
    base.update(overrides)
    return Settings(**base)


def test_production_rejects_test_bypass():
    settings = _production_settings(auth_test_bypass_enabled=True)
    with pytest.raises(AuthenticationConfigurationError, match="AUTH_TEST_BYPASS"):
        validate_auth_configuration(settings)


def test_production_rejects_loopback_opt_in_flag():
    settings = _production_settings(oidc_allow_insecure_loopback=True)
    with pytest.raises(AuthenticationConfigurationError, match="OIDC_ALLOW_INSECURE_LOOPBACK"):
        validate_auth_configuration(settings)


@pytest.mark.parametrize(
    "issuer",
    [
        "http://issuer.example/realms/vulnops",
        "http://127.0.0.1:8082/realms/vulnops",
    ],
)
def test_production_requires_https_issuer(issuer: str):
    settings = _production_settings(oidc_issuer_url=issuer)
    with pytest.raises(AuthenticationConfigurationError, match="HTTPS"):
        validate_auth_configuration(settings)


def test_production_https_issuer_passes_configuration_gate():
    settings = _production_settings()
    validate_auth_configuration(settings)


def test_production_http_issuer_fails_app_startup(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "http://issuer.example/realms/vulnops")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    monkeypatch.setenv("OIDC_ALLOW_INSECURE_LOOPBACK", "false")
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="HTTPS"):
        create_app()


@pytest.mark.parametrize("path", PRODUCTION_ENV_EXAMPLES)
def test_production_env_examples_use_fail_closed_oidc_defaults(path: Path):
    text = path.read_text(encoding="utf-8")
    assert path.is_file(), f"missing scaffold file: {path}"
    assert re.search(r"ENVIRONMENT\s*=\s*production", text, re.IGNORECASE)
    assert re.search(r"OIDC_ISSUER_URL\s*=\s*https://", text, re.IGNORECASE)
    assert re.search(r"OIDC_AUDIENCE\s*=\s*\S+", text, re.IGNORECASE)
    assert re.search(r"AUTH_TEST_BYPASS_ENABLED\s*=\s*false", text, re.IGNORECASE)
    assert re.search(r"OIDC_ALLOW_INSECURE_LOOPBACK\s*=\s*false", text, re.IGNORECASE)
    assert "AUTH_TEST_BYPASS_ENABLED=true" not in text
    assert "OIDC_ALLOW_INSECURE_LOOPBACK=true" not in text


def test_helm_production_idp_overlay_documents_https_oidc():
    text = HELM_PRODUCTION_OVERLAY.read_text(encoding="utf-8")
    assert "OIDC_ISSUER_URL: https://" in text
    assert 'OIDC_ALLOW_INSECURE_LOOPBACK: "false"' in text
    assert 'AUTH_TEST_BYPASS_ENABLED: "false"' in text


def test_default_helm_values_include_production_oidc_placeholders():
    text = HELM_DEFAULT_VALUES.read_text(encoding="utf-8")
    assert "OIDC_ISSUER_URL" in text
    assert 'AUTH_TEST_BYPASS_ENABLED: "false"' in text


def test_production_idp_integration_doc_covers_requirements():
    text = PRODUCTION_IDP_DOC.read_text(encoding="utf-8")
    for phrase in (
        "HTTPS",
        "JWKS",
        "OIDC_AUDIENCE",
        "AUTH_TEST_BYPASS",
        "OIDC_ALLOW_INSECURE_LOOPBACK",
        "live certification against a specific enterprise IdP",
    ):
        assert phrase in text
