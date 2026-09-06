from __future__ import annotations

import pytest
from oidc_test_issuer import (
    PLAYWRIGHT_POST_LOGOUT_REDIRECT_URI,
    PLAYWRIGHT_REDIRECT_URI,
    is_allowed_redirect_uri,
    validate_startup_configuration,
)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "localhost"])
def test_fixture_rejects_non_loopback_bind_hosts(host: str):
    with pytest.raises(ValueError, match="loopback"):
        validate_startup_configuration(host, None, 9000)


def test_fixture_accepts_default_loopback_configuration():
    assert validate_startup_configuration("127.0.0.1", None, 9000) == "http://127.0.0.1:9000"


@pytest.mark.parametrize(
    "issuer",
    [
        "http://issuer.example:9000",
        "http://0.0.0.0:9000",
        "http://localhost:9000",
    ],
)
def test_fixture_rejects_non_loopback_advertised_issuers(issuer: str):
    with pytest.raises(ValueError, match="loopback"):
        validate_startup_configuration("127.0.0.1", issuer, 9000)


def test_fixture_accepts_loopback_advertised_issuer():
    assert (
        validate_startup_configuration(
            "127.0.0.1",
            "http://127.0.0.1:9000",
            9000,
        )
        == "http://127.0.0.1:9000"
    )


def test_fixture_allows_only_the_playwright_callback_and_logout_redirects():
    assert is_allowed_redirect_uri(PLAYWRIGHT_REDIRECT_URI)
    assert is_allowed_redirect_uri(PLAYWRIGHT_POST_LOGOUT_REDIRECT_URI, post_logout=True)
    assert not is_allowed_redirect_uri("http://127.0.0.1:4173/collect")
    assert not is_allowed_redirect_uri(
        PLAYWRIGHT_POST_LOGOUT_REDIRECT_URI,
        post_logout=False,
    )
    assert not is_allowed_redirect_uri("https://evil.example/callback")
