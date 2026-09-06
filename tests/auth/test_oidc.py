from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

try:
    from vulnops.auth.oidc import OIDCVerificationError, OIDCVerifier
except ImportError:
    OIDCVerificationError = None  # type: ignore[assignment,misc]
    OIDCVerifier = None  # type: ignore[assignment,misc]


ISSUER = "https://issuer.example"
AUDIENCE = "vulnops-api"
NOW = 1_800_000_000.0


@dataclass
class KeyMaterial:
    private_key: Any
    public_jwk: dict[str, Any]

    @classmethod
    def create(cls, kid: str = "key-1") -> KeyMaterial:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
        public_jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
        return cls(private_key=private_key, public_jwk=public_jwk)

    def token(
        self,
        *,
        kid: str | None = None,
        payload: dict[str, Any] | None = None,
        key: Any | None = None,
        algorithm: str = "RS256",
    ) -> str:
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "exp": NOW + 300,
        }
        claims.update(payload or {})
        signing_key = self.private_key if key is None else key
        return jwt.encode(
            claims,
            signing_key,
            algorithm=algorithm,
            headers={"kid": kid or self.public_jwk["kid"]},
        )


class OIDCServer:
    def __init__(
        self,
        keys: list[dict[str, Any]],
        refreshed_keys: list[dict[str, Any]] | None = None,
        discovery_jwks_uri: str | None = None,
    ) -> None:
        self.keys = keys
        self.refreshed_keys = refreshed_keys
        self.discovery_jwks_uri = discovery_jwks_uri or f"{ISSUER}/keys"
        self.discovery_requests = 0
        self.jwks_requests = 0
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/.well-known/openid-configuration":
            self.discovery_requests += 1
            return httpx.Response(
                200,
                json={"issuer": ISSUER, "jwks_uri": self.discovery_jwks_uri},
                request=request,
            )
        if request.url.path == "/keys":
            self.jwks_requests += 1
            keys = self.keys
            if self.jwks_requests > 1 and self.refreshed_keys is not None:
                keys = self.refreshed_keys
            return httpx.Response(200, json={"keys": keys}, request=request)
        return httpx.Response(404, request=request)


def _require_implementation() -> None:
    if OIDCVerifier is None:
        pytest.fail("OIDCVerifier is not implemented")


def _make_verifier(
    server: OIDCServer,
    *,
    clock: Any = lambda: NOW,
    cache_age: float = 300,
    allowed_algorithms: tuple[str, ...] = ("RS256",),
    http_client: Any | None = None,
    **kwargs: Any,
):
    _require_implementation()
    client = http_client or httpx.Client(transport=httpx.MockTransport(server.handler))
    verifier = OIDCVerifier(
        issuer_url=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=allowed_algorithms,
        http_client=client,
        clock=clock,
        cache_age=cache_age,
        **kwargs,
    )
    return verifier, client


def _ed25519_material(kid: str = "ed-key") -> tuple[Any, dict[str, Any]]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": kid, "alg": "EdDSA", "use": "sig"})
    return private_key, public_jwk


def test_valid_rsa_access_token_returns_verified_claims():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    try:
        token = material.token(payload={"roles": ["viewer"]})

        claims = verifier.verify_token(token)

        assert claims["sub"] == "user-123"
        assert claims["iss"] == ISSUER
        assert claims["aud"] == AUDIENCE
        assert claims["roles"] == ["viewer"]
    finally:
        client.close()


def test_invalid_signature_is_rejected_without_exposing_token_contents():
    trusted = KeyMaterial.create()
    attacker = KeyMaterial.create()
    server = OIDCServer([trusted.public_jwk])
    verifier, client = _make_verifier(server)
    token = attacker.token(kid=trusted.public_jwk["kid"])
    try:
        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "signature"
        assert token not in str(exc_info.value)
    finally:
        client.close()


@pytest.mark.parametrize(
    ("claim", "category"),
    [("iss", "issuer"), ("aud", "audience")],
)
def test_registered_issuer_and_audience_are_checked(claim: str, category: str):
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    try:
        value = "https://other.example" if claim == "iss" else "other-api"
        token = material.token(payload={claim: value})

        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == category
    finally:
        client.close()


def test_expired_token_is_rejected_using_injected_clock():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server, clock=lambda: NOW + 301)
    try:
        token = material.token()

        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "expired"
    finally:
        client.close()


def test_future_iat_is_rejected_using_injected_clock():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server, clock=lambda: NOW)
    try:
        token = material.token(payload={"iat": NOW + 1})

        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "invalid_claim"
    finally:
        client.close()


def test_ed25519_access_token_uses_canonical_algorithm_name():
    private_key, public_jwk = _ed25519_material()
    server = OIDCServer([public_jwk])
    verifier, client = _make_verifier(server, allowed_algorithms=("EdDSA",))
    try:
        token = jwt.encode(
            {"iss": ISSUER, "aud": AUDIENCE, "sub": "ed-user", "exp": NOW + 300},
            private_key,
            algorithm="EdDSA",
            headers={"kid": public_jwk["kid"]},
        )

        claims = verifier.verify_token(token)

        assert claims["sub"] == "ed-user"
    finally:
        client.close()


@pytest.mark.parametrize("algorithm", ["HS256", "none"])
def test_symmetric_and_unsigned_algorithms_are_rejected(algorithm: str):
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    try:
        key = "shared-secret-0123456789abcdef0123456789" if algorithm == "HS256" else ""
        token = material.token(key=key, algorithm=algorithm)

        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "unsupported_algorithm"
    finally:
        client.close()


def test_configured_algorithm_must_be_asymmetric():
    _require_implementation()

    with pytest.raises(OIDCVerificationError) as exc_info:
        OIDCVerifier(  # type: ignore[misc]
            issuer_url=ISSUER,
            audience=AUDIENCE,
            allowed_algorithms=("HS256",),
            http_client=httpx.Client(transport=httpx.MockTransport(lambda request: None)),
        )

    assert exc_info.value.category == "configuration"


@pytest.mark.parametrize("missing_claim", ["iss", "aud", "exp", "sub"])
def test_required_registered_claims_cannot_be_omitted(missing_claim: str):
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    try:
        payload = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "exp": NOW + 300,
        }
        payload.pop(missing_claim)
        token = jwt.encode(
            payload,
            material.private_key,
            algorithm="RS256",
            headers={"kid": material.public_jwk["kid"]},
        )

        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "missing_claim"
    finally:
        client.close()


def test_malformed_issuer_url_is_reported_as_safe_configuration_error():
    _require_implementation()

    with pytest.raises(OIDCVerificationError) as exc_info:
        OIDCVerifier(
            issuer_url="https://[::1",
            audience=AUDIENCE,
            allowed_algorithms=("RS256",),
        )

    assert exc_info.value.category == "configuration"
    assert "::1" not in str(exc_info.value)


def test_malformed_discovery_jwks_url_is_reported_as_safe_provider_error():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk], discovery_jwks_uri="https://[::1")
    verifier, client = _make_verifier(server)
    try:
        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(material.token())

        assert exc_info.value.category == "discovery"
        assert "::1" not in str(exc_info.value)
    finally:
        client.close()


def test_huge_numeric_date_is_reported_as_safe_invalid_claim():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    try:
        token = material.token(payload={"exp": 10**1000})

        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "invalid_claim"
    finally:
        client.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("alg", None),
        ("alg", 123),
        ("use", 123),
        ("use", "enc"),
        ("key_ops", "verify"),
        ("key_ops", ["sign"]),
        ("key_ops", ["verify", 123]),
        ("key_ops", ["verify", "unknown-operation"]),
    ],
)
def test_jwk_metadata_with_wrong_type_or_value_fails_closed(field: str, value: Any):
    material = KeyMaterial.create()
    bad_jwk = dict(material.public_jwk)
    bad_jwk[field] = value
    server = OIDCServer([bad_jwk])
    verifier, client = _make_verifier(server)
    try:
        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(material.token())

        assert exc_info.value.category == "key_not_found"
    finally:
        client.close()


def test_unknown_kid_refreshes_jwks_once_then_fails_closed():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    token = material.token(kid="unknown-key")
    try:
        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(token)

        assert exc_info.value.category == "key_not_found"
        assert server.discovery_requests == 1
        assert server.jwks_requests == 2
        assert token not in str(exc_info.value)
    finally:
        client.close()


def test_unknown_kid_refresh_can_accept_a_rotated_provider_key():
    old_key = KeyMaterial.create(kid="old-key")
    rotated_key = KeyMaterial.create(kid="rotated-key")
    server = OIDCServer([old_key.public_jwk], refreshed_keys=[rotated_key.public_jwk])
    verifier, client = _make_verifier(server)
    try:
        claims = verifier.verify_token(rotated_key.token())

        assert claims["sub"] == "user-123"
        assert server.jwks_requests == 2
    finally:
        client.close()


def test_discovery_and_jwks_are_cached_until_cache_age_expires():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    current_time = [NOW]
    verifier, client = _make_verifier(server, clock=lambda: current_time[0], cache_age=60)
    try:
        token = material.token()
        verifier.verify_token(token)
        verifier.verify_token(token)
        assert server.discovery_requests == 1
        assert server.jwks_requests == 1

        current_time[0] = NOW + 61
        verifier.verify_token(token)
        assert server.discovery_requests == 2
        assert server.jwks_requests == 2
    finally:
        client.close()


def test_http_timeout_is_bounded_and_client_is_injectable():
    material = KeyMaterial.create()

    class RecordingClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any]]] = []

        def get(self, url: str, **kwargs: Any):
            self.calls.append((url, kwargs))
            if url.endswith("openid-configuration"):
                return httpx.Response(
                    200,
                    json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/keys"},
                )
            return httpx.Response(200, json={"keys": [material.public_jwk]})

    client = RecordingClient()
    _require_implementation()
    verifier = OIDCVerifier(
        issuer_url=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=("RS256",),
        http_client=client,
        clock=lambda: NOW,
        timeout=2,
    )

    verifier.verify_token(material.token())

    assert len(client.calls) == 2
    assert all(call[1]["timeout"] <= 2 for call in client.calls)


def test_validation_errors_use_safe_categories_for_malformed_token():
    material = KeyMaterial.create()
    server = OIDCServer([material.public_jwk])
    verifier, client = _make_verifier(server)
    secret_marker = "do-not-leak-this-token"
    try:
        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(secret_marker)

        error = exc_info.value
        assert error.category == "malformed_token"
        assert secret_marker not in str(error)
        assert error.code == "invalid_token"
    finally:
        client.close()


class BlockingUnknownKidClient:
    def __init__(self, key: dict[str, Any]) -> None:
        self.key = key
        self.discovery_requests = 0
        self.jwks_requests = 0
        self._count_lock = threading.Lock()
        self.first_forced_refresh_started = threading.Event()
        self.release_first_forced_refresh = threading.Event()

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        del kwargs
        if url.endswith("openid-configuration"):
            with self._count_lock:
                self.discovery_requests += 1
            return httpx.Response(
                200,
                json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/keys"},
            )
        with self._count_lock:
            self.jwks_requests += 1
            request_number = self.jwks_requests
        if request_number == 2:
            self.first_forced_refresh_started.set()
            if not self.release_first_forced_refresh.wait(timeout=2):
                raise RuntimeError("test refresh release timed out")
        return httpx.Response(200, json={"keys": [self.key]})


def test_concurrent_unknown_kid_uses_one_forced_jwks_refresh():
    material = KeyMaterial.create()
    client = BlockingUnknownKidClient(material.public_jwk)
    verifier, _ = _make_verifier(server=OIDCServer([material.public_jwk]), http_client=client)
    verifier.verify_token(material.token())
    unknown_token = material.token(kid="unknown-concurrent-key")
    start = threading.Barrier(3)

    def verify_unknown() -> OIDCVerificationError:
        start.wait()
        with pytest.raises(OIDCVerificationError) as exc_info:
            verifier.verify_token(unknown_token)
        return exc_info.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(verify_unknown) for _ in range(2)]
        start.wait()
        assert client.first_forced_refresh_started.wait(timeout=2)
        client.release_first_forced_refresh.set()
        errors = [future.result(timeout=3) for future in futures]

    assert [error.category for error in errors] == ["key_not_found", "key_not_found"]
    assert client.jwks_requests == 2
