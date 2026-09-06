"""OIDC discovery and signed access-token verification.

This module is deliberately a small authentication boundary.  It owns provider
metadata and key retrieval, verifies the JWT before callers inspect any claims,
and exposes only a safe error category to the API layer.  Claim-to-principal
mapping belongs to a later layer.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlparse

import httpx
import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidSignatureError,
    InvalidSubjectError,
    MissingRequiredClaimError,
)

from vulnops.config import get_settings

# These are the asymmetric algorithms supported by PyJWT and suitable for a
# provider JWKS.  HMAC (HS*), ``none``, and any future symmetric algorithm are
# intentionally excluded even when a caller tries to configure them.
ASYMMETRIC_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES256K",
        "ES384",
        "ES512",
        "EDDSA",
    }
)

_REQUIRED_CLAIMS = ("iss", "aud", "exp", "sub")
_MAX_HTTP_TIMEOUT_SECONDS = 30.0
_MAX_CACHE_AGE_SECONDS = 3_600.0
_JWK_KEY_OPERATIONS = frozenset(
    {
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "wrapKey",
        "unwrapKey",
        "deriveKey",
        "deriveBits",
    }
)
_CANONICAL_ALGORITHMS = {
    "RS256": "RS256",
    "RS384": "RS384",
    "RS512": "RS512",
    "PS256": "PS256",
    "PS384": "PS384",
    "PS512": "PS512",
    "ES256": "ES256",
    "ES256K": "ES256K",
    "ES384": "ES384",
    "ES512": "ES512",
    "EDDSA": "EdDSA",
}


class OIDCVerificationError(Exception):
    """Safe authentication error with no token or claim content.

    ``category`` is intended for internal/API mapping.  The exception message
    contains only that stable category and never includes the bearer token,
    authorization header, key material, or raw claims.
    """

    def __init__(self, category: str, *, code: str = "invalid_token") -> None:
        self.category = category
        self.code = code
        super().__init__(f"OIDC validation failed: {category}")


OIDCValidationError = OIDCVerificationError


@dataclass(frozen=True)
class _DiscoveryDocument:
    issuer: str
    jwks_uri: str


Clock = Callable[[], float]


def _bounded_timeout(value: float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        raise OIDCVerificationError("configuration", code="oidc_configuration_error") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise OIDCVerificationError("configuration", code="oidc_configuration_error")
    return min(timeout, _MAX_HTTP_TIMEOUT_SECONDS)


def _bounded_cache_age(value: float) -> float:
    try:
        age = float(value)
    except (TypeError, ValueError):
        raise OIDCVerificationError("configuration", code="oidc_configuration_error") from None
    if not math.isfinite(age) or age < 0:
        raise OIDCVerificationError("configuration", code="oidc_configuration_error")
    return min(age, _MAX_CACHE_AGE_SECONDS)


def _valid_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _canonical_algorithm(value: str) -> str | None:
    return _CANONICAL_ALGORITHMS.get(value.strip().upper())


class OIDCVerifier:
    """Verify access tokens against one configured OIDC issuer and audience.

    The verifier is synchronous so it can be used by regular FastAPI
    dependencies.  A caller may inject an ``httpx.Client``-compatible object
    and a clock returning Unix seconds for deterministic tests and controlled
    deployments.
    """

    def __init__(
        self,
        issuer_url: str,
        audience: str,
        allowed_algorithms: Sequence[str] = ("RS256",),
        *,
        http_client: Any | None = None,
        clock: Clock | Any = time.time,
        timeout: float = 5.0,
        cache_age: float = 300.0,
        discovery_cache_age: float | None = None,
        jwks_cache_age: float | None = None,
    ) -> None:
        if not isinstance(issuer_url, str) or not issuer_url.strip():
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")
        if not _valid_http_url(issuer_url.strip()):
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")
        if not isinstance(audience, str) or not audience.strip():
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")
        if not isinstance(allowed_algorithms, Sequence) or isinstance(
            allowed_algorithms, (str, bytes)
        ):
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")

        algorithms: list[str] = []
        for algorithm in allowed_algorithms:
            if not isinstance(algorithm, str):
                raise OIDCVerificationError("configuration", code="oidc_configuration_error")
            normalized = algorithm.strip().upper()
            if not normalized or normalized not in ASYMMETRIC_ALGORITHMS:
                raise OIDCVerificationError("configuration", code="oidc_configuration_error")
            if normalized not in algorithms:
                algorithms.append(normalized)
        if not algorithms:
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")

        # Preserve the issuer's exact URL for claim comparison; a trailing
        # slash is significant in OIDC issuer matching.  Only discovery URL
        # construction below removes it to avoid a double slash.
        self.issuer_url = issuer_url.strip()
        self.audience = audience.strip()
        self.allowed_algorithms = tuple(algorithms)
        # Short aliases keep the boundary convenient for dependency wiring
        # while the explicit names remain the canonical configuration API.
        self.issuer = self.issuer_url
        self.algorithms = self.allowed_algorithms
        self.timeout = _bounded_timeout(timeout)
        base_cache_age = _bounded_cache_age(cache_age)
        self.cache_age = base_cache_age
        self.discovery_cache_age = _bounded_cache_age(
            base_cache_age if discovery_cache_age is None else discovery_cache_age
        )
        self.jwks_cache_age = _bounded_cache_age(
            base_cache_age if jwks_cache_age is None else jwks_cache_age
        )

        self._clock = clock if callable(clock) else getattr(clock, "time", None)
        if self._clock is None or not callable(self._clock):
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")

        if http_client is None:
            self._http_client = httpx.Client(timeout=httpx.Timeout(self.timeout))
            self._owns_http_client = True
        else:
            self._http_client = http_client
            self._owns_http_client = False

        self._discovery: _DiscoveryDocument | None = None
        self._discovery_fetched_at: float | None = None
        self._jwks: tuple[Mapping[str, Any], ...] | None = None
        self._jwks_fetched_at: float | None = None
        self._jwks_generation = 0
        self._kid_refresh_generations: dict[tuple[str, str], int] = {}
        self._kid_refresh_failures: dict[tuple[str, str], tuple[int, str, str]] = {}
        self._cache_lock = threading.RLock()

    @classmethod
    def from_settings(
        cls,
        settings: Any | None = None,
        **kwargs: Any,
    ) -> OIDCVerifier:
        """Build a verifier from the application's OIDC settings."""

        settings = settings or get_settings()
        issuer_url = getattr(settings, "oidc_issuer_url", None)
        audience = getattr(settings, "oidc_audience", None)
        if not issuer_url or not audience:
            raise OIDCVerificationError("configuration", code="oidc_configuration_error")
        algorithms = getattr(settings, "oidc_allowed_algorithms", ("RS256",))
        return cls(
            issuer_url=issuer_url,
            audience=audience,
            allowed_algorithms=algorithms,
            **kwargs,
        )

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer_url.rstrip('/')}/.well-known/openid-configuration"

    def close(self) -> None:
        """Close a client created by this verifier."""

        if self._owns_http_client:
            self._http_client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def verify(self, token: str) -> dict[str, Any]:
        """Compatibility alias for :meth:`verify_token`."""

        return self.verify_token(token)

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """Compatibility alias for callers that name the token type."""

        return self.verify_token(token)

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify a signed JWT and return its authenticated claims."""

        if not isinstance(token, str) or not token.strip():
            raise OIDCVerificationError("malformed_token")
        try:
            header = jwt.get_unverified_header(token)
        except Exception:  # PyJWT exception types vary by minor release.
            raise OIDCVerificationError("malformed_token") from None

        if not isinstance(header, Mapping):
            raise OIDCVerificationError("malformed_token")
        algorithm = header.get("alg")
        if not isinstance(algorithm, str):
            raise OIDCVerificationError("unsupported_algorithm")
        algorithm = algorithm.strip().upper()
        if algorithm not in self.allowed_algorithms or algorithm not in ASYMMETRIC_ALGORITHMS:
            raise OIDCVerificationError("unsupported_algorithm")
        algorithm = _canonical_algorithm(algorithm)
        if algorithm is None:
            raise OIDCVerificationError("unsupported_algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            raise OIDCVerificationError("missing_key_id")
        kid = kid.strip()

        keys, jwks_generation = self._jwks_snapshot()
        key = self._key_for_token(keys, kid=kid, algorithm=algorithm)
        if key is None:
            # A key rotation may race the cache.  Exactly one forced JWKS
            # refresh is allowed for this token; all remaining misses fail
            # closed without trying arbitrary keys or another network loop.
            refresh_key = (kid, algorithm)
            with self._cache_lock:
                if self._kid_refresh_generations.get(refresh_key) == self._jwks_generation:
                    failure = self._kid_refresh_failures.get(refresh_key)
                    if failure is not None:
                        _, category, code = failure
                        raise OIDCVerificationError(category, code=code)
                    keys = self._jwks or keys
                else:
                    try:
                        keys = self._get_jwks(
                            force=True,
                            observed_generation=jwks_generation,
                        )
                    except OIDCVerificationError as exc:
                        # A failed forced refresh is still a completed attempt
                        # for this generation.  Remember its safe category so
                        # concurrent/repeated callers do not stampede the
                        # provider until cache expiry advances the generation.
                        self._kid_refresh_generations[refresh_key] = self._jwks_generation
                        self._kid_refresh_failures[refresh_key] = (
                            self._jwks_generation,
                            exc.category,
                            exc.code,
                        )
                        raise
                    self._kid_refresh_generations[refresh_key] = self._jwks_generation
                    self._kid_refresh_failures.pop(refresh_key, None)
            key = self._key_for_token(keys, kid=kid, algorithm=algorithm)
        if key is None:
            raise OIDCVerificationError("key_not_found")

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[algorithm],
                issuer=self.issuer_url,
                audience=self.audience,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    # These date checks use the injected clock below.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except MissingRequiredClaimError:
            raise OIDCVerificationError("missing_claim") from None
        except InvalidIssuerError:
            raise OIDCVerificationError("issuer") from None
        except InvalidAudienceError:
            raise OIDCVerificationError("audience") from None
        except ExpiredSignatureError:
            raise OIDCVerificationError("expired") from None
        except InvalidSignatureError:
            raise OIDCVerificationError("signature") from None
        except (DecodeError, InvalidSubjectError, InvalidJTIError, InvalidIssuedAtError):
            raise OIDCVerificationError("invalid_claim") from None
        except ImmatureSignatureError:
            raise OIDCVerificationError("not_before") from None
        except Exception:  # Never expose provider/library internals.
            raise OIDCVerificationError("invalid_token") from None

        if not isinstance(claims, dict):
            raise OIDCVerificationError("invalid_claim")
        self._validate_claim_types_and_time(claims)
        return claims

    def _now(self) -> float:
        try:
            value = float(self._clock())
        except Exception:
            raise OIDCVerificationError("configuration", code="oidc_clock_error") from None
        if not math.isfinite(value):
            raise OIDCVerificationError("configuration", code="oidc_clock_error")
        return value

    def _cache_fresh(self, fetched_at: float | None, max_age: float) -> bool:
        if fetched_at is None:
            return False
        return self._now() - fetched_at < max_age

    def _get_discovery(self, *, force: bool = False) -> _DiscoveryDocument:
        with self._cache_lock:
            if (
                not force
                and self._discovery is not None
                and self._cache_fresh(self._discovery_fetched_at, self.discovery_cache_age)
            ):
                return self._discovery

            payload = self._fetch_json(self.discovery_url, category="discovery")
            provider_issuer = payload.get("issuer")
            jwks_uri = payload.get("jwks_uri")
            if provider_issuer != self.issuer_url:
                raise OIDCVerificationError("issuer", code="oidc_discovery_error")
            if not isinstance(jwks_uri, str) or not _valid_http_url(jwks_uri):
                raise OIDCVerificationError("discovery", code="oidc_discovery_error")

            self._discovery = _DiscoveryDocument(issuer=self.issuer_url, jwks_uri=jwks_uri)
            self._discovery_fetched_at = self._now()
            return self._discovery

    def _jwks_snapshot(self) -> tuple[tuple[Mapping[str, Any], ...], int]:
        with self._cache_lock:
            return self._get_jwks(), self._jwks_generation

    def _get_jwks(
        self,
        *,
        force: bool = False,
        observed_generation: int | None = None,
    ) -> tuple[Mapping[str, Any], ...]:
        with self._cache_lock:
            # Another caller may have completed the forced refresh while this
            # caller was waiting.  Reuse that generation instead of issuing a
            # provider request for the same unknown kid.
            if (
                force
                and observed_generation is not None
                and self._jwks_generation != observed_generation
                and self._jwks is not None
            ):
                return self._jwks
            if (
                not force
                and self._jwks is not None
                and self._cache_fresh(self._jwks_fetched_at, self.jwks_cache_age)
            ):
                return self._jwks

            discovery = self._get_discovery()
            payload = self._fetch_json(discovery.jwks_uri, category="jwks")
            raw_keys = payload.get("keys")
            if not isinstance(raw_keys, list):
                raise OIDCVerificationError("jwks", code="oidc_jwks_error")
            keys: list[Mapping[str, Any]] = []
            for raw_key in raw_keys:
                if isinstance(raw_key, Mapping):
                    keys.append(dict(raw_key))
            self._jwks = tuple(keys)
            self._jwks_fetched_at = self._now()
            self._jwks_generation += 1
            self._kid_refresh_generations.clear()
            self._kid_refresh_failures.clear()
            return self._jwks

    def _fetch_json(self, url: str, *, category: str) -> Mapping[str, Any]:
        try:
            response = self._http_client.get(url, timeout=self.timeout)
            status_code = getattr(response, "status_code", None)
            if not isinstance(status_code, int) or not 200 <= status_code < 300:
                raise OIDCVerificationError(category, code=f"oidc_{category}_error")
            payload = response.json()
        except OIDCVerificationError:
            raise
        except Exception:  # HTTP client and JSON parser details stay private.
            raise OIDCVerificationError(category, code=f"oidc_{category}_error") from None
        if not isinstance(payload, Mapping):
            raise OIDCVerificationError(category, code=f"oidc_{category}_error")
        return payload

    @staticmethod
    def _key_for_token(
        keys: Sequence[Mapping[str, Any]], *, kid: str, algorithm: str
    ) -> Any | None:
        for jwk in keys:
            if jwk.get("kid") != kid:
                continue
            if "use" in jwk and (not isinstance(jwk["use"], str) or jwk["use"] != "sig"):
                continue
            if "key_ops" in jwk:
                key_ops = jwk["key_ops"]
                if (
                    not isinstance(key_ops, list)
                    or any(not isinstance(operation, str) for operation in key_ops)
                    or any(operation not in _JWK_KEY_OPERATIONS for operation in key_ops)
                    or "verify" not in key_ops
                ):
                    continue
            if "alg" in jwk:
                jwk_algorithm = jwk["alg"]
                if not isinstance(jwk_algorithm, str):
                    continue
                if _canonical_algorithm(jwk_algorithm) != algorithm:
                    continue
            try:
                key = jwt.PyJWK(dict(jwk), algorithm=algorithm).key
            except Exception:
                # A malformed key is not evidence for trying a different
                # algorithm or key; the caller will fail closed.
                key = None
            if key is not None:
                return key
        return None

    def _validate_claim_types_and_time(self, claims: Mapping[str, Any]) -> None:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise OIDCVerificationError("invalid_claim")
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer != self.issuer_url:
            raise OIDCVerificationError("issuer")
        expiration = self._numeric_date(claims.get("exp"), "exp")
        now = self._now()
        if expiration <= now:
            raise OIDCVerificationError("expired")

        if "nbf" in claims:
            not_before = self._numeric_date(claims.get("nbf"), "nbf")
            if not_before > now:
                raise OIDCVerificationError("not_before")
        if "iat" in claims:
            issued_at = self._numeric_date(claims.get("iat"), "iat")
            if issued_at > now:
                raise OIDCVerificationError("invalid_claim")

    @staticmethod
    def _numeric_date(value: Any, claim: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise OIDCVerificationError("invalid_claim")
        try:
            numeric = float(value)
        except (OverflowError, ValueError):
            raise OIDCVerificationError("invalid_claim") from None
        if not math.isfinite(numeric):
            raise OIDCVerificationError("invalid_claim")
        return numeric


__all__ = [
    "ASYMMETRIC_ALGORITHMS",
    "OIDCValidationError",
    "OIDCVerificationError",
    "OIDCVerifier",
]
