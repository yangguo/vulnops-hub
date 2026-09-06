"""Small loopback-only OIDC issuer used by the Playwright verification suite.

This is deliberately a test fixture, not an identity provider for deployments.
It implements only the authorization-code + PKCE endpoints needed by the
console and a token helper used to seed API fixtures.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

CLIENT_ID = "vulnops-e2e"
AUDIENCE = "vulnops-api"
USER_COOKIE = "vulnops_test_user"
KEY_ID = "vulnops-e2e-key-1"


@dataclass(frozen=True)
class TestUser:
    subject: str
    organizations: tuple[str, ...]
    roles: tuple[str, ...]
    display_name: str
    expires_in: int = 3_600


TEST_USERS = {
    "owner": TestUser(
        subject="e2e-owner",
        organizations=("org-demo",),
        roles=("owner",),
        display_name="E2E Owner",
    ),
    "auditor": TestUser(
        subject="e2e-auditor",
        organizations=("org-demo",),
        roles=("auditor",),
        display_name="E2E Auditor",
    ),
    "cross-org": TestUser(
        subject="e2e-cross-org",
        organizations=("org-other",),
        roles=("owner",),
        display_name="E2E Cross Org",
    ),
    "expired": TestUser(
        subject="e2e-expired",
        organizations=("org-demo",),
        roles=("owner",),
        display_name="E2E Expired",
        expires_in=-1,
    ),
}


@dataclass(frozen=True)
class AuthorizationCode:
    user_name: str
    redirect_uri: str
    client_id: str
    code_challenge: str
    nonce: str | None
    expires_at: float


class IssuerState:
    def __init__(self, issuer: str) -> None:
        self.issuer = issuer.rstrip("/")
        self.private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public_jwk.update({"kid": KEY_ID, "use": "sig", "alg": "RS256", "key_ops": ["verify"]})
        self.public_jwk = public_jwk
        self._codes: dict[str, AuthorizationCode] = {}
        self._lock = threading.Lock()

    def user(self, name: str) -> TestUser | None:
        return TEST_USERS.get(name)

    def user_for_subject(self, subject: str) -> TestUser | None:
        return next((user for user in TEST_USERS.values() if user.subject == subject), None)

    def create_code(
        self,
        *,
        user_name: str,
        redirect_uri: str,
        client_id: str,
        code_challenge: str,
        nonce: str | None,
    ) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._codes[code] = AuthorizationCode(
                user_name=user_name,
                redirect_uri=redirect_uri,
                client_id=client_id,
                code_challenge=code_challenge,
                nonce=nonce,
                expires_at=time.time() + 60,
            )
        return code

    def get_code(self, code: str) -> AuthorizationCode | None:
        with self._lock:
            record = self._codes.get(code)
            if record is None or record.expires_at <= time.time():
                self._codes.pop(code, None)
                return None
            return record

    def consume_code(self, code: str) -> None:
        with self._lock:
            self._codes.pop(code, None)

    def issue_tokens(self, user_name: str, *, nonce: str | None = None) -> dict[str, Any] | None:
        user = self.user(user_name)
        if user is None:
            return None
        issued_at = int(time.time())
        expires_at = issued_at + user.expires_in
        claims = {
            "iss": self.issuer,
            "sub": user.subject,
            "principal_type": "human",
            "organizations": list(user.organizations),
            "roles": list(user.roles),
            "name": user.display_name,
            "email": f"{user_name}@e2e.invalid",
            "iat": issued_at,
            "exp": expires_at,
        }
        access_token = jwt.encode(
            {**claims, "aud": AUDIENCE},
            self.private_key,
            algorithm="RS256",
            headers={"kid": KEY_ID},
        )
        id_claims = {**claims, "aud": CLIENT_ID}
        if nonce is not None:
            id_claims["nonce"] = nonce
        id_token = jwt.encode(
            id_claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": KEY_ID},
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": max(0, user.expires_in),
            "scope": "openid profile email",
            "id_token": id_token,
        }


class IssuerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: IssuerState) -> None:
        super().__init__(address, OIDCRequestHandler)
        self.state = state


def _first_query_value(query: str, name: str) -> str | None:
    values = parse_qs(query, keep_blank_values=True).get(name, [])
    return values[0] if values else None


def _append_query(url: str, values: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(values.items())
    return urlunparse(parsed._replace(query=urlencode(query)))


class OIDCRequestHandler(BaseHTTPRequestHandler):
    server: IssuerServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def state(self) -> IssuerState:
        return self.server.state

    def _send_json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, *, clear_cookie: bool = False) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        if clear_cookie:
            self.send_header("Set-Cookie", f"{USER_COOKIE}=; Max-Age=0; Path=/; HttpOnly")
        self.end_headers()

    def _cookie(self, name: str) -> str | None:
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookies.get(name)
        return morsel.value if morsel is not None else None

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        return {
            name: values[0]
            for name, values in parse_qs(body, keep_blank_values=True).items()
            if values
        }

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health/live":
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/.well-known/openid-configuration":
            self._send_json(
                {
                    "issuer": self.state.issuer,
                    "authorization_endpoint": f"{self.state.issuer}/authorize",
                    "token_endpoint": f"{self.state.issuer}/token",
                    "userinfo_endpoint": f"{self.state.issuer}/userinfo",
                    "jwks_uri": f"{self.state.issuer}/jwks.json",
                    "end_session_endpoint": f"{self.state.issuer}/logout",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "scopes_supported": ["openid", "profile", "email"],
                    "token_endpoint_auth_methods_supported": ["none"],
                }
            )
            return
        if parsed.path == "/jwks.json":
            self._send_json({"keys": [self.state.public_jwk]})
            return
        if parsed.path == "/test/token":
            user_name = _first_query_value(parsed.query, "user") or "owner"
            tokens = self.state.issue_tokens(user_name)
            if tokens is None:
                self._send_json({"error": "unknown_test_user"}, HTTPStatus.NOT_FOUND)
            else:
                self._send_json(tokens)
            return
        if parsed.path == "/authorize":
            self._authorize(parsed.query)
            return
        if parsed.path == "/userinfo":
            self._userinfo()
            return
        if parsed.path == "/logout":
            self._logout(parsed.query)
            return
        self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if urlparse(self.path).path == "/token":
            self._token()
            return
        self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def _authorize(self, query: str) -> None:
        client_id = _first_query_value(query, "client_id")
        redirect_uri = _first_query_value(query, "redirect_uri")
        state = _first_query_value(query, "state")
        code_challenge = _first_query_value(query, "code_challenge")
        if (
            client_id != CLIENT_ID
            or not redirect_uri
            or not state
            or not code_challenge
            or _first_query_value(query, "response_type") != "code"
        ):
            self._send_json({"error": "invalid_authorization_request"}, HTTPStatus.BAD_REQUEST)
            return
        user_name = self._cookie(USER_COOKIE) or "owner"
        if self.state.user(user_name) is None:
            self._send_json({"error": "unknown_test_user"}, HTTPStatus.BAD_REQUEST)
            return
        code = self.state.create_code(
            user_name=user_name,
            redirect_uri=redirect_uri,
            client_id=client_id,
            code_challenge=code_challenge,
            nonce=_first_query_value(query, "nonce"),
        )
        self._redirect(_append_query(redirect_uri, {"code": code, "state": state}))

    def _token(self) -> None:
        form = self._form()
        if form.get("grant_type") != "authorization_code":
            self._send_json({"error": "unsupported_grant_type"}, HTTPStatus.BAD_REQUEST)
            return
        code = form.get("code", "")
        record = self.state.get_code(code)
        if (
            record is None
            or form.get("client_id") != record.client_id
            or form.get("redirect_uri") != record.redirect_uri
        ):
            self._send_json({"error": "invalid_grant"}, HTTPStatus.BAD_REQUEST)
            return
        verifier = form.get("code_verifier", "")
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
        if not hmac.compare_digest(expected, record.code_challenge.encode()):
            self._send_json({"error": "invalid_grant"}, HTTPStatus.BAD_REQUEST)
            return
        self.state.consume_code(code)
        tokens = self.state.issue_tokens(record.user_name, nonce=record.nonce)
        if tokens is None:
            self._send_json({"error": "invalid_grant"}, HTTPStatus.BAD_REQUEST)
            return
        self._send_json(tokens)

    def _userinfo(self) -> None:
        authorization = self.headers.get("Authorization", "")
        if not authorization.lower().startswith("bearer "):
            self._send_json({"error": "invalid_token"}, HTTPStatus.UNAUTHORIZED)
            return
        try:
            claims = jwt.decode(
                authorization[7:].strip(),
                self.state.private_key.public_key(),
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except jwt.PyJWTError:
            self._send_json({"error": "invalid_token"}, HTTPStatus.UNAUTHORIZED)
            return
        user = self.state.user_for_subject(str(claims.get("sub", "")))
        if user is None:
            self._send_json({"error": "invalid_token"}, HTTPStatus.UNAUTHORIZED)
            return
        self._send_json(
            {
                "sub": user.subject,
                "name": user.display_name,
                "email": f"{user.subject}@e2e.invalid",
            }
        )

    def _logout(self, query: str) -> None:
        redirect_uri = _first_query_value(query, "post_logout_redirect_uri")
        state = _first_query_value(query, "state")
        if redirect_uri:
            values = {"state": state} if state else {}
            self._redirect(_append_query(redirect_uri, values), clear_cookie=True)
            return
        self._send_json({"status": "logged_out"})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--issuer", default=None)
    args = parser.parse_args()
    issuer = args.issuer or f"http://{args.host}:{args.port}"
    server = IssuerServer((args.host, args.port), IssuerState(issuer))
    print(f"OIDC test issuer listening at {server.state.issuer}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
