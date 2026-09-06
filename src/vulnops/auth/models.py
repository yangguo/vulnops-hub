"""Immutable identities derived from trusted authentication claims."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PrincipalType(StrEnum):
    """The two classes of authenticated callers supported by the service."""

    HUMAN = "human"
    SERVICE = "service"


_ROLE_CAPABILITIES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "viewer": frozenset({"case:read", "sbom:read"}),
        "owner": frozenset({"case:write", "risk:request", "verification:write"}),
        "auditor": frozenset({"audit:read", "provenance:read", "risk:read", "verification:read"}),
        "risk_approver": frozenset({"risk:approve"}),
        "security_lead": frozenset(),
        "admin": frozenset(
            {
                "case:write",
                "risk:approve",
                "risk:request",
                "sbom:write",
                "verification:write",
            }
        ),
    }
)


def _claim_values(value: Any, *, lower: bool = False) -> frozenset[str]:
    """Normalize a scalar or iterable claim into an immutable set of strings."""

    if value is None:
        return frozenset()
    if isinstance(value, str):
        values: Iterable[Any] = value.split()
    else:
        values = value

    normalized: set[str] = set()
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ValueError("claim values must be strings or iterables of strings") from exc

    for item in iterator:
        if not isinstance(item, str):
            raise ValueError("claim values must contain only strings")
        item = item.strip()
        if not item:
            continue
        if lower:
            item = item.lower()
        normalized.add(item)
    return frozenset(normalized)


def normalize_role(role: str) -> str:
    """Return the canonical role spelling used by authorization helpers."""

    if not isinstance(role, str):
        raise ValueError("role must be a string")
    normalized = role.strip().lower().replace("-", "_")
    if not normalized:
        raise ValueError("role must not be empty")
    return normalized


def normalize_scope(scope: str) -> str:
    """Return the canonical scope spelling used by authorization helpers."""

    if not isinstance(scope, str):
        raise ValueError("scope must be a string")
    normalized = scope.strip().lower()
    if not normalized:
        raise ValueError("scope must not be empty")
    return normalized


class Principal(BaseModel):
    """Immutable identity and authorization claims for one request actor.

    The model intentionally stores only claims that have already been
    authenticated by the OIDC boundary.  Route dependencies can use the
    helpers here without parsing bearer tokens or trusting request JSON.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str
    principal_type: PrincipalType
    organization_ids: frozenset[str] = Field(default_factory=frozenset)
    roles: frozenset[str] = Field(default_factory=frozenset)
    scopes: frozenset[str] = Field(default_factory=frozenset)
    permissions: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("subject")
    @classmethod
    def _normalize_subject(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("subject must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("subject must not be empty")
        return normalized

    @field_validator("principal_type", mode="before")
    @classmethod
    def _normalize_principal_type(cls, value: PrincipalType | str) -> PrincipalType:
        if isinstance(value, PrincipalType):
            return value
        if not isinstance(value, str):
            raise ValueError("principal_type must be human or service")
        normalized = value.strip().lower()
        try:
            return PrincipalType(normalized)
        except ValueError as exc:
            raise ValueError("principal_type must be human or service") from exc

    @field_validator("organization_ids", mode="before")
    @classmethod
    def _normalize_organizations(cls, value: Any) -> frozenset[str]:
        return _claim_values(value)

    @field_validator("roles", mode="before")
    @classmethod
    def _normalize_roles(cls, value: Any) -> frozenset[str]:
        raw = _claim_values(value)
        return frozenset(normalize_role(role) for role in raw)

    @field_validator("scopes", "permissions", mode="before")
    @classmethod
    def _normalize_scopes_and_permissions(cls, value: Any) -> frozenset[str]:
        raw = _claim_values(value)
        return frozenset(normalize_scope(item) for item in raw)

    @property
    def is_human(self) -> bool:
        return self.principal_type is PrincipalType.HUMAN

    @property
    def is_service(self) -> bool:
        return self.principal_type is PrincipalType.SERVICE

    @property
    def capabilities(self) -> frozenset[str]:
        """Return role-derived capabilities for human principals."""

        capabilities: set[str] = set()
        for role in self.roles:
            capabilities.update(_ROLE_CAPABILITIES.get(role, frozenset()))

        # These roles are cumulative by design, while keeping the role map
        # itself easy to inspect and extend.
        if "owner" in self.roles or "security_lead" in self.roles or "admin" in self.roles:
            capabilities.update(_ROLE_CAPABILITIES["viewer"])
        if "risk_approver" in self.roles or "security_lead" in self.roles or "admin" in self.roles:
            capabilities.update(_ROLE_CAPABILITIES["risk_approver"])
        if "security_lead" in self.roles:
            capabilities.update(_ROLE_CAPABILITIES["owner"])
            capabilities.update(_ROLE_CAPABILITIES["viewer"])
        if "admin" in self.roles:
            capabilities.update(
                {
                    "audit:read",
                    "case:read",
                    "provenance:read",
                    "risk:read",
                    "sbom:read",
                    "verification:read",
                }
            )
        return frozenset(capabilities)

    def has_organization(self, organization_id: str) -> bool:
        """Whether this principal belongs to the requested organization."""

        if not isinstance(organization_id, str):
            return False
        return organization_id.strip() in self.organization_ids

    def has_role(self, role: str) -> bool:
        """Whether this principal has a normalized role."""

        try:
            return normalize_role(role) in self.roles
        except ValueError:
            return False

    def has_scope(self, scope: str) -> bool:
        """Whether this principal carries the named service scope."""

        try:
            return normalize_scope(scope) in self.scopes
        except ValueError:
            return False

    def has_permission(self, permission: str) -> bool:
        """Whether this principal carries an explicit permission claim."""

        try:
            return normalize_scope(permission) in self.permissions
        except ValueError:
            return False

    def has_capability(self, capability: str) -> bool:
        """Check a role capability or a named scope for a service principal."""

        try:
            normalized = normalize_scope(capability)
        except ValueError:
            return False
        if self.is_service:
            return normalized in self.scopes
        return normalized in self.capabilities or normalized in self.permissions
