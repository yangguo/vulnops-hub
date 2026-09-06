from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Core
    app_name: str = Field(default="vulnops-hub")
    app_version: str = Field(default="0.1.0")
    environment: Literal["development", "staging", "production", "test"] = Field(
        default="development"
    )
    public_url: str = Field(default="http://localhost:8000")
    timezone: str = Field(default="UTC")
    log_level: str = Field(default="INFO")

    # Database — supports both DATABASE_URL and POSTGRES_DSN for compat
    database_url: str = Field(default="sqlite:///./vulnops.db")
    postgres_dsn: str | None = Field(default=None)

    # Object storage (S3/MinIO compatible)
    object_storage_endpoint: str | None = Field(default=None)
    object_storage_bucket: str = Field(default="vulnops-snapshots")
    object_storage_access_key: str | None = Field(default=None)
    object_storage_secret_key: str | None = Field(default=None)
    object_storage_region: str = Field(default="us-east-1")

    # Queue (Valkey/Redis)
    redis_url: str | None = Field(default=None)
    valkey_url: str | None = Field(default=None)

    # Auth
    oidc_issuer_url: str | None = Field(default=None)
    oidc_audience: str | None = Field(default=None)
    oidc_allowed_algorithms: Annotated[tuple[str, ...], NoDecode] = Field(default=("RS256",))
    oidc_organization_claim: str = Field(default="organizations")
    oidc_role_claim: str = Field(default="roles")
    oidc_service_scope_claim: str = Field(default="scope")
    auth_test_bypass_enabled: bool = Field(default=False)
    auth_test_principal_subject: str = Field(default="test-principal")

    @field_validator("oidc_allowed_algorithms", mode="before")
    @classmethod
    def _normalize_oidc_algorithms(cls, v: tuple[str, ...] | list[str] | str) -> tuple[str, ...]:
        if isinstance(v, str):
            text = v.strip()
            if text.startswith("["):
                try:
                    values = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError("oidc_allowed_algorithms must be a valid list") from exc
            else:
                values = text.replace(",", " ").split()
        else:
            values = v
        normalized = tuple(
            dict.fromkeys(str(item).strip().upper() for item in values if str(item).strip())
        )
        if not normalized:
            raise ValueError("oidc_allowed_algorithms must contain at least one algorithm")
        return normalized

    @field_validator(
        "oidc_organization_claim",
        "oidc_role_claim",
        "oidc_service_scope_claim",
    )
    @classmethod
    def _require_claim_name(cls, v: str) -> str:
        normalized = v.strip()
        if not normalized:
            raise ValueError("OIDC claim names must not be empty")
        return normalized

    @property
    def oidc_algorithms(self) -> tuple[str, ...]:
        """Compatibility alias for consumers using the shorter name."""

        return self.oidc_allowed_algorithms

    @property
    def oidc_org_claim(self) -> str:
        """Compatibility alias for the configured organization claim."""

        return self.oidc_organization_claim

    @property
    def oidc_scope_claim(self) -> str:
        """Compatibility alias for the configured service-scope claim."""

        return self.oidc_service_scope_claim

    # Adapters
    vulnerability_lookup_base_url: str | None = Field(default=None)
    defectdojo_base_url: str | None = Field(default=None)
    wazuh_base_url: str | None = Field(default=None)

    @field_validator("database_url", mode="before")
    @classmethod
    def _resolve_database_url(cls, v: str | None) -> str | None:
        # Allow DATABASE_URL or POSTGRES_DSN via env or direct field
        if v and v != "sqlite:///./vulnops.db":
            return v
        # Check explicit postgres_dsn first
        pg = os.getenv("POSTGRES_DSN") or os.getenv("DATABASE_URL")
        if pg:
            return pg
        # Fallback for test env: use in-memory sqlite if requested
        if os.getenv("PYTEST_CURRENT_TEST"):
            return "sqlite:///./vulnops-test.db"
        return v or "sqlite:///./vulnops.db"

    @property
    def effective_database_url(self) -> str:
        if self.postgres_dsn:
            return self.postgres_dsn
        return self.database_url

    @property
    def effective_redis_url(self) -> str | None:
        return self.valkey_url or self.redis_url

    def is_postgres(self) -> bool:
        url = self.effective_database_url
        return url.startswith(("postgresql", "postgres"))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
