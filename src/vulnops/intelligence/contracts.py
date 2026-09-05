from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AdvisoryRecord:
    """
    Normalized advisory assertion plus source provenance.
    This is the output of every intelligence adapter.
    Adapters must not update Cases directly.
    """

    vulnerability_id: str
    source: str
    retrieved_at: datetime | None
    source_url: str | None
    content: dict[str, Any] | None = None

    # Enriched fields
    description: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    kev: bool | None = None
    kev_due_date: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    vex_status: str | None = None
    affected_ranges: list[dict[str, Any]] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # Provenance
    source_snapshot_id: str | None = None
    retrieval_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceHealth:
    source: str
    last_success_at: datetime | None
    last_checked_at: datetime | None
    freshness: str  # fresh | stale | degraded | unknown
    cursor: str | None = None
    error: str | None = None
    enabled: bool = True


class IntelligenceAdapter(abc.ABC):
    """
    Narrow adapter contract per docs/modules.md:2
    discover -> validate -> normalize -> apply -> checkpoint
    """

    source: str

    @abc.abstractmethod
    def discover(self, config: dict, cursor: str | None) -> list[dict]:
        """Fetch raw source records using config and cursor."""
        raise NotImplementedError

    @abc.abstractmethod
    def validate(self, raw: dict) -> tuple[bool, str | None]:
        """Validate raw payload; returns (is_valid, error)."""
        raise NotImplementedError

    @abc.abstractmethod
    def normalize(self, validated: dict, retrieved_at: datetime, source_url: str) -> AdvisoryRecord:
        """Convert validated record to canonical AdvisoryRecord."""
        raise NotImplementedError

    @abc.abstractmethod
    def apply(self, records: list[AdvisoryRecord], session) -> int:
        """Idempotently apply normalized observations to DB; return count applied."""
        raise NotImplementedError

    @abc.abstractmethod
    def checkpoint(self, result: Any) -> tuple[str | None, SourceHealth]:
        """Return next cursor and health."""
        raise NotImplementedError
