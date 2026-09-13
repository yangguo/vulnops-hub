"""Idempotent upserts for vulnerability intelligence tables."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from vulnops.intelligence.contracts import AdvisoryRecord, SourceHealth
from vulnops.intelligence.models import (
    AdvisoryAssertion,
    AffectedRange,
    SourceStatus,
    Vulnerability,
    VulnerabilityAlias,
)


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return f"{prefix}_{digest}"


def upsert_advisory_records(session: Session, records: list[AdvisoryRecord]) -> int:
    """Persist normalized advisory observations; safe to replay."""

    valid_records = [
        rec for rec in records if rec.vulnerability_id and rec.vulnerability_id != "unknown"
    ]
    for rec in valid_records:
        _upsert_vulnerability(session, rec)

    # The mapped child tables use scalar foreign-key columns without ORM
    # relationships, so PostgreSQL cannot infer their insert ordering from a
    # single unit-of-work flush. Materialize parents before aliases, ranges,
    # and assertions are added.
    if valid_records:
        session.flush()

    for rec in valid_records:
        seen_aliases = {rec.vulnerability_id}
        for alias in rec.aliases or []:
            if alias and alias not in seen_aliases:
                _upsert_alias(session, rec.vulnerability_id, alias, rec.source)
                seen_aliases.add(alias)
        for rng in rec.affected_ranges or []:
            _upsert_affected_range(session, rec.vulnerability_id, rec.source, rng)
        _upsert_advisory_assertion(session, rec)
    return len(valid_records)


def is_kev_persisted(session: Session, cve_id: str) -> bool:
    """Return whether intel tables mark this CVE as KEV (source=kev, kev=true)."""

    row = (
        session.query(AdvisoryAssertion)
        .filter_by(vulnerability_id=cve_id, source="kev", kev=True)
        .first()
    )
    return row is not None


def upsert_source_health(session: Session, health: SourceHealth, scope: str = "global") -> None:
    """Mirror adapter SourceHealth into source_statuses (polling contract)."""

    status = session.query(SourceStatus).filter_by(source=health.source, scope=scope).first()
    if status is None:
        status = SourceStatus(
            id=f"src_{health.source}_{uuid.uuid4().hex[:12]}",
            source=health.source,
            scope=scope,
        )
        session.add(status)
    status.last_checked_at = health.last_checked_at or datetime.now(UTC)
    status.freshness = health.freshness
    status.last_error = health.error
    status.enabled = health.enabled
    if health.freshness == "fresh":
        status.last_success_at = health.last_success_at or status.last_checked_at
    if health.cursor is not None:
        status.cursor = health.cursor


def refresh_kev_catalog(
    session: Session,
    adapter: Any,
    raw_fixture: dict | None = None,
    source_url: str | None = None,
) -> int:
    """Fetch KEV catalog, upsert intel rows, and checkpoint source health."""

    adapter.fetch_catalog(raw_fixture=raw_fixture, source_url=source_url)
    records: list[AdvisoryRecord] = []
    catalog = getattr(adapter, "_catalog", None) or {}
    for cve_id in catalog:
        rec = adapter.get_record(cve_id)
        if rec is not None:
            records.append(rec)
    count = upsert_advisory_records(session, records)
    upsert_source_health(session, adapter.get_health())
    return count


def _upsert_vulnerability(session: Session, rec: AdvisoryRecord) -> None:
    row = session.get(Vulnerability, rec.vulnerability_id)
    now = datetime.now(UTC)
    merged_aliases = list(rec.aliases or [])
    if row is None:
        session.add(
            Vulnerability(
                id=rec.vulnerability_id,
                description=rec.description,
                cvss_vector=rec.cvss_vector,
                cvss_score=rec.cvss_score,
                aliases=merged_aliases or None,
                modified_at=rec.retrieved_at,
            )
        )
        return
    if rec.description:
        row.description = rec.description
    if rec.cvss_vector:
        row.cvss_vector = rec.cvss_vector
    if rec.cvss_score is not None:
        row.cvss_score = rec.cvss_score
    if merged_aliases:
        existing = set(row.aliases or [])
        row.aliases = list(existing | set(merged_aliases))
    if rec.retrieved_at:
        row.modified_at = rec.retrieved_at
    row.updated_at = now


def _upsert_alias(session: Session, vulnerability_id: str, alias: str, source: str | None) -> None:
    alias_id = _stable_id("valias", vulnerability_id, alias)
    row = session.get(VulnerabilityAlias, alias_id)
    if row is not None:
        return
    existing = (
        session.query(VulnerabilityAlias)
        .filter_by(vulnerability_id=vulnerability_id, alias=alias)
        .first()
    )
    if existing is not None:
        return
    session.add(
        VulnerabilityAlias(
            id=alias_id,
            vulnerability_id=vulnerability_id,
            alias=alias,
            source=source,
        )
    )


def _upsert_affected_range(
    session: Session, vulnerability_id: str, source: str, rng: dict[str, Any]
) -> None:
    ecosystem = rng.get("ecosystem")
    purl = rng.get("purl")
    introduced = rng.get("introduced")
    fixed = rng.get("fixed")
    range_id = _stable_id(
        "rng", vulnerability_id, source, ecosystem or "", purl or "", introduced or "", fixed or ""
    )
    row = session.get(AffectedRange, range_id)
    if row is not None:
        return
    session.add(
        AffectedRange(
            id=range_id,
            vulnerability_id=vulnerability_id,
            ecosystem=ecosystem,
            purl=purl,
            introduced=introduced,
            fixed=fixed,
            last_affected=rng.get("last_affected"),
            source=source,
            confidence=rng.get("confidence"),
        )
    )


def _upsert_advisory_assertion(session: Session, rec: AdvisoryRecord) -> None:
    assertion_id = _stable_id("adv", rec.vulnerability_id, rec.source)
    row = session.get(AdvisoryAssertion, assertion_id)
    if row is None:
        row = (
            session.query(AdvisoryAssertion)
            .filter_by(vulnerability_id=rec.vulnerability_id, source=rec.source)
            .first()
        )
    if row is None:
        session.add(
            AdvisoryAssertion(
                id=assertion_id,
                vulnerability_id=rec.vulnerability_id,
                source=rec.source,
                source_snapshot_id=rec.source_snapshot_id,
                content=rec.content,
                kev=rec.kev,
                epss_score=rec.epss_score,
                epss_percentile=rec.epss_percentile,
                vex_status=rec.vex_status,
                retrieved_at=rec.retrieved_at,
                source_url=rec.source_url,
            )
        )
        return
    row.content = rec.content if rec.content is not None else row.content
    if rec.kev is not None:
        row.kev = rec.kev
    if rec.epss_score is not None:
        row.epss_score = rec.epss_score
    if rec.epss_percentile is not None:
        row.epss_percentile = rec.epss_percentile
    if rec.vex_status is not None:
        row.vex_status = rec.vex_status
    if rec.retrieved_at:
        row.retrieved_at = rec.retrieved_at
    if rec.source_url:
        row.source_url = rec.source_url
