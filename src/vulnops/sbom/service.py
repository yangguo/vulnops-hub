from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnops.config import get_settings
from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.db.models.source_snapshot import SourceSnapshot
from vulnops.sbom.models import Component, ComponentOccurrence, SbomDocument
from vulnops.sbom.parser import SBOMParser


def _utcnow():
    return datetime.now(UTC)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _persist_raw_bytes(raw_bytes: bytes, bucket: str, organization_id: str, digest: str) -> str:
    """Persist raw SBOM bytes to local storage and return the object URI.

    Uses the configured bucket name instead of a hard-coded default so the
    recorded URI always matches deployment configuration. Returns an
    ``s3://`` logical URI; locally the bytes live under ``./storage`` for
    replay and digest verification.
    """
    import os

    object_uri = f"s3://{bucket}/sbom/{organization_id}/{digest}.json"
    # Local backing store for MVP / dev (MinIO/S3 in production).
    local_path = os.path.join("storage", "sbom", organization_id, f"{digest}.json")
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    # Idempotent write: only write when missing or digest differs.
    if not os.path.exists(local_path):
        with open(local_path, "wb") as f:
            f.write(raw_bytes)
    return object_uri


class SBOMService:
    def __init__(self, session: Session, parser_version: str | None = None):
        self.session = session
        self.parser = SBOMParser()
        self.parser_version = parser_version or SBOMParser.PARSER_VERSION

    def ingest(
        self,
        raw_data: dict[str, Any],
        organization_id: str,
        correlation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        """
        Ingest an SBOM document (CycloneDX or SPDX).
        - Validates schema
        - Captures immutable source snapshot provenance
        - Parses components, preserves raw identifiers
        - Emits outbox event atomically
        - Handles idempotent replay via content digest
        """
        # Serialize deterministically for hashing
        raw_bytes = json.dumps(raw_data, sort_keys=True, separators=(",", ":")).encode()
        digest = _sha256_bytes(raw_bytes)
        # Idempotency: check existing SBOM by digest + org
        existing = (
            self.session.execute(
                select(SbomDocument).where(
                    SbomDocument.content_sha256 == digest,
                    SbomDocument.organization_id == organization_id,
                )
            )
            .scalars()
            .first()
        )
        if existing:
            return {
                "id": existing.id,
                "sbom_id": existing.id,
                "submission_id": f"sub_{existing.id}",
                "content_sha256": digest,
                "content_hash": digest,
                "digest": digest,
                "status": "accepted",
                "received_at": existing.created_at.isoformat(),
            }

        # Parse and validate - raises ValueError on malformed
        parsed = self.parser.parse(raw_data)

        # Determine format and metadata
        sbom_id = f"sbom_{uuid.uuid4().hex[:12]}"
        # Use serialNumber or documentNamespace as source_record_id
        serial = (
            parsed.serial_number
            or parsed.raw.get("serialNumber")
            or parsed.raw.get("documentNamespace")
            or sbom_id
        )
        settings = get_settings()
        # Persist raw bytes first so the recorded URI is retrievable and
        # digest-verifiable; bucket comes from deployment configuration.
        object_uri = _persist_raw_bytes(
            raw_bytes, settings.object_storage_bucket, organization_id, digest
        )

        # Create source snapshot for provenance
        snapshot = SourceSnapshot(
            id=f"ss_{uuid.uuid4().hex[:12]}",
            source="sbom",
            source_record_id=str(serial),
            content_sha256=digest,
            content_size=len(raw_bytes),
            object_uri=object_uri,
            validation_state="valid",
            adapter_version=self.parser_version,
            organization_id=organization_id,
            correlation_id=correlation_id or idempotency_key or str(uuid.uuid4()),
        )

        # Create SBOM document
        sbom_doc = SbomDocument(
            id=sbom_id,
            organization_id=organization_id,
            serial_number=str(serial)[:256] if serial else None,
            version=parsed.raw.get("version")
            if isinstance(parsed.raw.get("version"), int)
            else None,
            format=parsed.format,
            spec_version=parsed.spec_version,
            content_sha256=digest,
            content_size=len(raw_bytes),
            object_uri=object_uri,
            parser_version=self.parser_version,
            validation_state="valid",
        )

        # Atomic persist: SBOM + occurrences + source snapshot + outbox
        # We use explicit transaction
        correlation = snapshot.correlation_id
        try:
            # We'll add SBOM doc and components within same transaction as provenance
            # Persist snapshot + outbox first via provenance helper, then add SBOM?
            # To keep atomic, we manually handle transaction
            # Check if session already in transaction
            if self.session.in_transaction():
                # flush existing pending
                self.session.rollback()

            with self.session.begin():
                # Add snapshot + outbox via direct inserts (avoid nested helper which does its own begin)
                # Create outbox for sbom ingestion
                outbox = OutboxEvent(
                    id=f"evt_{uuid.uuid4().hex[:12]}",
                    aggregate_type="sbom",
                    aggregate_id=sbom_id,
                    event_type="vulnops.sbom.processed.v1",
                    payload={
                        "sbom_id": sbom_id,
                        "organization_id": organization_id,
                        "content_sha256": digest,
                        "format": parsed.format,
                        "component_count": len(parsed.components),
                    },
                    correlation_id=correlation,
                )
                audit = AuditEvent(
                    id=f"aud_{uuid.uuid4().hex[:12]}",
                    actor="system",
                    action="sbom.ingested",
                    subject_type="sbom",
                    subject_id=sbom_id,
                    correlation_id=correlation,
                    reason="sbom ingestion",
                    organization_id=organization_id,
                )
                self.session.add(snapshot)
                self.session.add(outbox)
                self.session.add(audit)
                self.session.add(sbom_doc)
                self.session.flush()

                # Add components/occurrences
                for pc in parsed.components:
                    # Find or create component by purl if present
                    comp_id = None
                    if pc.purl:
                        existing_comp = (
                            self.session.execute(select(Component).where(Component.purl == pc.purl))
                            .scalars()
                            .first()
                        )
                        if existing_comp:
                            comp_id = existing_comp.id
                        else:
                            comp = Component(
                                id=f"comp_{uuid.uuid4().hex[:12]}",
                                purl=pc.purl,
                                ecosystem=pc.ecosystem,
                                normalized_name=pc.normalized_name,
                                raw_name=pc.raw_name,
                                raw_version=pc.raw_version,
                                cpe=pc.cpe,
                            )
                            self.session.add(comp)
                            self.session.flush()
                            comp_id = comp.id
                    else:
                        # No purl - create ad-hoc component
                        comp = Component(
                            id=f"comp_{uuid.uuid4().hex[:12]}",
                            purl=None,
                            ecosystem=pc.ecosystem,
                            normalized_name=pc.normalized_name,
                            raw_name=pc.raw_name,
                            raw_version=pc.raw_version,
                            cpe=pc.cpe,
                        )
                        self.session.add(comp)
                        self.session.flush()
                        comp_id = comp.id

                    occ = ComponentOccurrence(
                        id=f"occ_{uuid.uuid4().hex[:12]}",
                        sbom_id=sbom_id,
                        component_id=comp_id,
                        purl=pc.purl,
                        ecosystem=pc.ecosystem,
                        normalized_name=pc.normalized_name,
                        raw_name=pc.raw_name,
                        raw_version=pc.raw_version,
                        cpe=pc.cpe,
                        version_scheme=pc.version_scheme,
                        source="sbom",
                        evidence_ref=snapshot.id,
                    )
                    self.session.add(occ)

            # After commit, return
            return {
                "id": sbom_id,
                "sbom_id": sbom_id,
                "submission_id": f"sub_{uuid.uuid4().hex[:8]}",
                "content_sha256": digest,
                "content_hash": digest,
                "digest": digest,
                "status": "accepted",
                "received_at": _utcnow().isoformat(),
            }
        except ValueError:
            # Validation errors should bubble as 422 without persisting
            self.session.rollback()
            raise
        except Exception:
            self.session.rollback()
            raise

    def replay_with_version(
        self, raw_data: dict[str, Any], parser_version: str, organization_id: str
    ) -> dict:
        """
        Replay an older source snapshot under an explicit parser version
        without mutating raw evidence. Returns parsed result.
        """
        # This method proves that raw evidence is retained and re-parseable
        # Temporarily override version
        svc = SBOMService(self.session, parser_version=parser_version)
        parsed = svc.parser.parse(raw_data)
        # Ensure raw preserved
        assert parsed.raw == raw_data
        return {"parser_version": parser_version, "component_count": len(parsed.components)}
