from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.db.models.source_snapshot import SourceSnapshot
from vulnops.integrations.mapping import AssetMapper, MappingResult


@dataclass
class WazuhIngestResult:
    source_snapshot: SourceSnapshot
    evidence_ref: str
    mapping: MappingResult
    agent_id: str | None
    package_name: str | None
    package_version: str | None
    package_purl: str | None
    scan_metadata: dict[str, Any]
    should_update_case: bool
    case_id: str | None


class WazuhBridge:
    """
    Wazuh adapter imports managed endpoint identity, package inventory,
    and vulnerability detection events. Preserves Wazuh agent/index/event identifiers
    and treats Wazuh status as evidence, not overall case state.
    """

    def __init__(self, session: Session):
        self.session = session
        self.mapper = AssetMapper(session)

    def _sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def ingest_event(self, raw: dict[str, Any], organization_id: str) -> WazuhIngestResult:
        agent = raw.get("agent", {})
        package = raw.get("package", {})
        vulnerability = raw.get("vulnerability", {})

        agent_id = str(agent.get("id") or agent.get("agent_id") or "unknown")
        cve = vulnerability.get("id") or raw.get("cve") or "unknown"
        # Determine source_record_id: combine agent + cve + package
        source_record_id = (
            f"{agent_id}:{cve}:{package.get('name', '')}:{package.get('version', '')}"
        )
        raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        digest = self._sha256(raw_bytes)

        existing = (
            self.session.query(SourceSnapshot)
            .filter_by(source="wazuh", source_record_id=source_record_id, content_sha256=digest)
            .first()
        )
        if existing:
            mapping = self.mapper.map_wazuh(raw, organization_id)
            scan_meta = self._extract_scan_metadata(raw)
            return WazuhIngestResult(
                source_snapshot=existing,
                evidence_ref=existing.id,
                mapping=mapping,
                agent_id=agent_id,
                package_name=package.get("name"),
                package_version=package.get("version"),
                package_purl=package.get("purl"),
                scan_metadata=scan_meta,
                should_update_case=False,
                case_id=None,
            )

        mapping = self.mapper.map_wazuh(raw, organization_id)
        scan_metadata = self._extract_scan_metadata(raw)

        object_uri = f"wazuh://agent/{agent_id}/event/{digest[:12]}"
        snapshot = SourceSnapshot(
            id=f"ss_{uuid.uuid4().hex[:12]}",
            source="wazuh",
            source_record_id=source_record_id,
            content_sha256=digest,
            content_size=len(raw_bytes),
            object_uri=object_uri,
            validation_state="valid",
            adapter_version="2026.1",
            organization_id=organization_id,
            correlation_id=str(uuid.uuid4()),
        )

        # Wazuh status is evidence, not case state
        should_update_case = False
        case_id = None

        try:
            self.session.add(snapshot)
            audit = AuditEvent(
                id=f"aud_{uuid.uuid4().hex[:12]}",
                actor="wazuh-bridge",
                action="evidence.wazuh.ingested",
                subject_type="source_snapshot",
                subject_id=snapshot.id,
                correlation_id=snapshot.correlation_id,
                reason="wazuh event ingested",
                organization_id=organization_id,
            )
            self.session.add(audit)
            outbox = OutboxEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                aggregate_type="evidence",
                aggregate_id=snapshot.id,
                event_type="vulnops.evidence.wazuh.ingested.v1",
                payload={
                    "agent_id": agent_id,
                    "cve": cve,
                    "package": package,
                    "mapping": {"status": mapping.status, "asset_id": mapping.asset_id},
                    "scan_metadata": scan_metadata,
                },
                correlation_id=snapshot.correlation_id,
            )
            self.session.add(outbox)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

        return WazuhIngestResult(
            source_snapshot=snapshot,
            evidence_ref=snapshot.id,
            mapping=mapping,
            agent_id=agent_id,
            package_name=package.get("name"),
            package_version=package.get("version"),
            package_purl=package.get("purl"),
            scan_metadata=scan_metadata,
            should_update_case=should_update_case,
            case_id=case_id,
        )

    def _extract_scan_metadata(self, raw: dict) -> dict:
        scan = raw.get("scan", {})
        agent = raw.get("agent", {})
        return {
            "scope_status": scan.get("scope_status")
            or scan.get("status")
            or raw.get("scan", {}).get("scope_status")
            or "unknown",
            "scan_id": scan.get("id") or raw.get("scan", {}).get("id"),
            "agent": agent,
            "agent_id": agent.get("id"),
        }
