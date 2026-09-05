import hashlib
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.source_snapshot import SourceSnapshot
from vulnops.domain.provenance import persist_snapshot_with_event


def _engine_with_all():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine


def test_snapshot_and_audit_and_outbox_atomic():
    engine = _engine_with_all()
    Session = sessionmaker(bind=engine)
    session = Session()

    content = b'{"id":"CVE-2026-9"}'
    digest = hashlib.sha256(content).hexdigest()
    snapshot = SourceSnapshot(
        id=f"ss_{uuid.uuid4().hex[:8]}",
        source="vulnerability-lookup",
        source_record_id="CVE-2026-9",
        content_sha256=digest,
        content_size=len(content),
        object_uri=f"s3://bucket/{digest}.json",
        validation_state="valid",
        adapter_version="2026.1",
        correlation_id="corr_int_01",
    )

    # Persist with audit: every state-changing command requires audit event
    audit = AuditEvent(
        id=f"aud_{uuid.uuid4().hex[:8]}",
        actor="system",
        action="source.snapshot.created",
        subject_type="source_snapshot",
        subject_id=snapshot.id,
        correlation_id="corr_int_01",
        reason="ingest",
    )

    persist_snapshot_with_event(
        session, snapshot, event_type="source.snapshot.created", audit_event=audit
    )

    cnt_snap = session.execute(text("SELECT COUNT(*) FROM source_snapshots")).scalar()
    cnt_out = session.execute(text("SELECT COUNT(*) FROM outbox_events")).scalar()
    cnt_aud = session.execute(text("SELECT COUNT(*) FROM audit_events")).scalar()
    assert cnt_snap == 1
    assert cnt_out == 1
    assert cnt_aud == 1
    session.close()


def test_failed_audit_rolls_back_all():
    engine = _engine_with_all()
    Session = sessionmaker(bind=engine)
    session = Session()

    content = b'{"id":"CVE-2026-10"}'
    digest = hashlib.sha256(content).hexdigest()
    snapshot = SourceSnapshot(
        id=f"ss_{uuid.uuid4().hex[:8]}",
        source="osv",
        source_record_id="CVE-2026-10",
        content_sha256=digest,
        content_size=len(content),
        object_uri=f"s3://bucket/{digest}.json",
        validation_state="valid",
        adapter_version="2026.1",
        correlation_id="corr_int_02",
    )
    # Create audit event missing required action -> should fail validation/DB constraint
    bad_audit = AuditEvent(
        id=f"aud_{uuid.uuid4().hex[:8]}",
        actor="system",
        action=None,  # type: ignore - violates NOT NULL to force failure
        subject_type="source_snapshot",
        subject_id=snapshot.id,
        correlation_id="corr_int_02",
    )
    try:
        persist_snapshot_with_event(
            session, snapshot, event_type="source.snapshot.created", audit_event=bad_audit
        )
        assert False, "should have raised"
    except Exception:
        pass

    cnt_snap = session.execute(text("SELECT COUNT(*) FROM source_snapshots")).scalar()
    cnt_out = session.execute(text("SELECT COUNT(*) FROM outbox_events")).scalar()
    cnt_aud = session.execute(text("SELECT COUNT(*) FROM audit_events")).scalar()
    assert cnt_snap == 0
    assert cnt_out == 0
    assert cnt_aud == 0
    session.close()
