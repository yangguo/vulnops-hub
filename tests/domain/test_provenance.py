import hashlib
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.db.models.source_snapshot import SourceSnapshot
from vulnops.domain.provenance import persist_snapshot_with_event


def _test_engine():
    # Use in-memory sqlite for unit
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine


def count_rows(session, table: str) -> int:
    result = session.execute(text(f"SELECT COUNT(*) FROM {table}"))
    return result.scalar() or 0


def test_snapshot_and_event_are_atomic():
    engine = _test_engine()
    Session = sessionmaker(bind=engine)
    session = Session()

    content = b'{"id":"CVE-2026-1"}'
    digest = hashlib.sha256(content).hexdigest()
    snapshot = SourceSnapshot(
        id=f"ss_{uuid.uuid4().hex[:8]}",
        source="osv",
        source_record_id="CVE-2026-1",
        content_sha256=digest,
        content_size=len(content),
        object_uri=f"s3://bucket/{digest}.json",
        validation_state="valid",
        adapter_version="2026.1",
        correlation_id="corr_01",
    )
    persist_snapshot_with_event(session, snapshot, event_type="source.snapshot.created")

    assert count_rows(session, "source_snapshots") == 1
    assert count_rows(session, "outbox_events") == 1
    session.close()


def test_rollback_leaves_no_rows():
    engine = _test_engine()
    Session = sessionmaker(bind=engine)
    session = Session()

    content = b'{"id":"CVE-2026-2"}'
    digest = hashlib.sha256(content).hexdigest()
    snapshot = SourceSnapshot(
        id=f"ss_{uuid.uuid4().hex[:8]}",
        source="kev",
        source_record_id="CVE-2026-2",
        content_sha256=digest,
        content_size=len(content),
        object_uri=f"s3://bucket/{digest}.json",
        validation_state="valid",
        adapter_version="2026.1",
        correlation_id="corr_02",
    )
    # Simulate failure after snapshot insert by using invalid event_type that violates NOT NULL
    # Our function should wrap in transaction and rollback on exception
    try:
        persist_snapshot_with_event(session, snapshot, event_type=None)  # type: ignore
        assert False, "should have raised"
    except Exception:
        pass

    # After rollback, neither row should exist
    assert count_rows(session, "source_snapshots") == 0
    assert count_rows(session, "outbox_events") == 0
    session.close()


def test_duplicate_content_is_idempotent():
    engine = _test_engine()
    Session = sessionmaker(bind=engine)
    session = Session()

    content = b'{"id":"CVE-2026-3"}'
    digest = hashlib.sha256(content).hexdigest()
    snap1 = SourceSnapshot(
        id=f"ss_{uuid.uuid4().hex[:8]}",
        source="epss",
        source_record_id="CVE-2026-3",
        content_sha256=digest,
        content_size=len(content),
        object_uri=f"s3://bucket/{digest}.json",
        validation_state="valid",
        adapter_version="2026.1",
        correlation_id="corr_03a",
    )
    snap2 = SourceSnapshot(
        id=f"ss_{uuid.uuid4().hex[:8]}",
        source="epss",
        source_record_id="CVE-2026-3",
        content_sha256=digest,
        content_size=len(content),
        object_uri=f"s3://bucket/{digest}.json",
        validation_state="valid",
        adapter_version="2026.1",
        correlation_id="corr_03b",
    )
    persist_snapshot_with_event(session, snap1, event_type="source.snapshot.created")
    # second call with same natural key should be idempotent
    result = persist_snapshot_with_event(session, snap2, event_type="source.snapshot.created")

    assert count_rows(session, "source_snapshots") == 1
    assert count_rows(session, "outbox_events") == 1
    # result should be original snapshot
    assert result.source_record_id == "CVE-2026-3"
    assert result.content_sha256 == digest
    session.close()
