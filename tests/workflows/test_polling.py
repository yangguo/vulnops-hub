"""Polling worker tests: fetch -> enqueue -> checkpoint per the onboarding contract."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import vulnops.db.models.outbox_event
import vulnops.intelligence.models  # noqa: F401  (register SourceStatus metadata)
from vulnops.config import Settings
from vulnops.db import Base


@pytest.fixture()
def db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


def _settings(**overrides) -> Settings:
    defaults: dict = {
        "oidc_issuer_url": "http://127.0.0.1:8082/realms/vulnops",
        "oidc_audience": "vulnops-api",
    }
    defaults.update(overrides)
    return Settings(**defaults)


class _RecordingEnqueuer:
    def __init__(self, fail: bool = False):
        self.jobs: list[list[dict]] = []
        self.fail = fail

    def __call__(self, jobs: list[dict]) -> None:
        if self.fail:
            raise RuntimeError("queue down")
        self.jobs.append(jobs)


class _FakeDDClient:
    """DefectDojo stand-in: two pages keyed by cursor."""

    def __init__(self):
        self.pages = {
            None: [{"id": 1, "title": "a"}, {"id": 2, "title": "b"}],
            "2": [{"id": 3, "title": "c"}],
        }
        self.requests: list[str | None] = []

    def fetch(self, cursor):
        self.requests.append(cursor)
        records = self.pages.get(cursor, [])
        next_cursor = str(max((r["id"] for r in records), default=0)) or None
        return records, (next_cursor if records else cursor)


def test_defectdojo_jobs_shape_and_cursor_advance(db):
    from vulnops.workers.polling import PollingWorker

    enqueuer = _RecordingEnqueuer()
    worker = PollingWorker(
        session_factory=lambda: db,
        clients={"defectdojo": _FakeDDClient(), "wazuh": None},
        enqueuer=enqueuer,
        settings=_settings(),
    )
    stats = worker.cycle()
    assert stats["defectdojo"] == 2
    assert enqueuer.jobs[0] == [
        {
            "source": "defectdojo",
            "payload": {"id": 1, "title": "a"},
            "organization_id": "org-demo",
            "idempotency_key": "defectdojo:1",
        },
        {
            "source": "defectdojo",
            "payload": {"id": 2, "title": "b"},
            "organization_id": "org-demo",
            "idempotency_key": "defectdojo:2",
        },
    ]
    from vulnops.intelligence.models import SourceStatus

    status = db.query(SourceStatus).filter_by(source="defectdojo").one()
    assert status.cursor == "2"
    assert status.freshness == "fresh"
    assert status.last_success_at is not None


def test_wazuh_events_shaped_for_bridge(db):
    from vulnops.workers.polling import PollingWorker, WazuhClient

    class _Resp:
        def __init__(self, body, text=""):
            self._body = body
            self.text = text

        def json(self):
            return self._body

        def raise_for_status(self):
            return None

    class _FakeTransport:
        def post(self, url, **kwargs):
            return _Resp({}, text="tok")

        def get(self, url, **kwargs):
            if "/agents?" in url:
                return _Resp({"data": {"affected_items": [{"id": 7, "name": "h1"}]}})
            return _Resp({"data": {"affected_items": [{"name": "openssl", "version": "3.0.2"}]}})

    client = WazuhClient("https://wazuh", "wazuh", "pw", http_client=_FakeTransport())
    enqueuer = _RecordingEnqueuer()
    worker = PollingWorker(
        session_factory=lambda: db,
        clients={"defectdojo": None, "wazuh": client},
        enqueuer=enqueuer,
        settings=_settings(),
    )
    stats = worker.cycle()
    assert stats["wazuh"] == 1
    job = enqueuer.jobs[0][0]
    assert job["source"] == "wazuh"
    assert job["payload"] == {
        "agent": {"id": 7, "name": "h1"},
        "package": {"name": "openssl", "version": "3.0.2"},
    }
    assert job["idempotency_key"] == "wazuh:7:openssl:3.0.2"


class _Resp:
    def __init__(self, body, text=""):
        self._body = body
        self.text = text

    def json(self):
        return self._body

    def raise_for_status(self):
        return None


def test_defectdojo_client_requests_related_fields():
    from vulnops.workers.polling import DefectDojoClient

    class _FakeTransport:
        def __init__(self):
            self.url = None
            self.headers = None

        def get(self, url, **kwargs):
            self.url = url
            self.headers = kwargs["headers"]
            return _Resp({"results": [{"id": 11, "related_fields": {}}]})

    transport = _FakeTransport()
    client = DefectDojoClient("https://dojo/", "token", http_client=transport)

    records, cursor = client.fetch(None)

    assert records == [{"id": 11, "related_fields": {}}]
    assert cursor == "11"
    assert transport.url == (
        "https://dojo/api/v2/findings/?ordering=id&limit=100&related_fields=true&offset=0"
    )
    assert transport.headers == {"authorization": "Token token"}


def test_defectdojo_client_filters_a_cursor_ignored_by_the_upstream():
    """A DefectDojo server may accept, but ignore, ``id__gt`` filters."""
    from vulnops.workers.polling import DefectDojoClient

    class _IgnoringFilterTransport:
        def __init__(self):
            self.urls: list[str] = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            return _Resp({"results": [{"id": 1}, {"id": 2}, {"id": 3}]})

    transport = _IgnoringFilterTransport()
    client = DefectDojoClient("https://dojo", "token", http_client=transport)

    records, cursor = client.fetch("2")

    assert records == [{"id": 3}]
    assert cursor == "3"
    assert transport.urls == [
        "https://dojo/api/v2/findings/?ordering=id&limit=100&related_fields=true&offset=0&id__gt=2"
    ]


def test_defectdojo_client_keeps_cursor_when_the_filtered_page_has_no_new_records():
    from vulnops.workers.polling import DefectDojoClient

    class _IgnoringFilterTransport:
        def get(self, url, **kwargs):
            return _Resp({"results": [{"id": 1}, {"id": 2}]})

    client = DefectDojoClient("https://dojo", "token", http_client=_IgnoringFilterTransport())

    records, cursor = client.fetch("2")

    assert records == []
    assert cursor == "2"


def test_defectdojo_client_pages_past_the_saved_cursor():
    from vulnops.workers.polling import DefectDojoClient

    class _PagedTransport:
        def __init__(self):
            self.urls: list[str] = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            if "offset=0" in url:
                return _Resp({"results": [{"id": item} for item in range(1, 101)]})
            return _Resp({"results": [{"id": 101}]})

    transport = _PagedTransport()
    client = DefectDojoClient("https://dojo", "token", http_client=transport)

    records, cursor = client.fetch("100")

    assert records == [{"id": 101}]
    assert cursor == "101"
    assert transport.urls == [
        "https://dojo/api/v2/findings/?ordering=id&limit=100&related_fields=true&offset=0&id__gt=100",
        "https://dojo/api/v2/findings/?ordering=id&limit=100&related_fields=true&offset=100&id__gt=100",
    ]


def test_checkpoint_only_after_enqueue(db):
    from vulnops.intelligence.models import SourceStatus
    from vulnops.workers.polling import PollingWorker

    enqueuer = _RecordingEnqueuer(fail=True)
    worker = PollingWorker(
        session_factory=lambda: db,
        clients={"defectdojo": _FakeDDClient(), "wazuh": None},
        enqueuer=enqueuer,
        settings=_settings(),
    )
    stats = worker.cycle()
    assert stats["defectdojo"] == 0
    status = db.query(SourceStatus).filter_by(source="defectdojo").one()
    assert status.cursor is None  # cursor not advanced: jobs were not durably enqueued
    assert status.freshness == "stale"
    assert status.last_error


def test_fetch_failure_marks_stale_keeps_cursor(db):
    from vulnops.intelligence.models import SourceStatus
    from vulnops.workers.polling import PollingWorker

    class _Broken:
        def fetch(self, cursor):
            raise RuntimeError("upstream 500")

    enqueuer = _RecordingEnqueuer()
    worker = PollingWorker(
        session_factory=lambda: db,
        clients={"defectdojo": _Broken(), "wazuh": None},
        enqueuer=enqueuer,
        settings=_settings(),
    )
    worker.cycle()
    status = db.query(SourceStatus).filter_by(source="defectdojo").one()
    assert status.freshness == "stale"
    assert status.cursor is None
    assert not enqueuer.jobs


def test_unconfigured_source_skipped(db):
    from vulnops.intelligence.models import SourceStatus
    from vulnops.workers.polling import PollingWorker

    worker = PollingWorker(
        session_factory=lambda: db,
        clients={"defectdojo": None, "wazuh": None},
        enqueuer=_RecordingEnqueuer(),
        settings=_settings(),
    )
    stats = worker.cycle()
    assert stats == {}
    assert db.query(SourceStatus).count() == 0


def test_cursor_persisted_across_cycles(db):
    from vulnops.workers.polling import PollingWorker

    client = _FakeDDClient()
    worker = PollingWorker(
        session_factory=lambda: db,
        clients={"defectdojo": client, "wazuh": None},
        enqueuer=_RecordingEnqueuer(),
        settings=_settings(),
    )
    worker.cycle()
    worker.cycle()
    assert client.requests == [None, "2"]  # second cycle resumes from checkpoint
