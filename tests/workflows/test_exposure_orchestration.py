"""Orchestration worker tests: outbox events -> exposures -> auto cases."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.config import Settings
from vulnops.db import Base
from vulnops.db.models.outbox_event import OutboxEvent


def _settings(**overrides) -> Settings:
    """Settings instance safe for unit tests (no test bypass needed here)."""

    defaults: dict = {
        "oidc_issuer_url": "http://127.0.0.1:8082/realms/vulnops",
        "oidc_audience": "vulnops-api",
    }
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture()
def db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


def _outbox(event_type: str, payload: dict) -> OutboxEvent:
    return OutboxEvent(
        id=f"evt_{uuid.uuid4().hex[:12]}",
        aggregate_type="test",
        aggregate_id="agg-1",
        event_type=event_type,
        payload=payload,
        created_at=datetime.now(UTC),
    )


def test_orchestration_settings_defaults():
    s = _settings()
    assert s.orchestrator_poll_interval_seconds == 5.0
    assert s.orchestrator_batch_size == 50
    assert s.orchestrator_max_attempts == 8
    assert s.case_auto_create_enabled is True
    assert s.default_case_owner_team == "unassigned"
