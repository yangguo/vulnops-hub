from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from vulnops.config import get_settings

REPO_ROOT = Path(__file__).parents[2]


def _migrate(db_path: Path, revision: str, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    get_settings.cache_clear()
    config = Config(str(REPO_ROOT / "alembic.ini"))
    command.upgrade(config, revision)


def _downgrade(db_path: Path, revision: str, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    get_settings.cache_clear()
    config = Config(str(REPO_ROOT / "alembic.ini"))
    command.downgrade(config, revision)


def test_actor_provenance_migration_backfills_legacy_approvers_across_round_trip(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "migration-round-trip.db"
    _migrate(db_path, "de6d30ecc5de", monkeypatch)

    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO remediation_cases
                    (id, case_key, title, organization_id, owner_team, assignee,
                     priority, policy_version, status, version, due_at, sla_breached,
                     closure_reason, external_ticket_id, exposures, created_at, updated_at)
                VALUES
                    ('case_legacy', 'CASE-LEGACY', 'legacy', 'org1', 'security', NULL,
                     'P2', NULL, 'triage', 2, NULL, 0,
                     NULL, NULL, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO risk_decisions
                    (id, case_id, type, status, scope_exposure_ids, reason,
                     compensating_controls, evidence_ids, requested_by, approver,
                     approver_role, expires_at, created_at, updated_at)
                VALUES
                    ('rdec_legacy', 'case_legacy', 'risk_accepted', 'approved', NULL,
                     'legacy approval', NULL, '["ev-legacy"]', 'alice', 'bob',
                     'risk_approver', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO audit_events
                    (id, actor, action, subject_type, subject_id, prior_state,
                     new_state, reason, policy_version, correlation_id, evidence_refs,
                     organization_id, created_at)
                VALUES
                    ('aud_legacy', 'bob', 'risk.accepted', 'risk_decision',
                     'rdec_legacy', 'pending_approval', 'approved', 'legacy approval',
                     NULL, 'corr-legacy', NULL, 'org1', CURRENT_TIMESTAMP)
                """
            )
        )

    _migrate(db_path, "head", monkeypatch)
    with engine.connect() as connection:
        risk = connection.execute(
            text(
                "SELECT requested_by, approver, approver_provenance "
                "FROM risk_decisions WHERE id = 'rdec_legacy'"
            )
        ).one()
        audit = connection.execute(
            text(
                "SELECT actor, correlation_id, request_id FROM audit_events WHERE id = 'aud_legacy'"
            )
        ).one()
    assert tuple(risk) == ("alice", "bob", "legacy_request")
    assert tuple(audit) == ("bob", "corr-legacy", None)

    _downgrade(db_path, "de6d30ecc5de", monkeypatch)
    inspector = inspect(engine)
    assert "approver_provenance" not in {
        column["name"] for column in inspector.get_columns("risk_decisions")
    }
    with engine.connect() as connection:
        legacy_bytes = connection.execute(
            text("SELECT requested_by, approver FROM risk_decisions WHERE id = 'rdec_legacy'")
        ).one()
    assert tuple(legacy_bytes) == ("alice", "bob")

    _migrate(db_path, "head", monkeypatch)
    with engine.connect() as connection:
        reupgraded = connection.execute(
            text(
                "SELECT requested_by, approver, approver_provenance "
                "FROM risk_decisions WHERE id = 'rdec_legacy'"
            )
        ).one()
    assert tuple(reupgraded) == ("alice", "bob", "legacy_request")
