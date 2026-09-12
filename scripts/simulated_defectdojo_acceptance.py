"""Enqueue an explicitly simulated DefectDojo finding for local acceptance.

The fixture is intentionally marked as simulated. It exercises the normal
Valkey -> ingestion worker -> outbox -> orchestrator path and must never be
reported as a scanner-produced finding.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
from typing import Any

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/defectdojo/simulated_acceptance_finding.json"
)


def load_fixture() -> dict[str, Any]:
    """Load the checked-in simulated finding and reject an unmarked payload."""

    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    title = payload.get("title")
    if not isinstance(title, str) or not title.startswith("[SIMULATED ACCEPTANCE]"):
        raise ValueError("fixture must have a [SIMULATED ACCEPTANCE] title marker")
    return payload


def build_job(fixture: dict[str, Any], *, organization_id: str, run_id: str) -> dict[str, Any]:
    """Create a stable, replayable normal ingestion job for one acceptance run."""

    normalized_run_id = run_id.strip()
    if not normalized_run_id:
        raise ValueError("run_id must not be empty")

    finding_id = f"simulated-{normalized_run_id}"
    payload = copy.deepcopy(fixture)
    payload["id"] = finding_id
    payload["url"] = f"https://simulated.invalid/defectdojo/findings/{finding_id}"
    payload["simulation"] = {**payload.get("simulation", {}), "run_id": normalized_run_id}
    return {
        "source": "defectdojo",
        "payload": payload,
        "organization_id": organization_id,
        "idempotency_key": f"defectdojo:{finding_id}",
    }


def main() -> None:
    # This module is also imported by tests; direct script execution makes the
    # sibling helper importable without turning the operational scripts into a
    # production Python package.
    from sandbox_fetch import enqueue

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization-id", default="org-demo")
    parser.add_argument(
        "--run-id", required=True, help="stable ID; reuse it to prove replay safety"
    )
    parser.add_argument(
        "--redis-url",
        default=None,
        help="default: REDIS_URL or redis://localhost:6379/0",
    )
    args = parser.parse_args()

    redis_url = args.redis_url or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
    job = build_job(load_fixture(), organization_id=args.organization_id, run_id=args.run_id)
    enqueue([job], redis_url)
    print(f"enqueued simulated DefectDojo finding {job['payload']['id']}")


if __name__ == "__main__":
    main()
