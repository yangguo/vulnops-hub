"""Product-level polling adapters: fetch upstream records and enqueue jobs.

Implements the adapter-onboarding contract for pull sources: discover ->
validate -> enqueue as ingestion jobs -> checkpoint. The ingestion bridges
remain the apply layer (snapshot dedup makes re-listing safe); checkpoints
persist cursor and health only after jobs are durably enqueued. Replaces
scripts/sandbox_fetch.py as the production ingestion path.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from vulnops.config import get_settings
from vulnops.intelligence.models import SourceStatus

logger = logging.getLogger("vulnops.workers.polling")


class DefectDojoClient:
    """Fetch findings incrementally; cursor = highest finding id seen."""

    source = "defectdojo"

    def __init__(self, base_url: str, token: str, http_client: Any = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.http_client = http_client or _make_client()

    def fetch(self, cursor: str | None) -> tuple[list[dict], str | None]:
        query = "/api/v2/findings/?ordering=id&limit=100&related_fields=true"
        if cursor:
            query += f"&id__gt={cursor}"
        resp = self.http_client.get(
            f"{self.base_url}{query}", headers={"authorization": f"Token {self.token}"}
        )
        resp.raise_for_status()
        records = resp.json().get("results", [])
        next_cursor = str(max((int(r["id"]) for r in records), default=0)) or cursor
        return records, next_cursor


class WazuhClient:
    """Fetch agent package inventories; full re-list per poll (bridge dedupes)."""

    source = "wazuh"

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        http_client: Any = None,
        verify_tls: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        # verify_tls defaults False because sandbox deployments use the
        # manager's self-signed certificate; set WAZUH_TLS_VERIFY=true with a
        # trusted CA in production.
        self.http_client = http_client or _make_client(verify=verify_tls)

    def fetch(self, cursor: str | None) -> tuple[list[dict], str | None]:
        del cursor  # full re-list per poll; the bridge dedupes by record digest
        token = self._token()
        bearer = {"authorization": f"Bearer {token}"}
        agents = self.http_client.get(f"{self.base_url}/agents?limit=500", headers=bearer).json()[
            "data"
        ]["affected_items"]
        events: list[dict] = []
        for agent in agents:
            agent_id = agent.get("id")
            if agent_id is None:
                continue
            try:
                packages = self.http_client.get(
                    f"{self.base_url}/syscollector/{agent_id}/packages?limit=500",
                    headers=bearer,
                ).json()["data"]["affected_items"]
            except Exception as exc:
                logger.warning("wazuh package fetch failed for agent %s: %s", agent_id, exc)
                continue
            for package in packages:
                events.append({"agent": agent, "package": package})
        return events, None

    def _token(self) -> str:
        resp = self.http_client.post(
            f"{self.base_url}/security/user/authenticate?raw=true",
            headers=_basic(self.user, self.password),
        )
        resp.raise_for_status()
        return resp.text.strip() if isinstance(resp.text, str) else resp.text


def _basic(user: str, password: str) -> dict[str, str]:
    import base64

    encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"authorization": f"Basic {encoded}"}


def _make_client(verify: bool = True) -> Any:
    import httpx

    return httpx.Client(timeout=30, verify=verify)


def _job(source: str, payload: dict, organization_id: str) -> dict:
    natural = payload.get("id")
    if source == "wazuh":
        agent = payload.get("agent", {})
        package = payload.get("package", {})
        natural = f"{agent.get('id')}:{package.get('name')}:{package.get('version')}"
    return {
        "source": source,
        "payload": payload,
        "organization_id": organization_id,
        "idempotency_key": f"{source}:{natural}",
    }


class PollingWorker:
    """Poll configured sources and enqueue ingestion jobs; checkpoint after."""

    def __init__(self, session_factory, clients: dict[str, Any], enqueuer, settings=None):
        self.session_factory = session_factory
        self.clients = clients  # source name -> client or None (unconfigured)
        self.enqueuer = enqueuer  # Callable[[list[dict]], None]
        self.settings = settings or get_settings()

    def cycle(self) -> dict[str, int]:
        stats: dict[str, int] = {}
        for source, client in self.clients.items():
            if client is None:
                continue
            stats[source] = self._poll_source(source, client)
        return stats

    def _poll_source(self, source: str, client: Any) -> int:
        session = self.session_factory()
        try:
            status = self._get_status(session, source)
            cursor = status.cursor if status else None
            try:
                records, next_cursor = client.fetch(cursor)
            except Exception as exc:
                self._checkpoint(session, source, "stale", None, str(exc)[:512])
                logger.warning("poll of %s failed: %s", source, exc)
                return 0
            jobs = [_job(source, record, self.settings.poll_organization_id) for record in records]
            try:
                self.enqueuer(jobs)
            except Exception as exc:
                self._checkpoint(session, source, "stale", None, f"enqueue failed: {exc}"[:512])
                logger.warning("enqueue of %s jobs failed: %s", source, exc)
                return 0
            self._checkpoint(session, source, "fresh", next_cursor, None)
            return len(jobs)
        finally:
            session.close()

    def _get_status(self, session: Session, source: str) -> SourceStatus | None:
        return session.query(SourceStatus).filter_by(source=source, scope="global").first()

    def _checkpoint(
        self,
        session: Session,
        source: str,
        freshness: str,
        cursor: str | None,
        error: str | None,
    ) -> None:
        status = self._get_status(session, source)
        if status is None:
            status = SourceStatus(
                id=f"src_{source}_{uuid4hex()}",
                source=source,
                scope="global",
            )
            session.add(status)
        status.last_checked_at = datetime.now(UTC)
        status.freshness = freshness
        status.last_error = error
        if freshness == "fresh":
            status.last_success_at = datetime.now(UTC)
            if cursor is not None:
                status.cursor = cursor
        session.commit()

    def run_forever(self, max_iterations: int | None = None) -> None:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            try:
                stats = self.cycle()
                if any(stats.values()):
                    logger.info("polling cycle enqueued %s", stats)
            except Exception:
                logger.exception("polling loop error; backing off")
            interval = min(
                (
                    self.settings.defectdojo_poll_interval_seconds,
                    self.settings.wazuh_poll_interval_seconds,
                )
            )
            time.sleep(interval)


def uuid4hex() -> str:
    import uuid

    return uuid.uuid4().hex[:12]


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    from vulnops.db import get_engine, get_sessionmaker

    settings = get_settings()
    clients: dict[str, Any] = {"defectdojo": None, "wazuh": None}
    if settings.defectdojo_base_url and settings.defectdojo_api_token:
        clients["defectdojo"] = DefectDojoClient(
            settings.defectdojo_base_url, settings.defectdojo_api_token
        )
    else:
        logger.info("DefectDojo polling disabled (base URL or token unconfigured)")
    if settings.wazuh_base_url and settings.wazuh_api_password:
        clients["wazuh"] = WazuhClient(
            settings.wazuh_base_url,
            settings.wazuh_api_user,
            settings.wazuh_api_password,
        )
    else:
        logger.info("Wazuh polling disabled (base URL or password unconfigured)")

    def enqueuer(jobs: list[dict]) -> None:
        import json as _json

        import redis

        client = redis.from_url(
            settings.effective_redis_url or "redis://localhost:6379/0",
            socket_connect_timeout=2,
            socket_timeout=5,
        )
        client.ping()
        pipeline = client.pipeline()
        for job in jobs:
            pipeline.lpush("vulnops:ingest", _json.dumps(job))
        pipeline.execute()

    worker = PollingWorker(
        session_factory=lambda: get_sessionmaker(get_engine())(),
        clients=clients,
        enqueuer=enqueuer,
        settings=settings,
    )
    worker.run_forever()


if __name__ == "__main__":
    main()
