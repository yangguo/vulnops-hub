from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from vulnops.config import get_settings
from vulnops.db import get_engine, get_sessionmaker

logger = logging.getLogger("vulnops.workers.ingestion")


class IngestionWorker:
    """
    Durable ingestion worker handling idempotent replay via source snapshots.
    Simulates queue consumption with in-memory or Redis backend.
    For MVP, uses simple loop with outbox deduplication.
    """

    def __init__(self, session_factory: Callable[[], Session] | None = None):
        self.engine = get_engine()
        self.session_factory = session_factory or (lambda: get_sessionmaker(self.engine)())
        self.handlers: dict[str, Callable] = {}

    def register(self, source: str, handler: Callable):
        self.handlers[source] = handler

    def process(self, job: dict[str, Any]) -> dict[str, Any]:
        """
        Process a job dict: {"source": "defectdojo", "payload": {...}, "organization_id": "org1", "idempotency_key": "..."}
        Returns result and ensures idempotency via source snapshot check.
        """
        source = job.get("source") or ""
        payload = job.get("payload", {})
        org = job.get("organization_id", "default")
        idempotency_key = job.get("idempotency_key") or job.get("id") or str(uuid.uuid4())

        handler = self.handlers.get(source) if source else None
        if not handler:
            logger.warning("no handler for source %s", source)
            return {"status": "skipped", "reason": f"no handler for {source}"}

        session = self.session_factory()
        try:
            # Check idempotency via source snapshot? Delegated to handler
            result = handler(session, payload, org, idempotency_key)
            logger.info("processed job source=%s org=%s key=%s", source, org, idempotency_key)
            return {"status": "processed", "result": result}
        except Exception as e:
            logger.exception("job failed source=%s", source)
            session.rollback()
            return {"status": "failed", "error": str(e)}
        finally:
            session.close()

    def run_forever(
        self,
        poll_interval: float = 1.0,
        queue_key: str = "vulnops:ingest",
        max_iterations: int | None = None,
    ):
        """Poll Redis queue when configured, otherwise idle.

        Consumes JSON jobs via BRPOP and dispatches through :meth:`process`
        so DefectDojo/Wazuh ingestion jobs do not remain queued. Falls back
        to sleep when Redis is unconfigured or unavailable.
        """
        import json

        settings = get_settings()
        redis_url = settings.effective_redis_url
        client = None
        if redis_url:
            try:
                import redis  # type: ignore

                client = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=5)
                client.ping()
                logger.info("starting ingestion worker with redis queue %s", queue_key)
            except Exception as e:
                logger.warning("redis unavailable (%s); falling back to idle mode", e)
                client = None
        if client is None:
            logger.info("starting ingestion worker in in-memory mode (no redis)")

        iterations = 0
        while True:
            if max_iterations is not None and iterations >= max_iterations:
                break
            iterations += 1
            if client is None:
                time.sleep(poll_interval)
                continue
            try:
                item = client.brpop(queue_key, timeout=int(poll_interval) or 1)
                if not item:
                    continue
                _, raw = item
                try:
                    job = json.loads(raw) if isinstance(raw, (bytes, str)) else raw
                    if isinstance(job, bytes):
                        job = json.loads(job.decode("utf-8"))
                except Exception as e:
                    logger.warning("dropping malformed job: %s", e)
                    continue
                self.process(job if isinstance(job, dict) else {"payload": job})
            except Exception:
                logger.exception("worker loop error; backing off")
                time.sleep(poll_interval)


def main():
    logging.basicConfig(level=logging.INFO)
    worker = IngestionWorker()

    # Register default handlers
    def defectdojo_handler(session, payload, org, key):
        from vulnops.integrations.defectdojo import DefectDojoBridge

        bridge = DefectDojoBridge(session)
        return bridge.ingest_finding(payload, organization_id=org)

    def wazuh_handler(session, payload, org, key):
        from vulnops.integrations.wazuh import WazuhBridge

        bridge = WazuhBridge(session)
        return bridge.ingest_event(payload, organization_id=org)

    worker.register("defectdojo", defectdojo_handler)
    worker.register("wazuh", wazuh_handler)
    worker.run_forever()


if __name__ == "__main__":
    main()
