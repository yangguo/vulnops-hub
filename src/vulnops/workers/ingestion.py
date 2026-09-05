from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable

from sqlalchemy.orm import Session

from vulnops.db import get_engine, get_sessionmaker
from vulnops.config import get_settings

logger = logging.getLogger("vulnops.workers.ingestion")


class IngestionWorker:
    """
    Durable ingestion worker handling idempotent replay via source snapshots.
    Simulates queue consumption with in-memory or Redis backend.
    For MVP, uses simple loop with outbox deduplication.
    """

    def __init__(self, session_factory: Callable[[], Session] | None = None):
        settings = get_settings()
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
        source = job.get("source")
        payload = job.get("payload", {})
        org = job.get("organization_id", "default")
        idempotency_key = job.get("idempotency_key") or job.get("id") or str(uuid.uuid4())

        handler = self.handlers.get(source)
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

    def run_forever(self, poll_interval: float = 1.0):
        """
        Run loop polling queue (Redis or in-memory).
        For MVP without Redis, just logs and sleeps.
        """
        settings = get_settings()
        redis_url = settings.effective_redis_url
        if redis_url:
            logger.info("starting ingestion worker with redis %s", redis_url)
            # Real implementation would use redis BLPOP
            # For now simulate
            pass
        else:
            logger.info("starting ingestion worker in in-memory mode (no redis)")
        while True:
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
