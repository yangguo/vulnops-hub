"""Periodic refresh for pull-based intelligence sources (KEV catalog)."""

from __future__ import annotations

import logging
import time

from vulnops.config import get_settings
from vulnops.intelligence.kev import KEVAdapter
from vulnops.intelligence.persistence import refresh_kev_catalog

logger = logging.getLogger("vulnops.workers.intel_refresh")


class IntelRefreshWorker:
    """Refresh intel catalogs and persist normalized rows + source health."""

    def __init__(self, session_factory, kev: KEVAdapter | None = None, settings=None):
        self.session_factory = session_factory
        self.kev = kev or KEVAdapter()
        self.settings = settings or get_settings()

    def refresh_kev(self) -> int:
        session = self.session_factory()
        try:
            count = refresh_kev_catalog(session, self.kev)
            session.commit()
            return count
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def cycle(self) -> dict[str, int]:
        stats: dict[str, int] = {}
        try:
            stats["kev"] = self.refresh_kev()
        except Exception as exc:
            logger.warning("KEV catalog refresh failed: %s", exc)
            stats["kev"] = 0
        return stats

    def run_forever(self, max_iterations: int | None = None) -> None:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            try:
                stats = self.cycle()
                if stats.get("kev"):
                    logger.info("intel refresh applied %s KEV record(s)", stats["kev"])
            except Exception:
                logger.exception("intel refresh loop error; backing off")
            time.sleep(self.settings.kev_refresh_interval_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    from vulnops.db import get_engine, get_sessionmaker

    worker = IntelRefreshWorker(session_factory=lambda: get_sessionmaker(get_engine())())
    worker.run_forever()


if __name__ == "__main__":
    main()
