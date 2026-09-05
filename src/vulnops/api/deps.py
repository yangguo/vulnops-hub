from __future__ import annotations

from typing import Generator

from sqlalchemy.orm import Session

from vulnops.db import get_engine, get_sessionmaker
from vulnops.config import get_settings


_engine = None
_SessionLocal = None


def get_db() -> Generator[Session, None, None]:
    global _engine, _SessionLocal
    if _engine is None:
        _engine = get_engine()
        _SessionLocal = get_sessionmaker(_engine)
        # Ensure tables exist for sqlite dev (alembic handles prod)
        from vulnops.db import Base
        import vulnops.db.models.source_snapshot  # noqa
        import vulnops.db.models.audit_event  # noqa
        import vulnops.db.models.outbox_event  # noqa
        import vulnops.assets.models  # noqa
        import vulnops.sbom.models  # noqa
        # Create all if not exists (idempotent)
        try:
            Base.metadata.create_all(bind=_engine)
        except Exception:
            pass

    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
