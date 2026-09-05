from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from vulnops.db import get_engine, get_sessionmaker

_engine = None
_SessionLocal = None


def get_db() -> Generator[Session, None, None]:
    global _engine, _SessionLocal
    if _engine is None:
        _engine = get_engine()
        _SessionLocal = get_sessionmaker(_engine)
        # Ensure tables exist for sqlite dev (alembic handles prod)
        import vulnops.assets.models
        import vulnops.db.models.audit_event
        import vulnops.db.models.outbox_event
        import vulnops.db.models.source_snapshot
        import vulnops.sbom.models  # noqa
        from vulnops.db import Base

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
