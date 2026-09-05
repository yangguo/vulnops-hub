from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from vulnops.config import get_settings

Base = declarative_base()


def get_engine(echo: bool = False):
    settings = get_settings()
    url = settings.effective_database_url
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            echo=echo,
            connect_args={"check_same_thread": False},
        )
    else:
        engine = create_engine(
            url,
            echo=echo,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5},
        )
    return engine


def get_sessionmaker(engine=None):
    eng = engine or get_engine()
    return sessionmaker(bind=eng, autoflush=False, autocommit=False)


def init_db(engine=None):
    eng = engine or get_engine()
    Base.metadata.create_all(bind=eng)
    return eng
