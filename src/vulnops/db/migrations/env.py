from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy import engine_from_config
from alembic import context
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
# fallback: also add src
sys.path.insert(0, "src")

from vulnops.db import Base
from vulnops.config import get_settings

# Ensure models are imported
import vulnops.db.models.source_snapshot
import vulnops.db.models.audit_event
import vulnops.db.models.outbox_event
import vulnops.assets.models  # noqa: F401
import vulnops.sbom.models  # noqa: F401
import vulnops.intelligence.models  # noqa: F401
import vulnops.matching.models  # noqa: F401
import vulnops.cases.models  # noqa: F401
# future models will be imported here

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def get_url():
    settings = get_settings()
    return settings.effective_database_url

def run_migrations_offline() -> None:
    url = get_url()
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
