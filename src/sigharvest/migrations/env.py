"""Alembic environment for sigharvest (SQLite, batch mode for ALTER TABLE support)."""

from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

from sigharvest.models import Base

config = context.config
target_metadata = Base.metadata


def include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
    """FTS5 tables (rules_fts and its shadow tables) are managed by hand in migrations."""
    return not (type_ == "table" and name is not None and name.startswith("rules_fts"))


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        render_as_batch=True,
        literal_binds=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.begin() as connection:
        # sqlite3's legacy transaction mode does not BEGIN for DDL. Without an
        # explicit transaction every CREATE/ALTER can fsync separately and a
        # failed upgrade can leave tables ahead of alembic_version.
        connection.exec_driver_sql("BEGIN")
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True, include_object=include_object, transactional_ddl=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
