"""The single baseline migration: transactional DDL, and a schema identical to the models."""

import sqlite3
from contextlib import closing

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, create_engine, event

from sigharvest.db import alembic_config
from sigharvest.models import Base
from sigharvest.schema import head_revision


def snapshot(path):
    with closing(sqlite3.connect(path)) as db:
        return db.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall()


def test_failed_ddl_leaves_no_partial_schema(tmp_path):
    path = tmp_path / "migration.db"
    cfg = alembic_config(path)
    before = snapshot(path)
    executed = []

    def fail_after_ddl(conn, cursor, statement, parameters, context, executemany):
        if "CREATE TABLE collections" in statement:
            executed.append(statement)
            raise RuntimeError("injected failure after DDL")

    event.listen(Engine, "after_cursor_execute", fail_after_ddl)
    try:
        with pytest.raises(RuntimeError, match="injected failure after DDL"):
            command.upgrade(cfg, "head")
    finally:
        event.remove(Engine, "after_cursor_execute", fail_after_ddl)
    assert executed
    assert snapshot(path) == before
    command.upgrade(cfg, "head")
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchone() == (head_revision(),)
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_baseline_matches_the_models(tmp_path):
    path = tmp_path / "schema.db"
    command.upgrade(alembic_config(path), "head")
    assert head_revision() == "0001"
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"include_object": lambda obj, name, type_, reflected, compare_to: not (type_ == "table" and str(name).startswith("rules_fts"))},
            )
            diffs = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()
    # SQLite reflection cannot read expression indexes; check those by name below.
    expression = {"ix_groups_search_rank", "ix_telemetry_conversion_current"}
    assert [d for d in diffs if not (d[0] in ("add_index", "remove_index") and d[1].name in expression)] == []
    with closing(sqlite3.connect(path)) as db:
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master")}
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "rules_fts" in names and expression <= names
    assert {t for t in tables if not t.startswith(("rules_fts", "sqlite_"))} == set(Base.metadata.tables) | {"alembic_version"}


def test_baseline_cannot_be_downgraded(tmp_path):
    path = tmp_path / "migration.db"
    cfg = alembic_config(path)
    command.upgrade(cfg, "head")
    before = snapshot(path)
    with pytest.raises(NotImplementedError):
        command.downgrade(cfg, "base")
    assert snapshot(path) == before
