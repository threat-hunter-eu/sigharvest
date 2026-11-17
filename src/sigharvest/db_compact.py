"""Bound test projection history without deleting current results or evidence history.

The unique result key already prevents superseded rows in test_results. Historical
snapshots are disposable only after their run ends; unfinished runs remain pinned.
Maintenance opens existing SQLite files directly so dry runs never migrate them.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from sigharvest.errors import SigharvestError
from sigharvest.lock import database_lease

DEFAULT_HISTORY = 5
VACUUM_MARGIN = 64 * 1024 * 1024


def history_limit(value: int | None = None) -> int:
    """Use an explicit override or SIGHARVEST_TEST_HISTORY (default five prior states)."""
    try:
        result = int(os.environ.get("SIGHARVEST_TEST_HISTORY", str(DEFAULT_HISTORY))) if value is None else value
    except ValueError as exc:
        raise SigharvestError("SIGHARVEST_TEST_HISTORY must be a nonnegative integer") from exc
    if result < 0:
        raise SigharvestError("test history limit must be a nonnegative integer")
    return result


def prune_test_history(conn: sqlite3.Connection, limit: int, *, dry_run: bool = False) -> dict[str, int]:
    """Plan/delete superseded snapshots in the caller's transaction, using compact temp rows.

    Compare each historical status with its immediate successor (including current).
    Conversion implementation changes also retain the previous diagnostic snapshot.
    Keep the newest snapshot of each previous status run, then the newest N changes.
    Missing run records and running runs fail closed. Current rows are never deleted.
    """
    history_limit(limit)
    conn.execute("DROP TABLE IF EXISTS temp.sigharvest_history_drop")
    conn.execute("""CREATE TEMP TABLE sigharvest_history_drop (id INTEGER PRIMARY KEY)""")
    try:
        conn.execute(
            """INSERT INTO sigharvest_history_drop
            WITH statuses AS (
                SELECT h.id, h.result_id, json_extract(h.snapshot, '$.status') AS status,
                       json_extract(h.snapshot, '$.run_id') AS run_id,
                       r.stage, h.fingerprint,
                       lead(h.fingerprint, 1, r.fingerprint)
                           OVER (PARTITION BY h.result_id ORDER BY h.id) AS newer_fingerprint,
                       lead(json_extract(h.snapshot, '$.status'), 1, r.status)
                           OVER (PARTITION BY h.result_id ORDER BY h.id) AS newer
                FROM test_result_history h JOIN test_results r ON r.id = h.result_id
            ), changes AS (
                SELECT id, row_number() OVER (PARTITION BY result_id ORDER BY id DESC) AS rank
                FROM statuses WHERE status IS NOT newer
                    OR (stage = 'convert' AND fingerprint IS NOT newer_fingerprint)
            )
            SELECT s.id FROM statuses s LEFT JOIN changes c ON c.id=s.id
            WHERE (c.id IS NULL OR c.rank > ?)
              AND (s.run_id IS NULL OR EXISTS (
                  SELECT 1 FROM test_runs run WHERE run.id=s.run_id
                  AND (run.finished_at IS NOT NULL OR run.status IN ('ok','error','failed','interrupted'))
              ))""",
            (limit,),
        )
        removed = conn.execute("SELECT count(*) FROM sigharvest_history_drop").fetchone()[0]
        if not dry_run:
            conn.execute("DELETE FROM test_result_history WHERE id IN (SELECT id FROM sigharvest_history_drop)")
        return {"history_rows": removed, "superseded_result_rows": 0}
    finally:
        conn.execute("DROP TABLE temp.sigharvest_history_drop")


def backup_candidates(db_path: Path, keep: int = 1) -> list[Path]:
    """Only completed backups owned by this database; ignore symlinks and foreign files."""
    if keep < 1:
        raise SigharvestError("keep must be at least one migration backup")
    folder = db_path.parent / "migration-backups"
    if folder.is_symlink():
        return []
    pattern = re.compile(re.escape(db_path.name) + r"\.[0-9a-f]{32}\.sqlite3")
    files = [p for p in folder.iterdir() if pattern.fullmatch(p.name) and not p.is_symlink() and p.is_file()] if folder.is_dir() else []
    return sorted(files, key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)[keep:]


def prune_backups(db_path: Path, keep: int = 1) -> int:
    """Remove old completed migration backups after a replacement has been published."""
    paths = backup_candidates(db_path, keep)
    for path in paths:
        path.unlink()
    return len(paths)


def storage_stats(conn: sqlite3.Connection, db_path: Path) -> dict[str, Any]:
    """Allocated table/index bytes, reusable free pages and on-disk main/WAL sizes."""
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    tables: dict[str, int] = {}
    try:
        for name, size in conn.execute("""SELECT coalesce(m.tbl_name, d.name), sum(d.pgsize)
            FROM dbstat d LEFT JOIN sqlite_schema m ON m.name=d.name
            GROUP BY coalesce(m.tbl_name, d.name) ORDER BY sum(d.pgsize) DESC"""):
            tables[name] = size
    except sqlite3.OperationalError as exc:
        raise SigharvestError("SQLite dbstat support is required for per-table space reporting") from exc
    wal = db_path.with_name(db_path.name + "-wal")
    return {
        "database_bytes": db_path.stat().st_size,
        "wal_bytes": wal.stat().st_size if wal.exists() else 0,
        "allocated_bytes": conn.execute("PRAGMA page_count").fetchone()[0] * page_size,
        "reusable_bytes": conn.execute("PRAGMA freelist_count").fetchone()[0] * page_size,
        "tables_bytes": tables,
        "result_rows": conn.execute("SELECT count(*) FROM test_results").fetchone()[0],
        "history_rows": conn.execute("SELECT count(*) FROM test_result_history").fetchone()[0],
    }


def vacuum_required(conn: sqlite3.Connection) -> int:
    """Conservative admission: two entire database files plus a fixed reserve."""
    return int(conn.execute("PRAGMA page_count").fetchone()[0] * conn.execute("PRAGMA page_size").fetchone()[0] * 2 + VACUUM_MARGIN)


def compact(db_path: Path, *, dry_run: bool = False, history: int | None = None, keep: int = 1, vacuum: bool = False) -> dict[str, Any]:
    """Compact only disposable test history and migration backups, under the writer lease."""
    limit = history_limit(history)
    backups = backup_candidates(db_path, keep)
    if not db_path.is_file():
        raise SigharvestError("workspace database does not exist")
    if dry_run:
        # No schema upgrade, write lease, checkpoint, backup deletion or VACUUM.
        with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
            conn.execute("BEGIN")
            before = storage_stats(conn, db_path)
            plan = prune_test_history(conn, limit, dry_run=True)
            required = vacuum_required(conn) if vacuum else 0
            conn.rollback()
        return {
            "dry_run": True,
            "history_limit": limit,
            "before": before,
            "after": before,
            "prune": plan,
            "backup_files": len(backups),
            "backup_bytes": sum(p.stat().st_size for p in backups),
            "vacuum_required_bytes": required,
        }
    with database_lease(db_path) as lease:
        lease.assert_owned()
        backups = backup_candidates(db_path, keep)
        with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=30)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("BEGIN IMMEDIATE")
            before = storage_stats(conn, db_path)
            required = vacuum_required(conn) if vacuum else 0
            # Check before deletion: a refused vacuum does not partially apply the request.
            if vacuum and shutil.disk_usage(db_path.parent).free < required:
                raise SigharvestError(f"VACUUM needs at least {required} free bytes; compact without --vacuum first")
            try:
                plan = prune_test_history(conn, limit)
                lease.assert_owned()
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            lease.assert_owned()
            backup_bytes = sum(p.stat().st_size for p in backups)
            pruned_backups = prune_backups(db_path, keep)
            checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if vacuum:
                lease.assert_owned()
                conn.execute("VACUUM")
                checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            after = storage_stats(conn, db_path)
        return {
            "dry_run": False,
            "history_limit": limit,
            "before": before,
            "after": after,
            "prune": plan,
            "backup_files": pruned_backups,
            "backup_bytes": backup_bytes,
            "vacuum": vacuum,
            "checkpoint_busy": bool(checkpoint[0]),
        }
