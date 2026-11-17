"""`sigharvest doctor`: is this workspace healthy? Each check is ok, warn or fail, with one line and the fixing command.

Checks read the database and the file system only; nothing is changed (except the automatic schema upgrade that
every command does, and `clean_discovery_cache` when asked).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest.config import Workspace, load_sources
from sigharvest.models import Source, SyncLog, TestResult, TestRun, UpdateRun, utcnow

STALE_DAYS = 7  # a source not synced for longer is reported
UPDATE_STALE_HOURS = 48  # the last update is older than this: is the scheduler running?
DISK_FAIL = 2 * 1024**3  # free bytes below which a sync can fail mid-way
DISK_WARN = 10 * 1024**3
DISCOVERY_WARN = 1024**3  # the discovery cache holds verification clones that are only needed during `sigharvest discover`
VERIFY_CACHE = "_verify.json"  # discovery's result cache: kept by clean_discovery_cache (it makes reruns cheap)


@dataclass
class Check:
    """One line of the doctor report."""

    name: str
    status: str  # ok | warn | fail
    message: str
    fix: str = ""


def _gb(n: float) -> str:
    return f"{n / 1024**3:.1f} GB" if n >= 1024**3 else f"{n / 1024**2:.0f} MB"


def dir_size(path: Path) -> int:
    """Bytes used by the files under a folder (0 when it does not exist); symlinks are not followed."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                continue
    return total


def _names(items: list[str], n: int = 8) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


# ----------------------------------------------------------------------------- checks without the ORM


def schema_check(ws: Workspace) -> Check:
    """Database revision against the newest migration of this sigharvest (read before anything upgrades it)."""
    from alembic.script import ScriptDirectory

    from sigharvest.db import alembic_config

    head = ScriptDirectory.from_config(alembic_config(ws.db_path)).get_current_head()
    try:
        with sqlite3.connect(f"file:{ws.db_path}?mode=ro", uri=True, timeout=5) as conn:
            row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    except sqlite3.Error as exc:
        return Check("schema", "fail", f"cannot read the schema version: {exc}", "check data/sigharvest.db; restore a backup if it is damaged")
    current = row[0] if row else None
    if current == head:
        return Check("schema", "ok", f"at the newest migration ({head})")
    known = {r.revision for r in ScriptDirectory.from_config(alembic_config(ws.db_path)).walk_revisions()}
    if current not in known:
        return Check("schema", "fail", f"database at {current}, newer than this sigharvest (head {head})", "upgrade sigharvest (uv tool upgrade sigharvest)")
    return Check("schema", "fail", f"database is at {current}, head is {head}", "run sigharvest doctor")


def lock_check(ws: Workspace) -> Check:
    """Who holds the workspace lock, and whether SQLite itself has an active writer."""
    from sigharvest.lock import holder, lock_path

    owner = holder(lock_path(ws))
    busy = False
    try:
        conn = sqlite3.connect(ws.db_path, timeout=0.2, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")
        finally:
            conn.close()
    except sqlite3.OperationalError as exc:
        busy = "locked" in str(exc) or "busy" in str(exc)
    if owner is not None:
        return Check("lock", "ok", f"a workspace mutation is running ({owner})" + ("; the database is busy" if busy else ""))
    if busy:
        return Check("lock", "warn", "another command is writing the database (sync, test or index)", "wait for it to finish")
    return Check("lock", "ok", "no writer holds the workspace lock, database not busy")


def disk_checks(ws: Workspace) -> list[Check]:
    """Free space and the size of the database and caches."""
    free = shutil.disk_usage(ws.root).free
    sizes = {p.name: dir_size(p) for p in sorted(ws.cache.iterdir()) if p.is_dir()} if ws.cache.exists() else {}
    db = sum(p.stat().st_size for p in ws.db_path.parent.glob(ws.db_path.name + "*") if p.is_file())
    detail = f"{_gb(free)} free; database {_gb(db)}" + "".join(f", cache/{k} {_gb(v)}" for k, v in sizes.items() if v)
    out = []
    if free < DISK_FAIL:
        out.append(Check("disk", "fail", detail, "free disk space, e.g. `sigharvest doctor --clean-cache`"))
    elif free < DISK_WARN:
        out.append(Check("disk", "warn", detail, "free disk space before the next sync"))
    else:
        out.append(Check("disk", "ok", detail))
    disc = sizes.get("discovery", 0)
    if disc > DISCOVERY_WARN:
        out.append(
            Check(
                "discovery cache",
                "warn",
                f"{_gb(disc)} of verification clones, only needed while `sigharvest discover` runs",
                "sigharvest doctor --clean-cache",
            )
        )
    return out


def integrity_check(ws: Workspace) -> Check:
    """PRAGMA quick_check (reads the whole database: about a minute per GB)."""
    with sqlite3.connect(f"file:{ws.db_path}?mode=ro", uri=True, timeout=30) as conn:
        rows = [r[0] for r in conn.execute("PRAGMA quick_check").fetchall()]
    if rows == ["ok"]:
        return Check("integrity", "ok", "PRAGMA quick_check: ok")
    return Check(
        "integrity", "fail", f"PRAGMA quick_check: {'; '.join(rows[:3])}", "restore data/sigharvest.db from a backup, or rebuild with `sigharvest update`"
    )


def clean_discovery_cache(ws: Workspace) -> int:
    """Delete the verification clones in data/cache/discovery (the result cache _verify.json is kept). Returns the
    bytes freed."""
    folder = ws.cache / "discovery"
    freed = 0
    if not folder.exists():
        return 0
    for p in folder.iterdir():
        if p.name == VERIFY_CACHE:
            continue
        if p.is_dir() and not p.is_symlink():
            freed += dir_size(p)
            shutil.rmtree(p, ignore_errors=True)
        else:
            freed += p.lstat().st_size
            p.unlink(missing_ok=True)
    return freed


def discovery_clones_size(ws: Workspace) -> int:
    folder = ws.cache / "discovery"
    return dir_size(folder) - ((folder / VERIFY_CACHE).stat().st_size if (folder / VERIFY_CACHE).exists() else 0)


# ----------------------------------------------------------------------------- checks on the database


def _age(t: datetime | None, now: datetime) -> str:
    if t is None:
        return "never"
    d = now - t
    return f"{d.days} d ago" if d.days else f"{d.seconds // 3600} h ago" if d.seconds >= 3600 else f"{d.seconds // 60} min ago"


def index_check(s: Session, ws: Workspace | None = None) -> Check:
    from sigharvest.db import INDEXED_RESULTS_REVISION, INDEXED_SYNC_REVISION, RESULTS_REVISION, SYNC_REVISION, get_meta
    from sigharvest.index import INDEX_BUILT_AT

    if ws is not None:
        from sigharvest.lock import holder, lock_path

        if holder(lock_path(ws)) is not None:
            return Check("index", "warn", "update or another workspace mutation is running; published index retained", "wait for it to finish")
    from sigharvest.runs import corpus_counts

    c = corpus_counts(s)
    built = get_meta(s, INDEX_BUILT_AT)
    last_sync = s.scalar(select(func.max(SyncLog.finished_at)).where(SyncLog.status == "ok"))
    last_test = s.scalar(select(func.max(TestRun.finished_at)).where(TestRun.status == "ok"))
    if c["index_missing"] or (c["index_groups"] != c["unique_logic"]):
        return Check(
            "index",
            "fail",
            f"{c['index_groups']:,} groups for {c['unique_logic']:,} live logic ({c['index_missing']:,} missing): search and exports are out of date",
            "sigharvest index",
        )
    if built is None:
        return Check("index", "warn", f"{c['index_groups']:,} groups; build time unknown (built by an older sigharvest)", "sigharvest index")
    b = datetime.fromisoformat(built)
    sync_revision = get_meta(s, SYNC_REVISION)
    if sync_revision:
        late = ["sync"] if get_meta(s, INDEXED_SYNC_REVISION) != sync_revision else []
    else:  # recorded by an older sigharvest: only timestamps are available
        late = ["sync"] if last_sync is not None and last_sync > b else []
    revision = get_meta(s, RESULTS_REVISION)
    if revision:
        if get_meta(s, INDEXED_RESULTS_REVISION) != revision:
            late.append("test")
    elif last_test is not None and last_test > b:
        late.append("test")
    if late:
        return Check("index", "warn", f"built {b:%Y-%m-%d %H:%M} UTC, before the last {' and '.join(late)}", "sigharvest index")
    return Check("index", "ok", f"{c['index_groups']:,} groups, {c['families']:,} families, built {b:%Y-%m-%d %H:%M} UTC")


def correlation_reference_check(s: Session) -> Check:
    from sigharvest.correlation_references import status

    state = status(s)
    return Check(
        "correlation references",
        "ok" if state == "ready" else "warn",
        "exact reference projection ready" if state == "ready" else f"projection {state}; using the streamed resolver",
        "" if state == "ready" else "sigharvest index",
    )


def source_checks(ws: Workspace, s: Session, stale_days: int, now: datetime) -> list[Check]:
    from sigharvest.runs import Thresholds

    configs = load_sources(ws)
    enabled = [c.name for c in configs if c.enabled]
    disabled = [c.name for c in configs if not c.enabled]
    rows = {r.name: r for r in s.scalars(select(Source))}
    latest = select(func.max(SyncLog.id)).group_by(SyncLog.source_id)
    last = {
        name: (st, err)
        for name, st, err in s.execute(
            select(Source.name, SyncLog.status, SyncLog.error).join(SyncLog, SyncLog.source_id == Source.id).where(SyncLog.id.in_(latest))
        )
    }
    failing = sorted(n for n in enabled if last.get(n, ("", ""))[0] == "error")
    limit = now - timedelta(days=stale_days)
    never = sorted(n for n in enabled if n not in rows or rows[n].last_sync_at is None)
    stale = sorted(n for n in enabled if n in rows and (rows[n].last_sync_at or limit) < limit)
    out = [
        Check(
            "sources",
            "ok" if enabled else "fail",
            f"{len(enabled)} enabled, {len(disabled)} disabled",
            "" if enabled else "sigharvest sources enable NAME",
        )
    ]
    if failing:
        share = 100 * len(failing) / max(1, len(enabled))
        first = (last[failing[0]][1] or "").splitlines()[-1:] or [""]
        out.append(
            Check(
                "failing sources",
                "fail" if share > Thresholds().max_failed_sources else "warn",
                f"{len(failing)} failed their last sync: {_names(failing)} (e.g. {first[0][:120]})",
                "sigharvest sync -s NAME to retry; sigharvest sources disable NAME if the repository is gone",
            )
        )
    if never:
        out.append(Check("unsynced sources", "warn", f"{len(never)} enabled but never synced: {_names(never)}", "sigharvest update"))
    if stale:
        out.append(
            Check(
                "stale sources",
                "warn",
                f"{len(stale)} not synced for more than {stale_days} days: {_names(stale)}",
                "sigharvest update (is the scheduler running?)",
            )
        )
    return out


def test_check(s: Session) -> Check:
    from sigharvest.query import live_version_ids
    from sigharvest.testing import _done

    live = set(s.scalars(live_version_ids()))
    validated = set(s.scalars(select(TestResult.version_id).where(TestResult.stage == "validate").distinct()))
    no_validate = len(live - validated)
    report: dict[str, Any] = {}
    # The convert key change goes into this check's message, not onto stderr before the report.
    no_convert = len(live - _done(s, "convert", report=report, quiet=True))
    change = report.get("key_change")
    # Conversion is on demand (`update` validates only); stored conversions come from `update --convert` or
    # `test --stage convert`, so missing ones are not a problem, but stored results a converter change invalidated are.
    converted = len(live) - no_convert
    conv_text = (
        "all converted with the current toolchain" if not no_convert else f"{converted:,} with a stored up-to-date conversion (queries are converted on demand)"
    )
    if not no_validate and not change:
        return Check("tests", "ok", f"all {len(live):,} live versions validated; {conv_text}")
    msg = f"{no_validate:,} live versions without validation; {conv_text}"
    if change:
        targets = sorted({target for group in change["groups"] for target in group["targets"]})
        msg += f"; a converter change invalidated {change['results']:,} stored results ({', '.join(targets)})"
    return Check("tests", "warn", msg, "sigharvest test --stage validate" if not change else "sigharvest test")


def attack_check(ws: Workspace) -> Check:
    from sigharvest.attack import ATTACK_VERSION

    if (ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json").exists():
        return Check("ATT&CK data", "ok", f"Enterprise ATT&CK {ATTACK_VERSION} cached")
    return Check("ATT&CK data", "warn", f"ATT&CK {ATTACK_VERSION} not downloaded yet: coverage needs it", "sigharvest coverage (downloads it once)")


def update_check(s: Session, now: datetime) -> Check:
    run = s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(1)).first()
    if run is None:
        return Check("updates", "warn", "no `sigharvest update` recorded yet", "sigharvest update (schedule it: docs/getting-started.md)")
    text = f"last update {run.id}: {run.status}, {_age(run.finished_at or run.started_at, now)}"
    from sigharvest.runs import incomplete_corpus, incomplete_text

    if (partial := incomplete_corpus(s)) is not None and partial.finished_at is None and now - partial.started_at < timedelta(hours=UPDATE_STALE_HOURS):
        return Check("updates", "warn", incomplete_text(partial), "wait for the first update, or run `sigharvest update` again")
    if partial is not None:
        fix = f"sigharvest runs accept {partial.id}" if partial.status == "failed gate" else "sigharvest update"
        return Check("updates", "fail", incomplete_text(partial), fix)
    if run.status in ("failed gate", "error", "interrupted"):
        return Check("updates", "fail", text + (f" ({run.reasons[0][:140]})" if run.reasons else ""), f"sigharvest runs show {run.id}")
    if run.status == "running":
        return Check("updates", "ok" if (now - run.started_at) < timedelta(hours=UPDATE_STALE_HOURS) else "warn", text + " (still running or interrupted)")
    if now - (run.finished_at or run.started_at) > timedelta(hours=UPDATE_STALE_HOURS):
        return Check("updates", "warn", text + ": is the scheduled update running?", "docs/getting-started.md#5-keep-it-up-to-date")
    return Check("updates", "ok", text)


def run_checks(ws: Workspace, deep: bool = False, stale_days: int = STALE_DAYS) -> list[Check]:
    """Every check, in the order the report shows them."""
    from sigharvest.service import open_db

    if not ws.db_path.exists():
        return [Check("database", "fail", f"no database at {ws.db_path}", "sigharvest init, then sigharvest update")]
    checks = [schema_check(ws)]
    if checks[0].status == "fail":
        return checks
    now = utcnow()
    with open_db(ws)() as s:
        checks.append(update_check(s, now))
        checks.append(index_check(s, ws))
        checks.append(correlation_reference_check(s))
        checks += source_checks(ws, s, stale_days, now)
        checks.append(test_check(s))
    checks.append(attack_check(ws))
    checks.append(lock_check(ws))
    checks += disk_checks(ws)
    checks.append(integrity_check(ws) if deep else Check("integrity", "ok", "not checked (use --deep: PRAGMA quick_check)"))
    return _clean(checks)  # messages quote source names and git errors


def _clean(checks: list[Check]) -> list[Check]:
    from sigharvest.runs import clean_text

    return [Check(c.name, c.status, clean_text(c.message), clean_text(c.fix)) for c in checks]


def as_json(checks: list[Check]) -> dict[str, Any]:
    worst = "fail" if any(c.status == "fail" for c in checks) else "warn" if any(c.status == "warn" for c in checks) else "ok"
    return {"status": worst, "checks": [asdict(c) for c in checks]}
