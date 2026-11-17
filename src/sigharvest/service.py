"""Workspace operations used by the CLI: open the database, sync sources.

`sync_all` fetches sources in parallel threads (network and disk only) and ingests them one at a time, because
SQLite has a single writer. A failing source is logged in sync_log and never stops the others."""

from __future__ import annotations

import logging
import os
import shutil
import sys
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, replace

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sigharvest import space
from sigharvest.config import SourceConfig, Workspace, load_sources
from sigharvest.db import get_meta, mark_sync_changed, session_factory, set_meta
from sigharvest.errors import SigharvestError
from sigharvest.ingest import Ingestor
from sigharvest.models import Occurrence, Source, SyncLog, utcnow
from sigharvest.snapshot_reads import manifest_hashes, verified_snapshot
from sigharvest.source_selection import path_selected
from sigharvest.source_snapshots import ACTIVE_PREFIX, CONFIG_PREFIX, attach, capture, config_fingerprint, policy_current
from sigharvest.source_snapshots import rescan as rescan_snapshot
from sigharvest.sync import SyncError, SyncResult, _diff_trees, selected_files, sync_git, sync_http, sync_local

# Update enables INFO on this namespace even when the CLI's root level is WARNING.
log = logging.getLogger("sigharvest.update.sync")

PROGRESS_EVERY_FILES = 500  # Flush/report progress without exposing a partially ingested source.
MAX_ERROR_CHARS = 2000  # of the error stored on a failed sync_log entry
FETCH_SWITCH_INTERVAL = 0.0005  # seconds; see fetch_pool


class NoWorkspace(SigharvestError, RuntimeError):
    """Raised instead of silently creating a database in a folder that is not a sigharvest workspace."""


def open_db(ws: Workspace, *, migrate: bool = False, migration_timeout: float = 30.0, readonly: bool = False) -> sessionmaker[Session]:
    """Open the workspace without migration unless an explicit schema operation opts in."""
    if not ws.db_path.exists() and not ws.sources_file.exists():
        raise NoWorkspace(
            f"not a sigharvest workspace: {ws.root} has no sources.yaml or data/sigharvest.db; cd into your workspace, "
            "set SIGHARVEST_HOME to it, or create one with `sigharvest init DIR`."
        )
    return session_factory(ws.db_path, migrate=migrate, migration_timeout=migration_timeout, readonly=readonly)


def upsert_source_rows(s: Session, configs: list[SourceConfig]) -> dict[str, Source]:
    """Copy sources.yaml into the `sources` table (new rows for new names); returns the rows by name."""
    rows = {r.name: r for r in s.scalars(select(Source))}
    for c in configs:
        row = rows.get(c.name)
        if row is None:
            row = Source(name=c.name, type=c.type, url=c.url)
            s.add(row)
            rows[c.name] = row
        row.type, row.url, row.ref, row.licence, row.priority, row.enabled = c.type, c.url, c.ref, c.licence, c.priority, c.enabled
    s.flush()
    return rows


@dataclass
class SourceSyncOutcome:
    """What happened to one source in `sync_all`: status "ok" or "error", the sync log entry and a summary."""

    name: str
    status: str
    log: SyncLog
    message: str = ""
    # Plain copy of the log's file counts, read while its session is open: a later source's rollback expires
    # every loaded row, so the SyncLog must not be read after sync_all returns.
    touched: bool = False


class _Deferred(Exception):
    """A fetch not started before the sync deadline (sync_all `deadline`)."""


def _local_previous(s: Session, source: Source) -> dict[str, str]:
    """File hashes from the last ingest, for local diffs and remote ingest recovery."""
    rows = s.execute(select(Occurrence.path, Occurrence.file_hash).where(Occurrence.source_id == source.id, Occurrence.present.is_(True)))
    return {p: h for p, h in rows}


def fetch_source(ws: Workspace, cfg: SourceConfig, last_commit: str | None, local_prev: dict[str, str], remote_check: bool = False) -> SyncResult:
    """Fetch and freeze a complete eligible inventory (thread-safe: no database access)."""
    # Retain unselected eligible content too, so globs can widen during an offline
    # rescan. Selection only affects membership, never the retained inventory.
    acquisition = replace(cfg, paths=["**/*"], exclude=[])
    if cfg.type == "git":
        try:
            cached = verified_snapshot(ws, cfg)
        except (OSError, SyncError):
            cached = None
        result = sync_git(acquisition, ws, last_commit, remote_check=remote_check, cached_files=cached.hashes if cached else {})
        if remote_check and not result.full_scan and result.new_commit == last_commit:
            return result  # DB-only restores need neither a clone nor a snapshot.
        if (
            cached
            and not result.full_scan
            and not (result.added | result.changed | result.removed)
            and cached.manifest["revision"] == result.new_commit
            and policy_current(cfg, cached.manifest["config"])
        ):
            return attach(result, cached, cfg)
    elif cfg.type in ("http-files", "html", "huggingface"):
        from sigharvest.sync_remote import sync_remote

        result = sync_remote(acquisition, ws, last_commit, local_prev)
    else:
        result = sync_http(acquisition, ws) if cfg.type == "http" else sync_local(acquisition, ws, local_prev)
    if last_commit is None:
        result.full_scan = True
    return attach(result, capture(ws, cfg, result), cfg)


def ingest_result(s: Session, source: Source, entry: SyncLog, cfg: SourceConfig, result: SyncResult, progress: Callable[[str], None] | None = None) -> str:
    """Database part of a sync: ingest the added/changed files, mark removed ones, fill the sync log entry.
    Returns a one-line summary for the CLI."""
    files = selected_files(result, cfg)
    ing = Ingestor(s, source, result.new_commit, batch=True)
    ing.expected_hashes = result.file_hashes
    for i, rel in enumerate(files, 1):
        ing.ingest_file(result.root, rel)
        if i % PROGRESS_EVERY_FILES == 0:
            ing.flush()
            s.flush()
            if progress:
                progress(f"{cfg.name}: {i}/{len(files)} files")
    ing.flush()
    for rel in sorted(result.removed):
        ing.remove(rel)
    # One shared reconciliation covers Git recovery and every non-git full snapshot.
    # Run only after ingestion succeeds; incremental/remote-check skips have no inventory.
    reconciled = ing.reconcile_paths(set(files)) if result.full_scan else set()
    entry.new_commit = result.new_commit
    entry.files_added, entry.files_changed, entry.files_removed = len(result.added), len(result.changed), len(result.removed)
    if result.full_scan:
        entry.files_added = len(files)
        entry.files_removed = len(result.removed | reconciled)
    st = ing.stats
    entry.rules_new, entry.versions_new, entry.quarantined = st.rules_new, st.versions_new, st.quarantined
    entry.status = "ok"
    mark_sync_changed(s)
    source.last_commit = result.new_commit
    source.last_sync_at = utcnow()
    source.type, source.url, source.ref = cfg.type, cfg.url, cfg.ref
    source.licence, source.priority, source.enabled = cfg.licence, cfg.priority, cfg.enabled
    set_meta(s, f"{CONFIG_PREFIX}{cfg.name}", config_fingerprint(cfg))
    if result.snapshot_id:
        set_meta(s, f"{ACTIVE_PREFIX}{cfg.name}", result.snapshot_id)
    return (
        f"{st.files_sigma} sigma files, {st.documents} docs, +{st.versions_new} versions, +{st.rules_new} rule ids, {st.quarantined} quarantined; "
        f"skipped: {result.skipped_non_sigma} non-Sigma YAML, {result.skipped_large} large files"
        + (f", {result.skipped_unsafe_path} unsafe paths" if result.skipped_unsafe_path else "")
    )


def _finish(s: Session, entry: SyncLog, exc: BaseException | None) -> str:
    """Close a sync log entry (as failed when `exc` is given); returns the stored error, or ""."""
    if exc is not None:
        s.rollback()
        entry = s.merge(entry)
        entry.status, entry.error = "error", f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]
    entry.finished_at = utcnow()
    s.commit()
    return entry.error or ""


@contextmanager
def fetch_pool(workers: int) -> Iterator[ThreadPoolExecutor]:
    """Interrupted updates write their outcome before waiting for active fetches."""
    from sigharvest.update_publication import defer_shutdown

    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    deferred = False
    # The single writer releases the GIL around every SQLite call; while fetch threads
    # run Python-heavy snapshot work, each reacquisition waited a full switch interval
    # (5 ms by default). A source re-ingested during the fetch phase was 5-8x slower
    # than the same ingest alone (nrgline4sec__sagan2sigma: 230 s instead of 30 s).
    interval = sys.getswitchinterval()
    sys.setswitchinterval(min(interval, FETCH_SWITCH_INTERVAL))
    try:
        yield pool
    except BaseException:
        deferred = defer_shutdown(pool)
        raise
    finally:
        try:
            if not deferred:
                pool.shutdown(wait=True, cancel_futures=True)
        finally:
            sys.setswitchinterval(interval)


def sync_all(
    ws: Workspace,
    names: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
    workers: int = 8,
    remote_check: bool = False,
    rescan: bool = False,
    deadline: float | None = None,
    deferred: list[str] | None = None,
) -> list[SourceSyncOutcome]:
    """Fetch sources in parallel threads; ingest them one at a time (SQLite has a single writer).

    deadline (a time.monotonic() value): a source not fetched, or fetched but not ingested, by then is skipped and its
    name appended to `deferred` (no outcome, no sync log: the source keeps its last ingested commit). With a deadline, sources never
    synced go first, then the least recently synced, so a run cut short by its time budget is continued by the next.
    Each fetch is admitted on disk when it starts (space.FetchBudget); with a `deferred` list a refused fetch is deferred
    like one past the deadline, otherwise the source fails with the SpaceError. SIGHARVEST_GIT_CACHE=drop deletes a git
    source's bare clone once it is ingested (the next fetch clones again; --remote-check skips unchanged sources)."""
    from sigharvest.job_control import SyncProgress, source_progress
    from sigharvest.lock import mutation_lease

    if rescan and remote_check:
        raise SigharvestError("--rescan and --remote-check cannot be combined")
    with mutation_lease(ws):
        all_configs = load_sources(ws)
        configs = [c for c in all_configs if c.enabled and (not names or c.name in names)]
        if names:
            missing = set(names) - {c.name for c in configs}
            if missing:
                from difflib import get_close_matches

                known = [c.name for c in all_configs]
                disabled = sorted(n for n in missing if n in known)
                parts = []
                for name in sorted(missing - set(disabled)):
                    close = get_close_matches(name, known, n=3)
                    parts.append(f"unknown source {name!r}" + (f" (did you mean {', '.join(close)}?)" if close else ""))
                parts += [f"source {name!r} is disabled in its sources file" for name in disabled]
                raise SigharvestError("; ".join(parts) + ". List sources with `sigharvest sources list`.")
        space.before_sync(ws, configs, workers)
        budget = space.FetchBudget(ws)
        drop_git = os.environ.get("SIGHARVEST_GIT_CACHE", "keep") == "drop"
        no_space: list[str] = []
        Session_ = open_db(ws)
        outcomes: list[SourceSyncOutcome] = []
        with Session_() as s:
            # Existing accepted provenance changes only with successful ingest.
            rows = {r.name: r for r in s.scalars(select(Source))}
            configured = {cfg.name: cfg for cfg in all_configs}
            for row in rows.values():
                cfg = configured.get(row.name)
                if cfg is None or not cfg.enabled:
                    Ingestor(s, row, row.last_commit).reconcile_paths(set())
                    row.enabled = False
                    # Re-enabling must ingest even when upstream HEAD did not move.
                    set_meta(s, f"{CONFIG_PREFIX}{row.name}", "")
            for cfg in all_configs:
                if cfg.name not in rows:
                    rows.update(upsert_source_rows(s, [cfg]))
                rows[cfg.name].enabled = cfg.enabled
            s.commit()
            jobs = {}
            fetch_seconds: dict[str, float] = {}

            def fetch(cfg: SourceConfig, last_commit: str | None, prev: dict[str, str]) -> SyncResult:
                started = time.monotonic()
                if deadline is not None and started >= deadline:
                    raise _Deferred(cfg.name)
                try:
                    budget.acquire(cfg)
                except space.SpaceError as exc:
                    fetch_seconds[cfg.name] = 0.0
                    if deferred is None:
                        raise
                    log.warning("%s: deferred, %s", cfg.name, exc)
                    no_space.append(cfg.name)
                    raise _Deferred(cfg.name) from exc
                try:
                    return rescan_snapshot(ws, cfg, last_commit) if rescan else fetch_source(ws, cfg, last_commit, prev, remote_check)
                finally:
                    budget.release(cfg.name)
                    fetch_seconds[cfg.name] = time.monotonic() - started

            if deadline is not None:

                def order(cfg: SourceConfig) -> tuple[bool, str]:
                    last = rows[cfg.name].last_sync_at
                    return (last is not None, last.isoformat() if last else "")

                configs = sorted(configs, key=order)
            with fetch_pool(workers) as pool:
                for cfg in configs:
                    src = rows[cfg.name]
                    prev = _local_previous(s, src) if cfg.type in ("local", "http-files", "html", "huggingface") else {}
                    last_commit = src.last_commit
                    if not policy_current(cfg, get_meta(s, f"{CONFIG_PREFIX}{cfg.name}")):
                        last_commit = None
                    jobs[pool.submit(fetch, cfg, src.last_commit if rescan else last_commit, prev)] = cfg
                for n, fut in enumerate(as_completed(jobs), 1):
                    ingest_started = time.monotonic()
                    cfg = jobs[fut]
                    # Past the deadline nothing more is ingested either (fetches run ahead of the one-at-a-time
                    # ingest): a fetched source is left in the cache and ingested by the next run.
                    if isinstance(fut.exception(), _Deferred) or (deadline is not None and time.monotonic() >= deadline):
                        if deferred is not None:
                            deferred.append(cfg.name)
                        continue
                    source = rows[cfg.name]
                    entry = SyncLog(source_id=source.id, old_commit=source.last_commit)
                    s.add(entry)
                    s.commit()
                    msg = ""
                    try:
                        result = fut.result()
                        # Adapter caches can be ahead of SQLite after a failed or
                        # interrupted ingest. Diff against accepted bytes instead.
                        active = get_meta(s, f"{ACTIVE_PREFIX}{cfg.name}")
                        policy = get_meta(s, f"{CONFIG_PREFIX}{cfg.name}")
                        rebaselined = False
                        if not active and not rescan and (policy is None or policy_current(cfg, policy)):
                            from sigharvest.source_rebaseline import rebaseline

                            rebaselined = rebaseline(s, source, cfg, result)
                        if result.snapshot_id and not result.full_scan and not rebaselined:
                            before: dict[str, str] | None
                            try:
                                # The fetch thread verified the current generation; for an
                                # older one the diff needs only its checksummed manifest.
                                # Damage to the active generation after that check is not
                                # re-detected here; rescan (load_snapshot) and the next
                                # fetch's cache verification catch it before reuse.
                                if active and active == result.snapshot_id and result.file_hashes is not None:
                                    before = dict(result.file_hashes)
                                else:
                                    before = manifest_hashes(ws, cfg, active) if active else None
                            except (OSError, SyncError):
                                before = None
                            if before is None:
                                result.full_scan = True
                            else:
                                _diff_trees(
                                    {p: h for p, h in before.items() if path_selected(p, cfg)},
                                    {p: h for p, h in (result.file_hashes or {}).items() if path_selected(p, cfg)},
                                    result,
                                )
                        source_progress(SyncProgress(n - 1, len(configs), cfg.name, status="ingesting"))
                        msg = ingest_result(s, source, entry, cfg, result, progress)
                        _finish(s, entry, None)
                        if drop_git and cfg.type == "git":
                            # The database and the retained snapshot hold what was ingested; the clone is refetched.
                            shutil.rmtree(ws.git_repo(cfg.name), ignore_errors=True)
                    except Exception as exc:
                        if space.is_full(exc):
                            s.rollback()
                            for job in jobs:
                                job.cancel()
                            raise space.SpaceError("storage exhausted during sync; free space and rerun sync; accepted sources are retained") from exc
                        msg = _finish(s, entry, exc)
                        entry = s.get(SyncLog, entry.id) or entry
                        source = s.get(Source, source.id) or source
                        rows[cfg.name] = source
                    from sigharvest.job_control import progress as job_progress

                    job_progress("sync", n, len(configs))
                    detail = SyncProgress(
                        n,
                        len(configs),
                        cfg.name,
                        entry.files_added or 0,
                        entry.files_changed or 0,
                        entry.files_removed or 0,
                        fetch_seconds[cfg.name] + time.monotonic() - ingest_started,
                        entry.status,
                    )
                    log.info("%s", detail.text)
                    source_progress(detail)
                    outcomes.append(
                        SourceSyncOutcome(cfg.name, entry.status, entry, msg, bool(entry.files_added or entry.files_changed or entry.files_removed))
                    )
                    if progress:
                        progress(detail.text)
        if no_space and progress:
            progress(
                f"disk admission: {len(no_space)} sources deferred to the next run (not enough free space; free space or adjust SIGHARVEST_DISK_* estimates)"
            )
        return outcomes
