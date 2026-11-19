"""Building the corpus: `init`, `sync`, `test`, `index`, `update` (all of them in order, then gates and a run report)
and `stats`."""

from __future__ import annotations

import logging
import os
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.markup import escape
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest.cli.choices import STAGES, ConvertScope, Preset
from sigharvest.cli.common import DEFAULT_WORKERS, console, mutation_command, open_session
from sigharvest.cli.common import error as show_error
from sigharvest.config import PRESETS, Workspace, find_workspace, load_sources, save_sources
from sigharvest.job_control import Cancelled, cancellation, cancellation_requested, terminal_publication
from sigharvest.job_control import progress as job_progress
from sigharvest.models import Occurrence, Quarantine, RuleVersion
from sigharvest.observability import CONTEXT, count, metrics
from sigharvest.runs import clean_text
from sigharvest.service import SourceSyncOutcome, open_db, sync_all

if TYPE_CHECKING:
    from sigharvest.runs import Gate, Thresholds

log = logging.getLogger("sigharvest.update")


@mutation_command(workspace_arg="path")
def init(
    path: Path = typer.Argument(None, help="Workspace folder (default: SIGHARVEST_HOME or the current folder)."),
    preset: Preset = typer.Option(
        "curated",
        help="curated (about 25 well-maintained repos, minutes), sigmahq (SigmaHQ only), all (curated + about 1,180 more public "
        "repos: hours and many GB; --from-release latest gets the same corpus in minutes).",
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing sources.yaml."),
    from_release: str | None = typer.Option(
        None,
        "--from-release",
        help="Start from a published release pack instead of cloning: 'latest', a release download URL or a local "
        "release folder. Takes a few minutes (the nightly pack holds every redistributable rule of the full public corpus); "
        "no git needed.",
    ),
    sums_sha256: str | None = typer.Option(
        None,
        "--sums-sha256",
        help="With --from-release: the SHA-256 of the pack's SHA256SUMS, obtained separately (release notes, a signed "
        "message). Without it the checksums prove the files are intact, not who published them.",
    ),
) -> None:
    """Create a workspace with a curated list of rule sources, then run `sigharvest update`.

    With --from-release the workspace is filled from a nightly release pack (its redistributable rules, one local
    source per original source) and indexed at once: search, export and serve work right away."""
    import os

    from sigharvest.config import Workspace, preset_sources

    if preset not in PRESETS:
        raise typer.BadParameter(f"preset must be one of {', '.join(PRESETS)}")
    root = (path or Path(os.environ.get("SIGHARVEST_HOME") or ".")).resolve()
    ws = Workspace(root)
    if ws.sources_file.exists() and not force:
        console.print(f"[yellow]{escape(str(ws.sources_file))} already exists[/] (use --force to replace it)")
        raise typer.Exit(1)
    root.mkdir(parents=True, exist_ok=True)
    if from_release is not None:
        _init_from_release(ws, from_release, sums_sha256)  # on failure mutation_command removes a folder it created
        return
    if sums_sha256:
        raise typer.BadParameter("--sums-sha256 goes with --from-release")
    sources = preset_sources(preset)
    save_sources(ws, sources)
    open_db(ws, migrate=True)  # explicit workspace initialization under its lease
    console.print(f"workspace {escape(str(root))}: {len(sources)} sources (preset {preset})")
    here = Path.cwd().resolve()
    hint = "" if root == here else f"{escape(cd_command(root))} && "
    # soft_wrap: a long workspace path must stay one copy-pasteable line, not be wrapped by the terminal width
    console.print(f"next: {hint}sigharvest update   (sync, validate, index; queries are converted on demand)", soft_wrap=True)
    if preset == "all":
        console.print(
            "[yellow]the all preset clones about 1,200 repositories: the first update takes hours (`update --time-budget "
            "MINUTES` runs it in pieces) and many GB of disk. The same corpus in minutes: init --from-release latest[/]",
            soft_wrap=True,
        )


def _init_from_release(ws: Workspace, location: str, sums_sha256: str | None = None) -> None:
    from sigharvest.cli.common import user_errors
    from sigharvest.release_bootstrap import bootstrap

    started = time.monotonic()
    with user_errors(), console.status("starting from a release...") as status:
        # Progress lines in a log or pipe too (a terminal gets the live status): one per step, and per source at
        # most every HEARTBEAT_SECONDS while ingesting; keepalive repeats a long step so the output never stalls.
        phase = Heartbeat("init --from-release")
        # Started by the first hash count, not here: download and ingest come first, and their minutes would turn
        # the rate-based time left into hours.
        semantic: list[Heartbeat] = []

        def say(message: str) -> None:
            status.update(message)
            if message.startswith("ingest: ") and time.monotonic() - phase.last_said < HEARTBEAT_SECONDS:
                phase.remember(message)
                return
            phase.say(message)

        def hashes(done: int, total: int) -> None:
            status.update(f"semantic hashes: {done:,}/{total:,}")
            if not semantic:
                semantic.append(Heartbeat("index: semantic hashes"))
            semantic[0](done, total)

        with phase.keepalive():
            boot = bootstrap(
                ws, location, progress=say, workers=cpu_workers(), sums_sha256=sums_sha256, counts=hashes, note=lambda m: console.print(f"note: {escape(m)}")
            )
    console.print(
        f"workspace {escape(str(ws.root))}: {boot.rules:,} rules from {len(boot.sources)} sources of release "
        f"{boot.content_id[:16]} ({boot.created[:10]}), indexed in {_duration(time.monotonic() - started)}",
        soft_wrap=True,
    )
    if boot.incomplete:
        console.print(
            "[bold yellow]this pack is marked incomplete[/] (built from a first update that did not pass its gates): "
            "rules may be missing. Prefer a newer release, or run `sigharvest update` with live sources.",
            soft_wrap=True,
        )
    if boot.metadata_only:
        console.print(f"[dim]{boot.metadata_only:,} rules of the pack are metadata only (no licence or restricted): not included[/]", soft_wrap=True)
    here = Path.cwd().resolve()
    hint = "" if ws.root == here else f"{escape(cd_command(ws.root))} && "
    console.print(f"next: {hint}sigharvest search mimikatz   (or serve; `sigharvest update` validates the rules)", soft_wrap=True)
    console.print("[dim]live sources instead of the pack: sigharvest init --force, then sigharvest update[/]", soft_wrap=True)


def cd_command(root: Path) -> str:
    """A `cd` the user can paste: quoted (paths with spaces), and with /d on Windows (cmd needs it to change drive)."""
    if os.name == "nt":
        return f'cd /d "{root}"'
    import shlex

    return f"cd {shlex.quote(str(root))}"


@mutation_command()
def sync(
    source: list[str] = typer.Option(None, "--source", "-s", help="Only these sources (repeatable)."),
    workers: int = typer.Option(DEFAULT_WORKERS, "--workers", "-j", min=1, help="Parallel fetches."),
    remote_check: bool = typer.Option(False, "--remote-check", help="Compare remote Git refs with ingested commits before cloning or fetching."),
    rescan: bool = typer.Option(False, "--rescan", help="Reingest the latest complete cached snapshot without fetching upstream."),
    allow_failures: bool = typer.Option(False, "--allow-failures", help="Exit 0 even if some sources failed."),
) -> None:
    """Fetch sources incrementally and index their Sigma rules. Exits 1 if a source failed."""
    if rescan and remote_check:
        raise typer.BadParameter("--rescan and --remote-check cannot be combined")
    if _sync(source or [], workers, remote_check, rescan) and not allow_failures:
        raise typer.Exit(1)


def _sync(source: list[str], workers: int, remote_check: bool = False, rescan: bool = False) -> list[str]:
    """Sync and rebuild the index; returns the names of the sources that failed."""
    outcomes = _sync_sources(source, workers, remote_check, rescan)
    # Like update: an unchanged corpus with a current index needs no rebuild, whose
    # global passes cost minutes on a large workspace even with an empty delta.
    touched = any(o.status == "ok" and o.touched for o in outcomes)
    with open_db(find_workspace())() as s:
        why = _index_needed(s, 0, touched)
    if why:
        log.info("index rebuild: %s", why)
        index_cmd(workers=workers)
    else:
        console.print("index up to date (nothing changed): not rebuilt")
    return _failed(outcomes)


def _failed(outcomes: list[SourceSyncOutcome]) -> list[str]:
    failed = [o.name for o in outcomes if o.status != "ok"]
    if failed:
        show_error(f"{len(failed)} sources failed: {escape(clean_text(', '.join(failed[:20])))}")
    return failed


def _sync_sources(
    source: list[str],
    workers: int,
    remote_check: bool = False,
    rescan: bool = False,
    *,
    deadline: float | None = None,
    deferred: list[str] | None = None,
) -> list[SourceSyncOutcome]:
    """Fetch and ingest sources (all enabled ones when `source` is empty) and print what changed."""
    ws = find_workspace()
    if not ws.sources_file.exists():
        show_error(f"no sources.yaml in {escape(str(ws.root))}: cd into your workspace, set SIGHARVEST_HOME to it, or create one with `sigharvest init DIR`")
        raise typer.Exit(2)
    with console.status("syncing...") as status:

        def progress(message: str) -> None:
            status.update(message)
            console.print(escape(clean_text(message)))
            log.info("sync: %s", clean_text(message))

        outcomes = sync_all(
            ws,
            source or None,
            progress=progress,
            workers=workers,
            remote_check=remote_check,
            rescan=rescan,
            deadline=deadline,
            deferred=deferred,
        )
    t = Table("source", "status", "result")
    shown = [
        o
        for o in outcomes
        if o.status != "ok"
        or not o.message.startswith("0 sigma files")
        or ("skipped:" in o.message and not o.message.endswith("skipped: 0 non-Sigma YAML, 0 large files"))
    ]
    if console.is_terminal:
        for o in shown:
            t.add_row(escape(clean_text(o.name)), "[green]ok[/]" if o.status == "ok" else "[red]error[/]", escape(clean_text(o.message)))
        if shown:
            console.print(t)
    else:
        # A log or pipe: one line per source (a table wraps every row over several lines at 80 columns).
        for o in shown:
            state = "ok" if o.status == "ok" else "error"
            console.print(f"{escape(clean_text(o.name))}: {state}: {escape(clean_text(o.message))}", soft_wrap=True, highlight=False)
    failed_n = sum(o.status != "ok" for o in outcomes)
    if outcomes and not console.is_terminal:
        console.print(f"sync: {len(outcomes)} sources, {len(outcomes) - failed_n} ok, {failed_n} failed", highlight=False)
    elif not outcomes and not deferred:
        console.print("No enabled sources to sync. Add one with: sigharvest sources add NAME URL")
    unchanged = len(outcomes) - len(shown)
    if unchanged:
        console.print(f"{unchanged} sources unchanged")
    if deferred:
        console.print(f"{len(deferred)} sources left for the next run (time budget or disk space)")
    return outcomes


@mutation_command(wait_arg="wait")
def update(
    source: list[str] = typer.Option(None, "--source", "-s", help="Only sync these enabled sources (repeatable); default all."),
    sources_file: list[Path] = typer.Option(
        None,
        "--sources",
        help="Use this sources file (same format as sources.yaml); it replaces the workspace sources.yaml. Repeatable: "
        "the files are joined in order (e.g. sources/curated.yaml then sources/extended.yaml).",
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-j", min=1, help=f"Parallel fetches and test/index processes (default: {DEFAULT_WORKERS} fetches, every CPU up to 22 for the rest)."
    ),
    report_too: bool = typer.Option(True, "--report/--no-report", help="Write reports/summary.md at the end."),
    remote_check: bool = typer.Option(False, "--remote-check", help="Compare remote Git refs with ingested commits before cloning or fetching."),
    allow_failures: bool = typer.Option(False, "--allow-failures", help="Exit 0 even if some sources failed (gates still apply)."),
    force_index: bool = typer.Option(False, "--force-index", help="Rebuild the index even if nothing changed."),
    convert: bool = typer.Option(
        False,
        "--convert",
        help="Also convert every rule with every installed backend and store the results (slow once; for releases and the "
        "'converts to' filter). Later updates then keep them current. Without it, queries are converted on demand.",
    ),
    max_logic_drop: float = typer.Option(5.0, help="Gate: unique logic may drop by at most this percentage."),
    max_quarantine_growth: float = typer.Option(20.0, help="Gate: quarantined documents may grow by at most this percentage."),
    max_failed_sources: float = typer.Option(10.0, help="Gate: at most this percentage of enabled sources may fail."),
    failed_sources_floor: int = typer.Option(1, min=0, help="Gate: tolerate this many failed sources regardless of percentage."),
    keep_runs: int = typer.Option(30, help="Run reports kept in reports/runs/."),
    notify_cmd: str | None = typer.Option(None, "--notify-cmd", help="Command run with the report path as last argument when a gate fails."),
    report_file: Path | None = typer.Option(None, "--report-file", help="Also copy the run report here (.json for JSON, otherwise markdown)."),
    wait: float = typer.Option(0, "--wait", min=0, metavar="SECONDS", help="If another command holds the workspace, wait up to this long for it."),
    time_budget: float | None = typer.Option(
        None,
        "--time-budget",
        min=0,
        metavar="MINUTES",
        help="Start no new fetch or conversion after this many minutes: what is left (sources never or least recently "
        "synced first) waits for the next update, which resumes it. Validation, index, gates and reports still run, "
        "so leave time for them. The run report counts what was left. 0: no budget.",
    ),
    convert_scope: ConvertScope = typer.Option(
        "all",
        "--convert-scope",
        help="With stored conversions: all (every live copy of every rule) or canonical (one copy per logic, the one "
        "the index, search filters and releases read; far less work on a large corpus).",
    ),
) -> None:
    """Everything in one go, then check the result: sync, validate, index, gates, reports.

    Query conversion is on demand (rule pages, `convert`, backend exports); --convert also converts every rule now.

    Failed sources do not stop the other steps, but the exit code is 1 (unless --allow-failures). The gates compare
    the corpus with the last run that passed them; a failed gate also exits 1 (see docs/getting-started.md). Each run
    writes reports/runs/<UTC time>.md and .json (`sigharvest runs show latest`) and logs to data/logs/."""
    from sigharvest.lock import mutation_lease
    from sigharvest.runs import Thresholds, close_log, open_log
    from sigharvest.update_publication import pending_workers

    ws = find_workspace()
    if sources_file:
        from sigharvest.config import read_sources_file

        configured = []
        for one in sources_file:
            try:
                if not one.is_file():
                    raise FileNotFoundError("file not found")
                configured += read_sources_file(one)
            except (OSError, ValueError, TypeError) as exc:
                show_error(f"cannot read {escape(str(one))}: {escape(str(exc))}")
                raise typer.Exit(2) from None
        names = [c.name for c in configured]
        if dupes := sorted({n for n in names if names.count(n) > 1}):
            show_error(f"the --sources files name the same source more than once: {escape(', '.join(dupes[:10]))}")
            raise typer.Exit(2)
        save_sources(ws, configured)
        open_db(ws, migrate=True)
    if not ws.sources_file.exists():
        show_error(f"no sources.yaml in {escape(str(ws.root))}: cd into your workspace, set SIGHARVEST_HOME to it, or create one with `sigharvest init DIR`")
        raise typer.Exit(2)
    open_db(ws, migrate=True)  # create or upgrade the database before taking the update lease
    with cancellation(), mutation_lease(ws, timeout=wait) as lock:
        lock.set_operation("update")
        handler = None
        context_token = CONTEXT.set({"trace_id": uuid.uuid4().hex} if os.environ.get("SIGHARVEST_TRACE") == "1" else {})
        try:
            handler = open_log(ws)
            th = Thresholds(
                max_logic_drop=max_logic_drop,
                max_quarantine_growth=max_quarantine_growth,
                max_failed_sources=max_failed_sources,
                failed_sources_floor=failed_sources_floor,
            )
            cancelled = False
            with pending_workers():
                try:
                    code = _update(
                        ws,
                        workers,
                        report_too,
                        allow_failures,
                        force_index,
                        th,
                        keep_runs,
                        notify_cmd,
                        remote_check,
                        source or [],
                        report_file=report_file,
                        convert=convert,
                        deadline=_deadline(time_budget),
                        canonical_only=convert_scope == "canonical",
                    )
                except (Cancelled, KeyboardInterrupt):
                    cancelled = True
                except Exception as exc:
                    if not cancellation_requested():
                        # Anything escaping _update skipped its outcome block; without this the
                        # run stayed "running" and the traceback reached only stderr.
                        from sigharvest.update_publication import record_failure

                        log.exception("update failed before its outcome was recorded")
                        try:
                            record_failure(ws, run_id=(CONTEXT.get() or {}).get("run_id"), error=f"{type(exc).__name__}: {exc}")
                        except Exception as failure:
                            log.exception("could not record the failed update's outcome")
                            exc.add_note(f"recording the failed run also failed: {type(failure).__name__}: {failure}")
                        raise
                    # A cleanup error raised while the operator's cancellation unwinds the
                    # gate or report-only path is that cancellation, as in the stage loop.
                    log.warning("Cleanup raised %s during cancellation; recording the operator cancellation", type(exc).__name__)
                    cancelled = True
                if cancelled:
                    from sigharvest.update_publication import record_interruption

                    path = record_interruption(ws, run_id=(CONTEXT.get() or {}).get("run_id"), cancelled=True)
                    if notify_cmd and path is not None:
                        _notify(notify_cmd, path)
                    raise Cancelled() from None
        finally:
            if handler is not None:
                close_log(handler)
            CONTEXT.reset(context_token)
    if code:
        raise typer.Exit(code)


def _deadline(minutes: float | None) -> float | None:
    """The time.monotonic() value at which `--time-budget MINUTES` runs out (None: no budget)."""
    return time.monotonic() + minutes * 60 if minutes else None


class Heartbeat:
    """Progress lines for logs and pipes. A terminal gets Rich's live status; without one (cron, `| tee`, a log file)
    that status prints nothing, so a long stage looked hung. Prints at most every HEARTBEAT_SECONDS, plus the end,
    with the rate-based time left; also written to the update log.

    A stage whose items differ widely in cost (conversion: a 1 MB keyword rule against a 2 KB rule) reports its
    estimated work through `work()`; the time left then follows the share of work done, not of items."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.started = time.monotonic()
        self.last = 0.0
        self.tty = console.is_terminal
        self.work_done = 0
        self.work_total = 0

    def work(self, done: int, total: int) -> None:
        self.work_done, self.work_total = done, total

    def _left(self, elapsed: float, done: int, total: int) -> float | None:
        # The first seconds and percents (pool start-up, the largest rules first) say little about the rest: no
        # estimate before 10 s and 2 % of the work.
        if elapsed < 10:
            return None
        if self.work_total > 0 and 0 < self.work_done < self.work_total:
            if self.work_done < self.work_total * 0.02:
                return None
            return elapsed / self.work_done * (self.work_total - self.work_done)
        if 0 < done < total and done >= total * 0.02:
            return elapsed / done * (total - done)
        return None

    def __call__(self, done: int, total: int) -> None:
        now = time.monotonic()
        if done < total and now - self.last < HEARTBEAT_SECONDS:
            return
        self.last = now
        elapsed = now - self.started
        eta = ""
        left = self._left(elapsed, done, total) if done < total else None
        if left is not None and elapsed > 1:
            eta = f", about {_duration(left)} left"
        text = f"{self.label}: {done:,}/{total:,} ({done * 100 // max(total, 1)}%){eta}"
        log.info("%s", text)
        if not self.tty:
            console.print(text, soft_wrap=True)

    last_said = 0.0
    current = ""
    printed = ""

    def say(self, message: str) -> None:
        self.remember(message)
        self.printed = message.removesuffix(" (still running)")
        self.last_said = time.monotonic()
        log.info("%s", message)
        if not self.tty:
            console.print(f"{message} ({_duration(time.monotonic() - self.started)})", soft_wrap=True)

    def remember(self, message: str) -> None:
        """The step in progress, without printing it (repeated by keepalive)."""
        self.current = message

    @contextmanager
    def keepalive(self) -> Iterator[None]:
        """While the block runs, repeat the current step ("... still running") when nothing was said for
        HEARTBEAT_SECONDS, so a log or pipe never goes quiet during a long step (non-terminal output only)."""
        import threading

        stop = threading.Event()

        def tick() -> None:
            while not stop.wait(1.0):
                if self.current and time.monotonic() - self.last_said >= HEARTBEAT_SECONDS:
                    # a step remembered but not printed yet is news; the same step again is "still running"
                    step = self.current.removesuffix(" (still running)")
                    self.say(f"{step} (still running)" if step == self.printed else step)

        thread = threading.Thread(target=tick, name="sigharvest-heartbeat", daemon=True)
        if not self.tty:
            thread.start()
        try:
            yield
        finally:
            stop.set()
            if thread.is_alive():
                thread.join(timeout=2)


HEARTBEAT_SECONDS = 15.0


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"


@contextmanager
def _step(name: str, durations: dict[str, float]) -> Iterator[None]:
    job_progress(name)
    log.info("%s: started", name)
    t0 = time.monotonic()
    try:
        yield
    finally:
        durations[name] = round(time.monotonic() - t0, 1) + durations.get(name, 0.0)
        count("stage.finished", name)
        log.info("%s: %.1f s", name, time.monotonic() - t0, extra={"event": "stage.finished", "stage": name})


def _index_needed(s: Session, processed: int, corpus_changed: bool) -> str:
    """Why the index must be rebuilt, or "" when it is up to date (the rebuild takes minutes on a large corpus)."""
    from sigharvest import index_delta
    from sigharvest.db import INDEXED_RESULTS_REVISION, RESULTS_REVISION, get_meta
    from sigharvest.index import INDEX_BUILT_AT
    from sigharvest.models import LogicGroup
    from sigharvest.semantic import needs_refresh

    built = get_meta(s, INDEX_BUILT_AT)
    if built is None:
        return "no recorded build"
    if corpus_changed:
        return "the corpus changed"
    if processed:
        return f"{processed} new test results"
    if (get_meta(s, RESULTS_REVISION) or "") != (get_meta(s, INDEXED_RESULTS_REVISION) or ""):
        return "stored results changed since the last index build"
    if needs_refresh(s):
        return "semantic results changed or need refresh"
    if get_meta(s, index_delta.FORMAT_KEY) != index_delta.publication_fingerprint(s):
        return "the index format changed"
    from sigharvest.correlation_references import status as reference_status

    if reference_status(s) != "ready":
        return "correlation references need refresh"
    if get_meta(s, index_delta.USER_REVISION_KEY) != index_delta.user_revision(s):
        return "collections changed"
    live = select(RuleVersion.logic_hash).where(RuleVersion.id.in_(select(Occurrence.version_id).where(Occurrence.present.is_(True))))
    if s.scalar(select(func.count()).select_from(LogicGroup)) != s.scalar(select(func.count()).select_from(live.distinct().subquery())):
        return "the index does not match the live corpus"
    return ""


def _stores_conversions(ws: Workspace) -> bool:
    from sigharvest.conversion import BACKENDS
    from sigharvest.models import TestResult

    if not BACKENDS:
        return False
    with open_db(ws)() as s:
        return s.scalar(select(TestResult.id).where(TestResult.stage == "convert").limit(1)) is not None


def cpu_workers() -> int:
    """CPU-bound stages (validation, conversion, index) use every available CPU, up to 22, unless -j says otherwise."""
    try:
        available = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        available = os.cpu_count() or 1
    return max(1, min(available, 22))


def _update(
    ws: Workspace,
    workers: int | None,
    report_too: bool,
    allow_failures: bool,
    force_index: bool,
    th: Thresholds,
    keep_runs: int,
    notify_cmd: str | None,
    remote_check: bool = False,
    sources: list[str] | None = None,
    *,
    report_file: Path | None = None,
    convert: bool = False,
    deadline: float | None = None,
    canonical_only: bool = False,
) -> int:
    """The steps of `sigharvest update` under the lock; returns the exit code.

    deadline (time.monotonic()): no fetch or conversion starts after it (`--time-budget`); the rest is resumed by the
    next update. canonical_only: conversions for the canonical copy of each logic only (`--convert-scope canonical`)."""
    from sigharvest import runs
    from sigharvest.models import UpdateRun
    from sigharvest.report import build_summary
    from sigharvest.update_publication import candidate

    Session_ = open_db(ws)
    durations: dict[str, float] = {}
    notes: list[str] = []

    def note(text: str) -> None:
        notes.append(clean_text(text))
        console.print(f"[yellow]note:[/] {escape(clean_text(text))}")
        log.warning("%s", clean_text(text))

    with Session_() as s:
        if abandoned := runs.close_abandoned(s):
            note(f"{abandoned} earlier update run(s) never finished; recorded as interrupted")
        run = UpdateRun(counts={"phase": "sync"})
        s.add(run)
        s.commit()
        run_id, started = run.id, run.started_at
        CONTEXT.set((CONTEXT.get() or {}) | {"run_id": run_id})
        count("run.started")
        log.info("update %d started", run_id, extra={"event": "run.started"})
        with _step("snapshot", durations):
            before = runs.snapshot(s)

    @contextmanager
    def step(name: str, timing: dict[str, float]) -> Iterator[None]:
        phase = name
        with Session_() as progress:
            current = progress.get(UpdateRun, run_id)
            assert current is not None
            current.counts = current.counts | {"phase": phase}
            current.durations = dict(timing)
            progress.commit()
        with _step(name, timing):
            yield

    with candidate(ws) as publication:
        Session_ = open_db(ws)
        outcomes: list[SourceSyncOutcome] = []
        deferred: list[str] = []
        conversions_deferred = 0
        after = runs.Snapshot(before.by_source)  # if the sync fails: nothing changed
        error = None
        try:
            with step("sync", durations):
                outcomes = _sync_sources(sources or [], workers or DEFAULT_WORKERS, remote_check, deadline=deadline, deferred=deferred)
            if deferred:
                note(
                    f"time budget or disk space reached: {len(deferred)} sources not synced in this run (they keep their last "
                    "ingested commit); the next update syncs them first"
                )
            with Session_() as s:
                after = runs.snapshot(s)
            with step("test", durations):
                # Once a workspace stores conversions (update --convert, test --stage convert), later updates keep them
                # current for new rule versions; otherwise new rules would score lower than converted ones.
                stages = ["validate", "convert"] if convert or _stores_conversions(ws) else ["validate"]
                only = None
                if canonical_only and "convert" in stages:
                    from sigharvest.index import canonical_version_ids

                    with Session_() as s:
                        only = canonical_version_ids(s)
                summaries: list[Any] = []
                processed = _test(stages, True, workers or cpu_workers(), None, deadline=deadline, only=only, summaries=summaries)
                conversions_deferred = sum(x.deferred for x in summaries)
            if conversions_deferred:
                note(f"time budget reached: {conversions_deferred:,} rules not converted in this run; the next update converts them")
            with Session_() as s:
                # files added/changed/removed also catch new copies and metadata edits that keep the logic hash
                touched = any(o.status == "ok" and o.touched for o in outcomes)
                why = "--force-index" if force_index else _index_needed(s, processed, touched or after.by_source != before.by_source)
            if why:
                log.info("index rebuild: %s", why)
                with step("index", durations):
                    index_cmd(workers=workers or cpu_workers())
            else:
                console.print("index up to date (nothing changed): not rebuilt")
                log.info("index rebuild skipped: nothing changed")
            if not why:
                with Session_() as s:
                    # Even an unchanged sync advances source timestamps/revisions.
                    # Keep first-page projections current when the index is skipped.
                    from sigharvest.page_summaries import refresh as refresh_pages
                    from sigharvest.search_summary import refresh as refresh_search

                    refresh_search(s, source_ready=True)
                    refresh_pages(s)
                    s.commit()
        except Exception as exc:
            if cancellation_requested():
                log.warning("Cleanup raised %s during cancellation; recording the operator cancellation", type(exc).__name__)
                raise Cancelled() from None
            error = f"{type(exc).__name__}: {exc}"
            log.exception("update %d failed", run_id)
            show_error(f"update failed: {escape(clean_text(error))}")
        failed = [o.name for o in outcomes if o.status != "ok"]
        for o in outcomes:
            if o.status != "ok":
                log.warning("source %s failed: %s", o.name, clean_text(o.message), extra={"source_id": o.name})
        with Session_() as s:
            if error:
                # A failed sync can still have committed some sources before failing.
                after = runs.snapshot(s)
            # Gate path from here to runs.finish: counts, the previous baseline and the gates fail closed.
            ch = runs.changes(s, before, after)
            for o in outcomes:
                if o.status != "ok":
                    ch.sources.setdefault(o.name, runs.SourceChange()).error = o.message or "error"
            enabled = sum(c.enabled for c in load_sources(ws))
            counts = runs.corpus_counts(s) | {
                "sources_enabled": enabled,
                "sources_ok": len(outcomes) - len(failed),
                "sources_failed": len(failed),
                "new": len(ch.new),
                "changed": len(ch.changed),
                "removed": len(ch.removed),
            }
            if deadline is not None or deferred:
                counts |= {"sources_deferred": len(deferred), "conversions_deferred": conversions_deferred}
            prev = runs.previous_passed(s, run_id)
            gates = runs.evaluate(counts, prev.counts if prev else None, th)
            run = s.get(UpdateRun, run_id) or run
            run.counts = run.counts | counts
            runs.finish(run, gates, failed, error)
            if error == "interrupted":
                run.status = "interrupted"
            run.durations = dict(durations)
            # Everything below is report-only and never changes the gate decision taken above: a failure is a
            # note, and the corpus is still published when the gates passed.
            data = _report_only("run report", note, None, runs.build_report, s, run, prev, before, after, ch) or runs.report_skeleton(run, prev)
            for text in data.pop("report_notes", []):
                note(text)
            data["notes"] = list(notes)
            data["metrics"] = metrics()
            s.commit()
            publication.accepted = run.status in runs.PASSED
    # Persist the attempt even when all candidate corpus writes were rolled back.
    Session_ = open_db(ws)
    with Session_() as s:
        restored_run = s.get(UpdateRun, run_id)
        assert restored_run is not None
        run = restored_run
        run.status, run.reasons, run.counts = data["status"], data["reasons"], data["counts"]
        run.gates, run.durations = data["gates"], dict(durations)
        from sigharvest.models import utcnow

        run.finished_at = utcnow()
        with terminal_publication():
            s.commit()
        path = ws.reports / "runs" / f"{runs.stamp(started)}.md"
        report_failed = summary_failed = False
        if report_too:
            # The corpus outcome is committed above; the summary is report-only.
            try:
                with step("report", durations):
                    notice = None if run.status in runs.PASSED else f"The last update ({run.id}) did not pass: " + "; ".join(run.reasons[:3])
                    build_summary(s, ws.reports, rule_json=False, notice=notice)
            except Exception as exc:
                s.rollback()
                summary_failed = True
                cause = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}".rstrip(": ")
                show_error(f"summary report failed ({cause}); run outcome is committed in the database")
                log.error("summary report failed; committed outcome retained", exc_info=True)
                data["notes"] = [*data.get("notes", []), f"summary report not refreshed ({type(exc).__name__})"]
        try:
            run.durations = dict(durations)
            data["durations"] = dict(durations)
            path = runs.write_report(ws, data, started)
            from sigharvest.config import workspace_relative

            run.report = workspace_relative(path, ws.root)
            s.commit()
            if report_file is not None:
                report_file.parent.mkdir(parents=True, exist_ok=True)
                source = path.with_suffix(".json") if report_file.suffix.lower() == ".json" else path
                report_file.write_bytes(source.read_bytes())
        except Exception:
            s.rollback()
            report_failed = True
            show_error("report write failed; run outcome is committed in the database")
            log.error("report write failed; committed outcome retained", exc_info=True)
        run.counts = run.counts | {"phase": "finished"}
        s.commit()
        status, reasons = run.status, list(run.reasons)
        incomplete = runs.incomplete_corpus(s)
        incomplete_line = runs.incomplete_text(incomplete) if incomplete is not None else ""
    try:
        runs.prune_reports(ws, keep_runs)
    except Exception:
        log.warning("report retention failed; reports retained", exc_info=True)
    if not report_failed:
        _print_gates(gates, status, path)
    if incomplete_line:
        # The first update commits as it goes (nothing older to keep), so a failure here leaves a partial corpus
        # on display: say so plainly instead of letting it look like a normal index.
        console.print(f"[bold red]{escape(incomplete_line)}[/]", soft_wrap=True)
        log.warning("%s", incomplete_line)
    count("run.finished")
    log.info("update %d: %s%s", run_id, status, "".join(f"\n  {r}" for r in reasons), extra={"event": "run.finished", "status": status})
    bad = status in ("failed gate", "error", "interrupted")
    if bad and notify_cmd and not report_failed:
        _notify(notify_cmd, path)
    if summary_failed:
        # The summary page is report-only: a passed run stays passed (the cause is printed and noted in the run report).
        log.warning("summary report not refreshed; exit code follows the run status (%s)", status)
    if status == "error" or report_failed:
        return 2
    return 1 if bad or (failed and not allow_failures) else 0


def _report_only(what: str, note: Callable[[str], None], default: Any, fn: Callable[..., Any], *args: Any) -> Any:
    """Run report-only work inside the gated candidate. Any exception (not a cancellation, which is a
    BaseException) becomes a note and `default`; the gate decision and the corpus are not affected."""
    try:
        return fn(*args)
    except Exception as exc:
        if cancellation_requested():
            raise
        log.warning("%s unavailable", what, exc_info=True)
        note(f"{what} unavailable ({_stage_failure(exc)}); the corpus update is not affected")
        return default


def _stage_failure(exc: BaseException) -> str:
    """Type plus a short message that cannot carry paths, SQL or remote text, except for user-facing refusals."""
    from sigharvest.errors import SigharvestError

    if isinstance(exc, SigharvestError):
        detail = clean_text(str(exc))
        return f"{type(exc).__name__}: {detail[:300]}{'...' if len(detail) > 300 else ''}"
    if isinstance(exc, OSError):
        return f"{type(exc).__name__}: {exc.strerror or 'operating system error'}"
    if isinstance(exc, sqlite3.Error):
        return f"{type(exc).__name__}: {getattr(exc, 'sqlite_errorname', None) or 'SQLite error'}"
    return type(exc).__name__


def _print_gates(gates: list[Gate], status: str, path: Path) -> None:
    t = Table("gate", "result", "detail", title=f"update: {status}", title_justify="left")
    colour = {"pass": "green", "fail": "red", "warn": "yellow", "skipped": "dim"}
    for g in gates:
        t.add_row(g.name, f"[{colour[g.status]}]{g.status}[/]", escape(g.detail))
    console.print(t)
    console.print(f"report: {escape(str(path))}  (sigharvest runs show latest)")


def _notify(cmd: str, path: Path) -> None:
    """Run the --notify-cmd with the report path as its last argument (no shell); failures are only logged."""
    import shlex
    import subprocess

    try:
        proc = subprocess.run([*shlex.split(cmd), str(path)], capture_output=True, text=True, timeout=300, check=False)
        log.info("notify command exited %d", proc.returncode)
        if proc.returncode:
            log.warning("notify command failed: %s", (proc.stderr or proc.stdout).strip()[:500])
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        log.warning("notify command could not run: %s", exc)


def _stages(values: list[str]) -> list[str]:
    """--stage is repeatable; typer has no list-of-choices type, so the values are checked here."""
    bad = [v for v in values if v not in STAGES]
    if bad:
        raise typer.BadParameter(f"{bad[0]!r} is not one of {', '.join(STAGES)}")
    return values


@mutation_command()
def test_cmd(
    stage: list[str] = typer.Option(["validate", "convert"], "--stage", metavar="<validate|convert>", callback=_stages, help="validate, convert (repeatable)."),
    resume: bool = typer.Option(True, "--resume/--rerun", help="Skip rule versions that already have results."),
    workers: int = typer.Option(DEFAULT_WORKERS, "--workers", "-j", min=1, help="Parallel processes."),
    limit: int | None = typer.Option(None, min=1, help="Only the first N pending rule versions."),
    retry_resource_failures: bool = typer.Option(
        False, "--retry-resource-failures", help="Convert again rule versions whose conversion worker died (resource_failure)."
    ),
) -> None:
    """Run test stages on the live corpus and store results per rule version."""
    _test(stage, resume, workers, limit, retry_resource_failures)
    index_cmd(workers=workers)


def _test(
    stage: list[str],
    resume: bool,
    workers: int,
    limit: int | None,
    retry_resource_failures: bool = False,
    *,
    deadline: float | None = None,
    only: set[int] | None = None,
    summaries: list[Any] | None = None,
) -> int:
    """Run the stages and print their counts; returns the number of versions processed.

    `deadline` and `only` apply to conversion (see testing.run_stage); each StageSummary is appended to `summaries`."""
    from sigharvest.testing import run_stage

    ws = find_workspace()
    processed = 0
    for st in stage:
        with open_session() as s, console.status(f"{st}...") as status:
            beat = Heartbeat(st)

            def _progress(done: int, total: int, label: str = st, beat: Heartbeat = beat) -> None:
                job_progress(label, done, total)
                status.update(f"{label}: {done}/{total}")
                beat(done, total)

            _progress.work = beat.work  # type: ignore[attr-defined]  # weighted time left (conversion)
            convert = st == "convert"
            summary = run_stage(
                ws,
                s,
                st,
                resume=resume,
                workers=workers,
                limit=limit,
                progress=_progress,
                retry_resource_failures=retry_resource_failures,
                only=only if convert else None,
                deadline=deadline if convert else None,
            )
        if summaries is not None:
            summaries.append(summary)
        processed += summary.processed
        t = Table(
            "target",
            *sorted({k for v in summary.counts.values() for k in v}),
            title=f"{st}: {summary.processed:,} processed, {summary.skipped:,} already done",
        )
        statuses = sorted({k for v in summary.counts.values() for k in v})
        for target, counts in sorted(summary.counts.items()):
            t.add_row(target, *[str(counts.get(x, 0)) for x in statuses])
        console.print(t)
        for note in summary.notes:
            console.print(f"{st}: {note}", soft_wrap=True)
        if summary.regex_refused:
            n = summary.regex_refused
            console.print(
                f"{st}: {n:,} rule{'s' if n != 1 else ''} use a regular expression RE2 cannot run (lookahead, lookbehind or "
                "backreference): pySigma 2 refuses them, so they count as validation errors (`sigharvest search --validation error`)",
                soft_wrap=True,
            )
    return processed


@mutation_command()
def index_cmd(
    full: Annotated[bool, typer.Option("--full", help="Accepted for compatibility; every rebuild is complete.")] = False,
    workers: Annotated[int | None, typer.Option("--workers", "-j", min=1, help="Parallel index workers (default: available CPUs, up to 22).")] = None,
) -> None:
    """Rebuild the search index (semantic hashes, unique logic groups, families, scores, full-text).

    Runs automatically after sync and test."""
    from sigharvest.cli.common import user_errors
    from sigharvest.index import rebuild
    from sigharvest.semantic import backfill

    workers = max(1, min(workers or (os.cpu_count() or 1), 22))
    with open_db(find_workspace(), migrate=True)() as s, user_errors(), console.status("indexing...") as status:
        semantic = Heartbeat("index: semantic hashes")
        phase = Heartbeat("index")

        def hashes(done: int, total: int) -> None:
            status.update(f"semantic hashes: {done}/{total}")
            semantic(done, total)

        def step(message: str) -> None:
            status.update(message)
            phase.say(message)

        with phase.keepalive():
            backfill(s, workers=workers, progress=hashes)
            n = rebuild(s, progress=step, workers=workers)
    console.print(f"indexed {n:,} unique rules")


def stats(
    all_sources: bool = typer.Option(False, "--all-sources", help="List every source (default: the 20 largest)."),
    json_output: bool = typer.Option(False, "--json", help="Print the counts as JSON (every source)."),
) -> None:
    """Corpus counts, and per source: documents, distinct logic and logic found in no other source."""
    from sigharvest.corpus_stats import read

    with open_session(readonly=True) as s:
        counts = read(s)
        total_docs = counts.documents
        n_versions, n_rule_ids, n_logic, n_sem = counts.contents, counts.rule_ids, counts.logic, counts.semantic
        n_quar = s.scalar(select(func.count()).select_from(Quarantine).where(Quarantine.present.is_(True)))
        if json_output:
            import json

            from sigharvest.runs import incomplete_corpus

            per_source = [{"name": name, "documents": docs, "logic": logic, "only": counts.only.get(name, 0)} for name, docs, logic in counts.sources]
            payload = {
                "incomplete": incomplete_corpus(s) is not None,
                "documents": total_docs,
                "contents": n_versions,
                "rule_ids": n_rule_ids,
                "logic": n_logic,
                "semantic": n_sem,
                "families": counts.families,
                "quarantined": n_quar,
                "total": len(per_source),
                "offset": 0,
                "limit": len(per_source),
                "results": per_source,
            }
            typer.echo(json.dumps(payload))
            return
        if not total_docs:
            console.print("no rules yet: run `sigharvest update` to fetch and index the sources in sources.yaml")
            return
        from sigharvest.cli.common import warn_incomplete

        warn_incomplete(s)
        t = Table("metric", "value")
        t.add_row("rule documents (all copies, all sources)", str(total_docs))
        t.add_row("unique contents (content_hash)", str(n_versions))
        t.add_row("unique rule ids", str(n_rule_ids))
        t.add_row("unique logic (logic_hash)", str(n_logic))
        n_fam = counts.families
        t.add_row("unique detections (semantic_hash, parseable rules)", str(n_sem))
        t.add_row("rule families (same UUID, logic or detection)", str(n_fam or "run `sigharvest index`"))
        t.add_row("quarantined documents", str(n_quar))
        console.print(t)
        per = Table("source", "documents", "distinct logic", "only here")
        rows, only = counts.sources, counts.only
        shown = rows if all_sources else rows[:20]
        for name, docs, logic in shown:
            per.add_row(name, str(docs), str(logic), str(only.get(name, 0)))
        console.print(per)
        if len(rows) > len(shown):
            console.print(f"{len(rows) - len(shown)} more sources: `sigharvest stats --all-sources` lists all.")
