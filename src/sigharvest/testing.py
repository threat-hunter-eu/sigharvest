"""Rule test stages 1 (validate) and 2 (convert). Results are stored per rule version, so runs are resumable."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import httpx
import yaml
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from sigharvest import conversion, conversion_memory, conversion_output, conversion_scheduling, conversion_spills, space, update_publication
from sigharvest.config import Workspace
from sigharvest.conversion import BACKENDS, plan
from sigharvest.db import mark_results_changed
from sigharvest.documents import SigmaSafeLoader
from sigharvest.fingerprints import digest, result_key, text_digest
from sigharvest.job_control import Cancelled, cancellation_requested
from sigharvest.lock import mutation_lease
from sigharvest.models import Occurrence, RuleVersion, TestResult, TestResultHistory, TestRun, utcnow
from sigharvest.query import live_version_ids
from sigharvest.testing_conversion import _convert_one

SPEC_COMMIT = "ba9251aa834b11a70dbf80836b453dba99c5159e"
SPEC_URL = "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/{commit}/json-schema/{name}"
SCHEMAS = {
    "rule": "sigma-detection-rule-schema.json",
    "correlation": "sigma-correlation-rules-schema.json",
    "filter": "sigma-filters-schema.json",
}

log = logging.getLogger(__name__)

# Validators that compare rules with each other; sigharvest does that itself (dedupe), so they are skipped per rule.
COLLECTION_VALIDATORS = {"identifier_uniqueness", "duplicate_title", "duplicate_filename", "duplicate_references"}


def validation_toolchain(schemas: dict[str, Any], skipped_tags: tuple[str, ...] = ()) -> str:
    """Fingerprint the effective schemas, parser, validator set and the code validation executes (conversion_key.py).

    `skipped_tags`: tag catalogues that were unavailable (pysigma_tags.Prepared.skipped); results checked without
    them get another key, so they are validated again once the catalogue is there."""
    from sigma.validators.core import validators

    from sigharvest import conversion_key

    options: dict[str, Any] = {
        "spec_commit": SPEC_COMMIT,
        "schemas": schemas,
        "validators": sorted((n, v.__module__, v.__qualname__) for n, v in validators.items() if n not in COLLECTION_VALIDATORS),
    }
    if skipped_tags:
        options["skipped_tag_catalogues"] = sorted(skipped_tags)
    return conversion_key.validation_toolchain(options)


def native_backend(product: str | None, category: str | None, service: str | None) -> str:
    """The backend a rule is most likely meant for, among the installed ones. Heuristic, see docs/concepts.md "Validation and conversion"."""
    if "microsoft365defender" in BACKENDS and not plan("microsoft365defender", product, category, service).unsupported:
        return "microsoft365defender"
    return "splunk"


# ----------------------------------------------------------------------------- schemas


def load_schemas(ws: Workspace) -> dict[str, Any]:
    """The Sigma JSON schemas at SPEC_COMMIT, downloaded once into the cache."""
    folder = ws.cache / "sigma-specification" / SPEC_COMMIT
    folder.mkdir(parents=True, exist_ok=True)
    out = {}
    for kind, name in SCHEMAS.items():
        path = folder / name
        if not path.exists():
            r = httpx.get(SPEC_URL.format(commit=SPEC_COMMIT, name=name), timeout=60, follow_redirects=True)
            r.raise_for_status()
            with TemporaryDirectory(prefix="schema-", dir=folder) as temp:
                staged = Path(temp) / name
                staged.write_bytes(r.content)
                staged.replace(path)
        out[kind] = json.loads(path.read_text(encoding="utf-8"))
    return out


# ----------------------------------------------------------------------------- worker side

_W: dict[str, Any] = {}


def _init_worker(schemas: dict[str, Any], stage: str, tags: dict[str, dict[str, Any] | None] | None = None) -> None:
    import warnings

    import jsonschema

    from sigharvest import pysigma_limits

    pysigma_limits.install()  # also before any parse: RE2 must not print its parse errors to the terminal
    warnings.filterwarnings("ignore", category=UserWarning, module="sigma")
    _W["stage"] = stage
    _W["schema_validators"] = {k: jsonschema.Draft202012Validator(v) for k, v in schemas.items()}
    if stage == "validate":
        from sigma.validation import SigmaValidator
        from sigma.validators.core import validators

        from sigharvest import pysigma_tags

        # The parent prepared the tag catalogues once (pysigma_tags.prepare): no worker downloads them.
        excluded = pysigma_tags.install(tags or {})
        skipped = tuple(sorted(name for name, data in (tags or {}).items() if data is None))
        _W["validator"] = SigmaValidator([v for n, v in validators.items() if n not in COLLECTION_VALIDATORS and v.__name__ not in excluded])
        _W["toolchain"] = validation_toolchain(schemas, skipped)


def _parse(raw: str) -> Any:
    # Documents are validated one by one, so references to other documents (correlations) are not resolved here.
    return conversion.parse(raw)


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc).strip()[:400]}"


def _detection_parses(raw: str) -> bool:
    from sigharvest.detection import detection_only

    try:
        coll = _parse(detection_only(raw))
    except Exception:  # noqa: BLE001
        return False
    return bool(coll.rules) and not getattr(coll, "errors", []) and not any(getattr(r, "errors", []) for r in coll.rules)


def _validate_batch(items: list[tuple[int, str, str]]) -> list[tuple[int, str, str, dict[str, Any]]]:
    """Validate a few versions in a worker; a list so validate and convert share one result path."""
    return [_validate_one(item) for item in items]


_REFUSED_REGEX = re.compile(r"Regular expression .* is invalid: ")


def refused_regex(detail: dict[str, Any]) -> bool:
    """Whether a validation result failed on a `|re` value the regex engine refused (RE2: lookaround, backreference)."""
    return any(_REFUSED_REGEX.search(str(m)) for key in ("parse", "metadata") for m in detail.get(key) or [])


# Wall-clock limit for validating one document (pySigma expansion is bounded by pysigma_limits; this is the backstop
# so no single document can hold a validate worker, and with it `update`, indefinitely).
VALIDATE_TIMEOUT = 60.0


class ValidateTimeout(BaseException):
    """Escapes the `except Exception` handlers inside validation, like conversion.SourceTimeout."""


def _validate_one(item: tuple[int, str, str]) -> tuple[int, str, str, dict[str, Any]]:
    import signal
    import threading

    def timed_out() -> tuple[int, str, str, dict[str, Any]]:
        vid, kind, raw = item
        detail: dict[str, Any] = {"schema": [], "parse": [f"timeout: validation took longer than {VALIDATE_TIMEOUT:g} s"], "issues": []}
        detail["toolchain"] = _W["toolchain"]
        detail["fingerprint"] = result_key(_W["toolchain"], text_digest(raw), kind)
        return vid, "pysigma+schema", "error", detail

    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        from sigharvest.deadline import call_with_timeout

        return call_with_timeout(lambda: _validate_unbounded(item), VALIDATE_TIMEOUT, timed_out)

    def alarm(_signum: int, _frame: Any) -> None:
        raise ValidateTimeout

    previous = signal.signal(signal.SIGALRM, alarm)
    timer = signal.setitimer(signal.ITIMER_REAL, VALIDATE_TIMEOUT)
    try:
        return _validate_unbounded(item)
    except ValidateTimeout:
        return timed_out()
    finally:
        signal.setitimer(signal.ITIMER_REAL, *timer)
        signal.signal(signal.SIGALRM, previous)


def _validate_unbounded(item: tuple[int, str, str]) -> tuple[int, str, str, dict[str, Any]]:
    vid, kind, raw = item
    detail: dict[str, Any] = {"schema": [], "parse": [], "issues": []}
    try:
        data = yaml.load(raw, Loader=SigmaSafeLoader)  # noqa: S506 - SafeLoader subclass
        validator = _W["schema_validators"].get(kind)
        if validator is not None:
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path))[:20]:
                detail["schema"].append(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message[:200]}")
    except Exception as exc:  # noqa: BLE001
        detail["schema"].append(_err(exc))
    try:
        coll = _parse(raw)
        detail["parse"] += conversion.parse_errors(coll)  # each message once; "no rule could be parsed" when empty
        if kind == "rule" and not detail["parse"]:
            for issue in _W["validator"].validate_rule(coll.rules[0]):
                detail["issues"].append({"validator": type(issue).__name__, "severity": issue.severity.name.lower(), "description": issue.description[:300]})
    except Exception as exc:  # noqa: BLE001
        detail["parse"].append(_err(exc))
    if detail["parse"] and kind == "rule" and _detection_parses(raw):
        # Only the metadata is broken (date format, id, tags, level...): the detection itself is valid.
        detail["metadata"] = detail.pop("parse")
        detail["parse"] = []
    if detail["parse"]:
        status = "error"
    elif detail.get("metadata") or detail["schema"] or any(i["severity"] in ("high", "medium") for i in detail["issues"]):
        status = "warning"
    else:
        status = "ok"
    detail["toolchain"] = _W["toolchain"]
    detail["fingerprint"] = result_key(_W["toolchain"], text_digest(raw), kind)
    return vid, "pysigma+schema", status, detail


# ----------------------------------------------------------------------------- orchestration


@dataclass
class StageSummary:
    """Result of one `run_stage`: versions processed and skipped, and counts per target and status."""

    stage: str
    processed: int
    skipped: int
    counts: dict[str, dict[str, int]]
    regex_refused: int = 0  # validated documents with a `|re` value RE2 cannot run (lookaround, backreference)
    deferred: int = 0  # selected versions left for the next run because the deadline passed (conversion only)
    notes: list[str] = field(default_factory=list)  # one-line notes for the user (e.g. a tag check skipped offline)


def live_versions(s: Session) -> list[RuleVersion]:
    """Every live rule version, by id."""
    live = live_version_ids()
    return list(s.scalars(select(RuleVersion).where(RuleVersion.id.in_(live)).order_by(RuleVersion.id)))


def _done(
    s: Session,
    stage: str,
    schemas: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    retry_resource_failures: bool = False,
    quiet: bool = False,
    skipped_tags: tuple[str, ...] = (),
) -> set[int]:
    """Only reuse exact current implementation/input keys, including failed results.

    Validation requires the effective schemas, not just their nominal commit. Rows
    from other datasets or incomplete target sets cannot make a version complete.
    A changed convert key is logged with its changed components into `report`.
    With `retry_resource_failures`, versions with a resource_failure result are not done.
    With `quiet` the key change is logged at debug level only (callers that report it themselves).
    """
    if stage == "validate":
        if schemas is None:
            return set()
        current = {"pysigma+schema": validation_toolchain(schemas, skipped_tags)}
    elif stage == "convert":
        current = {t: conversion.toolchain(t) for t in BACKENDS}
    else:
        raise ValueError(f"unknown stage {stage}")
    contexts: dict[int, list[str]] = {}
    if stage == "convert":
        ids = list(s.scalars(select(RuleVersion.id).where(RuleVersion.kind == "correlation", RuleVersion.id.in_(live_version_ids()))))
        # Retain digests rather than every correlation graph's YAML at once.
        for vid in ids:
            contexts[vid] = []
            for raw in s.scalars(conversion_scheduling.sibling_query(s, vid)).yield_per(1):
                contexts[vid].append(text_digest(raw))
    keys: dict[int, dict[str, str]] = {}
    stale: dict[tuple[str, str], int] = {}
    stale_versions: set[int] = set()
    rows = s.execute(
        select(
            TestResult.version_id,
            TestResult.target,
            TestResult.fingerprint,
            func.json_extract(TestResult.detail, "$.toolchain"),
            TestResult.run_id,
            TestResult.status,
        ).where(TestResult.stage == stage, TestResult.dataset == "", TestResult.version_id.in_(live_version_ids()))
    ).yield_per(1000)
    retry: set[int] = set()
    for vid, target, fp, tc, _run_id, status in rows:
        if retry_resource_failures and status == RESOURCE_FAILURE:
            retry.add(vid)
        if target in current and tc == current[target] and fp:
            keys.setdefault(vid, {})[target] = fp
        elif stage == "convert" and target in current and tc != current[target]:
            stale[target, str(tc)] = stale.get((target, str(tc)), 0) + 1
            stale_versions.add(vid)
    if stale:
        explained = _explain_convert_key_change(s, stale, len(stale_versions), logging.DEBUG if quiet else logging.WARNING)
        if report is not None:
            report["key_change"] = explained
    complete = [vid for vid, targets in keys.items() if targets.keys() == current.keys() and vid not in retry]
    done = set()
    for ids in _chunks(complete, 200):
        versions = s.execute(select(RuleVersion.id, RuleVersion.raw, RuleVersion.kind).where(RuleVersion.id.in_(ids))).yield_per(1)
        for vid, raw, kind in versions:
            # Source identity may include inherited context or original undecodable
            # bytes. Workers consume effective UTF-8 YAML, so hash that same input.
            content = text_digest(raw)
            expected = {target: result_key(tc, content, kind, contexts.get(vid, [])) for target, tc in current.items()}
            if all(keys[vid][target] in (key, resource_key(key)) for target, key in expected.items()):
                done.add(vid)
    return done


def _explain_convert_key_change(s: Session, stale: dict[tuple[str, str], int], versions: int, level: int = logging.WARNING) -> dict[str, Any]:
    """Log which key components changed and how many stored results the change invalidates."""
    from sigharvest import conversion_key

    known: dict[str, dict[str, Any]] = {}
    for params in s.scalars(select(TestRun.params).where(TestRun.stage == "convert").order_by(TestRun.id.desc()).limit(200)):
        for entry in ((params or {}).get("toolchain_components") or {}).values():
            if isinstance(entry, dict) and isinstance(entry.get("toolchain"), str) and isinstance(entry.get("components"), dict):
                known.setdefault(entry["toolchain"], entry["components"])
    groups: dict[tuple[str, ...], dict[str, int]] = {}
    for (target, old), count in sorted(stale.items()):
        before = known.get(old)
        changed = tuple(conversion_key.changes(before, conversion_key.components(target))) if before else ("previous components not recorded",)
        group = groups.setdefault(changed, {})
        group[target] = group.get(target, 0) + count
    log = logging.getLogger(__name__)
    out = []
    for changed, targets in groups.items():
        log.log(
            level,
            "Convert key changed for %s (%s): %d stored results invalidated",
            ", ".join(sorted(targets)),
            "; ".join(changed),
            sum(targets.values()),
        )
        out.append({"targets": dict(sorted(targets.items())), "changed": list(changed)})
    total = sum(stale.values())
    log.log(level, "Convert key change invalidates %d stored results of %d rule versions", total, versions)
    return {"results": total, "versions": versions, "groups": out}


def siblings(s: Session, version_ids: list[int]) -> dict[int, list[str]]:
    """The other documents of the file each version lives in (first present occurrence), in file order."""
    out: dict[int, list[str]] = {}
    for vid in version_ids:
        occ = s.scalars(select(Occurrence).where(Occurrence.version_id == vid, Occurrence.present.is_(True)).order_by(Occurrence.id).limit(1)).first()
        if occ is None:
            continue
        rows = s.execute(
            select(RuleVersion.raw)
            .join(Occurrence, Occurrence.version_id == RuleVersion.id)
            .where(Occurrence.source_id == occ.source_id, Occurrence.path == occ.path, Occurrence.present.is_(True), Occurrence.version_id != vid)
            .order_by(Occurrence.doc_index, Occurrence.id)
        )
        out[vid] = [raw for (raw,) in rows]
    return out


def _chunks(items: list[Any], n: int) -> Iterator[list[Any]]:
    for i in range(0, len(items), n):
        yield items[i : i + n]


def _store(s: Session, run_id: int, stage: str, rows: list[tuple[int, str, str, dict[str, Any]]]) -> None:
    existing = {
        (r.version_id, r.target): r
        for r in s.scalars(select(TestResult).where(TestResult.stage == stage, TestResult.version_id.in_({r[0] for r in rows}), TestResult.dataset == ""))
    }
    now = utcnow()
    for vid, target, status, detail in rows:
        row = existing.get((vid, target))
        fingerprint = detail.get("fingerprint")
        if row is None:
            s.add(TestResult(version_id=vid, stage=stage, target=target, dataset="", status=status, detail=detail, fingerprint=fingerprint, run_id=run_id))
        else:
            if row.status != status or (stage == "convert" and row.fingerprint != fingerprint):
                s.add(
                    TestResultHistory(
                        result_id=row.id,
                        fingerprint=row.fingerprint,
                        snapshot={
                            "status": row.status,
                            "detail": row.detail,
                            "run_id": row.run_id,
                            "created_at": row.created_at.isoformat(),
                            "hits": row.hits,
                            "duration": row.duration,
                        },
                    )
                )
            row.status, row.detail, row.run_id, row.created_at = status, detail, run_id, now
            row.fingerprint = fingerprint
    if rows:
        mark_results_changed(s)


def run_stage(
    ws: Workspace,
    s: Session,
    stage: str,
    resume: bool = True,
    workers: int = 8,
    limit: int | None = None,
    progress: Callable[[int, int], None] | None = None,
    retry_resource_failures: bool = False,
    *,
    only: set[int] | None = None,
    deadline: float | None = None,
) -> StageSummary:
    """Run one test stage (validate or convert) on the live corpus and store a result per version and target.

    With resume, versions that already have up-to-date results are skipped. `only` restricts the stage to these
    version ids (e.g. the canonical copy of each logic). `deadline` (a time.monotonic() value, conversion only): no
    rule starts converting after it; the rest stays pending for the next run (StageSummary.deferred)."""
    if stage not in ("validate", "convert"):
        raise ValueError(f"unknown stage {stage}")
    if workers < 1 or (limit is not None and limit < 0):
        raise ValueError("workers must be positive and limit must be nonnegative")
    if stage == "convert" and not BACKENDS:
        log.warning("no pySigma conversion backend installed: conversion skipped (%s)", conversion.INSTALL_HINT)
        return StageSummary(stage, 0, 0, {})
    from sigharvest.db_compact import history_limit, prune_test_history

    retained = history_limit()
    with mutation_lease(ws) as lease:
        lease.assert_owned()
        # The exclusive workspace lease proves that no previous writer is alive.
        # Keep committed results: completion belongs to each result, not its run.
        s.execute(
            update(TestRun).where(TestRun.status == "running", TestRun.stage.in_(("validate", "convert"))).values(status="interrupted", finished_at=utcnow())
        )
        s.commit()

        def prune() -> None:
            s.flush()
            connection = s.connection().connection.driver_connection
            assert connection is not None
            prune_test_history(connection, retained)

        try:
            recovery = conversion_spills.recover(ws) if stage == "convert" else {}
            summary = _run_stage(ws, s, stage, resume, workers, limit, progress, recovery, retry_resource_failures, only=only, deadline=deadline)
            prune()
            # Release the read transaction opened by stage_counts before its
            # fencing lease ends, so callers can safely reuse this session.
            s.commit()
            return summary
        except BaseException as exc:
            # SIGTERM may unwind after SQLite committed but before SQLAlchemy
            # finished its commit transition. rollback() rejects that state.
            # close() resets the reusable session and rolls back only active work;
            # committed batches survive, then recovery uses a fresh transaction.
            s.close()
            try:
                s.execute(
                    update(TestRun)
                    .where(TestRun.status == "running", TestRun.stage.in_(("validate", "convert")))
                    .values(
                        status="cancelled" if isinstance(exc, (Cancelled, KeyboardInterrupt)) or cancellation_requested() else "interrupted",
                        finished_at=utcnow(),
                    )
                )
                if not isinstance(exc, conversion_output.CleanupFailure):
                    prune()
                s.commit()
            except Exception:  # noqa: BLE001 - preserve the original stage failure; recovery retries cleanup
                s.rollback()
                log.warning("Test history cleanup deferred until the next stage or db compact")
            raise


def _run_stage(
    ws: Workspace,
    s: Session,
    stage: str,
    resume: bool,
    workers: int,
    limit: int | None,
    progress: Callable[[int, int], None] | None,
    recovery: dict[str, int | float],
    retry_resource_failures: bool = False,
    *,
    only: set[int] | None = None,
    deadline: float | None = None,
) -> StageSummary:
    """Execute a stage while its caller holds the workspace mutation lease."""
    if stage not in ("validate", "convert"):
        raise ValueError(f"unknown stage {stage}")
    live = list(s.scalars(select(RuleVersion.id).where(RuleVersion.id.in_(live_version_ids())).order_by(RuleVersion.id)))
    if only is not None:
        live = [vid for vid in live if vid in only]
    schema_cache = ws.cache / "sigma-specification" / SPEC_COMMIT
    space.before_test(ws, s, 0, schema_cache)  # schema download; result growth is admitted once the work is known
    schemas = load_schemas(ws) if stage == "validate" else {}
    tags = None
    if stage == "validate" and live:
        from sigharvest import pysigma_tags

        tags = pysigma_tags.prepare(ws.cache)
    skipped_tags = tags.skipped if tags else ()
    notes = list(tags.notes) if tags else []
    key_report: dict[str, Any] = {}
    done = _done(s, stage, schemas, key_report, retry_resource_failures, skipped_tags=skipped_tags) if resume else set()
    todo_ids = [vid for vid in live if vid not in done][: limit or None]
    # Only the versions this run writes results for: a resumed stage on a large corpus has most of them done.
    space.before_test(ws, s, len(todo_ids), schema_cache)
    params: dict[str, Any] = {"resume": resume, "workers": workers, "limit": limit, "spec_commit": SPEC_COMMIT, **recovery, **key_report}
    if only is not None:
        params["selection"] = "subset"
    if stage == "convert":
        from sigharvest import conversion_key

        params["toolchain"] = {t: conversion.toolchain(t) for t in BACKENDS}
        # Recorded so a later key change can name the components that changed.
        params["toolchain_components"] = {t: {"toolchain": conversion.toolchain(t), "components": conversion_key.components(t)} for t in BACKENDS}
    else:
        params["toolchain"] = validation_toolchain(schemas, skipped_tags)
        if skipped_tags:
            params["skipped_tag_catalogues"] = list(skipped_tags)
    run = TestRun(stage=stage, params=params)
    s.add(run)
    s.commit()
    processed = 0
    if not todo_ids:  # nothing new: no process pool (starting it imports pySigma in every worker)
        run.finished_at, run.status = utcnow(), "ok"
        s.commit()
        return StageSummary(stage, 0, len(live), stage_counts(s, stage), notes=notes)
    if stage == "convert":
        return _scheduled_conversion(ws, s, run, todo_ids, len(live), workers, progress, deadline)
    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker, initargs=(schemas, stage, tags.data if tags else None)) as pool:
        # No barrier between batches: every idle worker takes the next version at once, so one slow rule never
        # stalls the others. At most `window` versions are in flight; results are stored as they arrive.
        window = max(64, workers * 16)
        pending: dict[Future[list[tuple[int, str, str, dict[str, Any]]]], int] = {}
        rows: list[tuple[int, str, str, dict[str, Any]]] = []
        finished = 0
        flush_every = 0  # commit every completed chunk-size worth of versions (resume granularity)
        regex_refused = [0]

        def flush() -> None:
            nonlocal rows, processed
            if not rows and not finished - processed:
                return
            try:
                _store(s, run.id, stage, rows)
                s.commit()
            except Exception:
                s.rollback()
                raise
            rows = []
            processed = finished
            if progress:
                progress(processed, len(todo_ids))

        def drain(block_until: int) -> None:
            nonlocal finished
            while len(pending) > block_until:
                done_set, _ = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done_set:
                    pending.pop(fut)
                    result = fut.result()
                    regex_refused[0] += sum(1 for row in result if refused_regex(row[3]))
                    rows.extend(result)
                    finished += 1
                    if finished - processed >= flush_every:
                        flush()

        for ids in _chunks(todo_ids, 200):
            # Only the versions to test are loaded (with their text), 200 at a time.
            batch = list(s.scalars(select(RuleVersion).where(RuleVersion.id.in_(ids)).order_by(RuleVersion.id)))
            flush_every = flush_every or len(ids)
            for v in batch:
                fut = pool.submit(_validate_batch, [(v.id, v.kind, v.raw)])
                pending[fut] = v.id
                drain(window)
        drain(0)
        flush()
    run.finished_at, run.status = utcnow(), "ok"
    s.commit()
    return StageSummary(stage, processed, len(live) - len(todo_ids), stage_counts(s, stage), regex_refused[0], notes=notes)


# Consecutive worker losses with no conversion in between before the stage gives up. A loss
# isolated to one rule's target is recorded as resource_failure and the stage continues.
MAX_LOSSES_WITHOUT_PROGRESS = 3
RESOURCE_FAILURE = "resource_failure"


@dataclass
class Losses:
    """Worker losses of one stage; resource rows of a run of failures wait for proof the workers are sound."""

    gated: bool = False
    streak: int = 0
    total: int = 0
    held: list[tuple[int, str, str, dict[str, Any]]] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    # Rules left without a result because a worker died for a reason that depends on the
    # host (signal, OOM killer); converted again by the next run.
    unconverted: list[dict[str, Any]] = field(default_factory=list)

    def progress(self) -> list[tuple[int, str, str, dict[str, Any]]]:
        self.streak = 0
        held, self.held = self.held, []
        return held

    def lost(self, exc: conversion_memory.WorkerLost) -> None:
        self.total += 1
        if exc.setup:
            raise conversion_memory.ResourceFailure(
                "conversion resource failure: worker lost: memory protection unavailable during setup "
                f"(address-space cap at most {conversion_memory.WORKER_ADDRESS_SPACE_BYTES} bytes). " + self._outcome()
            ) from None
        self.streak += 1
        if self.streak >= MAX_LOSSES_WITHOUT_PROGRESS:
            raise conversion_memory.ResourceFailure(
                f"conversion resource failure: worker lost {self.streak} times in a row without converting anything "
                f"(last: a worker {exc.reason}; address-space cap {conversion_memory.WORKER_ADDRESS_SPACE_BYTES} bytes per worker). " + self._outcome()
            ) from None

    def rule_lost(self, rows: list[tuple[int, str, str, dict[str, Any]]]) -> None:
        """Every target of one rule lost its worker. Only pool losses count toward the abort
        (a few giant rules in a row are not a broken platform); the rows wait for a success."""
        self.held += rows

    def _outcome(self) -> str:
        if self.gated:
            return "This update is gated: nothing was published and the published corpus is unchanged. Fix the cause, then run the update again."
        return "Results converted before the failure are saved. Check worker memory/platform, then resume with `sigharvest test --stage convert`."


def _isolated(
    item: tuple[int, str, str, list[str]],
    attempt: conversion_spills.Attempt,
    expected: dict[str, tuple[str, str]],
    losses: Losses,
) -> tuple[list[tuple[int, str, str, dict[str, Any]]], list[tuple[int, str, str, dict[str, Any]]], list[str]]:
    """Convert one rule that was in flight when a worker died, alone; then target by target.

    Returns the converted rows, a resource_failure row for each target that hit the
    address-space cap, and the reasons of losses that depend on the host (not cached).
    """
    vid = item[0]

    def once(targets: list[str]) -> list[tuple[int, str, str, dict[str, Any]]]:
        attempt.discard(vid)
        with conversion_memory.pool(ProcessPoolExecutor, 1, _init_worker) as pool:
            receipt = pool.submit(conversion_output.owned_spill, item, targets, attempt.ticket, _convert_one).result()
        return conversion_output.receive(receipt, attempt.slot(vid), vid, {t: expected[t] for t in targets})

    try:
        return once(list(BACKENDS)), [], []
    except conversion_memory.WorkerLost as lost:
        if lost.setup:
            losses.lost(lost)
    rows: list[tuple[int, str, str, dict[str, Any]]] = []
    failed: list[tuple[int, str, str, dict[str, Any]]] = []
    uncached: list[str] = []
    for target in BACKENDS:
        try:
            rows += once([target])
        except conversion_memory.WorkerLost as lost:
            if lost.setup:
                losses.lost(lost)
            if lost.cause == conversion_memory.MEMORY_EXIT:
                log.warning("rule version %d: the %s conversion worker %s; recorded as %s", vid, target, lost.reason, RESOURCE_FAILURE)
                failed.append(_resource_row(vid, target, lost, expected[target]))
            else:
                log.warning("rule version %d: the %s conversion worker %s; left unconverted for the next run", vid, target, lost.reason)
                uncached.append(f"{target}: the conversion worker {lost.reason}")
    return rows, failed, uncached


def resource_key(key: str) -> str:
    """Key of a resource_failure: the result key plus the address-space cap it hit, so raising the cap retries it."""
    return digest([key, RESOURCE_FAILURE, conversion_memory.WORKER_ADDRESS_SPACE_BYTES])


def _resource_row(vid: int, target: str, lost: conversion_memory.WorkerLost, binding: tuple[str, str]) -> tuple[int, str, str, dict[str, Any]]:
    """Cached under the current key and cap like a timeout; `sigharvest test --retry-resource-failures` converts it again."""
    reason = f"the conversion worker {lost.reason} on this rule; retry with `sigharvest test --stage convert --retry-resource-failures`"
    detail = conversion.Conversion(target, RESOURCE_FAILURE, reason=reason).detail()
    if detail["toolchain"] != binding[0]:
        raise conversion_output.OutputFailure("conversion toolchain changed during the stage; resume unfinished work")
    detail["fingerprint"] = resource_key(binding[1])
    detail["address_space_bytes"] = conversion_memory.WORKER_ADDRESS_SPACE_BYTES
    return vid, target, RESOURCE_FAILURE, detail


def _scheduled_conversion(
    ws: Workspace,
    s: Session,
    run: TestRun,
    selected: list[int],
    live_count: int,
    workers: int,
    progress: Callable[[int, int], None] | None,
    deadline: float | None = None,
) -> StageSummary:
    """Cost-order a fixed selection and publish bounded batches of whole rules (none started after `deadline`)."""
    schedule = conversion_scheduling
    budget = conversion_memory.memory_budget()
    workers = conversion_memory.admit_workers(workers, budget)
    queue = schedule.jobs(s, selected)
    output = conversion_output
    pending_output = output.pending_output_bytes(workers)
    # Reserve complete spill slots, one read/decoding slot and the publication buffer.
    slots = (pending_output - output.BUFFER_OUTPUT_BYTES - output.RULE_REPLY_BYTES) // output.RULE_REPLY_BYTES
    if slots < 1 or output.BUFFER_OUTPUT_BYTES < output.RULE_REPLY_BYTES:
        raise ValueError("conversion output budgets cannot hold one complete rule")
    window = min(max(1, workers * 4), slots)
    flush_every = len(next(_chunks(selected, schedule.RESULT_BATCH_SIZE)))
    stats = schedule.Admission()
    run.params = {
        **run.params,
        "scheduling": schedule.SCHEDULING_VERSION,
        "selected_count": len(selected),
        "selected_digest": digest(selected),
        "order_digest": digest([job.version_id for job in queue]),
        "max_pending_tasks": window,
        "max_pending_bytes": schedule.MAX_PENDING_BYTES,
        "result_batch_size": flush_every,
        "target_reply_bytes": output.TARGET_REPLY_BYTES,
        "rule_reply_bytes": output.RULE_REPLY_BYTES,
        "pending_output_bytes": pending_output,
        "buffer_output_bytes": output.BUFFER_OUTPUT_BYTES,
        "ipc_receipt_bytes": output.IPC_RECEIPT_BYTES,
        "output_protocol": output.PROTOCOL,
        "memory_contract": conversion_memory.CONTRACT,
        "worker_address_space_bytes": conversion_memory.WORKER_ADDRESS_SPACE_BYTES,
        "conversion_memory_bytes": budget,
        "parent_reserve_bytes": conversion_memory.PARENT_RESERVE_BYTES,
        "admitted_workers": workers,
    }
    s.commit()
    processed = 0
    finished = 0
    buffered_bytes = 0
    buffered: list[tuple[int, str, str, dict[str, Any]]] = []
    peak_buffered = 0
    reply_bytes = 0
    max_reply = 0
    bindings: dict[int, dict[str, tuple[str, str]]] = {}
    # Time left follows estimated work (input bytes plus a per-rule cost), not rule counts: a giant keyword rule costs
    # as much as hundreds of ordinary ones. A progress callback with a `work` attribute receives (done, total) of it.
    weights = {job.version_id: schedule.work(job) for job in queue}
    total_work = sum(weights.values())
    done_work = 0
    report_work = getattr(progress, "work", None)

    def flush() -> None:
        nonlocal processed, buffered_bytes, buffered
        if not buffered:
            return
        _store(s, run.id, "convert", buffered)
        run.params = {
            **run.params,
            "completed_count": finished,
            "peak_pending_bytes": stats.peak_bytes,
            "peak_pending_tasks": stats.peak_tasks,
            "peak_reserved_output_bytes": stats.peak_tasks * output.RULE_REPLY_BYTES + output.BUFFER_OUTPUT_BYTES + output.RULE_REPLY_BYTES,
            "peak_buffered_output_bytes": peak_buffered,
            "reply_bytes": reply_bytes,
            "max_reply_bytes": max_reply,
        }
        s.commit()
        processed = finished
        buffered, buffered_bytes = [], 0
        if report_work:
            report_work(done_work, total_work)
        if progress:
            progress(processed, len(selected))

    def bind(item: tuple[int, str, str, list[str]]) -> dict[str, tuple[str, str]]:
        _, kind, raw, siblings_raw = item
        raw_key = text_digest(raw)
        sibling_keys = [text_digest(raw) for raw in siblings_raw]
        return {target: (key := conversion.toolchain(target), result_key(key, raw_key, kind, sibling_keys)) for target in BACKENDS}

    def consume(receipt: Any, attempt: conversion_spills.Attempt) -> None:
        nonlocal buffered_bytes, reply_bytes, max_reply, peak_buffered, finished, done_work
        if type(receipt) is not output.Receipt or type(receipt.version_id) is not int or receipt.version_id not in bindings:
            raise output.OutputFailure("conversion output resource failure: unexpected or duplicate receipt; resume unfinished work")
        cost = receipt.size
        if type(cost) is not int or not 0 <= cost <= output.RULE_REPLY_BYTES:
            raise output.OutputFailure("conversion output resource failure: invalid receipt size; resume unfinished work")
        if buffered_bytes + cost > output.BUFFER_OUTPUT_BYTES:
            flush()
        rows = output.receive(receipt, attempt.slot(receipt.version_id), receipt.version_id, bindings.pop(receipt.version_id))
        buffered.extend(rows)
        del rows
        buffered_bytes += cost
        reply_bytes += cost
        max_reply = max(max_reply, cost)
        peak_buffered = max(peak_buffered, buffered_bytes)
        finished += 1
        done_work += weights.get(receipt.version_id, 0)
        if finished - processed >= flush_every or buffered_bytes >= output.BUFFER_OUTPUT_BYTES:
            flush()

    consumed: set[int] = set()
    losses = Losses(gated=update_publication.gated())
    remaining = list(queue)
    with conversion_spills.create(ws) as attempt:
        while remaining:
            try:
                with conversion_memory.pool(ProcessPoolExecutor, workers, _init_worker) as pool:

                    def submit(job: conversion_scheduling.Job) -> Future[Any]:
                        item = schedule.load(s, job)
                        bindings[job.version_id] = bind(item)
                        return pool.submit(output.owned_spill, item, BACKENDS, attempt.ticket, _convert_one)

                    results = schedule.admitted_results(
                        remaining,
                        submit,
                        max_tasks=window,
                        max_bytes=schedule.MAX_PENDING_BYTES,
                        stats=stats,
                        before_tail_wait=flush,
                        deadline=deadline,
                    )
                    try:
                        for receipt in results:
                            consume(receipt, attempt)
                            consumed.add(receipt.version_id)
                            buffered.extend(losses.progress())
                    finally:
                        results.close()
                remaining = []
            except conversion_memory.WorkerLost as lost:
                # Results received before the loss are complete and valid.
                flush()
                suspects = [job for job in remaining if job.version_id in bindings]
                bindings.clear()
                losses.lost(lost)
                log.warning("conversion worker lost (a worker %s); converting %d in-flight rules one at a time", lost.reason, len(suspects))
                # Each suspect gets its own one-worker pool; together no more than the admitted workers.
                items = [conversion_scheduling.load(s, job) for job in suspects]
                if workers == 1 or len(items) == 1:
                    results_by_rule = [_isolated(item, attempt, bind(item), losses) for item in items]
                else:
                    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as isolation:
                        outcomes = [isolation.submit(_isolated, item, attempt, bind(item), losses) for item in items]
                        results_by_rule = [outcome.result() for outcome in outcomes]
                for job, (rows, failed, uncached) in zip(suspects, results_by_rule, strict=True):
                    consumed.add(job.version_id)
                    if rows:
                        buffered.extend(losses.progress())
                    if uncached:
                        # Never a partial target set: the whole rule waits for the next run.
                        losses.unconverted.append({"version_id": job.version_id, "reasons": uncached})
                        flush()
                        continue
                    losses.failures += [{"version_id": job.version_id, "target": row[1], "reason": row[3]["reason"]} for row in failed]
                    if rows:
                        buffered.extend([*rows, *failed])
                    else:
                        losses.rule_lost(failed)
                    finished += 1
                    done_work += weights.get(job.version_id, 0)
                    flush()
                remaining = [job for job in remaining if job.version_id not in consumed]
            finally:
                bindings.clear()
        # The last rules may all have failed; nothing followed to prove the workers sound.
        buffered.extend(losses.progress())
        flush()
        if losses.total:
            run.params = {
                **run.params,
                "worker_losses": losses.total,
                "resource_failures": losses.failures[:200],
                "unconverted": losses.unconverted[:200],
                "unconverted_count": len(losses.unconverted),
            }
            s.commit()
            if losses.unconverted:
                log.warning("%d rule versions left unconverted after worker losses; the next run converts them", len(losses.unconverted))
    deferred = len(selected) - finished - len(losses.unconverted)
    if deferred > 0:
        run.params = {**run.params, "deferred_count": deferred}
        log.warning("conversion stopped at its deadline: %d rule versions left for the next run", deferred)
    run.finished_at, run.status = utcnow(), "ok"
    s.commit()
    return StageSummary("convert", processed, live_count - len(selected), stage_counts(s, "convert"), deferred=max(0, deferred))


def stage_counts(s: Session, stage: str) -> dict[str, dict[str, int]]:
    """Stored results of a stage on the live corpus: target -> status -> count."""
    live = live_version_ids()
    rows = s.execute(
        select(TestResult.target, TestResult.status, func.count())
        .where(TestResult.stage == stage, TestResult.version_id.in_(live), TestResult.dataset == "")
        .group_by(TestResult.target, TestResult.status)
    )
    out: dict[str, dict[str, int]] = {}
    for target, status, n in rows:
        out.setdefault(target, {})[status] = n
    return out
