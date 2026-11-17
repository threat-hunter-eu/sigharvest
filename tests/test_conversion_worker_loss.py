"""A conversion worker that dies on one rule costs that rule, not the stage (decision 522)."""

from __future__ import annotations

import os
import signal
from concurrent.futures import Future

import pytest
from sqlalchemy import select

from sigharvest import conversion_memory, testing, update_publication
from sigharvest import conversion_scheduling as schedule
from sigharvest.models import TestResult, TestRun
from sigharvest.testing_conversion import _convert_one
from tests.conversion_pools import spawn_pool
from tests.test_versioned_results import corpus as _corpus

corpus = _corpus
TARGETS = ["splunk", "microsoft365defender"]
_KILL_TARGET = ""


def kill_one_target(item, targets):
    if item[0] in _CULPRITS and (_KILL_TARGET == "*" or _KILL_TARGET in targets):
        if _HOW == "cap":
            os._exit(conversion_memory.MEMORY_EXIT)  # what the address-space monitor does
        os.kill(os.getpid(), signal.SIGKILL)
    return _convert_one(item, targets)


def kill_everything(item, targets):
    os.kill(os.getpid(), signal.SIGKILL)


_CULPRITS: set[int] = set()
_HOW = "cap"


def culprit_pool(culprits, target, how):
    """Fresh-interpreter workers (tests/conversion_pools.py) told which rule to lose and how."""
    return spawn_pool((__name__, "_CULPRITS", set(culprits)), (__name__, "_KILL_TARGET", target), (__name__, "_HOW", how))


class SerialThreads:
    """Isolation without threads, so each test's worker-loss order stays deterministic.

    Production pools use forkserver; test_parallel_isolation_with_forkserver covers threads."""

    def __init__(self, max_workers):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, *args):
        future = Future()
        try:
            future.set_result(fn(*args))
        except BaseException as exc:  # noqa: BLE001 - delivered through the future like a thread pool
            future.set_exception(exc)
        return future


@pytest.fixture
def forked(monkeypatch):
    monkeypatch.setattr(testing, "ProcessPoolExecutor", spawn_pool())
    monkeypatch.setattr(testing, "ThreadPoolExecutor", SerialThreads)
    monkeypatch.setattr(testing, "BACKENDS", TARGETS)


def _more_rules(s, root, n):
    from tests.test_versioned_results import ingest

    for i in range(n):
        ingest(s, root, f"extra{i}.yml", f"title: extra {i}\nlogsource: {{product: linux}}\ndetection: {{s: {{a: '{i}'}}, condition: s}}\n")


def _rows(s):
    return {(r.version_id, r.target): r for r in s.scalars(select(TestResult))}


@pytest.mark.backend("microsoft365defender")
@pytest.mark.parametrize("workers", [1, 3])
def test_a_rule_that_hits_the_cap_on_one_target_costs_only_that_target(corpus, forked, monkeypatch, workers):
    ws, factory, _ = corpus
    with factory() as s:
        ordered = schedule.jobs(s, [v.id for v in testing.live_versions(s)])
        culprit = ordered[len(ordered) // 2].version_id
        monkeypatch.setattr(testing, "ProcessPoolExecutor", culprit_pool({culprit}, "microsoft365defender", "cap"))
        monkeypatch.setattr(testing, "_convert_one", kill_one_target)
        summary = testing.run_stage(ws, s, "convert", workers=workers)
        assert summary.processed == len(ordered)
        rows = _rows(s)
        assert len(rows) == len(ordered) * len(TARGETS)
        failed = {key for key, row in rows.items() if row.status == testing.RESOURCE_FAILURE}
        assert failed == {(culprit, "microsoft365defender")}
        row = rows[culprit, "microsoft365defender"]
        assert "address-space cap" in row.detail["reason"] and "--retry-resource-failures" in row.detail["reason"]
        assert row.detail["address_space_bytes"] == conversion_memory.WORKER_ADDRESS_SPACE_BYTES
        # Every other result, the culprit's splunk one included, equals a plain conversion.
        for v in testing.live_versions(s):
            for vid, target, status, detail in _convert_one((v.id, v.kind, v.raw, []), TARGETS):
                if (vid, target) not in failed:
                    stored = rows[vid, target]
                    assert stored.status == status and stored.detail["fingerprint"] == detail["fingerprint"]
        run = s.scalars(select(TestRun).order_by(TestRun.id.desc())).first()
        assert run.status == "ok" and run.params["worker_losses"] >= 1
        assert run.params["resource_failures"][0]["version_id"] == culprit
        # Cached under the current key and cap; retried on request or when the cap changes.
        monkeypatch.setattr(testing, "_convert_one", _convert_one)
        assert testing.run_stage(ws, s, "convert", workers=workers).processed == 0
        monkeypatch.setattr(conversion_memory, "WORKER_ADDRESS_SPACE_BYTES", 2 * conversion_memory.WORKER_ADDRESS_SPACE_BYTES)
        assert culprit not in testing._done(s, "convert") and len(testing._done(s, "convert")) == len(ordered) - 1
        monkeypatch.undo()
        monkeypatch.setattr(testing, "ProcessPoolExecutor", spawn_pool())
        monkeypatch.setattr(testing, "ThreadPoolExecutor", SerialThreads)
        monkeypatch.setattr(testing, "BACKENDS", TARGETS)
        assert testing.run_stage(ws, s, "convert", workers=workers, retry_resource_failures=True).processed == 1
        assert all(r.status != testing.RESOURCE_FAILURE for r in s.scalars(select(TestResult)))


@pytest.mark.backend("microsoft365defender")
def test_a_host_dependent_loss_is_not_cached(corpus, forked, monkeypatch):
    """SIGKILL (OOM killer, operator) depends on host load: no row, the next run converts the rule."""
    ws, factory, _ = corpus
    with factory() as s:
        ordered = schedule.jobs(s, [v.id for v in testing.live_versions(s)])
        culprit = ordered[0].version_id
        monkeypatch.setattr(testing, "ProcessPoolExecutor", culprit_pool({culprit}, "splunk", "sigkill"))
        monkeypatch.setattr(testing, "_convert_one", kill_one_target)
        assert testing.run_stage(ws, s, "convert", workers=2).processed == len(ordered) - 1
        assert culprit not in {vid for vid, _ in _rows(s)}
        run = s.scalars(select(TestRun).order_by(TestRun.id.desc())).first()
        assert run.status == "ok" and run.params["unconverted_count"] == 1
        assert "SIGKILL" in run.params["unconverted"][0]["reasons"][0]
        monkeypatch.setattr(testing, "_convert_one", _convert_one)
        assert testing.run_stage(ws, s, "convert", workers=2).processed == 1


def test_giant_rules_failing_in_a_row_do_not_abort(corpus, forked, monkeypatch):
    """One pool loss followed by several rules that lose every target is not a broken platform."""
    ws, factory, _ = corpus
    with factory() as s:
        ordered = schedule.jobs(s, [v.id for v in testing.live_versions(s)])
        culprits = {job.version_id for job in ordered[-3:]}
        monkeypatch.setattr(testing, "ProcessPoolExecutor", culprit_pool(culprits, "*", "cap"))  # every target
        monkeypatch.setattr(testing, "_convert_one", kill_one_target)
        assert testing.run_stage(ws, s, "convert", workers=3).processed == len(ordered)
        statuses = {key: row.status for key, row in _rows(s).items()}
        assert {vid for (vid, _), st in statuses.items() if st == testing.RESOURCE_FAILURE} == culprits


@pytest.mark.parametrize("gated", [False, True])
def test_workers_dying_without_progress_abort_with_an_accurate_message(corpus, forked, monkeypatch, gated):
    ws, factory, root = corpus
    monkeypatch.setattr(testing, "_convert_one", kill_everything)
    monkeypatch.setattr(update_publication, "gated", lambda: gated)
    with factory() as s:
        _more_rules(s, root, 12)
        # One rule in flight per pool: every restart dies again without converting anything.
        with pytest.raises(conversion_memory.ResourceFailure, match="worker lost 3 times in a row") as raised:
            testing.run_stage(ws, s, "convert", workers=1)
        message = str(raised.value)
        if gated:
            assert "nothing was published" in message and "committed" not in message
        else:
            assert "Results converted before the failure are saved" in message
        # No resource_failure row is kept for losses that never proved the workers sound.
        assert s.scalar(select(TestResult)) is None
        assert s.scalar(select(TestRun)).status == "interrupted"


def test_broken_pool_cause_is_read_after_the_manager_reaps_the_workers():
    """The executor's manager thread reaps a broken pool's workers; reading exit codes while it
    still holds a reaped status (waitpid ECHILD in this thread) turned a capped worker into
    "was lost", which left its rule uncached instead of resource_failure."""
    import threading
    import time
    from concurrent.futures.process import BrokenProcessPool

    class Reaped:
        exitcode = None

        def is_alive(self):
            return False

        def join(self, timeout=None):
            pass

    class Executor:
        def __init__(self, **kwargs):
            worker = Reaped()
            self._processes = {1: worker}

            def reap():
                time.sleep(0.2)
                worker.exitcode = conversion_memory.MEMORY_EXIT

            self._executor_manager_thread = threading.Thread(target=reap)
            self._executor_manager_thread.start()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._executor_manager_thread.join()
            return False

        def submit(self, fn, *args):
            future = Future()
            future.set_result(fn(*args))
            return future

    with pytest.raises(conversion_memory.WorkerLost) as raised, conversion_memory.pool(Executor, 1, testing._init_worker):
        raise BrokenProcessPool("a worker died")
    assert raised.value.cause == conversion_memory.MEMORY_EXIT and not raised.value.setup


def test_worker_lost_describes_the_cause():
    lost = conversion_memory.WorkerLost([-15, conversion_memory.MEMORY_EXIT, -15])
    assert lost.reason == f"exceeded its {conversion_memory.WORKER_ADDRESS_SPACE_BYTES} byte address-space cap" and not lost.setup
    assert conversion_memory.WorkerLost([-9]).reason == "was killed by SIGKILL"
    assert conversion_memory.WorkerLost([conversion_memory.SETUP_EXIT]).setup
    assert conversion_memory.WorkerLost([conversion_memory.MEMORY_EXIT], during_setup=True).setup


@pytest.mark.backend("microsoft365defender")
def test_resource_failures_are_scored_reported_and_flagged(corpus, forked, monkeypatch, tmp_path):
    from sigharvest import conversion, index, report, runs

    ws, factory, _ = corpus
    assert "resource_failure" in conversion.APPLICABLE and "resource_failure" in index.SCORED_CONVERSION  # like a timeout
    with factory() as s:
        culprit = schedule.jobs(s, [v.id for v in testing.live_versions(s)])[0].version_id
        monkeypatch.setattr(testing, "ProcessPoolExecutor", culprit_pool({culprit}, "splunk", "cap"))
        monkeypatch.setattr(testing, "_convert_one", kill_one_target)
        testing.run_stage(ws, s, "convert", workers=1)
        counts = runs.corpus_counts(s)
        assert counts["conversion_resource_failures"] == 1
        gate = next(g for g in runs.evaluate(counts | {"sources_enabled": 1}, None, runs.Thresholds()) if g.name == "conversion resource failures")
        assert gate.status == "warn" and "--retry-resource-failures" in gate.detail
        failed = [g for g in runs.evaluate(counts | {"sources_enabled": 1}, None, runs.Thresholds()) if g.status == "fail"]
        assert all(g.name != "conversion resource failures" for g in failed)
        summary = report.build_summary(s, tmp_path / "reports", rule_json=False).read_text()
        assert "worker resource limit" in summary and "1 conversion results hit the per-worker address-space cap" in summary


def kill_marked(item, targets):
    """Picklable by reference for forkserver workers: the culprit is marked in its own text."""
    if "kill-this-worker" in item[2]:
        os._exit(conversion_memory.MEMORY_EXIT)
    return _convert_one(item, targets)


@pytest.mark.backend("microsoft365defender")
def test_parallel_isolation_with_forkserver(corpus, monkeypatch):
    """The production pools (forkserver) with suspects isolated in parallel threads."""
    from tests.test_versioned_results import ingest

    ws, factory, root = corpus
    monkeypatch.setattr(testing, "BACKENDS", TARGETS)
    monkeypatch.setattr(testing, "_convert_one", kill_marked)
    with factory() as s:
        _more_rules(s, root, 6)
        for i in range(2):
            ingest(
                s,
                root,
                f"giant{i}.yml",
                f"title: giant {i}\nlogsource: {{product: linux}}\ndetection: {{s: {{a: kill-this-worker-{i}}}, condition: s}}\n",
            )
        total = len(testing.live_versions(s))
        assert testing.run_stage(ws, s, "convert", workers=4).processed == total
        failed = {vid for (vid, _), row in _rows(s).items() if row.status == testing.RESOURCE_FAILURE}
        marked = {v.id for v in testing.live_versions(s) if "kill-this-worker" in v.raw}
        assert failed == marked and len(marked) == 2
