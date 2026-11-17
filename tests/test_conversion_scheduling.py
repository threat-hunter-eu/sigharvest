"""Deterministic completion barriers exercise scheduling without worker sleeps."""

import os
from concurrent.futures import Future

import pytest
from sqlalchemy import insert, select

from sigharvest import conversion, fingerprints, testing
from sigharvest import conversion_scheduling as schedule
from sigharvest.models import Occurrence, RuleVersion, Source, TestResult, TestRun
from tests.test_conversion import BASE, CORRELATION, DNS, LINUX_NET
from tests.test_versioned_results import InlinePool, ingest
from tests.test_versioned_results import corpus as _corpus

corpus = _corpus


def test_global_order_across_metadata_chunks_and_stable_ties(corpus):
    _, factory, _ = corpus
    with factory() as s:
        source_id = s.scalar(select(Source.id))
        versions = [
            dict(id=1000 + i, content_hash=str(i), logic_hash=str(i), rule_id=str(i), kind="rule", raw="x" * (9000 if i % 200 == 0 else 10)) for i in range(403)
        ]
        s.execute(insert(RuleVersion), versions)
        s.execute(insert(Occurrence), [dict(version_id=v["id"], source_id=source_id, path=str(v["id"]), file_hash="x") for v in versions])
        s.commit()
        ids = [v["id"] for v in versions]
        ordered = schedule.jobs(s, ids[::-1])
        # Largest first, so the giants never form the last minutes' tail; equal sizes in ID order.
        assert [j.version_id for j in ordered[:3]] == [1000, 1200, 1400]
        assert len({j.version_id for j in ordered}) == 403
        assert ordered == schedule.jobs(s, ids)
        assert [j.version_id for j in ordered[3:]] == sorted(set(ids) - {1000, 1200, 1400})
        assert schedule.work(ordered[0]) == 9000 + schedule.RULE_OVERHEAD_BYTES


def test_admission_waits_for_bytes_and_count_without_bypassing_head(monkeypatch):
    queue = [schedule.Job(i, "rule", n) for i, n in enumerate([3, 3, 8, 9])]
    submitted, barriers = [], []
    stats = schedule.Admission()

    def submit(job):
        f = Future()
        submitted.append((job.version_id, f))
        return f

    def complete(pending, **kwargs):
        barriers.append([i for i, _ in submitted])
        f = next(iter(pending))
        f.set_result(next(i for i, candidate in submitted if candidate is f))
        return {f}, set(pending) - {f}

    monkeypatch.setattr(schedule, "wait", complete)
    assert list(schedule.admitted_results(queue, submit, max_tasks=2, max_bytes=10, stats=stats)) == [0, 1, 2, 3]
    assert barriers == [[0, 1], [0, 1], [0, 1, 2], [0, 1, 2, 3]]
    assert stats.peak_bytes == 9 and stats.peak_tasks == 2


def test_oversized_input_refused_before_any_submission():
    with pytest.raises(schedule.InputBudgetExceeded, match="admission limit"):
        list(schedule.admitted_results([schedule.Job(1, "rule", 1), schedule.Job(2, "rule", 11)], lambda job: pytest.fail(), max_tasks=2, max_bytes=10))


def test_generator_cancellation_cancels_queued_work(monkeypatch):
    futures = []

    def submit(job):
        future = Future()
        futures.append(future)
        if job.version_id == 0:
            future.set_result(0)
        return future

    output = schedule.admitted_results([schedule.Job(i, "rule", 1) for i in range(5)], submit, max_tasks=2)
    assert next(output) == 0
    output.close()
    assert len(futures) == 2 and futures[1].cancelled()


def test_limit_precedes_order_and_repeated_limits_cannot_starve(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        expected = list(s.scalars(select(RuleVersion.id).order_by(RuleVersion.id)))
        first = s.get(RuleVersion, expected[0])
        first.raw += "#" + "large" * 1000
        s.commit()
        for vid in expected:
            assert testing.run_stage(ws, s, "convert", workers=1, limit=1).processed == 1
            latest = s.scalar(select(TestRun.id).order_by(TestRun.id.desc()))
            assert set(s.scalars(select(TestResult.version_id).where(TestResult.run_id == latest))) == {vid}
        assert testing.run_stage(ws, s, "convert", workers=4).processed == 0


def test_interruption_preserves_committed_keys_and_all_remaining_work(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(schedule, "RESULT_BATCH_SIZE", 1)

    def stop(done, total):
        assert done == 1 and total == 3
        raise KeyboardInterrupt

    with factory() as s:
        with pytest.raises(KeyboardInterrupt):
            testing.run_stage(ws, s, "convert", workers=1, progress=stop)
        kept = list(s.execute(select(TestResult.id, TestResult.fingerprint, TestResult.created_at)))
        old = s.scalar(select(TestRun))
        assert old.status == "cancelled" and len(kept) == len(conversion.BACKENDS)
        assert old.params["selected_count"] == 3 and old.params["completed_count"] == 1
        assert testing.run_stage(ws, s, "convert", workers=4).processed == 2
        assert list(s.execute(select(TestResult.id, TestResult.fingerprint, TestResult.created_at).where(TestResult.run_id == old.id))) == kept
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0


def test_correlation_bytes_and_context_follow_first_live_occurrence(corpus):
    _, factory, root = corpus
    with factory() as s:
        ingest(s, root, "corr.yml", BASE + "---\n" + CORRELATION)
        corr = s.scalar(select(RuleVersion).where(RuleVersion.kind == "correlation"))
        job = schedule.jobs(s, [corr.id])[0]
        assert job.input_bytes == len((corr.raw + BASE).encode())
        assert schedule.load(s, job) == (corr.id, "correlation", corr.raw, testing.siblings(s, [corr.id])[corr.id])
        with pytest.raises(schedule.InputBudgetExceeded, match="admission limit"):
            list(schedule.admitted_results([job], lambda job: pytest.fail(), max_tasks=1, max_bytes=len(corr.raw.encode())))


def test_utf8_size_is_bytes_not_characters(corpus):
    _, factory, _ = corpus
    with factory() as s:
        row = s.scalar(select(RuleVersion))
        row.raw = "é🙂"
        s.commit()
        assert schedule.jobs(s, [row.id])[0].input_bytes == 6


def test_capability_policy_and_backend_changes_invalidate_but_scheduler_does_not(monkeypatch):
    original = fingerprints.source_digest
    conversion.toolchain.cache_clear()
    try:
        before = conversion.toolchain("splunk")
        monkeypatch.setattr(
            fingerprints,
            "source_digest",
            lambda m: "next" if m in {"testing.py", "conversion_scheduling.py", "conversion_output.py"} else original(m),
        )
        conversion.toolchain.cache_clear()
        assert conversion.toolchain("splunk") == before
        monkeypatch.setattr(conversion, "SELECTION_VERSION", conversion.SELECTION_VERSION + 1)
        conversion.toolchain.cache_clear()
        assert conversion.toolchain("splunk") != before
        changed = conversion.toolchain("splunk")
        old_version = fingerprints.package_version
        monkeypatch.setattr(fingerprints, "package_version", lambda p: "next" if p == "pysigma-backend-splunk" else old_version(p))
        conversion.toolchain.cache_clear()
        assert conversion.toolchain("splunk") != changed
    finally:
        conversion.toolchain.cache_clear()


@pytest.mark.backend("microsoft365defender")
def test_only_existing_capability_proof_avoids_backend(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unsupported/partial contract invoked backend")

    with monkeypatch.context() as patch:
        patch.setattr(conversion, "_entry", forbidden)
        result = conversion.convert(DNS, "microsoft365defender")
        assert result.status == "unsupported"
        assert result.results[0].reason == conversion.plan("microsoft365defender", "windows", "dns_query", None).unsupported
        assert not result.queries
        assert conversion.convert(LINUX_NET, "microsoft365defender").status == "partial"
    # No pipeline does not prove a successful raw query: the backend must still run.
    calls = []
    entry = conversion._entry

    def counted(*args):
        calls.append(args)
        return entry(*args)

    monkeypatch.setattr(conversion, "_entry", counted)
    raw = conversion.convert(LINUX_NET, "splunk")
    assert raw.status == "raw" and raw.queries and calls
    # Newly supported categories must reach the backend, never a cached failure.
    monkeypatch.setitem(conversion.MDE_TABLES, "dns_query", "DeviceNetworkEvents")
    calls.clear()
    conversion.convert(DNS, "microsoft365defender")
    assert calls


@pytest.mark.backend("microsoft365defender")
def test_new_capability_retests_stored_unsupported_result(corpus, monkeypatch):
    ws, factory, root = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["microsoft365defender"])
    conversion.toolchain.cache_clear()
    try:
        with factory() as s:
            ingest(s, root, "dns.yml", DNS)
            vid = s.scalar(select(RuleVersion.id).where(RuleVersion.raw == DNS))
            testing.run_stage(ws, s, "convert", workers=1)
            row = s.scalar(select(TestResult).where(TestResult.version_id == vid))
            assert row.status == "unsupported"
            before = row.fingerprint
            monkeypatch.setitem(conversion.MDE_TABLES, "dns_query", "DeviceNetworkEvents")
            monkeypatch.setattr(conversion, "SELECTION_VERSION", conversion.SELECTION_VERSION + 1)
            monkeypatch.setattr(conversion, "_run", lambda target, *args: conversion.Conversion(target, "ok", queries=["new support"]))
            conversion.toolchain.cache_clear()
            assert vid not in testing._done(s, "convert")
            testing.run_stage(ws, s, "convert", workers=4)
            s.refresh(row)
            assert row.status == "ok" and row.fingerprint != before
    finally:
        conversion.toolchain.cache_clear()


def test_failed_submission_leaves_no_silent_skip(corpus, monkeypatch):
    ws, factory, _ = corpus

    class BrokenPool(InlinePool):
        def submit(self, *args):
            raise RuntimeError("injected submission barrier")

    monkeypatch.setattr(testing, "ProcessPoolExecutor", BrokenPool)
    with factory() as s:
        with pytest.raises(RuntimeError, match="submission barrier"):
            testing.run_stage(ws, s, "convert", workers=1)
        assert testing._done(s, "convert") == set()
        assert s.scalar(select(TestRun)).status == "interrupted"
        monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 3


def test_zero_limit_is_unlimited_and_oversized_graph_stays_resumable(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        with monkeypatch.context() as patch:
            patch.setattr(schedule, "MAX_PENDING_BYTES", 1)
            patch.setattr(schedule, "load", lambda *args: pytest.fail("loaded input before admission"))
            with pytest.raises(schedule.InputBudgetExceeded):
                testing.run_stage(ws, s, "convert", workers=1, limit=0)
        assert testing._done(s, "convert") == set()
        assert s.scalar(select(TestRun)).params["selected_count"] == 3
        assert testing.run_stage(ws, s, "convert", workers=1, limit=0).processed == 3


def test_publish_ordinary_remainder_before_waiting_for_large_tail(monkeypatch):
    monkeypatch.setattr(schedule, "TAIL_INPUT_BYTES", 50)
    seen, published = [], []
    giant = Future()

    def submit(job):
        if job.version_id == 2:
            return giant
        first = Future()
        first.set_result(1)
        return first

    def barrier(pending, **kwargs):
        ready = {f for f in pending if f.done()}
        if not ready:
            assert published == [[1]]  # publication must precede releasing the slow completion
            giant.set_result(2)
            ready = {giant}
        return ready, set(pending) - ready

    monkeypatch.setattr(schedule, "wait", barrier)
    for result in schedule.admitted_results(
        [schedule.Job(1, "rule", 1), schedule.Job(2, "rule", 100)],
        submit,
        max_tasks=2,
        before_tail_wait=lambda: published.append(list(seen)),
    ):
        seen.append(result)
    assert seen == [1, 2]


def test_memory_admission_reserves_parent_and_limits_workers():
    from sigharvest import conversion_memory as memory

    budget = 3 * 1024**3
    assert memory.admit_workers(1, budget) == 1
    assert memory.admit_workers(2, budget) == 2
    admitted = memory.admit_workers(100, budget)
    assert admitted == 4
    assert admitted * memory.WORKER_ADDRESS_SPACE_BYTES + memory.PARENT_RESERVE_BYTES <= budget


def test_memory_budget_follows_host_memory_and_admits_requested_workers(monkeypatch):
    from sigharvest import conversion_memory as memory

    monkeypatch.delenv(memory.MEMORY_ENV, raising=False)
    # This host: 22 cores and about 24 GB available.
    monkeypatch.setattr(memory, "available_memory", lambda: 24 * 1000**3)
    budget = memory.memory_budget()
    assert budget == int(24 * 1000**3 * memory.MEMORY_FRACTION)
    assert memory.admit_workers(20) == 20
    assert memory.admit_workers(64) == (budget - memory.PARENT_RESERVE_BYTES) // memory.WORKER_ADDRESS_SPACE_BYTES == 20
    assert memory.WORKER_ADDRESS_SPACE_BYTES == 512 * 1024**2
    # Unknown host memory keeps the previous fixed budget; low memory still admits one worker.
    monkeypatch.setattr(memory, "available_memory", lambda: None)
    assert memory.memory_budget() == memory.CONVERSION_MEMORY_BYTES and memory.admit_workers(20) == 4
    monkeypatch.setattr(memory, "available_memory", lambda: 256 * 1024**2)
    assert memory.admit_workers(20) == 1


@pytest.mark.parametrize(("value", "expected"), [("8G", 8 * 1024**3), ("6144M", 6 * 1024**3), ("2GiB", 2 * 1024**3), (str(2**31), 2**31)])
def test_memory_budget_override(monkeypatch, value, expected):
    from sigharvest import conversion_memory as memory

    monkeypatch.setattr(memory, "available_memory", lambda: 1024**4)
    monkeypatch.setenv(memory.MEMORY_ENV, value)
    assert memory.memory_budget() == expected


@pytest.mark.parametrize("value", ["lots", "0", "-1G", "G"])
def test_invalid_memory_budget_override_fails_closed(monkeypatch, value):
    from sigharvest import conversion_memory as memory

    monkeypatch.setenv(memory.MEMORY_ENV, value)
    with pytest.raises(memory.ResourceFailure, match=memory.MEMORY_ENV):
        memory.admit_workers(2)


def test_available_memory_reads_meminfo(tmp_path):
    from sigharvest import conversion_memory as memory

    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       32000000 kB\nMemFree:  100 kB\nMemAvailable:   24000000 kB\n")
    assert memory.available_memory(str(meminfo)) == 24000000 * 1024
    meminfo.write_text("MemTotal:       32000000 kB\n")
    assert memory.available_memory(str(meminfo)) is None
    assert memory.available_memory(str(tmp_path / "missing")) is None


def test_output_window_grows_with_admitted_workers():
    from sigharvest import conversion_output as output

    def slots(workers):
        return (output.pending_output_bytes(workers) - output.BUFFER_OUTPUT_BYTES - output.RULE_REPLY_BYTES) // output.RULE_REPLY_BYTES

    assert output.pending_output_bytes(1) == output.pending_output_bytes(6) == output.PENDING_OUTPUT_BYTES
    assert all(slots(n) >= n for n in range(1, 63))
    assert output.pending_output_bytes(1000) == output.MAX_PENDING_OUTPUT_BYTES
    from sigharvest import conversion_spills

    assert conversion_spills.MAX_WORK_BYTES >= output.MAX_PENDING_OUTPUT_BYTES


def test_requested_workers_take_effect_up_to_the_budget(corpus, monkeypatch):
    from sigharvest import conversion_memory as memory

    ws, factory, root = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setenv(memory.MEMORY_ENV, str(memory.PARENT_RESERVE_BYTES + 12 * memory.WORKER_ADDRESS_SPACE_BYTES))
    with factory() as s:
        ingest(s, root, "dns.yml", DNS)
        testing.run_stage(ws, s, "convert", workers=20)
        params = s.scalars(select(TestRun.params).where(TestRun.stage == "convert")).one()
        assert params["admitted_workers"] == 12 and params["max_pending_tasks"] >= 12
        assert params["conversion_memory_bytes"] == memory.PARENT_RESERVE_BYTES + 12 * memory.WORKER_ADDRESS_SPACE_BYTES


def test_missing_memory_primitive_fails_before_submission(corpus, monkeypatch):
    from sigharvest import conversion_memory as memory

    ws, factory, _ = corpus
    monkeypatch.setattr(memory.sys, "platform", "unsupported")
    monkeypatch.setattr(testing, "ProcessPoolExecutor", lambda **kwargs: pytest.fail("submitted unprotected work"))
    with factory() as s:
        with pytest.raises(memory.ResourceFailure, match="protection unavailable"):
            testing.run_stage(ws, s, "convert", workers=2)
        assert testing._done(s, "convert") == set()
        assert s.scalar(select(TestRun)).status == "interrupted"


def test_memory_install_refuses_host_process():
    from sigharvest import conversion_memory as memory

    with pytest.raises(memory.ResourceFailure, match=r"only.*child"):
        memory.install()
    with pytest.raises(memory.ResourceFailure, match=r"only.*child"):
        memory.initialize(testing._init_worker)


def wait_for_cancel(path):
    import time
    from pathlib import Path

    Path(path).write_text("ready")
    time.sleep(60)


def test_cancel_terminates_running_child_promptly(tmp_path):
    import time
    from concurrent.futures import ProcessPoolExecutor

    from sigharvest import conversion_memory as memory

    processes = []
    ready = tmp_path / "ready"
    # The production forkserver pool: a forked copy of a long-lived xdist worker can
    # already map more than the worker cap, which makes install() refuse by design.
    # Timing starts once the workers are up, so it measures cancellation only.
    with pytest.raises(KeyboardInterrupt), memory.pool(ProcessPoolExecutor, 2, testing._init_worker) as pool:
        start = time.monotonic()
        pool.submit(wait_for_cancel, str(ready))
        processes = list(pool._processes.values())
        while not ready.exists() and time.monotonic() - start < 4:
            time.sleep(0.01)
        assert ready.exists()
        raise KeyboardInterrupt
    assert time.monotonic() - start < 5
    assert processes and all(not p.is_alive() for p in processes)


@pytest.mark.parametrize("primitive", ["address_space", "exception_monitor"])
def test_missing_worker_memory_primitives_are_explicit(monkeypatch, primitive):
    import resource

    from sigharvest import conversion_memory as memory

    if primitive == "address_space":
        monkeypatch.delattr(resource, "RLIMIT_AS")
    else:
        monkeypatch.delattr(memory.sys, "monitoring")
    with pytest.raises(memory.ResourceFailure, match="protection unavailable"):
        memory.admit_workers(1)


def test_memory_budget_does_not_invalidate_semantic_keys(monkeypatch):
    from sigharvest import conversion_memory as memory

    before = conversion.toolchain("splunk")
    monkeypatch.setattr(memory, "WORKER_ADDRESS_SPACE_BYTES", 256 * 1024**2)
    monkeypatch.setattr(memory, "CONTRACT", "different-admission-only")
    conversion.toolchain.cache_clear()
    assert conversion.toolchain("splunk") == before


def test_no_pending_work_still_recovers_without_republishing(corpus, monkeypatch):
    from sigharvest import conversion_spills
    from tests.test_conversion_output import abandoned

    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        testing.run_stage(ws, s, "convert", workers=1)
        kept = list(s.execute(select(TestResult.__table__)))
        abandoned(ws)
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert list(s.execute(select(TestResult.__table__))) == kept
        run = s.scalar(select(TestRun).order_by(TestRun.id.desc()))
        assert run.params["recovered_attempts"] == 1 and run.params["recovered_bytes"] > 0
        assert conversion_spills.recover(ws)["recovered_attempts"] == 0


def test_cleanup_failure_is_not_stage_success(corpus, monkeypatch):
    from sigharvest import conversion_spills
    from sigharvest.conversion_output import OutputFailure
    from sigharvest.models import TestResultHistory

    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    original = conversion_spills.Attempt.remove

    def fail(attempt):
        raise PermissionError

    monkeypatch.setattr(conversion_spills.Attempt, "remove", fail)
    with factory() as s:
        with pytest.raises(OutputFailure, match="cleanup failed"):
            testing.run_stage(ws, s, "convert", workers=1)
        kept = list(s.execute(select(TestResult.__table__)))
        assert len(kept) == 3 * len(conversion.BACKENDS)
        assert s.scalar(select(TestRun)).status == "interrupted"
        assert s.scalar(select(TestResultHistory)) is None
        monkeypatch.setattr(conversion_spills.Attempt, "remove", original)
        # Simulate the original owner exiting; a still-live identity fails closed.
        monkeypatch.setattr(conversion_spills, "_alive", lambda _: False)
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert list(s.execute(select(TestResult.__table__))) == kept


def _stage_wait_after_commit(root, sender):
    import signal
    from pathlib import Path
    from unittest.mock import patch

    from sigharvest import conversion_output
    from sigharvest.config import Workspace
    from sigharvest.db import session_factory

    def committed(done, total):
        sender.send(done)
        while True:
            signal.pause()

    with (
        patch.object(testing, "ProcessPoolExecutor", InlinePool),
        patch.object(testing, "BACKENDS", ["splunk"]),
        patch.object(schedule, "RESULT_BATCH_SIZE", 1),
        patch.object(conversion_output, "PENDING_OUTPUT_BYTES", 3 * conversion_output.RULE_REPLY_BYTES),
        session_factory(Workspace(Path(root)).db_path)() as session,
    ):
        testing.run_stage(Workspace(Path(root)), session, "convert", workers=1, progress=committed)


def test_sigkill_after_committed_batch_recovers_and_resumes_without_duplicates(corpus, monkeypatch):
    import multiprocessing
    import signal

    from sigharvest import conversion_spills
    from sigharvest.models import TestResultHistory

    ws, factory, _ = corpus
    factory.kw["bind"].dispose()
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    parent = context.Process(target=_stage_wait_after_commit, args=(str(ws.root), sender))
    parent.start()
    sender.close()
    try:
        assert receiver.poll(15) and receiver.recv() == 1
        parent.kill()
        parent.join(10)
        assert parent.exitcode == -signal.SIGKILL
    finally:
        if parent.is_alive():
            parent.kill()
        parent.join()
        parent.close()
        receiver.close()
    assert list((ws.db_path.parent / conversion_spills.ROOT).iterdir())
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    with factory() as s:
        kept = list(s.execute(select(TestResult.__table__)))
        assert len(kept) == 1 and s.scalar(select(TestRun)).status == "running"
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 2
        assert list(s.execute(select(TestResult.__table__).where(TestResult.id == kept[0].id))) == kept
        assert s.scalar(select(TestRun).order_by(TestRun.id)).status == "interrupted"
        assert len(list(s.scalars(select(TestResult)))) == 3
        assert s.scalar(select(TestResultHistory)) is None
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
    assert not list((ws.db_path.parent / conversion_spills.ROOT).iterdir())


def test_cleanup_error_does_not_apply_history_retention(corpus, monkeypatch):
    from sigharvest import conversion_spills
    from sigharvest.conversion_output import CleanupFailure
    from sigharvest.models import TestResultHistory

    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    with factory() as s:
        testing.run_stage(ws, s, "convert", workers=1)
        row = s.scalar(select(TestResult))
        for i in range(10):
            s.add(TestResultHistory(result_id=row.id, fingerprint=str(i), snapshot={"status": "retained"}))
        s.commit()
        history = list(s.execute(select(TestResultHistory.__table__)))

        def fail(attempt):
            raise PermissionError

        monkeypatch.setattr(conversion_spills.Attempt, "remove", fail)
        with pytest.raises(CleanupFailure):
            testing.run_stage(ws, s, "convert", resume=False, workers=1)
        assert list(s.execute(select(TestResultHistory.__table__))) == history


def test_cleanup_inventory_holds_every_slot_of_twenty_workers(corpus):
    """With -j 20 an abort can leave 20+ reserved spills; cleanup must not mask the error."""
    from sigharvest import conversion_output as output
    from sigharvest import conversion_spills

    ws, _, _ = corpus
    workers = 20
    slots = (output.pending_output_bytes(workers) - output.BUFFER_OUTPUT_BYTES - output.RULE_REPLY_BYTES) // output.RULE_REPLY_BYTES
    assert slots >= workers
    for n in range(1, 63):
        reserved = (output.pending_output_bytes(n) - output.BUFFER_OUTPUT_BYTES - output.RULE_REPLY_BYTES) // output.RULE_REPLY_BYTES
        assert reserved + 2 <= conversion_spills.MAX_FILES  # spill slots plus a legacy marker and guard
    with pytest.raises(RuntimeError, match="the real failure"), conversion_spills.create(ws) as attempt:
        for vid in range(1, slots + 1):
            with open(attempt.slot(vid), "xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(b"{}\n")
        raise RuntimeError("the real failure")
    assert conversion_spills.recover(ws)["recovered_attempts"] == 0


@pytest.mark.parametrize("phase", ["after_marker", "after_payload", "before_rmdir"])
def test_empty_resume_recovers_transition_without_changing_results_or_history(corpus, monkeypatch, phase):
    from sigharvest import conversion_spills
    from sigharvest.models import TestResultHistory
    from tests.test_conversion_output import kill_transition

    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    with factory() as s:
        testing.run_stage(ws, s, "convert", workers=1)
        row = s.scalar(select(TestResult))
        s.add(TestResultHistory(result_id=row.id, fingerprint="retained", snapshot={"status": "retained"}))
        s.commit()
        kept = list(s.execute(select(TestResult.__table__)))
        history = list(s.execute(select(TestResultHistory.__table__)))
    factory.kw["bind"].dispose()
    kill_transition(ws, phase)
    with factory() as s:
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert list(s.execute(select(TestResult.__table__))) == kept
        assert list(s.execute(select(TestResultHistory.__table__))) == history
        run = s.scalar(select(TestRun).order_by(TestRun.id.desc()))
        assert run.params["recovered_attempts"] == 1
        assert conversion_spills.recover(ws)["recovered_attempts"] == 0


def test_time_left_follows_work_not_rule_count(monkeypatch):
    from sigharvest.cli import pipeline

    beat = pipeline.Heartbeat("convert")
    beat.started = 900.0
    monkeypatch.setattr(pipeline.time, "monotonic", lambda: 1000.0)
    lines = []
    monkeypatch.setattr(pipeline.log, "info", lambda fmt, text: lines.append(text))
    # 97% of the rules but only half of the work done in 100 s: about 100 s left, not 3 s.
    beat.work(500, 1000)
    beat(97, 100)
    assert lines == ["convert: 97/100 (97%), about 1m40s left"]


def test_no_time_left_before_ten_seconds_and_two_percent(monkeypatch):
    from sigharvest.cli import pipeline

    beat = pipeline.Heartbeat("validate")
    lines = []
    monkeypatch.setattr(pipeline.log, "info", lambda fmt, text: lines.append(text))
    beat.started = 995.0
    monkeypatch.setattr(pipeline.time, "monotonic", lambda: 1000.0)
    beat(50, 1000)  # 5 s in: too early
    beat.last, beat.started = 0.0, 900.0
    beat(10, 1000)  # 1 %: too little
    beat.last = 0.0
    beat(100, 1000)
    assert lines == ["validate: 50/1,000 (5%)", "validate: 10/1,000 (1%)", "validate: 100/1,000 (10%), about 15m00s left"]


def test_scheduled_conversion_reports_work(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    reported = []

    def progress(done, total):
        pass

    progress.work = lambda done, total: reported.append((done, total))
    with factory() as s:
        testing.run_stage(ws, s, "convert", workers=1, progress=progress)
    assert reported and reported[-1][0] == reported[-1][1] > 0


def test_deadline_stops_admission_and_drains_what_was_submitted(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(schedule.time, "monotonic", lambda: clock[0])

    def submit(job):
        future = Future()
        future.set_result(job.version_id)
        clock[0] += 1.0  # each admission takes a second
        return future

    queue = [schedule.Job(i, "rule", 1) for i in range(6)]
    # Admitted at t=0 and t=1 (two slots), then t=2 reaches the deadline: nothing more starts, both results arrive.
    assert sorted(schedule.admitted_results(queue, submit, max_tasks=2, deadline=2.0)) == [0, 1]
    clock[0] = 10.0
    assert list(schedule.admitted_results(queue, submit, max_tasks=2, deadline=5.0)) == []  # already past
    assert sorted(schedule.admitted_results(queue, submit, max_tasks=2)) == list(range(6))  # no deadline


def test_summary_conversion_table_binds_no_id_list(corpus):
    """A full corpus has more live versions than an older SQLite allows bound variables (32,766): the summary report
    failed with "too many SQL variables" after a passed update. The conversion table joins instead of listing ids."""
    import sqlite3

    from sigharvest import report

    _, factory, _ = corpus
    with factory() as s:
        source_id = s.scalar(select(Source.id))
        versions = [dict(id=5000 + i, content_hash=f"c{i}", logic_hash=f"l{i}", rule_id=str(i), kind="rule", raw="x", product="windows") for i in range(40)]
        s.execute(insert(RuleVersion), versions)
        s.execute(insert(Occurrence), [dict(version_id=v["id"], source_id=source_id, path=str(v["id"]), file_hash="x") for v in versions])
        target = conversion.BACKENDS[0] if conversion.BACKENDS else "splunk"
        s.execute(insert(TestResult), [dict(version_id=v["id"], stage="convert", target=target, status="ok", detail={}) for v in versions])
        s.commit()
        raw = s.connection().connection.driver_connection
        raw.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 20)  # fewer than the 40 live versions
        rows, _, _ = report._conversion(s)
    assert any(row[0] == target and row[2] >= 40 for row in rows) or not conversion.BACKENDS
