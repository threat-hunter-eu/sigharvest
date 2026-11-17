"""Reply byte limits, exact envelopes and recoverable publication faults."""

import errno
import hashlib
import json
import multiprocessing
import os
import pickle
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import select

from sigharvest import conversion, conversion_spills, testing
from sigharvest import conversion_output as output
from sigharvest import conversion_scheduling as schedule
from sigharvest.models import TestResult, TestResultHistory, TestRun
from tests.conversion_pools import spawn_pool
from tests.test_conversion import BASE
from tests.test_versioned_results import InlinePool
from tests.test_versioned_results import corpus as _corpus

corpus = _corpus
ITEM = (1, "rule", "tiny", [])
EXPECTED = {"splunk": ("implementation", "input-key")}


def test_complete_real_backend_results_round_trip_exactly(tmp_path):
    from sigharvest.fingerprints import result_key, text_digest
    from sigharvest.testing_conversion import _convert_one

    item = (7, "rule", BASE, [])
    expected_rows = _convert_one(item, conversion.BACKENDS)
    expected_keys = {target: (key := conversion.toolchain(target), result_key(key, text_digest(BASE), "rule", [])) for target in conversion.BACKENDS}
    path = tmp_path / "reply"
    receipt = output.spill(item, conversion.BACKENDS, str(path), lambda *_: expected_rows)
    assert output.receive(receipt, path, item[0], expected_keys) == expected_rows
    assert not path.exists()


def rows(query="é🙂", targets=("splunk",)):
    return [(1, t, "ok", {"toolchain": "implementation", "fingerprint": "input-key", "results": [{"queries": [query, "second"]}]}) for t in targets]


def write(path, value):
    payload = b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for row in value)
    path.write_bytes(payload)
    return output.Receipt(1, len(payload), hashlib.sha256(payload).hexdigest())


def test_exact_unicode_multiple_queries_and_boundary(tmp_path, monkeypatch):
    path = tmp_path / "reply"
    expected_rows = rows()
    size = write(path, expected_rows).size
    path.unlink()
    assert size > len(json.dumps(expected_rows[0], ensure_ascii=False, separators=(",", ":")))
    monkeypatch.setattr(output, "TARGET_REPLY_BYTES", size)
    monkeypatch.setattr(output, "RULE_REPLY_BYTES", size)
    receipt = output.spill(ITEM, ["splunk"], str(path), lambda *_: expected_rows)
    assert receipt.size == size and not receipt.error
    assert output.receive(receipt, path, 1, EXPECTED) == expected_rows
    assert not path.exists()
    monkeypatch.setattr(output, "TARGET_REPLY_BYTES", size - 1)
    receipt = output.spill(ITEM, ["splunk"], str(path), lambda *_: expected_rows)
    assert receipt.error == "reply-cap" and path.stat().st_size < size
    with pytest.raises(output.OutputFailure, match="reply-cap"):
        output.receive(receipt, path, 1, EXPECTED)
    assert not path.exists()


@pytest.mark.parametrize("mb", [1, 8, 32])
def test_small_input_large_bounded_reply(tmp_path, mb):
    path = tmp_path / "reply"
    # 32 MiB is the complete target envelope, not query characters alone.
    empty_size = write(path, rows("")).size
    path.unlink()
    value = rows("x" * (mb * 1024**2 - empty_size))
    receipt = output.spill(ITEM, ["splunk"], str(path), lambda *_, value=value: value)
    assert receipt.size == mb * 1024**2 and not receipt.error
    assert output.receive(receipt, path, 1, EXPECTED) == value


def test_over_cap_and_multi_target_rule_cap(tmp_path, monkeypatch):
    path = tmp_path / "reply"
    monkeypatch.setattr(output, "TARGET_REPLY_BYTES", 1024)
    monkeypatch.setattr(output, "RULE_REPLY_BYTES", 1500)
    for value in [rows("x" * 1024), rows("x" * 700, ("splunk", "sqlite"))]:
        receipt = output.spill(ITEM, ["splunk"], str(path), lambda *_, value=value: value)
        assert receipt.error == "reply-cap"
        assert path.stat().st_size <= 1500
        with pytest.raises(output.OutputFailure):
            output.receive(receipt, path, 1, EXPECTED)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "unexpected", "rule", "implementation", "fingerprint", "digest", "size", "protocol", "malformed"])
def test_bad_envelopes_never_return_rows(tmp_path, fault):
    path = tmp_path / "reply"
    value = rows()
    if fault == "missing":
        value = []
    elif fault == "duplicate":
        value *= 2
    elif fault == "unexpected":
        value = rows(targets=("sqlite",))
    elif fault == "rule":
        value[0] = (2, *value[0][1:])
    elif fault in {"implementation", "fingerprint"}:
        value[0][3]["toolchain" if fault == "implementation" else fault] = "wrong"
    elif fault == "malformed":
        value = [[1]]
    receipt = write(path, value)
    if fault == "digest":
        receipt = replace(receipt, sha256="0" * 64)
    elif fault == "size":
        receipt = replace(receipt, size=receipt.size + 1)
    elif fault == "protocol":
        receipt = replace(receipt, protocol=2)
    with pytest.raises(output.OutputFailure):
        output.receive(receipt, path, 1, EXPECTED)
    assert not path.exists()


def test_disk_full_and_large_exception_are_fixed_receipts(tmp_path, monkeypatch):
    path = tmp_path / "reply"

    def full(*args, **kwargs):
        raise OSError(errno.ENOSPC, "private " * 10000)

    monkeypatch.setattr(output, "open", full, raising=False)
    receipt = output.spill(ITEM, ["splunk"], str(path), lambda *_: rows())
    assert receipt.error == "spill-io" and len(repr(receipt)) < 200
    with pytest.raises(output.OutputFailure, match="spill-io"):
        output.receive(receipt, path, 1, EXPECTED)

    def broken(*_):
        raise ValueError("private " * 10000)

    receipt = output.spill(ITEM, ["splunk"], str(path), broken)
    assert receipt.error == "worker-failure" and len(repr(receipt)) < 200
    assert not path.exists()


def test_ipc_receipt_bound_including_executor_frame():
    from concurrent.futures.process import _ResultItem
    from multiprocessing.reduction import ForkingPickler

    for error in ("", "reply-cap", "spill-io", "worker-failure", "worker-memory", "spill-ownership"):
        receipt = output.Receipt(2**63 - 1, output.RULE_REPLY_BYTES, "f" * 64, error)
        frame = _ResultItem(2**63 - 1, result=receipt)
        assert len(ForkingPickler.dumps(frame, protocol=pickle.HIGHEST_PROTOCOL)) <= output.IPC_RECEIPT_BYTES


def test_disk_full_after_partial_write_closes_and_removes_file(tmp_path, monkeypatch):
    path = tmp_path / "reply"
    handles = []

    class FullFile:
        def __init__(self, filename, mode, **kwargs):
            self.file = open(filename, mode, **kwargs)  # noqa: SIM115 - the fake context closes it in __exit__
            handles.append(self.file)

        def __enter__(self):
            return self

        def write(self, data):
            self.file.write(data)
            self.file.flush()
            if self.file.tell() > 10:
                raise OSError(errno.ENOSPC, "injected disk full")

        def __exit__(self, *args):
            self.file.close()

    monkeypatch.setattr(output, "open", FullFile, raising=False)
    receipt = output.spill(ITEM, ["splunk"], str(path), lambda *_: rows())
    assert receipt.error == "spill-io" and path.stat().st_size > 0
    assert handles and all(handle.closed for handle in handles)
    with pytest.raises(output.OutputFailure, match="spill-io"):
        output.receive(receipt, path, 1, EXPECTED)
    assert not path.exists()


def die_during_spill(item, targets):
    def iterator():
        yield rows("x" * (128 * 1024))[0]
        os._exit(7)

    return iterator()


def test_child_dies_during_spill(tmp_path):
    # A real child dies after its first row; no receipt or completed set exists.
    from tempfile import TemporaryDirectory

    with TemporaryDirectory(dir=tmp_path) as folder:
        child = multiprocessing.get_context("fork").Process(target=output.spill, args=(ITEM, ["splunk"], str(Path(folder) / "1"), die_during_spill))
        child.start()
        child.join(10)
        assert not child.is_alive() and child.exitcode == 7
        child.close()
        assert 0 < (Path(folder) / "1").stat().st_size <= output.TARGET_REPLY_BYTES
    assert list(tmp_path.iterdir()) == []


def test_failure_preserves_prior_commit_and_resumes_only_unfinished(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(schedule, "RESULT_BATCH_SIZE", 1)
    original = testing._convert_one
    calls = []

    def fail_second(item, targets):
        calls.append(item[0])
        if len(calls) == 2:
            raise ValueError("injected failure")
        return original(item, targets)

    monkeypatch.setattr(testing, "_convert_one", fail_second)
    # Keep completion order deterministic in this publication fault probe.
    monkeypatch.setattr(output, "PENDING_OUTPUT_BYTES", 3 * output.RULE_REPLY_BYTES)
    with factory() as s:
        with pytest.raises(output.OutputFailure, match="worker-failure"):
            testing.run_stage(ws, s, "convert", workers=1)
        kept = list(s.execute(select(TestResult.id, TestResult.fingerprint, TestResult.created_at)))
        assert len(kept) == len(conversion.BACKENDS)
        assert s.scalar(select(TestRun)).status == "interrupted"
        assert s.scalar(select(TestResultHistory)) is None
        monkeypatch.setattr(testing, "_convert_one", original)
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 2
        assert list(s.execute(select(TestResult.id, TestResult.fingerprint, TestResult.created_at).where(TestResult.id.in_([r.id for r in kept])))) == kept
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0


def test_actual_buffer_bytes_and_owned_files_on_cancellation(corpus, monkeypatch, tmp_path):
    ws, factory, _ = corpus
    directories = []
    real_worker = testing._convert_one
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    monkeypatch.setattr(output, "TARGET_REPLY_BYTES", 4096)
    monkeypatch.setattr(output, "RULE_REPLY_BYTES", 4096)
    monkeypatch.setattr(output, "BUFFER_OUTPUT_BYTES", 4096)
    monkeypatch.setattr(output, "PENDING_OUTPUT_BYTES", 5 * 4096)

    original_create = conversion_spills.create

    @contextmanager
    def directory(workspace):
        with original_create(workspace) as attempt:
            directories.append(Path(attempt.ticket.root) / attempt.ticket.name)
            yield attempt

    def amplified(item, targets):
        result = real_worker(item, targets)
        detail = result[0][3]
        result[0] = (item[0], "splunk", "ok", {"toolchain": detail["toolchain"], "fingerprint": detail["fingerprint"], "queries": ["x" * 2500]})
        return result

    monkeypatch.setattr(conversion_spills, "create", directory)
    monkeypatch.setattr(testing, "_convert_one", amplified)

    def cancel(done, total):
        assert done == 1
        raise KeyboardInterrupt

    with factory() as s:
        with pytest.raises(KeyboardInterrupt):
            testing.run_stage(ws, s, "convert", workers=1, progress=cancel)
        assert len(list(s.scalars(select(TestResult)))) == 1
        params = s.scalar(select(TestRun)).params
        assert 2500 < params["peak_buffered_output_bytes"] <= 4096
        assert params["peak_reserved_output_bytes"] <= 5 * 4096
        assert directories and all(not p.exists() for p in directories)
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 2
        assert directories and all(not p.exists() for p in directories)


def killed_worker(item, targets):
    import signal

    os.kill(os.getpid(), signal.SIGKILL)


def test_broken_pool_cleans_spills_and_leaves_all_work_pending(corpus, monkeypatch, tmp_path):
    ws, factory, _ = corpus
    directories = []
    original_create = conversion_spills.create

    @contextmanager
    def directory(workspace):
        with original_create(workspace) as attempt:
            directories.append(Path(attempt.ticket.root) / attempt.ticket.name)
            yield attempt

    monkeypatch.setattr(conversion_spills, "create", directory)
    monkeypatch.setattr(testing, "ProcessPoolExecutor", spawn_pool())
    monkeypatch.setattr(testing, "_convert_one", killed_worker)
    with factory() as s:
        # SIGKILL depends on the host: every rule is left unconverted, none is cached (decision 522).
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert testing._done(s, "convert") == set()
        run = s.scalar(select(TestRun))
        assert run.status == "ok" and run.params["unconverted_count"] == len(testing.live_versions(s))
        assert directories and all(not p.exists() for p in directories)


def test_rejected_refresh_preserves_results_and_history(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        testing.run_stage(ws, s, "convert", workers=1)
        row = s.scalar(select(TestResult))
        changed_status = "warning" if row.status != "warning" else "error"
        testing._store(s, row.run_id, "convert", [(row.version_id, row.target, changed_status, row.detail)])
        s.commit()
        kept = list(s.execute(select(TestResult.id, TestResult.status, TestResult.fingerprint, TestResult.created_at, TestResult.detail)))
        history = list(s.execute(select(TestResultHistory.__table__)))
        assert history
        monkeypatch.setattr(output, "TARGET_REPLY_BYTES", 1)
        progress = []
        with pytest.raises(output.OutputFailure, match="reply-cap"):
            testing.run_stage(ws, s, "convert", workers=1, resume=False, progress=lambda *args: progress.append(args))
        assert not progress
        assert list(s.execute(select(TestResult.id, TestResult.status, TestResult.fingerprint, TestResult.created_at, TestResult.detail))) == kept
        assert list(s.execute(select(TestResultHistory.__table__))) == history


def memory_bomb(catch=False):
    blocks = []
    try:
        while True:
            blocks.append(bytearray(1024**2))
    except MemoryError:
        if not catch:
            raise
    # A backend that swallows MemoryError must never reach this success.
    return rows("partial result disguised as success")


def limited_bomb(catch):
    from sigharvest import conversion_memory as memory

    memory.install()
    memory_bomb(catch)
    os._exit(99)


@pytest.mark.parametrize("catch", [False, True])
def test_real_growth_before_serialization_cannot_be_swallowed(catch):
    import resource

    from sigharvest import conversion_memory as memory

    before = resource.getrlimit(resource.RLIMIT_AS)
    # A fresh interpreter: a forked copy of a long-lived xdist worker can already
    # map more than the worker cap, which makes install() refuse by design.
    child = multiprocessing.get_context("spawn").Process(target=limited_bomb, args=(catch,))
    child.start()
    try:
        child.join(15)  # parent is an external watchdog, never allocates the bomb
        assert not child.is_alive()
        assert child.exitcode == memory.MEMORY_EXIT
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        child.close()
    assert resource.getrlimit(resource.RLIMIT_AS) == before
    assert bytearray(1024**2)  # caller remains usable


def test_uncaught_memory_error_is_a_resource_receipt(tmp_path):
    def fail(*args):
        raise MemoryError

    path = tmp_path / "reply"
    receipt = output.spill(ITEM, ["splunk", "sqlite"], str(path), fail)
    assert receipt.error == "worker-memory"
    with pytest.raises(output.OutputFailure, match="worker-memory"):
        output.receive(receipt, path, 1, EXPECTED)
    assert not path.exists()


_FAIL_MEMORY_ID = -1


def fail_selected_memory(item, targets):
    from sigharvest.testing_conversion import _convert_one

    if item[0] == _FAIL_MEMORY_ID:
        # First create a complete source/target result, then fail before the
        # whole rule can be serialized. Neither source nor target may publish.
        _convert_one(item, targets[:1])
        memory_bomb(catch=True)
    return _convert_one(item, targets)


@pytest.mark.backend("microsoft365defender")
def test_real_memory_failure_after_commit_and_resume(corpus, monkeypatch, tmp_path):
    from sigharvest import conversion_memory as memory

    ws, factory, _ = corpus
    directories = []
    original_create = conversion_spills.create

    @contextmanager
    def directory(workspace):
        with original_create(workspace) as attempt:
            directories.append(Path(attempt.ticket.root) / attempt.ticket.name)
            yield attempt

    monkeypatch.setattr(conversion_spills, "create", directory)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk", "microsoft365defender"])
    monkeypatch.setattr(schedule, "RESULT_BATCH_SIZE", 1)
    monkeypatch.setattr(output, "PENDING_OUTPUT_BYTES", 3 * output.RULE_REPLY_BYTES)
    with factory() as s:
        ids = list(s.scalars(select(testing.RuleVersion.id)))
        ordered = schedule.jobs(s, ids)
        # Fresh-interpreter workers (see tests/conversion_pools.py) get the culprit explicitly.
        monkeypatch.setattr(testing, "ProcessPoolExecutor", spawn_pool((__name__, "_FAIL_MEMORY_ID", ordered[1].version_id)))
        original = testing._convert_one
        monkeypatch.setattr(testing, "_convert_one", fail_selected_memory)
        progress = []
        # A real address-space failure on one rule no longer aborts the stage (decision 522):
        # that rule is recorded as resource_failure for each target, the others convert.
        assert testing.run_stage(ws, s, "convert", workers=1, progress=lambda *args: progress.append(args)).processed == 3
        assert progress[-1] == (3, 3)
        rows = {(r.version_id, r.target): r for r in s.scalars(select(TestResult))}
        culprit = ordered[1].version_id
        for (vid, _target), row in rows.items():
            if vid == culprit:
                assert row.status == "resource_failure"
                assert f"exceeded its {memory.WORKER_ADDRESS_SPACE_BYTES} byte address-space cap" in row.detail["reason"]
                assert row.detail["fingerprint"] == row.fingerprint and row.detail["toolchain"]
            else:
                assert row.status != "resource_failure"
        assert s.scalar(select(TestRun)).status == "ok"
        assert directories and all(not p.exists() for p in directories)
        assert testing._done(s, "convert") == {job.version_id for job in ordered}
        kept = list(s.execute(select(TestResult.id, TestResult.fingerprint, TestResult.created_at).where(TestResult.version_id != culprit)))
        monkeypatch.setattr(testing, "_convert_one", original)
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert testing.run_stage(ws, s, "convert", workers=1, retry_resource_failures=True).processed == 1
        assert all(r.status != "resource_failure" for r in s.scalars(select(TestResult)))
        assert list(s.execute(select(TestResult.id, TestResult.fingerprint, TestResult.created_at).where(TestResult.id.in_([r.id for r in kept])))) == kept
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert directories and all(not p.exists() for p in directories)


def failed_initialization(*args):
    raise MemoryError


def test_worker_initialization_failure_is_resumable(corpus, monkeypatch):
    from sigharvest import conversion_memory as memory

    ws, factory, _ = corpus
    # Fresh interpreters: a forked large parent would fail setup for the wrong reason.
    monkeypatch.setattr(testing, "ProcessPoolExecutor", spawn_pool())
    monkeypatch.setattr(testing, "_init_worker", failed_initialization)
    with factory() as s:
        with pytest.raises(memory.ResourceFailure, match="memory protection unavailable"):
            testing.run_stage(ws, s, "convert", workers=1)
        assert testing._done(s, "convert") == set()
        assert s.scalar(select(TestResult)) is None
        assert s.scalar(select(TestRun)).status == "interrupted"


def inherit_soft_limit(path):
    import resource

    from sigharvest import conversion_memory as memory

    mapped = int(memory.open_statm().split()[0]) * os.sysconf("SC_PAGE_SIZE")
    wanted = mapped + 32 * 1024**2
    assert wanted < memory.WORKER_ADDRESS_SPACE_BYTES
    _, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (wanted, hard))
    memory.install()
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    Path(path).write_text(json.dumps([wanted, soft, hard]))


def test_child_preserves_lower_inherited_soft_limit(tmp_path):
    import resource

    before = resource.getrlimit(resource.RLIMIT_AS)
    path = tmp_path / "limits"
    # A fresh interpreter: a forked copy of a long-lived xdist worker can already
    # map more than the worker cap, which makes install() refuse by design.
    child = multiprocessing.get_context("spawn").Process(target=inherit_soft_limit, args=(str(path),))
    child.start()
    try:
        child.join(10)
        assert not child.is_alive() and child.exitcode == 0
        wanted, soft, hard = json.loads(path.read_text())
        assert soft == hard == wanted
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        child.close()
    assert resource.getrlimit(resource.RLIMIT_AS) == before


def limited_complete_spill(path, sender):
    from sigharvest import conversion_memory as memory

    memory.install()
    overhead = len(json.dumps(rows("")[0], ensure_ascii=False, separators=(",", ":")).encode()) + 1
    value = rows("x" * (output.TARGET_REPLY_BYTES - overhead))
    sender.send(output.spill(ITEM, ["splunk"], path, lambda *_: value))
    sender.close()


def test_limited_child_preserves_exact_32_mib_target(tmp_path):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    path = tmp_path / "reply"
    child = context.Process(target=limited_complete_spill, args=(str(path), sender))
    child.start()
    sender.close()
    try:
        assert receiver.poll(10)
        receipt = receiver.recv()
        child.join(10)
        assert not child.is_alive() and child.exitcode == 0
        assert receipt.size == output.TARGET_REPLY_BYTES and not receipt.error
        received = output.receive(receipt, path, 1, EXPECTED)
        overhead = len(json.dumps(rows("")[0], ensure_ascii=False, separators=(",", ":")).encode()) + 1
        assert received == rows("x" * (output.TARGET_REPLY_BYTES - overhead))
        assert not path.exists()
    finally:
        receiver.close()
        if child.is_alive():
            child.kill()
        child.join()
        child.close()


def abandon_spill(root, sender, protocol=2):
    from sigharvest.config import Workspace

    ws = Workspace(Path(root))
    with conversion_spills.create(ws) as attempt:
        path = attempt.slot(1)
        path.write_bytes(b"incomplete query")
        path.chmod(0o600)
        if protocol == 1:
            directory = Path(attempt.ticket.root) / attempt.ticket.name
            data = json.loads(os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE))
            guard = directory / "guard"
            guard.touch(mode=0o600)
            data.update(protocol=1, guard=guard.stat().st_ino)
            marker = directory / "marker"
            marker.write_text(json.dumps(data))
            marker.chmod(0o600)
            os.removexattr(directory, conversion_spills.OWNER_ATTRIBUTE)
        sender.send(attempt.ticket)
        sender.close()
        os._exit(0)


def abandoned(ws, protocol=2):
    ws.db_path.parent.mkdir(parents=True, exist_ok=True)
    ctx = multiprocessing.get_context("fork")
    receiver, sender = ctx.Pipe(duplex=False)
    child = ctx.Process(target=abandon_spill, args=(str(ws.root), sender, protocol))
    child.start()
    sender.close()
    try:
        assert receiver.poll(10)
        ticket = receiver.recv()
        child.join(10)
        assert child.exitcode == 0
        return ticket
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        child.close()
        receiver.close()


@pytest.mark.parametrize("protocol", [1, 2])
def test_recovery_removes_only_eligible_spills_and_is_idempotent(tmp_path, protocol):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    legacy = tmp_path / "sigharvest-conversion-legacy"
    legacy.mkdir()
    (legacy / "query").write_text("retain")
    ticket = abandoned(ws, protocol)
    directory = Path(ticket.root) / ticket.name
    total = sum(p.stat().st_size for p in directory.iterdir())
    if protocol == 2:
        total += len(os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE))
    result = conversion_spills.recover(ws)
    assert result["recovered_attempts"] == 1 and result["recovered_bytes"] == total
    assert not directory.exists() and (legacy / "query").read_text() == "retain"
    assert conversion_spills.recover(ws)["recovered_bytes"] == 0
    assert output.owned_spill(ITEM, ["splunk"], ticket, lambda *_: pytest.fail("late task ran")).error == "spill-ownership"
    assert not directory.exists()


@pytest.mark.parametrize("fault", ["partial", "unknown", "workspace", "pid", "symlink", "hardlink", "mode", "owner", "path", "legacy", "bytes"])
@pytest.mark.parametrize("protocol", [1, 2])
def test_recovery_refuses_unverifiable_inventory(tmp_path, monkeypatch, fault, protocol):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws, protocol)
    directory = Path(ticket.root) / ticket.name
    marker = directory / "marker"

    def write_marker(raw):
        if protocol == 1:
            marker.write_text(raw)
        else:
            os.setxattr(directory, conversion_spills.OWNER_ATTRIBUTE, raw.encode())

    data = json.loads(marker.read_text() if protocol == 1 else os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE))
    if fault == "partial":
        write_marker('{"protocol":')
    elif fault in {"workspace", "pid", "path"}:
        if fault == "workspace":
            data["workspace"] = "other workspace"
        elif fault == "pid":
            data["pid"] = os.getpid()
            data["process"] = conversion_spills._process_identity(os.getpid())
        else:
            data["attempt"] = "../outside"
        write_marker(json.dumps(data))
    elif fault == "unknown":
        (directory / "unknown").write_text("retain")
    elif fault == "symlink":
        (directory / "1").unlink()
        (directory / "1").symlink_to(directory)
    elif fault == "hardlink":
        os.link(directory / "1", directory / "2")
    elif fault == "mode":
        directory.chmod(0o755)
    elif fault == "owner":
        monkeypatch.setattr(conversion_spills.os, "geteuid", lambda: -1)
    elif fault == "legacy":
        if protocol == 1:
            marker.unlink()
        else:
            os.removexattr(directory, conversion_spills.OWNER_ATTRIBUTE)
    elif fault == "bytes":
        monkeypatch.setattr(conversion_spills, "MAX_WORK_BYTES", 1)
    kept = tree_snapshot(directory)
    with pytest.raises(output.OutputFailure, match="recovery refused"):
        conversion_spills.recover(ws)
    assert tree_snapshot(directory) == kept


def test_recovery_pid_reuse_requires_free_kernel_guard(tmp_path, monkeypatch):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    monkeypatch.setattr(conversion_spills, "_alive", lambda _: True)
    monkeypatch.setattr(conversion_spills, "_process_identity", lambda _: "different-boot-or-process")
    with conversion_spills.attach(ticket), pytest.raises(output.OutputFailure, match="active parent or worker"):
        conversion_spills.recover(ws)
    assert conversion_spills.recover(ws)["recovered_attempts"] == 1


def hold_worker(ticket, pipe):
    with conversion_spills.attach(ticket) as attempt:
        pipe.send("writing")
        assert pipe.recv() == "finish"
        with attempt.slot(1).open("ab") as stream:
            stream.write(b"still alive")


def test_dead_parent_live_writer_blocks_recovery(tmp_path):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    ctx = multiprocessing.get_context("fork")
    parent, child_pipe = ctx.Pipe()
    child = ctx.Process(target=hold_worker, args=(ticket, child_pipe))
    child.start()
    child_pipe.close()
    try:
        assert parent.poll(10) and parent.recv() == "writing"
        directory = Path(ticket.root) / ticket.name
        kept = tree_snapshot(directory)
        with pytest.raises(output.OutputFailure, match="active parent or worker"):
            conversion_spills.recover(ws)
        assert tree_snapshot(directory) == kept
        parent.send("finish")
        child.join(10)
        assert child.exitcode == 0
        assert conversion_spills.recover(ws)["recovered_attempts"] == 1
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        child.close()
        parent.close()


def test_recovery_revalidates_after_inventory_and_refuses_delayed_start(tmp_path, monkeypatch):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    marker = Path(ticket.root) / ticket.name / "marker"
    original = conversion_spills.Attempt.remove

    def changed(attempt):
        assert output.owned_spill(ITEM, ["splunk"], ticket, lambda *_: pytest.fail("late task wrote")).error == "spill-ownership"
        os.setxattr(marker.parent, conversion_spills.OWNER_ATTRIBUTE, b"{}")
        return original(attempt)

    monkeypatch.setattr(conversion_spills.Attempt, "remove", changed)
    with pytest.raises(output.OutputFailure, match="invalid marker"):
        conversion_spills.recover(ws)
    assert (marker.parent / "1").exists()


def test_recovery_inventory_limit_and_permission_failure(tmp_path, monkeypatch):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    with monkeypatch.context() as patch:
        patch.setattr(conversion_spills, "MAX_ATTEMPTS", 0)
        with pytest.raises(output.OutputFailure, match="inventory limit"):
            conversion_spills.recover(ws)
    original = os.unlink

    def denied(name, **kwargs):
        if name == "1":
            raise PermissionError
        return original(name, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(conversion_spills.os, "unlink", denied)
        with pytest.raises(output.OutputFailure, match="cleanup failed"):
            conversion_spills.recover(ws)
    assert (Path(ticket.root) / ticket.name / "1").exists()
    assert conversion_spills.recover(ws)["recovered_attempts"] == 1


def test_attempt_and_root_symlinks_are_never_followed(tmp_path):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    directory = Path(ticket.root) / ticket.name
    moved = directory.with_name("kept")
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises(output.OutputFailure):
        conversion_spills.recover(ws)
    directory.unlink()
    moved.rename(directory)
    root = Path(ticket.root)
    moved_root = root.with_name("foreign")
    root.rename(moved_root)
    root.symlink_to(moved_root, target_is_directory=True)
    with pytest.raises(output.OutputFailure):
        conversion_spills.recover(ws)
    assert (moved_root / ticket.name / "1").exists()


def test_worker_open_before_recovery_cannot_acquire_after_removal(tmp_path, monkeypatch):
    import threading

    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    opened, proceed = threading.Event(), threading.Event()
    original = conversion_spills._opened
    replies = []

    @contextmanager
    def delayed(name, flags, parent=None):
        with original(name, flags, parent) as fd:
            if name == ticket.name and threading.current_thread().name == "delayed-writer":
                opened.set()
                assert proceed.wait(10)
            yield fd

    monkeypatch.setattr(conversion_spills, "_opened", delayed)
    worker = threading.Thread(
        target=lambda: replies.append(output.owned_spill(ITEM, ["splunk"], ticket, lambda *_: pytest.fail("late writer ran"))),
        name="delayed-writer",
    )
    worker.start()
    try:
        assert opened.wait(10)
        assert conversion_spills.recover(ws)["recovered_attempts"] == 1
    finally:
        proceed.set()
        worker.join(10)
    assert not worker.is_alive() and replies[0].error == "spill-ownership"
    assert not (Path(ticket.root) / ticket.name).exists()


def test_moving_attempt_to_another_workspace_is_not_adoption(tmp_path):
    from sigharvest.config import Workspace

    first, second = Workspace(tmp_path / "first"), Workspace(tmp_path / "second")
    ticket = abandoned(first)
    second.db_path.parent.mkdir(parents=True)
    conversion_spills.recover(second)
    moved = second.db_path.parent / conversion_spills.ROOT / ticket.name
    (Path(ticket.root) / ticket.name).rename(moved)
    with pytest.raises(output.OutputFailure, match="workspace binding"):
        conversion_spills.recover(second)
    assert (moved / "1").exists()


def test_receive_refuses_symlink_without_unlinking_it(tmp_path):
    target = tmp_path / "foreign"
    receipt = write(target, rows())
    link = tmp_path / "slot"
    link.symlink_to(target)
    with pytest.raises(output.OutputFailure, match="unsafe-spill"):
        output.receive(receipt, link, 1, EXPECTED)
    assert link.is_symlink() and target.exists()


def tree_snapshot(directory):
    """Exact names, stable metadata, link targets and bytes without following links."""
    result = {}
    for path in directory.iterdir():
        info = path.lstat()
        metadata = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns)
        result[path.name] = (metadata, os.readlink(path) if path.is_symlink() else path.read_bytes())
    return result


def transition_child(root, phase, sender, recovery=False):
    """SIGKILL only at an explicit post-syscall/pre-syscall barrier."""
    import signal
    from unittest.mock import patch

    from sigharvest.config import Workspace

    def stop():
        sender.send(phase)
        sender.close()
        while True:
            signal.pause()

    mkdir, setxattr, unlink, rmdir = os.mkdir, os.setxattr, os.unlink, os.rmdir

    def make(name, *args, **kwargs):
        result = mkdir(name, *args, **kwargs)
        if len(str(name)) == 32 and phase == "after_mkdir":
            stop()
        return result

    def mark(*args, **kwargs):
        if phase == "before_marker":
            stop()
        result = setxattr(*args, **kwargs)
        if phase == "after_marker":
            stop()
        return result

    def delete(name, *args, **kwargs):
        if name == "1" and phase == "before_payload":
            stop()
        result = unlink(name, *args, **kwargs)
        if (
            (name == "1" and phase == "after_payload")
            or (name == "marker" and phase == "after_legacy_marker")
            or (name == "guard" and phase == "after_legacy_guard")
        ):
            stop()
        return result

    def remove(*args, **kwargs):
        if phase == "before_rmdir":
            stop()
        result = rmdir(*args, **kwargs)
        if phase == "after_rmdir":
            stop()
        return result

    ws = Workspace(Path(root))
    with patch.object(os, "mkdir", make), patch.object(os, "setxattr", mark), patch.object(os, "unlink", delete), patch.object(os, "rmdir", remove):
        if recovery:
            conversion_spills.recover(ws)
        else:
            with conversion_spills.create(ws) as attempt:
                for vid in (1, 2):
                    path = attempt.slot(vid)
                    path.write_bytes(b"partial query")
                    path.chmod(0o600)


def kill_transition(ws, phase, *, recovery=False):
    import signal

    ws.db_path.parent.mkdir(parents=True, exist_ok=True)
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    child = context.Process(target=transition_child, args=(str(ws.root), phase, sender, recovery))
    child.start()
    sender.close()
    try:
        assert receiver.poll(15) and receiver.recv() == phase
        child.kill()
        child.join(10)
        assert child.exitcode == -signal.SIGKILL
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        child.close()
        receiver.close()


@pytest.mark.parametrize("phase", ["after_mkdir", "before_marker", "after_marker", "before_payload", "after_payload", "before_rmdir", "after_rmdir"])
def test_sigkill_ownership_transitions(tmp_path, phase):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    kill_transition(ws, phase)
    root = ws.db_path.parent / conversion_spills.ROOT
    directories = list(root.iterdir())
    if phase in {"after_mkdir", "before_marker"}:
        assert len(directories) == 1 and tree_snapshot(directories[0]) == {}
        for _ in range(2):
            with pytest.raises(output.CleanupFailure):
                conversion_spills.recover(ws)
            assert list(root.iterdir()) == directories and tree_snapshot(directories[0]) == {}
        return
    expected = {"after_marker": set(), "before_payload": {"1", "2"}, "after_payload": {"2"}, "before_rmdir": set()}
    if phase != "after_rmdir":
        assert len(directories) == 1
        assert set(tree_snapshot(directories[0])) == expected[phase]
        assert json.loads(os.getxattr(directories[0], conversion_spills.OWNER_ATTRIBUTE))["protocol"] == 2
    assert conversion_spills.recover(ws)["recovered_attempts"] == (phase != "after_rmdir")
    assert list(root.iterdir()) == []
    assert conversion_spills.recover(ws)["recovered_attempts"] == 0


@pytest.mark.parametrize("phase", ["before_payload", "after_payload", "before_rmdir", "after_rmdir"])
def test_sigkill_recovery_itself_is_idempotent(tmp_path, phase):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    directory = Path(ticket.root) / ticket.name
    original = os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE)
    kill_transition(ws, phase, recovery=True)
    if phase != "after_rmdir":
        assert os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE) == original
        assert set(tree_snapshot(directory)) == ({"1"} if phase == "before_payload" else set())
        # Interrupt another recovery with its original evidence still unchanged.
        kill_transition(ws, "before_rmdir", recovery=True)
        assert os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE) == original
    assert conversion_spills.recover(ws)["recovered_attempts"] == (phase != "after_rmdir")
    assert conversion_spills.recover(ws)["recovered_attempts"] == 0


@pytest.mark.parametrize("error", [28, 13, 95])
def test_marker_publication_failure_preserves_unproven_directory(tmp_path, monkeypatch, error):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ws.db_path.parent.mkdir(parents=True)

    def fail(*args, **kwargs):
        raise OSError(error, "injected")

    monkeypatch.setattr(os, "setxattr", fail)
    with pytest.raises(output.CleanupFailure), conversion_spills.create(ws):
        pytest.fail("unpublished ticket escaped")
    root = ws.db_path.parent / conversion_spills.ROOT
    directories = list(root.iterdir())
    assert len(directories) == 1 and tree_snapshot(directories[0]) == {}
    with pytest.raises(output.CleanupFailure):
        conversion_spills.recover(ws)
    assert list(root.iterdir()) == directories and tree_snapshot(directories[0]) == {}


def test_replaced_directory_inode_refused_with_copied_proof(tmp_path):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    directory = Path(ticket.root) / ticket.name
    proof = os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE)
    moved = ws.root / "retained"
    directory.rename(moved)
    directory.mkdir(mode=0o700)
    os.setxattr(directory, conversion_spills.OWNER_ATTRIBUTE, proof)
    kept = tree_snapshot(moved)
    with pytest.raises(output.CleanupFailure, match="invalid marker"):
        conversion_spills.recover(ws)
    assert tree_snapshot(moved) == kept and tree_snapshot(directory) == {}


@pytest.mark.parametrize("phase,remaining", [("after_legacy_marker", {"guard"}), ("after_legacy_guard", set())])
def test_legacy_final_removal_gap_is_still_refused(tmp_path, phase, remaining):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws, protocol=1)
    directory = Path(ticket.root) / ticket.name
    kill_transition(ws, phase, recovery=True)
    kept = tree_snapshot(directory)
    assert set(kept) == remaining
    for _ in range(2):
        with pytest.raises(output.CleanupFailure):
            conversion_spills.recover(ws)
        assert tree_snapshot(directory) == kept


@pytest.mark.parametrize("name", ["marker", "guard", "foreign"])
def test_v2_never_adopts_metadata_files(tmp_path, name):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    directory = Path(ticket.root) / ticket.name
    foreign = directory / name
    foreign.write_bytes(b"foreign")
    foreign.chmod(0o600)
    kept = tree_snapshot(directory)
    with pytest.raises(output.CleanupFailure, match="unknown file"):
        conversion_spills.recover(ws)
    assert tree_snapshot(directory) == kept


def test_failed_final_rmdir_retains_proof_for_retry(tmp_path, monkeypatch):
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    ticket = abandoned(ws)
    directory = Path(ticket.root) / ticket.name
    proof = os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE)

    def denied(*args, **kwargs):
        raise PermissionError

    with monkeypatch.context() as patch:
        patch.setattr(os, "rmdir", denied)
        with pytest.raises(output.CleanupFailure):
            conversion_spills.recover(ws)
    assert tree_snapshot(directory) == {} and os.getxattr(directory, conversion_spills.OWNER_ATTRIBUTE) == proof
    assert conversion_spills.recover(ws)["recovered_attempts"] == 1
