"""Complete diagnostic parity across invocation order, sources and worker ownership."""

from __future__ import annotations

import dataclasses
import multiprocessing
import signal
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from sigharvest import conversion, testing
from sigharvest.fingerprints import digest
from sigharvest.models import TestResult, TestResultHistory
from tests.test_conversion import BASE, CORRELATION, DNS, SAFEBOOT, SECURITY
from tests.test_versioned_results import InlinePool, ingest
from tests.test_versioned_results import corpus as _corpus

corpus = _corpus
MDE = "microsoft365defender"


def rule(field: str) -> str:
    return f"title: State isolation\nlogsource: {{product: windows, category: process_creation}}\ndetection:\n  s:\n    {field}: example\n  condition: s\n"


A, B, GOOD = (rule(f) for f in ("IsolationMissingA", "IsolationMissingB", "Image"))


def normalized(value):
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items() if k != "ms"}
    if isinstance(value, list):
        return [normalized(v) for v in value]
    return value


def result(raw, target=MDE, sources=None):
    return normalized(dataclasses.asdict(conversion.convert(raw, target, sources=sources)))


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch):
    monkeypatch.setattr(conversion, "_CACHE", {})
    conversion.toolchain.cache_clear()
    yield
    conversion.toolchain.cache_clear()


@pytest.mark.backend("microsoft365defender")
def test_installed_backend_reproducer():
    """The installed transformation mutates its message; no mocked backend proves this."""
    cls = conversion._backend_class(MDE)
    backend = cls(conversion._pipeline("microsoft_xdr"))

    def failure(instance, raw):
        with pytest.raises(Exception, match="Invalid SigmaDetectionItem") as exc:
            instance.convert(conversion.parse(raw))
        return str(exc.value)

    failure(backend, A)
    warmed = failure(backend, B)
    fresh = failure(cls(conversion._pipeline("microsoft_xdr")), B)
    assert "IsolationMissingA" in warmed and "IsolationMissingB" in warmed
    assert "IsolationMissingA" not in fresh and "IsolationMissingB" in fresh
    assert result(B)["missing_fields"] == ["IsolationMissingB"]
    result(A)
    assert result(B)["missing_fields"] == ["IsolationMissingB"]


@pytest.mark.parametrize("target", conversion.BACKENDS)
def test_complete_output_permutations_and_cache_reset(target):
    inputs = [A, B, GOOD, DNS, SAFEBOOT, SECURITY]
    expected = {}
    for raw in inputs:
        conversion._CACHE.clear()
        expected[raw] = result(raw, target)
    for order in (inputs, inputs[::-1], [A, GOOD, B, A, B, GOOD, SAFEBOOT, DNS, SECURITY]):
        for raw in order:
            assert result(raw, target) == expected[raw]
    conversion._CACHE.clear()
    assert result(B, target) == expected[B]


@pytest.mark.backend("lucene")
def test_source_variants_remain_distinct_and_repeatable():
    raw = rule("ParentImage")
    expected = {source: result(raw, "lucene", [source]) for source in ("sysmon", "security")}
    assert expected["sysmon"] != expected["security"]
    assert expected["sysmon"]["queries"] != expected["security"]["queries"]
    for source in ("security", "sysmon", "security", "sysmon"):
        assert result(raw, "lucene", [source]) == expected[source]


@pytest.mark.parametrize("target", conversion.BACKENDS)
def test_cached_configuration_is_immutable_and_runtime_graph_is_owned(target):
    plan = conversion.plan(target, "windows", "process_creation", None)
    entry = conversion._entry(target, plan.pipelines)
    snapshot = entry.pipelines
    with entry.lock:
        first, second = entry.backend, entry.backend
    assert first is not second
    for attr in ("processing_pipeline", "backend_processing_pipeline", "output_format_processing_pipeline", "errors"):
        assert getattr(first, attr) is not getattr(second, attr)
    first.processing_pipeline.items[0].transformation._pipeline = "poison"
    first.processing_pipeline.state["poison"] = True
    first.errors.append("poison")
    first.backend_processing_pipeline.state["poison"] = True
    first.output_format_processing_pipeline[first.default_format].state["poison"] = True
    if target == "sqlite":
        first._correlation_plans["poison"] = True
        assert second._correlation_plans == {}
    assert second.processing_pipeline.state == {} and second.errors == []
    assert second.backend_processing_pipeline.state == {}
    assert second.output_format_processing_pipeline[second.default_format].state == {}
    result(A, target)
    assert entry.pipelines == snapshot
    assert conversion._entry(target, plan.pipelines) is entry


@pytest.mark.backend("microsoft365defender")
def test_threads_share_entry_lock_without_sharing_conversion_state(monkeypatch):
    expected = {raw: result(raw) for raw in (A, B, GOOD)}
    cls = conversion._backend_class(MDE)
    original = cls.convert
    active = threading.Lock()
    entered = []

    def checked(self, coll):
        assert conversion._entry(MDE, ("microsoft_xdr",)).lock.locked()
        assert active.acquire(blocking=False), "backend calls overlapped for one entry"
        try:
            entered.append(self)
            return original(self, coll)
        finally:
            active.release()

    monkeypatch.setattr(cls, "convert", checked)
    inputs = [A, GOOD, B] * 4
    with ThreadPoolExecutor(max_workers=3) as pool:
        actual = list(pool.map(result, inputs))
    assert actual == [expected[raw] for raw in inputs]
    assert len({id(backend) for backend in entered}) == len(inputs)


def worker(inputs):
    return [(raw, digest(result(raw))) for raw in inputs]


@pytest.mark.backend("microsoft365defender")
@pytest.mark.parametrize("workers", [1, 2])
def test_worker_assignment_preserves_full_diagnostics(workers):
    inputs = [A, GOOD, B, SAFEBOOT]
    expected = dict(worker(inputs))
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork")) as pool:
        for rows in pool.map(worker, [inputs, inputs[::-1], [B, A, GOOD, SAFEBOOT]]):
            assert dict(rows) == expected


@pytest.mark.backend("microsoft365defender")
@pytest.mark.parametrize("failure", [RuntimeError("injected backend error"), conversion.SourceTimeout(), "alarm"])
def test_exception_and_timeout_release_lock_and_discard_state(monkeypatch, failure):
    expected = result(B)
    cls = conversion._backend_class(MDE)
    original = cls.convert
    before_handler = signal.getsignal(signal.SIGALRM)
    before_timer = signal.getitimer(signal.ITIMER_REAL)
    poisoned = []

    def fail(self, coll):
        self.errors.append("poison")
        self.processing_pipeline.state["poison"] = True
        poisoned.append(self)
        if failure == "alarm":
            signal.raise_signal(signal.SIGALRM)
            pytest.fail("installed timeout handler did not interrupt the backend")
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(cls, "convert", fail)
        actual = conversion.convert(A, MDE, timeout=1)
        assert actual.status == ("timeout" if isinstance(failure, conversion.SourceTimeout) or failure == "alarm" else "error")
    assert signal.getsignal(signal.SIGALRM) == before_handler
    assert signal.getitimer(signal.ITIMER_REAL) == before_timer

    def recovered(self, coll):
        assert self is not poisoned[0] and self.errors == [] and self.processing_pipeline.state == {}
        return original(self, coll)

    monkeypatch.setattr(cls, "convert", recovered)
    assert result(B) == expected
    entry = conversion._entry(MDE, ("microsoft_xdr",))
    assert entry.lock.acquire(blocking=False)
    entry.lock.release()


@pytest.mark.parametrize(
    ("target", "logsource", "field"),
    [
        *[(target, "product: windows, category: process_creation", "Image") for target in conversion.BACKENDS],
        *[(target, "product: linux, service: auditd", "name") for target in conversion.BACKENDS],
        ("splunk", "product: windows, category: ps_script", "ScriptBlockText"),
        ("lucene", "product: zeek, service: dns", "query"),
        ("esql", "product: kubernetes, service: audit", "verb"),
        ("opensearch", "product: macos, service: endpointsecurity", "event_type"),
        ("loki", "product: okta, service: okta", "eventType"),
    ],
)
def test_all_factory_routes_match_fresh_installed_backends(monkeypatch, target, logsource, field):
    raw = f"title: Factory control\nlogsource: {{{logsource}}}\ndetection:\n  s:\n    {field}: example\n  condition: s\n"

    def fresh(name, pipelines):
        pipeline = None
        for pipe_name in pipelines:
            part = conversion._pipeline(pipe_name)
            pipeline = part if pipeline is None else pipeline + part
        return SimpleNamespace(backend=conversion._backend_class(name)(pipeline), lock=threading.Lock())

    with monkeypatch.context() as patch:
        patch.setattr(conversion, "_entry", fresh)
        expected = result(raw, target)
    assert result(raw, target) == expected
    result(A, target)
    assert result(raw, target) == expected


@pytest.mark.backend("microsoft365defender")
def test_pipeline_construction_timeout_does_not_publish_partial_cache(monkeypatch):
    original = conversion._pipeline

    def interrupted(name):
        raise conversion.SourceTimeout

    with monkeypatch.context() as patch:
        patch.setattr(conversion, "_pipeline", interrupted)
        assert conversion.convert(A, MDE, timeout=1).status == "timeout"
    assert not conversion._CACHE
    assert conversion._pipeline is original
    assert result(B)["missing_fields"] == ["IsolationMissingB"]


@pytest.mark.backend("microsoft365defender")
def test_snapshot_preserves_unknown_mutable_attributes_aliases_and_cycles(monkeypatch):
    """Optimization must preserve the entire graph, including future plugin state."""
    pipeline = conversion._pipeline("microsoft_xdr")
    shared = {"values": ["pristine"]}
    pipeline.state["extension"] = shared
    pipeline.items[0].transformation.extension = shared
    shared["cycle"] = pipeline
    monkeypatch.setattr(conversion, "_pipeline", lambda _: pipeline)
    entry = conversion._entry(MDE, ("microsoft_xdr",))
    with entry.lock:
        first, second = entry.backend.processing_pipeline, entry.backend.processing_pipeline
    for restored in (first, second):
        assert restored.state["extension"] is restored.items[0].transformation.extension
        assert restored.state["extension"]["cycle"] is restored
    first.state["extension"]["values"].append("poison")
    shared["values"].append("factory mutation")
    assert second.state["extension"]["values"] == ["pristine"]
    with entry.lock:
        assert entry.backend.processing_pipeline.state["extension"]["values"] == ["pristine"]


@pytest.mark.backend("microsoft365defender")
def test_snapshot_optimization_timeout_does_not_publish_partial_cache(monkeypatch):
    def interrupted(_snapshot):
        raise conversion.SourceTimeout

    with monkeypatch.context() as patch:
        patch.setattr(conversion.pickletools, "optimize", interrupted)
        assert conversion.convert(A, MDE, timeout=1).status == "timeout"
    assert not conversion._CACHE
    assert result(B)["missing_fields"] == ["IsolationMissingB"]


@pytest.mark.backend("microsoft365defender")
def test_real_deadline_during_restoration_discards_graph_and_releases_lock(monkeypatch):
    expected = result(B)
    original = conversion._Entry.backend.fget
    restored = []
    handler, timer = signal.getsignal(signal.SIGALRM), signal.getitimer(signal.ITIMER_REAL)

    def delayed(entry):
        backend = original(entry)
        backend.processing_pipeline.state["poison"] = True
        restored.append(backend)
        threading.Event().wait(10)
        pytest.fail("real source deadline did not interrupt restoration")

    with monkeypatch.context() as patch:
        patch.setattr(conversion._Entry, "backend", property(delayed))
        assert conversion.convert(A, MDE, timeout=1).status == "timeout"
    assert len(restored) == 1
    assert signal.getsignal(signal.SIGALRM) == handler
    assert signal.getitimer(signal.ITIMER_REAL) == timer
    assert not conversion._entry(MDE, ("microsoft_xdr",)).lock.locked()
    assert result(B) == expected


@pytest.mark.parametrize("target", sorted(conversion.CORRELATION_BACKENDS))
def test_repeated_correlation_graphs(target):
    def convert(base):
        return normalized(dataclasses.asdict(conversion.convert(CORRELATION, target, kind="correlation", siblings=[base])))

    expected = convert(BASE)
    convert(BASE.replace("4625", "4624"))
    assert convert(BASE) == expected


@pytest.mark.backend("microsoft365defender")
def test_fingerprint_refresh_retains_old_diagnostics_and_exact_noop(corpus, monkeypatch):
    ws, factory, root = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", [MDE])
    current_version = conversion.STATE_VERSION
    with factory() as s:
        ingest(s, root, "invalid.yml", B)
        monkeypatch.setattr(conversion, "STATE_VERSION", 0)
        conversion.toolchain.cache_clear()
        testing.run_stage(ws, s, "convert", workers=1)
        old = list(s.scalars(select(TestResult).order_by(TestResult.id)))
        # Inject historical contamination while retaining the original fingerprint/status.
        row = next(r for r in old if r.status == "partial")
        row.detail = {**row.detail, "reason": "legacy diagnostic with IsolationMissingA"}
        s.commit()
        before = {r.id: (r.fingerprint, r.detail, r.created_at, r.run_id) for r in old}
        monkeypatch.setattr(conversion, "STATE_VERSION", current_version)
        conversion.toolchain.cache_clear()
        assert not testing._done(s, "convert")
        assert testing.run_stage(ws, s, "convert", workers=1).processed == len(old)
        history = list(s.scalars(select(TestResultHistory).order_by(TestResultHistory.result_id)))
        assert len(history) == len(old)
        for snapshot in history:
            fingerprint, detail, created, run_id = before[snapshot.result_id]
            assert snapshot.fingerprint == fingerprint
            assert snapshot.snapshot["detail"] == detail
            assert snapshot.snapshot["created_at"] == created.isoformat()
            assert snapshot.snapshot["run_id"] == run_id
        s.expire_all()
        current = [(r.id, r.fingerprint, r.detail, r.created_at, r.run_id) for r in s.scalars(select(TestResult).order_by(TestResult.id))]
        snapshots = [(r.id, r.snapshot) for r in history]
        assert testing.run_stage(ws, s, "convert", workers=2).processed == 0
        assert [(r.id, r.fingerprint, r.detail, r.created_at, r.run_id) for r in s.scalars(select(TestResult).order_by(TestResult.id))] == current
        assert [(r.id, r.snapshot) for r in s.scalars(select(TestResultHistory).order_by(TestResultHistory.result_id))] == snapshots
