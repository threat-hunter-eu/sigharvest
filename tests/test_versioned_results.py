"""Offline migration, invalidation and publication contracts for cached stage results."""

from __future__ import annotations

import copy
import json

import pytest
from sqlalchemy import func, select

from sigharvest import collections, conversion, fingerprints, semantic, testing, testing_conversion
from sigharvest.cli.pipeline import _index_needed
from sigharvest.config import Workspace
from sigharvest.db import RESULTS_REVISION, get_meta, session_factory
from sigharvest.index import rebuild
from sigharvest.ingest import Ingestor
from sigharvest.models import LogicGroup, RuleVersion, SemanticResult, Source, TestResult, TestResultHistory, TestRun
from tests.helpers import SCHEMA_FIXTURES, seed_schemas
from tests.test_conversion import BASE, CORRELATION
from tests.test_semantic import A, B

BAD = "title: unparseable\nlogsource: {}\ndetection:\n  condition: absent\n"


class InlinePool:
    """Deterministic worker boundary for interruption/failure injection."""

    def __init__(self, *, max_workers, initializer=None, initargs=()):
        from sigharvest import conversion_memory

        # This fake runs in the test host. Real containment is exercised by child
        # process tests; never install resource limits in the pytest interpreter.
        if initializer is conversion_memory.initialize:
            initializer, initargs = initargs[0], ({}, "convert")
        if initializer:
            initializer(*initargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def map(self, worker, items, *, chunksize):
        return map(worker, items)

    def submit(self, worker, *args):
        from concurrent.futures import Future

        fut = Future()
        try:
            fut.set_result(worker(*args))
        except BaseException as exc:  # noqa: BLE001 - re-raised by Future.result() like a real pool
            fut.set_exception(exc)
        return fut


def ingest(s, root, name, raw, source=None):
    source = source or s.scalars(select(Source).order_by(Source.id)).first()
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw)
    Ingestor(s, source, "fixture").ingest_file(root, name)
    s.commit()


@pytest.fixture
def corpus(tmp_path):
    ws = Workspace(tmp_path / "workspace")
    seed_schemas(ws)
    factory = session_factory(ws.db_path, migrate=True)
    with factory() as s:
        source = Source(name="fixture", type="local", url=str(tmp_path))
        s.add(source)
        s.commit()
        for name, raw in (("a.yml", A), ("b.yml", B), ("bad.yml", BAD)):
            ingest(s, tmp_path, name, raw)
    yield ws, factory, tmp_path
    factory.kw["bind"].dispose()


@pytest.mark.parametrize("package", ["pysigma", "pyyaml", "pyparsing", "jsonschema"])
def test_dependency_changes_invalidate_relevant_stages(monkeypatch, package):
    before = testing.validation_toolchain(SCHEMA_FIXTURES)
    sem = semantic.toolchain()
    version = fingerprints.package_version
    monkeypatch.setattr(fingerprints, "package_version", lambda p: "changed" if p == package else version(p))
    assert testing.validation_toolchain(SCHEMA_FIXTURES) != before
    assert (semantic.toolchain() != sem) == (package != "jsonschema")


def test_schema_parser_algorithm_and_validator_policy_are_versioned(monkeypatch):
    schemas = copy.deepcopy(SCHEMA_FIXTURES)
    base = testing.validation_toolchain(schemas)
    assert base == testing.validation_toolchain(dict(reversed(list(schemas.items()))))
    schemas["rule"]["required"].append("description")
    assert testing.validation_toolchain(schemas) != base
    # Use an actual selected validator so registry changes cannot become a no-op.
    from sigma.validators.core import validators

    monkeypatch.setattr(testing, "COLLECTION_VALIDATORS", set(validators))
    assert testing.validation_toolchain(SCHEMA_FIXTURES) != base
    before = semantic.toolchain()
    monkeypatch.setattr(semantic, "SEMANTIC_VERSION", "next-algorithm")
    assert semantic.toolchain() != before
    before = semantic.toolchain()
    original = fingerprints.source_digest
    monkeypatch.setattr(fingerprints, "source_digest", lambda m: "changed" if m == "documents.py" else original(m))
    assert semantic.toolchain() != before


def test_validation_reuses_exact_keys_and_archives_stale_rows(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        versions = list(s.scalars(select(RuleVersion)))
        legacy = TestResult(version_id=versions[0].id, stage="validate", target="pysigma+schema", status="error", detail={})
        s.add(legacy)
        s.commit()
        assert testing._done(s, "validate", SCHEMA_FIXTURES) == set()
        assert testing.run_stage(ws, s, "validate").processed == 3
        rows = list(s.scalars(select(TestResult).order_by(TestResult.id)))
        assert {r.status for r in rows} >= {"warning", "error"}
        assert all(r.fingerprint and r.detail["toolchain"] for r in rows)
        assert s.scalars(select(TestResultHistory)).one().snapshot["status"] == "error"
        created = [(r.id, r.created_at) for r in rows]
        assert testing.run_stage(ws, s, "validate").processed == 0
        assert [(r.id, r.created_at) for r in s.scalars(select(TestResult).order_by(TestResult.id))] == created
        path = ws.cache / "sigma-specification" / testing.SPEC_COMMIT / testing.SCHEMAS["rule"]
        schema = json.loads(path.read_text())
        schema["required"].append("description")
        path.write_text(json.dumps(schema))
        assert testing.run_stage(ws, s, "validate").processed == 3
        # Only one of the three new fingerprints changed status.
        assert s.scalar(select(func.count()).select_from(TestResultHistory)) == 2
        assert s.scalars(select(TestRun).order_by(TestRun.id.desc())).first().params["toolchain"] == testing.validation_toolchain(testing.load_schemas(ws))


def test_validation_interruption_reuses_only_committed_batches(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    chunks = testing._chunks
    monkeypatch.setattr(testing, "_chunks", lambda items, n: chunks(items, 2))

    def interrupted(done, total):
        raise RuntimeError("interrupted")

    with factory() as s, pytest.raises(RuntimeError, match="interrupted"):
        testing.run_stage(ws, s, "validate", progress=interrupted)
    with factory() as s:
        assert len(testing._done(s, "validate", SCHEMA_FIXTURES)) == 2
        assert testing.run_stage(ws, s, "validate").processed == 1
        assert len(testing._done(s, "validate", SCHEMA_FIXTURES)) == 3


def test_completed_validation_still_requires_index_after_restart(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(semantic, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        semantic.backfill(s)
        rebuild(s)
        assert _index_needed(s, 0, False) == ""
        assert testing.run_stage(ws, s, "validate").processed == 3
    # All results were committed before the interruption; the next run does zero
    # worker work but must still replace its old validation/score projection.
    with factory() as s:
        assert testing.run_stage(ws, s, "validate").processed == 0
        assert _index_needed(s, 0, False) == "stored results changed since the last index build"
        rebuild(s)
        assert _index_needed(s, 0, False) == ""
        revision = get_meta(s, RESULTS_REVISION)
        row = s.scalars(select(TestResult)).first()
        run = s.scalars(select(TestRun)).first()
        testing._store(s, run.id, "validate", [(row.version_id, row.target, "error", {"fingerprint": "different"})])
        s.rollback()
        assert get_meta(s, RESULTS_REVISION) == revision
        assert _index_needed(s, 0, False) == ""


def test_same_toolchain_semantic_extension_still_requires_index(corpus, monkeypatch):
    _, factory, root = corpus
    monkeypatch.setattr(semantic, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        semantic.backfill(s)
        rebuild(s)
        key = get_meta(s, semantic.ACTIVE_FINGERPRINT)
        ingest(s, root, "a.yml", A.replace("title: a", "title: new metadata"))
        assert semantic.backfill(s) == 1
        assert get_meta(s, semantic.ACTIVE_FINGERPRINT) == key
        assert _index_needed(s, 0, False) == "stored results changed since the last index build"


@pytest.mark.parametrize("interrupt_after", [1, 2, 3])
def test_semantic_generation_resume_preserves_families_and_user_data(corpus, monkeypatch, interrupt_after):
    _, factory, _ = corpus
    # Exercise real process transport for the initial generation.
    with factory() as s:
        assert semantic.backfill(s, workers=1) == 3
        rebuild(s)
        assert _index_needed(s, 0, False) == ""
        old_key = get_meta(s, semantic.ACTIVE_FINGERPRINT)
        before = list(s.execute(select(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.semantic_hash).order_by(RuleVersion.id)))
        groups = list(s.scalars(select(LogicGroup).order_by(LogicGroup.logic_hash)))
        families = [(g.logic_hash, g.family_id, g.family_size) for g in groups]
        assert sorted(g.family_size for g in groups) == [1, 2, 2]
        c = collections.create(s, "keep-these")
        collections.add(s, c, groups)
        s.commit()
        collection_id = c.id
        # An unchanged generation must not even start a worker pool.
        monkeypatch.setattr(semantic, "ProcessPoolExecutor", lambda **kw: pytest.fail("unexpected pool"))
        assert semantic.backfill(s) == 0

    monkeypatch.setattr(semantic, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(semantic, "BATCH_SIZE", 1)
    monkeypatch.setattr(semantic, "toolchain", lambda: "b" * 64)
    called = []

    def work(item):
        vid, raw = item
        called.append(vid)
        # Previously successful rules now fail; the cached failure now succeeds.
        return vid, "c" * 64 if raw == BAD else None

    monkeypatch.setattr(semantic, "_work", work)

    def interrupted(done, total):
        if done == interrupt_after:
            raise RuntimeError("interrupted")

    with factory() as s, pytest.raises(RuntimeError, match="interrupted"):
        assert _index_needed(s, 0, False)
        semantic.backfill(s, progress=interrupted)
    with factory() as s:
        assert get_meta(s, semantic.ACTIVE_FINGERPRINT) == old_key
        assert list(s.execute(select(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.semantic_hash).order_by(RuleVersion.id))) == before
        # Even a direct rebuild while work is staged consumes only the old generation.
        rebuild(s)
        assert list(s.execute(select(LogicGroup.logic_hash, LogicGroup.family_id, LogicGroup.family_size).order_by(LogicGroup.logic_hash))) == families
        assert semantic.backfill(s) == 3 - interrupt_after
        assert len(called) == len(set(called)) == 3
        assert _index_needed(s, 0, False)  # promotion without index completion must be retried
        rebuild(s)
        assert _index_needed(s, 0, False) == ""
        assert list(s.scalars(select(RuleVersion.logic_hash).order_by(RuleVersion.id))) == [row.logic_hash for row in before]
        assert list(s.scalars(select(RuleVersion.semantic_hash).order_by(RuleVersion.id))) == ["", "", "c" * 64]
        assert set(s.scalars(select(LogicGroup.family_size))) == {1}
        c = collections.require(s, "keep-these")
        assert c.id == collection_id and all(r.state == "current" for r in collections.resolve(s, c))
        assert s.scalar(select(func.count()).select_from(SemanticResult)) == 6


def test_semantic_promotion_refuses_new_uncomputed_live_rules(corpus, monkeypatch):
    _, factory, root = corpus
    monkeypatch.setattr(semantic, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        semantic.backfill(s)
        old_key = get_meta(s, semantic.ACTIVE_FINGERPRINT)
        monkeypatch.setattr(semantic, "toolchain", lambda: "d" * 64)

        def new_rule(done, total):
            ingest(s, root, "new.yml", A.replace("whoami.exe", "another.exe"))

        with pytest.raises(RuntimeError, match="live rules changed"):
            semantic.backfill(s, progress=new_rule)
        assert get_meta(s, semantic.ACTIVE_FINGERPRINT) == old_key
        assert set(s.scalars(select(RuleVersion.semantic_fingerprint))) == {old_key, None}
        assert semantic.backfill(s) == 1
        assert set(s.scalars(select(RuleVersion.semantic_fingerprint))) == {"d" * 64}


def test_semantic_projection_write_failure_rolls_back_and_reuses_staging(corpus, monkeypatch):
    from sqlalchemy import event

    _, factory, _ = corpus
    monkeypatch.setattr(semantic, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        semantic.backfill(s)
        old_key = get_meta(s, semantic.ACTIVE_FINGERPRINT)
    monkeypatch.setattr(semantic, "toolchain", lambda: "e" * 64)
    engine = factory.kw["bind"]

    def fail_projection(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE rule_versions SET semantic_hash="):
            raise RuntimeError("write failure")

    event.listen(engine, "before_cursor_execute", fail_projection)
    try:
        with factory() as s, pytest.raises(RuntimeError, match="write failure"):
            semantic.backfill(s)
    finally:
        event.remove(engine, "before_cursor_execute", fail_projection)
    with factory() as s:
        assert get_meta(s, semantic.ACTIVE_FINGERPRINT) == old_key
        assert set(s.scalars(select(RuleVersion.semantic_fingerprint))) == {old_key}
        monkeypatch.setattr(semantic, "ProcessPoolExecutor", lambda **kw: pytest.fail("staged work was lost"))
        assert semantic.backfill(s) == 0
        assert get_meta(s, semantic.ACTIVE_FINGERPRINT) == "e" * 64


def test_shared_correlation_context_invalidates_without_changing_version(corpus, monkeypatch):
    ws, factory, root = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    seen = []

    def convert(raw, name, kind, siblings):
        seen.append((kind, list(siblings)))
        return "ok", {"toolchain": conversion.toolchain(name)}

    monkeypatch.setattr(testing_conversion, "_convert_with_timeout", convert)
    with factory() as s:
        ingest(s, root, "one.yml", BASE + "---\n" + CORRELATION)
        mirror = Source(name="mirror", type="local", url=str(root))
        s.add(mirror)
        s.commit()
        changed = BASE.replace("4625", "4624")
        ingest(s, root, "mirror.yml", changed + "---\n" + CORRELATION, mirror)
        corr = s.scalars(select(RuleVersion).where(RuleVersion.kind == "correlation")).one()
        assert testing.run_stage(ws, s, "convert").processed == 6
        assert testing.run_stage(ws, s, "convert").processed == 0
        assert corr.id in testing._done(s, "convert")
        # The exact correlation bytes are shared. Changing only the first file's
        # base rule must change its effective key despite an unchanged toolchain.
        ingest(s, root, "one.yml", changed + "---\n" + CORRELATION)
        assert corr.id not in testing._done(s, "convert")
        assert testing.run_stage(ws, s, "convert").processed == 1
        assert [raws for kind, raws in seen if kind == "correlation"] == [[BASE], [changed]]
        # Moving the authoritative occurrence to an identical mirror is a no-op.
        Ingestor(s, s.scalars(select(Source).order_by(Source.id)).first(), None).remove("one.yml")
        s.commit()
        assert testing.run_stage(ws, s, "convert").processed == 0


def test_other_dataset_cannot_complete_missing_conversion_target(corpus, monkeypatch):
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk", "sqlite"])
    monkeypatch.setattr(testing_conversion, "_convert_with_timeout", lambda raw, name, kind, siblings: ("error", {"toolchain": conversion.toolchain(name)}))
    with factory() as s:
        testing.run_stage(ws, s, "convert")
        row = s.scalars(select(TestResult).where(TestResult.target == "sqlite")).first()
        row.dataset = "another-dataset"
        s.commit()
        assert row.version_id not in testing._done(s, "convert")
