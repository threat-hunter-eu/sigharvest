"""Exact lookup parity, transactional freshness, recovery and reader isolation."""

from dataclasses import asdict

import pytest
from sqlalchemy import delete, event, func, select, text, update

from sigharvest import correlation_plan as planner
from sigharvest import correlation_references as refs
from sigharvest.db import session_factory
from sigharvest.health import correlation_reference_check
from sigharvest.ingest import Ingestor
from sigharvest.models import CorrelationReference, CorrelationReferenceDirty, LogicGroup, RuleVersion, Source
from tests.helpers import BASE_ID, base, corr


@pytest.fixture
def corpus(tmp_path):
    sessions = session_factory(tmp_path / "test.db", migrate=True)
    with sessions() as s:
        s.add(Source(name="a", type="local", url="local"))
        s.add(Source(name="b", type="local", url="local"))
        s.commit()
    return sessions


def ingest(s, tmp_path, raw, path="rule.yml", source="a"):
    folder = tmp_path / source
    folder.mkdir(exist_ok=True)
    (folder / path).write_text(raw)
    owner = s.scalar(select(Source).where(Source.name == source))
    worker = Ingestor(s, owner, None)
    worker.ingest_file(folder, path)
    s.flush()
    for version in s.scalars(select(RuleVersion)):
        if s.scalar(select(LogicGroup.id).where(LogicGroup.logic_hash == version.logic_hash)) is None:
            s.add(
                LogicGroup(
                    logic_hash=version.logic_hash,
                    canonical_version_id=version.id,
                    canonical_source=source,
                    rule_id=version.rule_id,
                    kind=version.kind,
                )
            )
            s.flush()
    return worker


def outcome(s, rules=None):
    return asdict(planner.build(rules or [("c", corr())], s))


def parity(s, monkeypatch, rules=None):
    assert refs.status(s) == "ready"
    actual = outcome(s, rules)
    with monkeypatch.context() as patch:
        patch.setattr(refs, "status", lambda _: "stale")
        assert outcome(s, rules) == actual
    return actual


def projection(s):
    return s.execute(
        select(CorrelationReference.name, CorrelationReference.content_hash, CorrelationReference.logic_hash).order_by(
            CorrelationReference.name, CorrelationReference.content_hash
        )
    ).all()


@pytest.mark.parametrize("reference", ["failed", BASE_ID, "never-known", "fa%_iled", "FAILED"])
def test_exact_names_ids_forks_and_equal_logic(corpus, tmp_path, monkeypatch, reference):
    with corpus() as s:
        ingest(s, tmp_path, base(id=BASE_ID))
        ingest(s, tmp_path, base(id=BASE_ID, description="equal logic copy"), source="b")
        refs.refresh(s)
        rules = [("c", corr(refs=[reference]))]
        result = parity(s, monkeypatch, rules)
        assert bool(result["correlations"][0]["error"]) == (reference not in {"failed", BASE_ID})
        ingest(s, tmp_path, base(value="fork", id=BASE_ID), path="fork.yml", source="b")
        assert refs.status(s) == "stale"
        stale = outcome(s, rules)
        refs.refresh(s)
        assert parity(s, monkeypatch, rules) == stale
        if reference in {"failed", BASE_ID}:
            assert "ambiguous" in stale["correlations"][0]["error"]


def test_same_file_scope_and_selected_invalid_override(corpus, tmp_path, monkeypatch):
    raw = corr()
    key = planner.logic_hash(planner.document(raw))
    rules = [(key, raw)]
    with corpus() as s:
        ingest(s, tmp_path, base(value="local") + "---\n" + raw, path="multi.yml")
        ingest(s, tmp_path, base(value="elsewhere"), path="multi.yml", source="b")
        refs.refresh(s)
        result = parity(s, monkeypatch, rules)
        assert result["correlations"][0]["error"] is None
        assert "local" in result["bases"][0][1]
        override = [*rules, ("selected", "name: failed\n")]
        assert "not a base" in parity(s, monkeypatch, override)["correlations"][0]["error"]
        selected = [("a.yml", base()), ("a.yml#1", raw), ("b.yml", base(value="other"))]
        assert parity(s, monkeypatch, selected)["correlations"][0]["keys"] == ["a.yml"]


def test_rename_retirement_rescan_and_full_incremental_equivalence(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        worker = ingest(s, tmp_path, base())
        refs.refresh(s)
        assert outcome(s)["correlations"][0]["error"] is None
        ingest(s, tmp_path, base(name="renamed"))
        assert refs.status(s) == "stale"
        expected = outcome(s)
        assert refs.refresh(s) == 1
        assert parity(s, monkeypatch) == expected
        assert "missing" in expected["correlations"][0]["error"]
        incremental = projection(s)
        refs.refresh(s, full=True)
        assert projection(s) == incremental
        # Rescanning/reactivating retained exact bytes needs no projection update.
        ingest(s, tmp_path, base())
        assert refs.status(s) == "ready"
        assert refs.refresh(s) == 0
        assert parity(s, monkeypatch)["correlations"][0]["error"] is None
        worker.reconcile_paths(set())
        assert refs.status(s) == "ready"
        assert "missing" in parity(s, monkeypatch)["correlations"][0]["error"]
        before = projection(s)
        refs.refresh(s, full=True)
        assert projection(s) == before


def test_effective_documents_and_malformed_aliases(corpus, tmp_path, monkeypatch):
    raw = "action: global\nname: failed\nlogsource: {category: application}\n---\ntitle: inherited\ndetection: {s: {action: failure}, condition: s}\n"
    with corpus() as s:
        ingest(s, tmp_path, raw)
        # Ingestion accepts bounded anchors, the reference parser deliberately refuses aliases.
        ingest(s, tmp_path, "name: failed\nlogsource: {category: application}\ndetection: {s: &s {action: other}, alias: *s, condition: s}\n", source="b")
        refs.refresh(s)
        result = parity(s, monkeypatch)
        assert result["correlations"][0]["error"] is None
        assert len(projection(s)) == 1


@pytest.mark.parametrize("damage", ["rows", "table", "dirty_table", "state", "trigger", "fingerprint"])
def test_loss_and_stale_receipts_fall_back_and_repair(corpus, tmp_path, monkeypatch, damage):
    with corpus() as s:
        ingest(s, tmp_path, base())
        refs.refresh(s)
        expected = outcome(s)
        statements = {
            "rows": "DELETE FROM correlation_references",
            "table": "DROP TABLE correlation_references",
            "dirty_table": "DROP TABLE correlation_reference_dirty",
            "state": "DELETE FROM correlation_reference_state",
            "trigger": "DROP TRIGGER correlation_ref_input_insert",
            "fingerprint": "UPDATE correlation_reference_state SET fingerprint='old'",
        }
        s.execute(text(statements[damage]))
        assert refs.status(s) != "ready"
        assert correlation_reference_check(s).status == "warn"
        assert outcome(s) == expected
        refs.refresh(s)
        assert correlation_reference_check(s).status == "ok"
        assert parity(s, monkeypatch) == expected


def test_raw_sql_changes_and_index_membership_are_rechecked(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        ingest(s, tmp_path, base())
        refs.refresh(s)
        version = s.scalar(select(RuleVersion))
        # Identity corrections use raw SQL too; metadata-only updates need no YAML work.
        s.execute(update(RuleVersion).values(title="changed"))
        assert refs.status(s) == "ready"
        s.execute(update(RuleVersion).values(raw=base("renamed")))
        assert refs.status(s) == "stale"
        refs.refresh(s)
        assert "missing" in parity(s, monkeypatch)["correlations"][0]["error"]
        rules = [("c", corr(refs=["renamed"]))]
        assert parity(s, monkeypatch, rules)["correlations"][0]["error"] is None
        s.execute(delete(LogicGroup).where(LogicGroup.logic_hash == version.logic_hash))
        assert "missing" in parity(s, monkeypatch, rules)["correlations"][0]["error"]


@pytest.mark.parametrize("fork", [False, True])
def test_escaped_spelling_resolves_and_exposes_ambiguity(corpus, tmp_path, monkeypatch, fork):
    with corpus() as s:
        raw = base(name="encoded").replace("name: encoded", 'name: "\\x66ailed"')
        ingest(s, tmp_path, raw)
        if fork:
            ingest(s, tmp_path, base(value="other"), source="b")
        refs.refresh(s)
        error = parity(s, monkeypatch)["correlations"][0]["error"]
        assert (error is not None and "ambiguous" in error) if fork else error is None


def test_generated_ids_are_not_authored_aliases(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        ingest(s, tmp_path, base())
        refs.refresh(s)
        generated = s.scalar(select(RuleVersion.rule_id))
        assert "missing" in parity(s, monkeypatch, [("c", corr(refs=[generated]))])["correlations"][0]["error"]


def test_interrupted_rebuild_cannot_publish_partial_even_if_caller_commits(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        ingest(s, tmp_path, base())
        refs.refresh(s)
        s.commit()
        original = projection(s)
        with monkeypatch.context() as patch:
            patch.setattr(planner, "document", lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
            with pytest.raises(KeyboardInterrupt):
                refs.refresh(s, full=True)
        s.commit()
        assert refs.status(s) == "ready"
        assert projection(s) == original
        ingest(s, tmp_path, base("renamed"))
        s.commit()
        with monkeypatch.context() as patch:
            patch.setattr(planner, "document", lambda _: (_ for _ in ()).throw(RuntimeError("injected")))
            with pytest.raises(RuntimeError):
                refs.refresh(s)
        s.commit()
        assert refs.status(s) == "stale"
        expected = outcome(s)
        refs.refresh(s)
        assert parity(s, monkeypatch) == expected


def test_reader_overlap_pins_generation_and_live_membership(corpus, tmp_path):
    with corpus() as writer:
        ingest(writer, tmp_path, base())
        refs.refresh(writer)
        writer.commit()
    with corpus() as reader, corpus() as writer:
        assert refs.status(reader) == "ready"
        ingest(writer, tmp_path, base("renamed"))
        refs.refresh(writer)
        writer.commit()
        assert outcome(reader)["correlations"][0]["error"] is None
        reader.rollback()
        assert "missing" in outcome(reader)["correlations"][0]["error"]


def test_failure_after_queue_clear_rolls_back_the_publication_receipt(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        ingest(s, tmp_path, base())
        refs.refresh(s)
        s.commit()
        before = projection(s)
        ingest(s, tmp_path, base("renamed"))
        s.commit()

        def interrupt(conn, cursor, statement, parameters, context, many):
            if statement.startswith("UPDATE correlation_reference_state SET fingerprint="):
                raise RuntimeError("receipt publication interrupted")

        event.listen(s.bind, "before_cursor_execute", interrupt)
        try:
            with pytest.raises(RuntimeError, match="receipt publication interrupted"):
                refs.refresh(s)
        finally:
            event.remove(s.bind, "before_cursor_execute", interrupt)
        s.commit()
        assert projection(s) == before
        assert refs.status(s) == "stale"
        assert s.scalar(select(CorrelationReferenceDirty.content_hash)) is not None
        refs.refresh(s)
        assert parity(s, monkeypatch, [("c", corr(refs=["renamed"]))])["correlations"][0]["error"] is None


@pytest.mark.parametrize("operation", ["delete", "update"])
def test_partial_change_queue_loss_forces_full_recovery(corpus, tmp_path, monkeypatch, operation):
    with corpus() as s:
        ingest(s, tmp_path, base())
        refs.refresh(s)
        ingest(s, tmp_path, base("one"))
        ingest(s, tmp_path, base("two"), path="second.yml")
        lost = s.scalar(select(CorrelationReferenceDirty.content_hash).limit(1))
        where = CorrelationReferenceDirty.content_hash == lost
        if operation == "delete":
            s.execute(delete(CorrelationReferenceDirty).where(where))
        else:
            s.execute(update(CorrelationReferenceDirty).where(where).values(content_hash="d" * 64))
        assert refs.status(s) != "ready"
        refs.refresh(s)
        for name in ("one", "two"):
            assert parity(s, monkeypatch, [("c", corr(refs=[name]))])["correlations"][0]["error"] is None
        incremental = projection(s)
        refs.refresh(s, full=True)
        assert projection(s) == incremental


def test_equal_logic_copies_only_parse_the_returned_representative(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        for number in range(12):
            ingest(s, tmp_path, base(description=f"copy {number}"), path=f"copy{number}.yml")
        refs.refresh(s)
        real = planner.document
        calls = []

        def parsed(raw):
            calls.append(1)
            return real(raw)

        monkeypatch.setattr(planner, "document", parsed)
        actual = outcome(s)
        assert len(calls) == 2
        assert "copy 0" in actual["bases"][0][1]
        monkeypatch.setattr(refs, "status", lambda _: "stale")
        calls.clear()
        assert outcome(s) == actual
        assert len(calls) == 13


def test_projection_reduces_parses_and_uses_exact_index(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        ingest(s, tmp_path, base())
        for i in range(15):
            ingest(s, tmp_path, base(name=f"other{i}", value=f"failed{i}"), path=f"other{i}.yml")
        refs.refresh(s)
        real = planner.document
        counts = []
        statements = []

        def parsed(raw):
            counts.append(1)
            return real(raw)

        monkeypatch.setattr(planner, "document", parsed)

        def sql(conn, cursor, statement, parameters, context, many):
            if "JOIN correlation_references" in statement:
                statements.append((statement, parameters))

        event.listen(s.bind, "before_cursor_execute", sql)
        try:
            expected = outcome(s)
        finally:
            event.remove(s.bind, "before_cursor_execute", sql)
        indexed = len(counts)
        counts.clear()
        monkeypatch.setattr(refs, "status", lambda _: "stale")
        assert outcome(s) == expected
        assert indexed == 2 and len(counts) >= 17
        statement, parameters = statements[-1]
        plan = s.connection().exec_driver_sql("EXPLAIN QUERY PLAN " + statement, parameters).all()
        assert any("SEARCH correlation_references" in row[3] and "name=?" in row[3] for row in plan)
        assert not any("SCAN rule_versions" in row[3] for row in plan)


@pytest.mark.parametrize("field", ["name", "id"])
@pytest.mark.parametrize(
    "decoded,spelling",
    [
        ("base_a", '"base_\\x61"'),
        ("base_a", '"base_\\u0061"'),
        ("base_a", '"base_\\U00000061"'),
        ("base_é", '"base_\\u00e9"'),
        ('base_"a', '"base_\\"a"'),
        ("base_'a", "'base_''a'"),
        ("base_\\a", '"base_\\\\a"'),
    ],
)
def test_decoded_alias_exact_bytes_and_equivalent_copies(corpus, tmp_path, monkeypatch, field, decoded, spelling):
    with corpus() as s:
        raw = base(name="placeholder", title="Fixture").replace("name: placeholder", f"{field}: {spelling}")
        ingest(s, tmp_path, raw)
        # Equivalent alias and detection, different bytes: retain the first representative.
        ingest(s, tmp_path, base(name=decoded, title="Copy"), source="b")
        refs.refresh(s)
        result = parity(s, monkeypatch, [("c", corr(refs=[decoded]))])
        assert result["correlations"][0]["error"] is None
        assert result["bases"][0][1] == raw
        for other in (decoded.upper(), decoded + " ", decoded.replace("é", "e\u0301")):
            if other != decoded:
                assert "missing" in parity(s, monkeypatch, [("c", corr(refs=[other]))])["correlations"][0]["error"]


@pytest.mark.parametrize("spelling", ["null", "123", "true", "[failed]", "{alias: failed}", '"\\qfailed"'])
def test_nonstring_and_invalid_scalar_never_supply_alias(corpus, tmp_path, monkeypatch, spelling):
    with corpus() as s:
        ingest(s, tmp_path, base())
        # Direct retained data exercises invalid YAML that ingestion would quarantine.
        s.execute(update(RuleVersion).values(raw=base().replace("name: failed", f"name: {spelling}")))
        refs.refresh(s)
        assert "missing" in parity(s, monkeypatch)["correlations"][0]["error"]


@pytest.mark.parametrize("damage", ["stale", "missing", "damaged", "incompatible"])
def test_decoded_fallback_is_readonly_and_caps_do_not_certify_unique(corpus, tmp_path, monkeypatch, damage):
    with corpus() as s:
        ingest(s, tmp_path, base())
        ingest(s, tmp_path, base(name="encoded", value="fork").replace("name: encoded", 'name: "\\x66ailed"'), source="b")
        refs.refresh(s)
        statements = {
            "stale": "UPDATE correlation_reference_state SET built_input='old'",
            "missing": "DROP TABLE correlation_references",
            "damaged": "DELETE FROM correlation_references",
            "incompatible": "UPDATE correlation_reference_state SET fingerprint='old'",
        }
        s.execute(text(statements[damage]))
        s.commit()
        s.execute(text("PRAGMA query_only=ON"))
        assert refs.status(s) == damage
        before = s.connection().exec_driver_sql("SELECT total_changes()").scalar()
        assert "ambiguous" in outcome(s)["correlations"][0]["error"]
        for budget in (planner.CatalogBudget(documents=1), planner.CatalogBudget(bytes=1)):
            plan = planner.build([("c", corr())], s, catalog_budget=budget)
            assert plan.correlations[0].error.startswith("reference resolution unavailable:")
            assert not plan.correlations[0].keys
        # The default check path also has a finite semantic scan, with an actionable error.
        planner_budget = planner.CatalogBudget(documents=1)
        monkeypatch.setattr(planner, "CatalogBudget", lambda: planner_budget)
        error = outcome(s)["correlations"][0]["error"]
        assert "unavailable" in error and "sigharvest index" in error
        assert s.connection().exec_driver_sql("SELECT total_changes()").scalar() == before


def test_decoded_same_file_override_and_occurrence_lifecycle(corpus, tmp_path, monkeypatch):
    raw = base(name="encoded", value="local").replace("name: encoded", 'name: "\\x66ailed"')
    correlation = corr()
    key = planner.logic_hash(planner.document(correlation))
    with corpus() as s:
        worker = ingest(s, tmp_path, raw + "---\n" + correlation, path="multi.yml")
        ingest(s, tmp_path, base(value="far"), source="b")
        refs.refresh(s)
        rules = [(key, correlation)]
        assert "local" in parity(s, monkeypatch, rules)["bases"][0][1]
        assert "not a base" in parity(s, monkeypatch, [*rules, ("override", 'name: "\\x66ailed"\n')])["correlations"][0]["error"]
        worker.reconcile_paths(set())
        assert "far" in parity(s, monkeypatch, rules)["bases"][0][1]
        ingest(s, tmp_path, raw + "---\n" + correlation, path="multi.yml")
        assert refs.status(s) == "ready"
        assert "local" in parity(s, monkeypatch, rules)["bases"][0][1]


def test_parallel_full_projection_matches_serial(corpus, tmp_path, monkeypatch):
    """A large full rebuild parses in worker processes; the projection is the same as the serial one."""
    with corpus() as s:
        for n in range(7):
            ingest(s, tmp_path, base(value=f"v{n}", id=f"6a3a1a40-0000-4000-8000-00000000010{n}"), path=f"r{n}.yml")
        ingest(s, tmp_path, "title: broken\ndetection: [unclosed\n", path="broken.yml")
        refs.refresh(s, full=True)
        serial = projection(s)
        monkeypatch.setattr(refs, "PARALLEL_MIN", 2)
        monkeypatch.setattr(refs, "WINDOW", 3)
        monkeypatch.setattr(refs, "CHUNK", 2)
        assert refs.refresh(s, full=True, workers=2) == s.scalar(select(func.count()).select_from(RuleVersion))
        assert projection(s) == serial and len(serial) >= 7
