import json
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select
from typer.testing import CliRunner

# Synthetic dependency bundles; these contain no production rule content.
from sigharvest import correlation_references as reference_index
from sigharvest import export_dependencies as closure
from sigharvest.cli import app
from sigharvest.config import Workspace
from sigharvest.conversion import toolchain
from sigharvest.correlation_plan import build
from sigharvest.documents import load_documents
from sigharvest.errors import SigharvestError
from sigharvest.export import export_jsonl, export_yaml, select_groups
from sigharvest.export_selection import select_documents
from sigharvest.fingerprints import result_key, text_digest
from sigharvest.index import GroupFilters, rebuild
from sigharvest.ingest import Ingestor
from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source, TestResult
from sigharvest.service import open_db, sync_all
from tests.helpers import BASE_ID, base, corr, seed_attack, seed_schemas
from tests.test_conversion import make_repo as conversion_repo
from tests.test_correlation_references import corpus as reference_corpus
from tests.test_correlation_references import ingest
from tests.test_datasources import PROCESS
from tests.test_pipeline import make_repo, workspace


def test_export_family_yaml_and_jsonl(tmp_path: Path) -> None:
    ws = workspace(tmp_path, make_repo(tmp_path))
    assert sync_all(ws)[0].status == "ok"
    S = open_db(ws, migrate=True)
    with S() as s:
        rebuild(s)
        # The fixture source states no licence: only a private copy contains the text.
        n = export_yaml(s, select_groups(s, "family", None, GroupFilters(), None), tmp_path / "out", include_private=True)
        assert n == 5 and "Private copy" in (tmp_path / "out" / "NOTICE.md").read_text()
        files = list((tmp_path / "out").rglob("*.yml"))
        assert len(files) == 5 and all(yaml.safe_load(f.read_text())["title"].startswith("Test") for f in files)
        assert all(f.parent.parent.name == "windows" for f in files)
        manifest = [json.loads(line) for line in (tmp_path / "out" / "manifest.jsonl").read_text().splitlines()]
        assert all("evidence_labels" not in m for m in manifest)
        assert {m["canonical_source"] for m in manifest} == {"local"} and all("licence" in m for m in manifest)
        m = export_jsonl(s, select_groups(s, "logic", "Test", GroupFilters(), None), tmp_path / "all.jsonl", include_private=True)
        assert m == 5
        assert "title:" in json.loads((tmp_path / "all.jsonl").read_text().splitlines()[0])["yaml"]
        export_jsonl(s, select_groups(s, "logic", "Test", GroupFilters(), None), tmp_path / "linked.jsonl")
        row = json.loads((tmp_path / "linked.jsonl").read_text().splitlines()[0])
        assert row["yaml"] is None and "no licence" in row["text_skipped"]


def test_export_zip_csv_and_all_copies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import csv
    import zipfile

    from sigharvest.export import export_csv, export_zip

    ws = workspace(tmp_path, make_repo(tmp_path))
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        rebuild(s)
        first = tmp_path / "a.zip"
        # The fixture source states no licence: a default zip only links its rules; a private copy has them all.
        assert export_zip(s, select_groups(s, "family", None, GroupFilters(), None), tmp_path / "linked.zip") == (0, 5)
        with zipfile.ZipFile(tmp_path / "linked.zip") as zf:
            assert not any(n.endswith(".yml") for n in zf.namelist()) and "Test" in zf.read("linked/SKIPPED.md").decode()
        assert export_zip(s, select_groups(s, "family", None, GroupFilters(), None), first, include_private=True) == (5, 0)
        second = tmp_path / "b" / "a.zip"  # same name, so the same top folder
        export_zip(s, select_groups(s, "family", None, GroupFilters(), None), second, include_private=True)
        assert first.read_bytes() == second.read_bytes()  # fixed timestamps: equal input, equal bytes
        with zipfile.ZipFile(first) as zf:
            names = zf.namelist()
            assert "a/manifest.jsonl" in names and "a/SKIPPED.md" in names and sum(n.endswith(".yml") for n in names) == 5
            assert all(yaml.safe_load(zf.read(n))["title"].startswith("Test") for n in names if n.endswith(".yml"))
        assert export_csv(s, select_groups(s, "logic", None, GroupFilters(), None), tmp_path / "rules.csv") == 5
        rows = list(csv.DictReader((tmp_path / "rules.csv").open(encoding="utf-8")))
        assert len(rows) == 5 and rows[0]["canonical_source"] == "local" and rows[0]["product"] == "windows"
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    runner = CliRunner()
    for fmt, out in (("zip", tmp_path / "cli.zip"), ("csv", tmp_path / "cli.csv"), ("jsonl", tmp_path / "copies.jsonl")):
        args = ["export", "--format", fmt, "--out", str(out)] + (["--unit", "all"] if fmt == "jsonl" else [])
        result = runner.invoke(app, args)
        assert result.exit_code == 0 and out.is_file(), result.output
    assert len((tmp_path / "copies.jsonl").read_text().splitlines()) == 5
    copies = runner.invoke(app, ["export", "--unit", "all", "--format", "zip", "--out", str(tmp_path / "x.zip")])
    assert copies.exit_code == 0, copies.output
    with zipfile.ZipFile(tmp_path / "x.zip") as zf:
        names = zf.namelist()
    assert "NOTICE.md" in names and "manifest.jsonl" in names and sum(n.endswith(".yml") for n in names) == 5
    bad = runner.invoke(app, ["export", "--unit", "all", "--format", "csv", "--out", str(tmp_path / "x.csv")])
    assert bad.exit_code == 2 and not (tmp_path / "x.csv").exists()
    empty = runner.invoke(app, ["export", "no-such-rule-anywhere", "--format", "jsonl", "--out", str(tmp_path / "empty.jsonl")])
    assert empty.exit_code == 1 and "no rules were exported" in empty.output
    assert "validated yet" not in empty.output
    # Nothing validated yet (as after `init --from-release`): --validation matches nothing, and the error says why.
    unvalidated = runner.invoke(app, ["export", "--validation", "ok", "--format", "csv", "--out", str(tmp_path / "ok.csv")])
    assert unvalidated.exit_code == 1 and "sigharvest test --stage validate" in unvalidated.output, unvalidated.output


def test_exact_correlation_context_and_stale_results(tmp_path):
    from sigharvest.export_selection import _contexts
    from sigharvest.testing import siblings
    from tests.test_conversion import BASE, CORRELATION

    ws = Workspace(tmp_path / "workspace")
    ws.root.mkdir()
    ws.sources_file.write_text("sources: []\n")
    seed_attack(ws)
    seed_schemas(ws)
    sessions = open_db(ws, migrate=True)
    (tmp_path / "correlation.yml").write_text(BASE + "---\n" + CORRELATION)
    with sessions() as s:
        source = Source(name="correlations", type="local", url=str(tmp_path))
        s.add(source)
        s.flush()
        Ingestor(s, source, None).ingest_file(tmp_path, "correlation.yml")
        rebuild(s)
        corr = s.scalar(select(RuleVersion).where(RuleVersion.kind == "correlation"))
        contexts = _contexts(s, [corr])
        assert contexts[corr.id] == [text_digest(raw) for raw in siblings(s, [corr.id])[corr.id]]
        tc = toolchain("splunk")
        stored = TestResult(
            version_id=corr.id,
            stage="convert",
            target="splunk",
            dataset="",
            status="ok",
            detail={"toolchain": tc},
            fingerprint=result_key(tc, text_digest(corr.raw), corr.kind, contexts[corr.id]),
        )
        s.add(stored)
        s.flush()
        assert corr.id in {v.id for v in select_documents(s, None, GroupFilters(backend="splunk", include_junk=True))}
        base = s.scalar(select(RuleVersion).where(RuleVersion.title == "Failed logon"))
        base.raw += "description: changed context\n"
        s.flush()
        assert corr.id not in {v.id for v in select_documents(s, None, GroupFilters(backend="splunk", include_junk=True))}


def test_convert_indexed_and_file_correlation_siblings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = workspace(tmp_path, conversion_repo(tmp_path))
    assert sync_all(ws)[0].status == "ok"
    factory = open_db(ws, migrate=True)
    with factory() as session:
        rebuild(session)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    runner = CliRunner()
    for key, file in [("6a3a1a40-0000-4000-8000-000000000001", "dns"), ("6a3a1a40-0000-4000-8000-000000000008", "corr")]:
        for choice in ("all", "security", "combined"):
            new = runner.invoke(app, ["convert", key, "--telemetry", choice])
            standalone = runner.invoke(app, ["convert", str(tmp_path / "upstream" / "rules" / f"{file}.yml"), "--telemetry", choice])
            assert new.exit_code == standalone.exit_code == 0, new.output
            # A corpus rule also prints its attribution line first (DRL 1.1); a local file has none.
            assert new.output.startswith("# attribution: ")
            assert new.output.split("\n", 1)[1] == standalone.output
            if file == "corr":
                assert "stats count" in new.output
                if choice == "combined":
                    assert "separate queries follow" in new.output
            elif choice == "security":
                assert "unsupported" in new.output


@pytest.mark.parametrize("target", ["splunk", "sqlite"])
def test_convert_combined_query_or_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    monkeypatch.setenv("SIGHARVEST_HOME", str(tmp_path))
    rule = tmp_path / "rule.yml"
    rule.write_text(PROCESS)
    result = CliRunner().invoke(app, ["convert", str(rule), "-t", target, "--telemetry", "combined"])
    assert result.exit_code == 0, result.output
    assert ("Combined:" in result.output) == (target == "splunk")
    assert ("separate queries follow" in result.output) == (target == "sqlite")


corpus = reference_corpus


def selected_roots(s):
    return iter(s.scalars(select(LogicGroup).where(LogicGroup.kind == "correlation")))


def manifest(out):
    return [json.loads(line) for line in (out / "manifest.jsonl").read_text().splitlines()]


def assert_bundle(out):
    records = manifest(out)
    by_key = {}
    rules = []
    for path in sorted(out.rglob("*.yml")):
        for doc in load_documents(path.read_bytes()):
            assert not doc.error
            key = f"{path.relative_to(out)}#{doc.index}"
            row = next(r for r in records if r["path"] == str(path.relative_to(out)) and r["document"] == doc.index)
            assert closure.sha256_hex(doc.raw) == row["yaml_sha256"]
            by_key[key] = row["content_hash"]
            rules.append((key, doc.rule_yaml))
    plan = build(rules)
    edges = []
    for spec in plan.correlations:
        assert not spec.error
        edges.extend({"parent": by_key[spec.key], "reference": ref, "document": by_key[key]} for ref, key in zip(spec.references, spec.keys, strict=True))
    assert sorted(edges, key=str) == sorted([e for r in records for e in r["references"]], key=str)
    return records


def test_dependency_shared_base_exact_bytes_and_empty_workspace(corpus, tmp_path):
    with corpus() as s:
        ingest(s, tmp_path, base().replace("\n", "\r\n"))
        ingest(s, tmp_path, corr(), path="c1.yml")
        ingest(s, tmp_path, corr(span="2h"), path="c2.yml")
        reference_index.refresh(s)
        versions = {v.content_hash: v.raw.encode() for v in s.scalars(select(RuleVersion))}
        out = tmp_path / "bundle"
        assert export_yaml(s, selected_roots(s), out, with_dependencies=True) == 3
        records = assert_bundle(out)
        assert [r["role"] for r in records].count("selected") == 2
        assert [r["role"] for r in records].count("dependency") == 1
        assert all((out / r["path"]).read_bytes() == versions[r["content_hash"]] for r in records)
        assert all("licence" in r and r["locations"] for r in records)
    assert_empty_import(out, tmp_path)


def assert_empty_import(out, tmp_path):
    # Re-ingest just exported files; compare each exact edge using corpus lookup.
    records = manifest(out)
    expected = {r["content_hash"] for r in records}
    from sigharvest.db import session_factory
    from sigharvest.ingest import Ingestor
    from sigharvest.models import Source

    empty = session_factory(tmp_path / "empty.db", migrate=True)
    with empty() as s:
        source = Source(name="bundle", type="local", url=str(out))
        s.add(source)
        s.flush()
        for path in out.rglob("*.yml"):
            Ingestor(s, source, None).ingest_file(out, str(path.relative_to(out)))
        for version in s.scalars(select(RuleVersion)):
            s.add(
                LogicGroup(
                    logic_hash=version.logic_hash,
                    canonical_version_id=version.id,
                    canonical_source="bundle",
                    kind=version.kind,
                    rule_id=version.rule_id,
                )
            )
        s.flush()
        reference_index.refresh(s)
        assert set(s.scalars(select(RuleVersion.content_hash))) == expected
        roots = list(s.scalars(select(RuleVersion).where(RuleVersion.kind == "correlation")))
        plan = build([(v.logic_hash, v.raw) for v in roots], s)
        assert all(not spec.error for spec in plan.correlations)
        by_logic = {v.logic_hash: v.content_hash for v in s.scalars(select(RuleVersion))}
        actual = {(by_logic[spec.key], ref, by_logic[key]) for spec in plan.correlations for ref, key in zip(spec.references, spec.keys, strict=True)}
        assert actual == {(e["parent"], e["reference"], e["document"]) for r in records for e in r["references"]}


def test_duplicate_names_between_graphs_keep_same_file_and_uuid_versions(corpus, tmp_path):
    with corpus() as s:
        ingest(s, tmp_path, base(id=BASE_ID, value="a") + "---\n" + corr(), path="a.yml")
        ingest(s, tmp_path, base(id=BASE_ID, value="b") + "---\n" + corr(span="2h"), path="b.yml")
        reference_index.refresh(s)
        out = tmp_path / "bundle"
        assert export_yaml(s, selected_roots(s), out, with_dependencies=True) == 4
        records = assert_bundle(out)
        assert len(list(out.rglob("*.yml"))) == 2
        bases = [r for r in records if r["role"] == "dependency"]
        assert len({r["content_hash"] for r in bases}) == 2
        for row in records:
            for edge in row["references"]:
                assert next(r for r in records if r["content_hash"] == edge["document"])["path"] == row["path"]

    assert_empty_import(out, tmp_path)


def test_dependency_selected_base_precedence_and_default_unchanged(corpus, tmp_path):
    with corpus() as s:
        ingest(s, tmp_path, base(value="near") + "---\n" + corr(), path="near.yml")
        ingest(s, tmp_path, base(value="selected"), source="b")
        reference_index.refresh(s)
        far = s.scalar(select(RuleVersion).where(RuleVersion.raw.contains("action: selected")))
        groups = [*selected_roots(s), s.scalar(select(LogicGroup).where(LogicGroup.logic_hash == far.logic_hash))]
        out = tmp_path / "bundle"
        assert export_yaml(s, iter(groups), out, with_dependencies=True) == 2
        records = assert_bundle(out)
        assert all(r["role"] == "selected" for r in records)
        assert next(r for r in records if r["references"])["references"][0]["document"] == far.content_hash
        assert export_yaml(s, selected_roots(s), tmp_path / "default", include_private=True) == 1
        assert "references" not in manifest(tmp_path / "default")[0]


def test_dependency_legacy_effective_and_original_bytes(corpus, tmp_path):
    legacy = (
        "action: global\nlogsource:\n  category: application\n---\nname: failed\ntitle: Legacy\ndetection:\n  sel:\n    action: failure\n  condition: sel\n"
    )
    with corpus() as s:
        ingest(s, tmp_path, legacy)
        ingest(s, tmp_path, corr(), path="corr.yml")
        reference_index.refresh(s)
        version = s.scalar(select(RuleVersion).where(RuleVersion.kind == "rule"))
        out = tmp_path / "legacy"
        export_yaml(s, selected_roots(s), out, with_dependencies=True)
        records = assert_bundle(out)
        row = next(r for r in records if r["role"] == "dependency")
        assert row["content_hash"] == version.content_hash
        assert row["context_digest"] == version.context_digest
        assert row["yaml_representation"] == "effective"
        assert (out / row["original_path"]).read_bytes() == version.original_raw
        assert (out / row["path"]).read_bytes() == version.raw.encode()
        assert closure.effective_content_hash((out / row["original_path"]).read_bytes(), row["context_digest"]) == row["content_hash"]


@pytest.mark.parametrize("fault", ["missing", "ambiguous", "cycle", "chain", "unsupported", "index", "unframed"])
def test_dependency_failures_publish_nothing(corpus, tmp_path, fault):
    with corpus() as s:
        raw = corr()
        if fault == "cycle":
            raw += "name: failed\n"
        elif fault == "unsupported":
            raw = corr(kind="unknown")
        ingest(s, tmp_path, raw, path="correlation.yml")
        if fault in {"ambiguous", "index"}:
            ingest(s, tmp_path, base())
        if fault == "ambiguous":
            ingest(s, tmp_path, base(value="fork"), source="b")
        if fault == "chain":
            ingest(s, tmp_path, corr(span="2h") + "name: failed\n", path="chain.yml")
        if fault == "unframed":
            # Real same-file contexts use framed slices. This synthetic stored context
            # cannot be re-created without adding bytes and must fail explicitly.
            from sigharvest.models import Occurrence

            ingest(s, tmp_path, base(), path="one.yml")
            ingest(s, tmp_path, base(value="other"), source="b", path="two.yml")
            ingest(s, tmp_path, corr(span="2h"), source="b", path="c2.yml")
            for occurrence in s.scalars(select(Occurrence)):
                occurrence.path = "synthetic-same-file.yml"
        reference_index.refresh(s)
        if fault == "index":
            from sqlalchemy import text

            s.execute(text("UPDATE correlation_reference_state SET built_input='stale'"))
        out = tmp_path / "refused"
        with pytest.raises(SigharvestError):
            export_yaml(s, selected_roots(s), out, with_dependencies=True)
        assert not out.exists()
        assert not list(tmp_path.glob(".export-*"))


@pytest.mark.parametrize("limit", ["roots", "documents", "bytes", "references", "candidates", "reader_bytes"])
def test_dependency_caps(corpus, tmp_path, monkeypatch, limit):
    with corpus() as s:
        ingest(s, tmp_path, base())
        ingest(s, tmp_path, corr(refs=[f"ref{i}" for i in range(65)]) if limit == "references" else corr(), path="corr.yml")
        reference_index.refresh(s)
        from sigharvest import correlation_dependencies as inspection

        if limit in {"roots", "documents", "bytes"}:
            monkeypatch.setattr(closure, {"roots": "MAX_ROOTS", "documents": "MAX_DOCUMENTS", "bytes": "MAX_BYTES"}[limit], 0)
        elif limit != "references":
            monkeypatch.setattr(inspection, "MAX_CANDIDATES" if limit == "candidates" else "MAX_BYTES", 0)
        with pytest.raises(SigharvestError):
            export_yaml(s, selected_roots(s), tmp_path / "capped", with_dependencies=True)
        assert not (tmp_path / "capped").exists()


@pytest.mark.parametrize("existing", ["directory", "file", "symlink", "raced_directory"])
def test_dependency_destination_never_overwritten(corpus, tmp_path, monkeypatch, existing):
    with corpus() as s:
        ingest(s, tmp_path, base())
        reference_index.refresh(s)
        out = tmp_path / "existing"
        if existing == "directory":
            out.mkdir()
        elif existing == "file":
            out.write_bytes(b"keep")
        elif existing == "symlink":
            out.symlink_to(tmp_path / "absent")
        else:
            original = closure.sync_directory

            def raced(stage):
                out.mkdir()
                original(stage)

            monkeypatch.setattr(closure, "sync_directory", raced)
        with pytest.raises(SigharvestError, match="already exists"):
            export_yaml(s, iter(s.scalars(select(LogicGroup))), out, with_dependencies=True)
        assert out.exists() or out.is_symlink()
        if existing == "file":
            assert out.read_bytes() == b"keep"
        assert not list(tmp_path.glob(".export-*"))


@pytest.mark.parametrize("exception", [OSError, KeyboardInterrupt])
def test_dependency_interrupted_write_cleans_stage(corpus, tmp_path, monkeypatch, exception):
    with corpus() as s:
        ingest(s, tmp_path, base())
        reference_index.refresh(s)
        original = Path.write_bytes

        def interrupted(path, raw):
            original(path, raw[:10])
            raise exception("injected write interruption")

        monkeypatch.setattr(Path, "write_bytes", interrupted)
        with pytest.raises(exception):
            export_yaml(s, iter(s.scalars(select(LogicGroup))), tmp_path / "interrupted", with_dependencies=True)
        assert not (tmp_path / "interrupted").exists()
        assert not list(tmp_path.glob(".export-*"))


@pytest.mark.parametrize("args", [["--format", "jsonl"], ["--format", "splunk"], ["--unit", "all"]])
def test_dependency_cli_unsupported_before_workspace_or_write(tmp_path, monkeypatch, args):
    monkeypatch.setenv("SIGHARVEST_HOME", str(tmp_path / "absent"))
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["export", "--with-dependencies", "--out", str(out), *args])
    assert result.exit_code == 2
    assert "--with-dependencies requires" in result.output
    assert not out.exists()


def test_dependency_exact_version_is_resolver_copy_not_canonical_substitute(corpus, tmp_path):
    with corpus() as s:
        ingest(s, tmp_path, base(id=BASE_ID, description="original representative"))
        first = s.scalar(select(RuleVersion))
        ingest(s, tmp_path, base(id=BASE_ID, description="different metadata bytes"), source="b")
        later = s.scalar(select(RuleVersion).where(RuleVersion.id != first.id))
        assert first.logic_hash == later.logic_hash and first.content_hash != later.content_hash
        group = s.scalar(select(LogicGroup).where(LogicGroup.logic_hash == first.logic_hash))
        group.canonical_version_id = later.id
        ingest(s, tmp_path, corr(refs=[BASE_ID]), path="corr.yml")
        reference_index.refresh(s)
        out = tmp_path / "bundle"
        export_yaml(s, selected_roots(s), out, with_dependencies=True)
        records = assert_bundle(out)
        assert next(r for r in records if r["role"] == "dependency")["content_hash"] == first.content_hash


def test_dependency_sixty_four_references_are_supported(corpus, tmp_path):
    with corpus() as s:
        refs = [f"base{i}" for i in range(64)]
        for ref in refs:
            ingest(s, tmp_path, base(name=ref, value=ref), path=f"{ref}.yml")
        ingest(s, tmp_path, corr(refs=refs), path="corr.yml")
        reference_index.refresh(s)
        out = tmp_path / "bundle"
        assert export_yaml(s, selected_roots(s), out, with_dependencies=True) == 65
        records = assert_bundle(out)
        assert len(next(r for r in records if r["references"])["references"]) == 64


def test_dependency_corrupt_source_identity_and_written_yaml_are_refused(corpus, tmp_path, monkeypatch):
    with corpus() as s:
        ingest(s, tmp_path, base())
        reference_index.refresh(s)
        version = s.scalar(select(RuleVersion))
        original = version.original_raw
        version.original_raw = b"corrupt original"
        s.flush()
        with pytest.raises(SigharvestError, match="source bytes"):
            export_yaml(s, iter(s.scalars(select(LogicGroup))), tmp_path / "bad-identity", with_dependencies=True)
        version.original_raw = original
        s.flush()
        write = Path.write_bytes

        def corrupt(path, raw):
            return write(path, raw + b"# changed after planning\n")

        monkeypatch.setattr(Path, "write_bytes", corrupt)
        with pytest.raises(SigharvestError, match="exact document bytes"):
            export_yaml(s, iter(s.scalars(select(LogicGroup))), tmp_path / "bad-write", with_dependencies=True)
        assert not (tmp_path / "bad-identity").exists()
        assert not (tmp_path / "bad-write").exists()
        assert not list(tmp_path.glob(".export-*"))


@pytest.mark.parametrize("change", ["metadata", "withdraw", "toolchain"])
def test_produced_correlation_result_requires_retest(tmp_path, monkeypatch, change):
    from sigharvest import conversion
    from sigharvest.testing import _store, siblings
    from sigharvest.testing_conversion import _convert_one
    from tests.test_conversion import BASE, CORRELATION

    ws = Workspace(tmp_path / "workspace")
    ws.root.mkdir()
    ws.sources_file.write_text("sources: []\n")
    seed_attack(ws)
    seed_schemas(ws)
    sessions = open_db(ws, migrate=True)
    (tmp_path / "correlation.yml").write_text(BASE + "---\n" + CORRELATION)
    with sessions() as s:
        source = Source(name="correlations", type="local", url=str(tmp_path))
        s.add(source)
        s.flush()
        Ingestor(s, source, None).ingest_file(tmp_path, "correlation.yml")
        rebuild(s)
        corr = s.scalar(select(RuleVersion).where(RuleVersion.kind == "correlation"))
        base = s.scalar(select(RuleVersion).where(RuleVersion.kind == "rule"))

        def produce():
            rows = _convert_one((corr.id, corr.kind, corr.raw, siblings(s, [corr.id]).get(corr.id, [])), ["splunk"])
            _store(s, None, "convert", rows)
            s.flush()
            return rows[0][2]

        def admitted():
            return corr.id in {v.id for v in select_documents(s, None, GroupFilters(backend="splunk", include_junk=True))}

        assert produce() == "ok"
        assert admitted()
        if change == "metadata":
            base.raw += "\n# synthetic sibling metadata change\n"
        elif change == "withdraw":
            occurrence = s.scalar(select(Occurrence).where(Occurrence.version_id == base.id))
            occurrence.present = False
        else:
            real = conversion.toolchain
            monkeypatch.setattr(conversion, "toolchain", lambda target: real(target) + "-synthetic-toolchain")
        s.flush()
        assert not admitted()
        status = produce()
        assert admitted() == (status == "ok")
        if change == "withdraw":
            assert status != "ok"
            occurrence.present = True
            s.flush()
            assert not admitted()
            assert produce() == "ok"
            assert admitted()
        else:
            assert status == "ok"


@pytest.mark.parametrize("position", [1, 2])
def test_multibase_produced_results_edit_withdraw_restore_and_local_aliases(tmp_path, monkeypatch, position):
    """Every sibling binds the result; local alias names cannot transfer success."""
    from sigharvest import testing
    from sigharvest.models import TestResultHistory
    from sigharvest.testing_conversion import _convert_one
    from tests.test_conversion import BASE, CORRELATION

    ws = Workspace(tmp_path / "workspace")
    ws.root.mkdir()
    ws.sources_file.write_text("sources: []\n")
    seed_attack(ws)
    seed_schemas(ws)
    sessions = open_db(ws, migrate=True)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    bases = [BASE.replace("failed_logon", f"local_{i}").replace("000000000009", f"00000000001{i}").replace("4625", str(4624 + i)) for i in range(3)]
    roots = [
        CORRELATION.replace("failed_logon", "local_0\n    - local_1\n    - local_2")
        .replace("Many failed logons", f"Root {i}")
        .replace("000000000008", f"00000000002{i}")
        for i in range(3)
    ]
    with sessions() as s:
        one = Source(name="one", type="local", url=str(tmp_path))
        two = Source(name="two", type="local", url=str(tmp_path))
        s.add_all([one, two])
        s.flush()

        def ingest_graph(source, name, docs):
            (tmp_path / name).write_text("---\n".join(docs))
            Ingestor(s, source, None).ingest_file(tmp_path, name)
            s.commit()
            s.expire_all()

        ingest_graph(one, "one.yml", [*bases, *roots[:2]])
        other_bases = [b.replace("462", "472") for b in bases]
        ingest_graph(two, "two.yml", [*other_bases, roots[2]])
        rebuild(s)
        correlations = list(s.scalars(select(RuleVersion).where(RuleVersion.kind == "correlation").order_by(RuleVersion.id)))
        affected = {v.id for v in correlations[:2]}
        independent = correlations[2].id

        def produce(versions):
            context = testing.siblings(s, [v.id for v in versions])
            for v in versions:
                testing._store(s, None, "convert", _convert_one((v.id, v.kind, v.raw, context.get(v.id, [])), ["splunk"]))
            s.commit()

        def admitted():
            return {v.id for v in select_documents(s, None, GroupFilters(backend="splunk", include_junk=True))}

        # A real successful conversion in source one must not qualify source two.
        produce(correlations[:2])
        assert admitted() == affected
        assert independent not in testing._done(s, "convert")
        produce(correlations[2:])
        assert admitted() == affected | {independent}
        assert affected | {independent} <= testing._done(s, "convert")
        original_rows = {r.version_id: (r.id, r.fingerprint, dict(r.detail)) for r in s.scalars(select(TestResult))}
        original_versions = set(s.scalars(select(RuleVersion.id)))
        changed = bases.copy()
        changed[position] += "\n# second or last base changed through ingestion\n"
        ingest_graph(one, "one.yml", [*changed, *roots[:2]])
        assert admitted() == {independent}
        assert not affected & testing._done(s, "convert")
        assert independent in testing._done(s, "convert")
        # Validation consumes only the document. Conversion consumes its context.
        produce(correlations[:2])
        assert admitted() == affected | {independent}
        history = list(s.scalars(select(TestResultHistory)))
        assert len(history) == 2
        for vid in affected:
            rid, fp, detail = original_rows[vid]
            assert any(h.result_id == rid and h.fingerprint == fp and h.snapshot["detail"] == detail for h in history)
        retained_history = [(h.id, h.fingerprint, dict(h.snapshot)) for h in history]
        ingest_graph(one, "one.yml", [*(b for i, b in enumerate(changed) if i != position), *roots[:2]])
        assert admitted() == {independent}
        produce(correlations[:2])
        assert admitted() == {independent}  # failed ordinary retests cannot grant eligibility
        assert all(s.scalar(select(TestResult.status).where(TestResult.version_id == vid)) != "ok" for vid in affected)
        ingest_graph(one, "one.yml", [*bases, *roots[:2]])
        assert admitted() == {independent}
        produce(correlations[:2])
        assert admitted() == affected | {independent}
        assert original_versions <= set(s.scalars(select(RuleVersion.id)))
        history = {h.id: (h.fingerprint, h.snapshot) for h in s.scalars(select(TestResultHistory))}
        assert all(history[hid] == (fp, snapshot) for hid, fp, snapshot in retained_history)
        assert len(history) == 6
        current = s.scalar(select(TestResult).where(TestResult.version_id == independent))
        assert (current.id, current.fingerprint, current.detail) == original_rows[independent]

        from sqlalchemy import event

        import sigharvest.export_selection as selection
        from sigharvest.export_selection import _contexts
        from sigharvest.query import export_backend, export_sigma

        statements = []

        def count_context_sql(*args):
            statements.append(1)

        event.listen(s.connection(), "before_cursor_execute", count_context_sql)
        try:
            _contexts(s, correlations)
        finally:
            event.remove(s.connection(), "before_cursor_execute", count_context_sql)
        assert len(statements) == 2  # ordered version edges, then one bounded raw batch
        with monkeypatch.context() as patch:
            patch.setattr(selection, "BATCH_SIZE", 1)
            assert admitted() == affected | {independent}

        # Selected-root order does not reorder each root's effective file context.
        assert _contexts(s, correlations) == _contexts(s, list(reversed(correlations)))
        context = testing.siblings(s, [v.id for v in correlations])
        assert _contexts(s, correlations) == {vid: [text_digest(raw) for raw in raws] for vid, raws in context.items()}
        for order, versions in enumerate((correlations, list(reversed(correlations)))):
            export_sigma(s, versions, tmp_path / f"yaml-{order}")
            export_sigma(s, versions, tmp_path / f"json-{order}", jsonl=True)
            export_backend(versions, "splunk", tmp_path / f"splunk-{order}", s=s)
        for fmt in ("yaml", "json", "splunk"):

            def records(order, fmt=fmt):
                path = tmp_path / f"{fmt}-{order}"
                manifest = path / "manifest.jsonl" if fmt == "yaml" else path if fmt == "json" else path.with_name(path.name + ".manifest.jsonl")
                return {row["content_hash"]: row for row in map(json.loads, manifest.read_text().splitlines())}

            assert records(0) == records(1)
        for v in correlations:
            name = f"{v.rule_id}_{v.content_hash[:8]}.yml"
            assert (tmp_path / "yaml-0" / name).read_bytes() == (tmp_path / "yaml-1" / name).read_bytes() == v.raw.encode()
    sessions.kw["bind"].dispose()


def test_identical_correlation_bytes_switch_local_source_context(tmp_path, monkeypatch):
    """One version has one producer slot; changing its first occurrence invalidates it."""
    from sigharvest import testing
    from sigharvest.testing_conversion import _convert_one
    from tests.test_conversion import BASE, CORRELATION

    ws = Workspace(tmp_path / "workspace")
    ws.root.mkdir()
    ws.sources_file.write_text("sources: []\n")
    seed_attack(ws)
    seed_schemas(ws)
    sessions = open_db(ws, migrate=True)
    monkeypatch.setattr(testing, "BACKENDS", ["splunk"])
    second = BASE.replace("failed_logon", "second").replace("000000000009", "000000000019").replace("4625", "4624")
    root = CORRELATION.replace("failed_logon", "failed_logon\n    - second")
    with sessions() as s:
        sources = [Source(name=name, type="local", url=str(tmp_path)) for name in ("first", "second")]
        s.add_all(sources)
        s.flush()
        for i, source in enumerate(sources):
            (tmp_path / f"{i}.yml").write_text("---\n".join([BASE, second + f"\n# local context {i}\n", root]))
            Ingestor(s, source, None).ingest_file(tmp_path, f"{i}.yml")
        rebuild(s)
        corr = s.scalars(select(RuleVersion).where(RuleVersion.kind == "correlation")).one()
        context = testing.siblings(s, [corr.id])[corr.id]
        testing._store(s, None, "convert", _convert_one((corr.id, corr.kind, corr.raw, context), ["splunk"]))
        s.commit()
        f = GroupFilters(backend="splunk", include_junk=True)
        assert [v.id for v in select_documents(s, None, f)] == [corr.id]
        Ingestor(s, sources[0], None).remove("0.yml")
        s.commit()
        assert testing.siblings(s, [corr.id])[corr.id] != context
        assert select_documents(s, None, f) == []
        assert corr.id not in testing._done(s, "convert")
        context = testing.siblings(s, [corr.id])[corr.id]
        testing._store(s, None, "convert", _convert_one((corr.id, corr.kind, corr.raw, context), ["splunk"]))
        s.commit()
        assert [v.id for v in select_documents(s, None, f)] == [corr.id]
    sessions.kw["bind"].dispose()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
        ("+1", "'+1"),
        ("-x", "'-x"),
        ("@SUM(1)", "'@SUM(1)"),
        ("\tx", "'\tx"),
        ("plain", "plain"),
        (None, ""),
        (["a", "b"], "a b"),
        (83.6, "83.6"),
        ("Report;=1+1", "'Report;=1+1"),
        ("x; @SUM(1+1)", "'x; @SUM(1+1)"),
        ("  =1", "'  =1"),
        ("a;b", "a;b"),
    ],
)
def test_csv_cells_never_start_a_formula(value: object, expected: str) -> None:
    from sigharvest.export import csv_cell

    assert csv_cell(value) == expected
