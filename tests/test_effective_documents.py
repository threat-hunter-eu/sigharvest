"""Strict YAML, exact original bytes, effective execution and reviewable identity migration."""

from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from sigharvest import conversion, testing
from sigharvest.config import Workspace, save_sources
from sigharvest.documents import SigmaSafeLoader, load_documents, split_documents
from sigharvest.export import export_yaml
from sigharvest.identity import content_hash, logic_hash
from sigharvest.index import rebuild
from sigharvest.ingest import Ingestor
from sigharvest.models import LogicGroup, Occurrence, RuleVersion, Source
from sigharvest.service import open_db
from tests.helpers import SCHEMA_FIXTURES

GOLDEN = Path(__file__).parent / "fixtures/effective-documents/bom-crlf-directive.yml"
GLOBAL = b"action: global\nlogsource: {product: windows, category: process_creation}\n"
CHILD = b"---\ntitle: Legacy\ndetection: {sel: {Image: cmd.exe}, condition: sel}\n"


@pytest.fixture
def workspace(tmp_path):
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    root = ws.source_dir("local")
    root.mkdir(parents=True)
    with open_db(ws, migrate=True)() as s:
        source = Source(name="local", type="local", url=str(root))
        s.add(source)
        s.commit()
        yield ws, s, source, root


def ingest(s, source, root, raw):
    (root / "rule.yml").write_bytes(raw)
    Ingestor(s, source, "rev").ingest_file(root, "rule.yml")
    s.commit()
    return s.scalars(select(RuleVersion).join(Occurrence).where(Occurrence.present.is_(True))).one()


def test_golden_original_span_and_effective_consumers(workspace, tmp_path):
    _ws, s, source, root = workspace
    raw = GOLDEN.read_bytes()
    assert b"".join(split_documents(raw)) == raw
    doc = load_documents(raw)[0]
    assert doc.error is None and doc.index == 1
    assert doc.identity_hash == "17744b65fd788f04da87eedcfe6513229ccf81c0aa1df7d4e08f142657025a1a"
    assert raw[doc.span_start : doc.span_start + len(doc.raw)] == doc.raw
    version = ingest(s, source, root, raw)
    assert version.original_raw == doc.raw
    assert version.raw == doc.rule_yaml and version.context_digest
    occ = s.scalars(select(Occurrence)).one()
    assert raw[occ.span_start : occ.span_end] == version.original_raw
    testing._init_worker(SCHEMA_FIXTURES, "validate")
    result = testing._validate_one((version.id, "rule", version.raw))
    assert not result[3]["schema"] and not result[3]["parse"]
    assert not conversion.parse_errors(conversion.parse(version.raw))
    rebuild(s)
    assert export_yaml(s, iter(s.scalars(select(LogicGroup))), tmp_path / "export", include_private=True) == 1
    exported = next((tmp_path / "export").rglob("*.yml")).read_text()
    assert yaml.safe_load(exported) == doc.data
    assert '"yaml_representation": "effective"' in (tmp_path / "export/manifest.jsonl").read_text()


def test_global_only_changes_get_distinct_versions(workspace):
    _, s, source, root = workspace
    first = ingest(s, source, root, GLOBAL + CHILD)
    second = ingest(s, source, root, GLOBAL.replace(b"windows", b"linux") + CHILD)
    assert first.original_raw == second.original_raw == CHILD
    assert first.content_hash != second.content_hash
    assert first.logic_hash != second.logic_hash
    third = ingest(s, source, root, GLOBAL.replace(b"windows", b"linux") + CHILD)
    assert third.id == second.id
    assert not s.scalars(select(Occurrence).where(Occurrence.version_id == first.id)).one().present
    # Even a fully overridden or metadata-only global edit is a different source context.
    a = load_documents(GLOBAL + CHILD)[0]
    b = load_documents(GLOBAL + b"author: someone\n" + CHILD)[0]
    assert a.identity_hash != b.identity_hash and logic_hash(a.data) == logic_hash(b.data)


def test_reset_repeat_and_malformed_context():
    docs = load_documents(GLOBAL + CHILD + b"---\naction: repeat\ntitle: Repeated\n---\naction: reset\n" + CHILD)
    assert len(docs) == 3
    assert docs[1].data["title"] == "Repeated" and docs[1].data["detection"] == docs[0].data["detection"]
    assert docs[1].context_digest and docs[1].identity_hash != docs[0].identity_hash
    assert docs[2].context_digest is None and docs[2].kind is None
    bad = load_documents(b"action: global\nlogsource: [broken\n" + CHILD + b"---\naction: reset\n---\n" + GLOBAL + CHILD)
    assert bad[0].error and bad[1].error
    assert bad[-1].kind == "rule" and not bad[-1].error
    assert load_documents(b"action: global\nlogsource: nope\n" + CHILD)[0].error
    assert load_documents(b"action: repeat\ntitle: orphan\n")[0].error


@pytest.mark.parametrize("body", [b"x: 1\nx: 2\n", b"x: {nested: 1, nested: 2}\n", b"x: {true: 1, 1: 2}\n"])
def test_duplicates_have_both_locations(body):
    doc = load_documents(body)[0]
    assert "duplicate YAML key" in doc.error and "first at line" in doc.error and "column" in doc.error
    with pytest.raises(ValueError, match="duplicate YAML key"):
        yaml.load(body, Loader=SigmaSafeLoader)
    with pytest.raises(ValueError, match="duplicate YAML key"):
        conversion.parse(body.decode())


def test_merge_overrides_and_directives_remain_valid():
    raw = b"base: &b {x: 1}\nchild: &c {<<: *b, x: 2}\nagain: {<<: *c, y: 3}\n"
    doc = load_documents(raw)[0]
    assert doc.error is None and doc.data["again"] == {"x": 2, "y": 3}
    assert doc.identity_hash == content_hash(raw)
    raw = b"%YAML 1.1\n---\nx: 1\n...\n%YAML 1.1\n---\nx: 2\n"
    assert b"".join(split_documents(raw)) == raw
    assert [d.data for d in load_documents(raw)] == [{"x": 1}, {"x": 2}]


def test_effective_output_obeys_budget(monkeypatch):
    from sigharvest import documents

    monkeypatch.setattr(documents, "MAX_FILE_BYTES", 180)
    raw = b"action: global\nlogsource: {}\n" + CHILD
    docs = load_documents(raw)
    assert not docs[0].error
    monkeypatch.setattr(documents, "MAX_YAML_NODES", 4)
    assert "limit" in load_documents(raw)[0].error


def test_many_children_obey_total_effective_budget(monkeypatch):
    from sigharvest import documents

    monkeypatch.setattr(documents, "MAX_EFFECTIVE_FILE_BYTES", 250)
    docs = load_documents(GLOBAL + CHILD * 10)
    assert docs[0].kind == "rule" and not docs[0].error
    assert any(d.error and "size limit" in d.error for d in docs[1:])
    assert sum(len(d.effective or "") for d in docs) < 500


def test_malformed_flow_global_cannot_leave_stale_context():
    docs = load_documents(GLOBAL + b"---\n{action: global, logsource: [broken\n" + CHILD)
    assert len(docs) == 2 and all(d.error for d in docs)


def test_comment_before_separator_keeps_ordinary_byte_identity():
    raw = b"x: 1\n# belongs to first chunk\n---\nx: 2\n"
    assert split_documents(raw) == [b"x: 1\n# belongs to first chunk\n", b"---\nx: 2\n"]


def test_leading_whitespace_keeps_original_rule_slice():
    docs = load_documents(b"\n\n" + CHILD)
    assert docs[-1].raw == CHILD and docs[-1].identity_hash == content_hash(CHILD)


@pytest.mark.parametrize(
    "raw",
    [
        GOLDEN.read_bytes(),
        GLOBAL + CHILD + b"---\naction: repeat\ntitle: repeated\n",
        b"base: &b {x: 1}\nchild: {<<: *b, x: 2}\nwhen: 2026-10-31\n",
        b"x: 1\nx: 2\n",
        b"x: &x [*x]\n",
        b"!!python/object/apply:os.system ['exit 1']\n",
        b"x: [unclosed\n",
        b"tags:\n- attack.t1059\t\n",  # Libyaml alone accepts this; the historical parser rejects it.
        b"x: 'quoted\ttab'\n",  # The compatibility fallback still accepts quoted tabs.
        b"x: [" + b"[" * 70 + b"0" + b"]" * 71,
    ],
)
def test_fast_ingest_matches_bounded_python_loader(raw, monkeypatch):
    from sigharvest import documents

    fast = load_documents(raw)
    monkeypatch.setattr(documents, "_load_ingest_yaml", lambda chunk: yaml.load(chunk, Loader=documents._IngestLoader))
    reference = load_documents(raw)
    assert len(fast) == len(reference)
    for left, right in zip(fast, reference, strict=True):
        assert bool(left.error) == bool(right.error)
        assert (left.raw, left.span_start, left.kind, left.context_digest, left.effective) == (
            right.raw,
            right.span_start,
            right.kind,
            right.context_digest,
            right.effective,
        )
        if not left.error:
            assert left.data == right.data and left.identity_hash == right.identity_hash


@pytest.mark.parametrize("limit", ["MAX_YAML_DEPTH", "MAX_YAML_NODES"])
def test_fast_yaml_checks_structure_before_composition(monkeypatch, limit):
    from sigharvest import documents

    if not getattr(yaml, "__with_libyaml__", False):
        pytest.skip("Libyaml is unavailable")
    monkeypatch.setattr(documents, limit, 4)
    monkeypatch.setattr(documents._FastIngestLoader, "__init__", lambda *args: pytest.fail("composed before checking the input budget"))
    raw = b"x: [[[[[0]]]]]\n" if limit == "MAX_YAML_DEPTH" else b"x: [0, 1, 2, 3, 4]\n"
    assert "limit" in load_documents(raw)[0].error


def test_fast_yaml_expanded_alias_budget_and_python_fallback(monkeypatch):
    from sigharvest import documents

    monkeypatch.setattr(documents, "MAX_YAML_NODES", 40)
    raw = b"a: &a [1,2,3,4]\nb: &b [*a,*a,*a,*a]\nc: [*b,*b,*b,*b]\n"
    assert "expanded node limit" in load_documents(raw)[0].error
    monkeypatch.setattr(yaml, "__with_libyaml__", False)
    assert "expanded node limit" in load_documents(raw)[0].error
    assert load_documents(b"date: 2026-10-31\n")[0].data == {"date": "2026-10-31"}
