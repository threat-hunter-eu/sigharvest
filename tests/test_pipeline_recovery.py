"""Offline regressions for source recovery, occurrence identity and poison documents."""

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from sigharvest import documents, service
from sigharvest.config import load_sources
from sigharvest.db import IN_CHUNK
from sigharvest.documents import MAX_FILE_BYTES, load_documents
from sigharvest.ingest import Ingestor
from sigharvest.models import Occurrence, Quarantine, RuleVersion, Source
from sigharvest.service import open_db, sync_all
from sigharvest.sync import sync_git
from tests.test_pipeline import RULE, UIDS, commit, git, make_repo, workspace


@pytest.mark.parametrize("recovery", ["cache", "corpus", "interrupted"])
def test_full_scan_reconciles_missing_paths(tmp_path: Path, recovery: str) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    (repo / "rules/a.yml").unlink()
    (repo / "rules/broken.yml").unlink()
    commit(repo, "remove valid and quarantined files")
    if recovery == "cache":
        shutil.rmtree(ws.git_repo("local"))
    elif recovery == "corpus":
        shutil.rmtree(ws.source_dir("local"))
    else:
        # Fetch publishes its marker but the process exits before any ingest.
        with open_db(ws, migrate=True)() as s:
            source = s.scalars(select(Source)).one()
            sync_git(load_sources(ws)[0], ws, source.last_commit)
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    assert outcome.log.files_removed == 2
    with open_db(ws, migrate=True)() as s:
        assert not s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one().present
        assert not s.scalars(select(Quarantine)).one().present
        assert len(s.scalars(select(RuleVersion)).all()) == 5  # history survives
        assert len(s.scalars(select(Occurrence).where(Occurrence.present.is_(True))).all()) == 4
    again = sync_all(ws)[0]
    assert again.status == "ok" and again.log.files_removed == again.log.versions_new == 0


def test_failed_full_scan_does_not_retire_unvisited_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    (repo / "rules/a.yml").unlink()
    commit(repo, "remove a")
    shutil.rmtree(ws.source_dir("local"))
    original = service.Ingestor.ingest_file

    def fail(*_args: object) -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(service.Ingestor, "ingest_file", fail)
    assert sync_all(ws)[0].status == "error"
    with open_db(ws, migrate=True)() as s:
        assert s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one().present
    monkeypatch.setattr(service.Ingestor, "ingest_file", original)
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        assert not s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one().present


def test_empty_snapshot_reconciliation_is_chunked_and_source_scoped(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        source = s.scalars(select(Source)).one()
        version = s.scalars(select(RuleVersion)).first()
        assert version is not None
        other = Source(name="other", type="local", url=str(repo))
        s.add(other)
        s.flush()
        for sid, count in ((source.id, IN_CHUNK + 1), (other.id, 1)):
            for i in range(count):
                path = f"extra/{i}.yml"
                s.add(Occurrence(source_id=sid, version_id=version.id, path=path, file_hash=version.content_hash))
                s.add(Quarantine(source_id=sid, path=path, content_hash="a" * 64, error="yaml: fixture"))
        s.commit()
        ing = Ingestor(s, source, source.last_commit)
        missing = ing.reconcile_paths(set())
        assert len(missing) == IN_CHUNK + 6  # extra paths plus four rule paths and one broken path
        s.commit()
        for model in (Occurrence, Quarantine):
            assert not s.scalars(select(model).where(model.source_id == source.id, model.present.is_(True))).all()
            assert s.scalars(select(model).where(model.source_id == other.id)).one().present
            assert s.scalars(select(model).where(model.source_id == source.id)).first()  # history retained
        assert ing.reconcile_paths(set()) == set()


def test_force_push_to_unrelated_history(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    git(repo, "checkout", "--orphan", "replacement")
    git(repo, "rm", "-rf", ".")
    (repo / "rules").mkdir()
    (repo / "rules/new.yml").write_text(RULE.format(n="new", uid=UIDS[0]))
    commit(repo, "unrelated history")
    git(repo, "branch", "-M", "main")
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    with open_db(ws, migrate=True)() as s:
        assert [o.path for o in s.scalars(select(Occurrence).where(Occurrence.present.is_(True)))] == ["rules/new.yml"]
        assert all(not q.present for q in s.scalars(select(Quarantine)))


def test_reordered_identical_documents_retire_old_positions(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    path = repo / "rules/positions.yml"
    rule = RULE.format(n="position", uid=UIDS[0])
    path.write_text("---\n" + rule + "---\n" + rule)
    commit(repo, "duplicate documents")
    assert sync_all(ws)[0].status == "ok"
    path.write_text("---\n" + rule)
    commit(repo, "remove second occurrence of the same version")
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        rows = s.scalars(select(Occurrence).where(Occurrence.path == "rules/positions.yml").order_by(Occurrence.doc_index)).all()
        assert len(rows) == 2 and rows[0].version_id == rows[1].version_id
        assert [o.present for o in rows] == [True, False]
    # Move exactly the same bytes to a new document index without changing its version.
    path.write_text("title: unrelated\n---\n" + rule)
    commit(repo, "move document")
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        rows = s.scalars(select(Occurrence).where(Occurrence.path == "rules/positions.yml").order_by(Occurrence.doc_index)).all()
        assert [o.present for o in rows] == [False, True]


@pytest.mark.parametrize(
    "poison",
    [
        b"logsource: {}\ndetection: " + b"[" * 80 + b"0" + b"]" * 80 + b"\n",
        b"logsource: {}\ndetection: &loop {selection: *loop}\n",
        b"logsource: {}\ndetection: {selection: 1}\ntitle: \xff\n",
        b"logsource: {}\ndetection: {selection: " + b"9" * 5000 + b"}\n",
    ],
)
def test_poison_is_quarantined_and_following_document_survives(tmp_path: Path, poison: bytes) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    path = repo / "rules/poison.yml"
    healthy = RULE.format(n="healthy", uid=UIDS[0]).encode()
    path.write_bytes(poison + b"---\n" + healthy)
    commit(repo, "one poison document next to a valid rule")
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok", outcome.message
    with open_db(ws, migrate=True)() as s:
        q = s.scalars(select(Quarantine).where(Quarantine.path == "rules/poison.yml")).one()
        assert q.present and q.doc_index == 0 and q.error.startswith("yaml:")
        assert s.scalars(select(RuleVersion).where(RuleVersion.title == "Test healthy")).one()
    # An unchanged retry must not duplicate dead letters.
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        assert len(s.scalars(select(Quarantine).where(Quarantine.path == "rules/poison.yml")).all()) == 1
    path.write_bytes(healthy)
    commit(repo, "repair poison file")
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as s:
        assert not s.scalars(select(Quarantine).where(Quarantine.path == "rules/poison.yml")).one().present


def test_alias_expansion_is_bounded_before_merge_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(documents, "MAX_YAML_NODES", 60)
    raw = b"a: &a {x: 1}\nb: &b {<<: [*a, *a, *a, *a]}\nc: {<<: [*b, *b, *b, *b, *b]}\n"
    assert "expanded node limit" in (load_documents(raw)[0].error or "")


def test_plain_node_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(documents, "MAX_YAML_NODES", 20)
    assert "node limit" in (load_documents(b"items: [" + b"1," * 30 + b"]")[0].error or "")


def test_loader_preserves_anchors_legacy_collections_and_exact_bytes() -> None:
    raw = (
        b"\xef\xbb\xbfaction: global\r\nlogsource: {product: windows}\r\n"
        b"---\r\ntitle: legacy\r\ndetection:\r\n  a: &a {Image: cmd.exe}\r\n  b: *a\r\n  condition: a or b\r\n"
    )
    doc = load_documents(raw)[0]
    assert doc.error is None and doc.kind == "rule" and doc.flags == ["legacy_collection"]
    assert doc.data["detection"]["a"] == doc.data["detection"]["b"]
    assert doc.raw == raw[raw.index(b"---") :]


def test_direct_parser_rejects_oversized_input() -> None:
    assert load_documents(b"x" * (MAX_FILE_BYTES + 1))[0].error == "yaml: file exceeds size limit"
