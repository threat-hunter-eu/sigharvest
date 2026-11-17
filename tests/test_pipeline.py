"""End-to-end: local git repo -> sync -> versions/occurrences/quarantine -> incremental re-sync -> dedupe."""

import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.models import Occurrence, Quarantine, RuleVersion, SyncLog
from sigharvest.query import dedupe
from sigharvest.service import open_db, sync_all

RULE = """title: Test {n}
id: {uid}
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\{n}.exe'
    condition: selection
level: low
"""

# Random-looking fixed ids (hand-made ones like ...-0000-0000-000000000001 are treated as placeholders).
UIDS = [
    "3f9c1e7a-52d8-4b6e-9a0f-c84e2d7b16a3",
    "b7e2049d-6c1f-4e83-a5d9-0f3c8b62e71c",
    "e41a8c63-9d07-4f25-b8e6-71c0d39a5f84",
    "5c08d7f2-a3e9-41b6-8d4c-e9271f0b63a5",
    "9a6e3b14-f8c2-4d07-b1a5-3e9d70c2f846",
    "d2f7a058-1b6e-4c93-8e0a-f564c9b31d27",
    "7b13e9c6-04da-4f81-9c2e-a8d5f61037be",
    "c590fa2d-e7b4-4318-a6c1-2d9e08f75b43",
    "18e6c3fb-9a52-4d0e-87b9-c4f1a03e6d25",
    "f0a49d71-3c8e-4b25-9e6d-57b2c18af039",
]


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def commit(repo: Path, msg: str) -> None:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", msg)


def make_repo(tmp: Path) -> Path:
    repo = tmp / "upstream"
    (repo / "rules").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "rules" / "a.yml").write_text(RULE.format(n="a", uid=UIDS[1]))
    (repo / "rules" / "b.yml").write_text(RULE.format(n="b", uid=UIDS[2]))
    # multi-document file: two rules
    (repo / "rules" / "multi.yaml").write_text(RULE.format(n="c", uid=UIDS[3]) + "---\n" + RULE.format(n="d", uid=UIDS[4]))
    # Sigma by content, odd extension
    (repo / "rules" / "e.txt").write_text(RULE.format(n="e", uid=UIDS[5]))
    # not Sigma
    (repo / "README.md").write_text("# rules\n")
    (repo / "config.yml").write_text("key: value\n")
    # broken YAML that looks like Sigma -> quarantine
    (repo / "rules" / "broken.yml").write_text("title: broken\ndetection:\n  sel: [unclosed\n")
    commit(repo, "init")
    return repo


def workspace(tmp: Path, repo: Path, *, initialize: bool = True) -> Workspace:
    ws = Workspace(tmp / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="local", type="git", url=str(repo.resolve()), paths=["rules/*"], priority=10)])
    if initialize:
        open_db(ws, migrate=True)
    return ws


def test_full_and_incremental_sync(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    out = sync_all(ws)
    assert out[0].status == "ok", out[0].message
    S = open_db(ws, migrate=True)
    with S() as s:
        versions = s.scalars(select(RuleVersion)).all()
        assert sorted(v.title for v in versions) == ["Test a", "Test b", "Test c", "Test d", "Test e"]
        multi = s.scalars(select(Occurrence).where(Occurrence.path == "rules/multi.yaml")).all()
        assert sorted(o.doc_index for o in multi) == [0, 1]
        q = s.scalars(select(Quarantine)).all()
        assert [x.path for x in q] == ["rules/broken.yml"]

    # change b, delete a, add a copy of c under another name, fix broken
    (repo / "rules" / "b.yml").write_text(RULE.format(n="b", uid=UIDS[2]).replace("level: low", "level: high"))
    (repo / "rules" / "a.yml").unlink()
    (repo / "rules" / "copy_of_c.yml").write_text(RULE.format(n="c", uid=UIDS[6]).replace("Test c", "Copy of c"))
    (repo / "rules" / "broken.yml").unlink()
    commit(repo, "update")

    out = sync_all(ws)
    assert out[0].status == "ok", out[0].message
    with S() as s:
        log = s.scalars(select(SyncLog).order_by(SyncLog.id.desc())).first()
        assert log is not None and log.files_changed == 1 and log.files_removed == 2 and log.files_added == 1
        b_versions = s.scalars(select(RuleVersion).where(RuleVersion.rule_id == UIDS[2])).all()
        assert len(b_versions) == 2  # history kept
        assert len({v.logic_hash for v in b_versions}) == 1  # level change does not change logic
        a = s.scalars(select(Occurrence).where(Occurrence.path == "rules/a.yml")).one()
        assert a.present is False
        assert all(not q.present for q in s.scalars(select(Quarantine)))

        rep = dedupe(s)
        assert rep.live_documents == 5  # b (new version), c and d (multi.yaml), e, copy_of_c
        assert any(g["copies"] == 2 for g in rep.logic_groups)  # c and copy_of_c share logic
        present = select(Occurrence.version_id).where(Occurrence.present.is_(True))
        assert len(set(s.scalars(select(RuleVersion.logic_hash).where(RuleVersion.id.in_(present))))) == rep.unique_logic

    # third sync without upstream changes: nothing new
    out = sync_all(ws)
    with S() as s:
        log = s.scalars(select(SyncLog).order_by(SyncLog.id.desc())).first()
        assert log is not None and log.versions_new == 0 and log.files_added == 0


def test_refuses_option_like_urls(tmp_path: Path) -> None:
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="evil", type="git", url="--upload-pack=touch /tmp/x", priority=10)])
    open_db(ws, migrate=True)
    out = sync_all(ws)
    assert out[0].status == "error"
    assert "refusing git url" in out[0].message


# Synthetic forms, deliberately separate from the real-document measurement.
METADATA_CASES = [
    ("", None, None),
    ("author: null\ndescription: null\n", None, None),
    ("author: true\ndescription: false\n", None, None),
    ("author: 123\ndescription: 456\n", None, None),
    ("author: 1.5\ndescription: 2.5\n", None, None),
    ("author: {fakeauthor: value}\ndescription: {fakedescription: value}\n", None, None),
    ("author: []\ndescription: []\n", None, None),
    ("author: [Alice, true]\ndescription: [fakedescription]\n", None, None),
    ("author: [Alice, 123]\ndescription: [123]\n", None, None),
    ("author: [Alice, null]\ndescription: [null]\n", None, None),
    ('author: [Alice, "\\u2003"]\ndescription: "\\u2003\\u00a0"\n', None, None),
    ('author: "\\u2003\\u00a0"\ndescription: ""\n', None, None),
    ('author: "true"\ndescription: "123"\n', "true", "123"),
    ('author: "123"\ndescription: "true"\n', "123", "true"),
    ('author: " Alice, Bob "\ndescription: "  validtext  "\n', " Alice, Bob ", "validtext"),
    ('author: [Alice, "Bob, Carol"]\ndescription: |\n  First line\n  Second line\n', "Alice, Bob, Carol", "First line\nSecond line"),
    ('author: "[red]Nickname[/red]"\ndescription: "<script>escapedtext</script>"\n', "[red]Nickname[/red]", "<script>escapedtext</script>"),
    ('author: ["Alice", ""]\ndescription: {}\n', None, None),
    ("author: [[Alice]]\ndescription: true\n", None, None),
    ("author: 2026-01-01\ndescription: 2026-01-02\n", "2026-01-01", "2026-01-02"),
    ("author: &name AliasWriter\ndescription: *name\n", "AliasWriter", "AliasWriter"),
]


def metadata_workspace(tmp: Path) -> tuple[Workspace, sessionmaker[Session]]:
    """Local ingested canonical documents, without git or network acquisition."""
    from uuid import NAMESPACE_URL, uuid5

    from sigharvest.ingest import Ingestor
    from sigharvest.models import Source

    ws = Workspace(tmp / "metadata-ws")
    ws.root.mkdir()
    save_sources(ws, [])
    factory = open_db(ws, migrate=True)
    with factory() as s:
        source = Source(name="metadata", type="local", url="")
        s.add(source)
        s.flush()
        for i, (metadata, _, _) in enumerate(METADATA_CASES):
            path = f"metadata-{i}.yml"
            (ws.root / path).write_text(RULE.format(n=f"metadata{i}", uid=str(uuid5(NAMESPACE_URL, f"metadata-{i}"))) + metadata)
            Ingestor(s, source, None).ingest_file(ws.root, path)
        # The child source slice has no author or description: use effective YAML.
        (ws.root / "inherited.yml").write_text(
            "action: global\nauthor: [Inherited, Writer]\ndescription: inheritedtext\n---\n" + RULE.format(n="inherited", uid=UIDS[0])
        )
        Ingestor(s, source, None).ingest_file(ws.root, "inherited.yml")
        s.commit()
    return ws, factory


def test_typed_metadata_search_and_preserved_score(tmp_path: Path) -> None:
    import yaml
    from sqlalchemy import text

    from sigharvest.index import GroupFilters, rebuild, score, search_groups
    from sigharvest.models import LogicGroup

    _, factory = metadata_workspace(tmp_path)
    with factory() as s:
        original = list(s.execute(select(RuleVersion.__table__)))
        rebuild(s, workers=1)
        for i, (_, author, description) in enumerate(METADATA_CASES):
            group = s.scalars(select(LogicGroup).where(LogicGroup.title == f"Test metadata{i}")).one()
            assert (group.author, group.description) == (author, description)
            version = s.get(RuleVersion, group.canonical_version_id)
            data = yaml.load(version.raw, Loader=yaml.BaseLoader)
            assert group.score == score(version, None, 0, 0, 1, str(data.get("description") or "").strip() or None)
            assert s.execute(text("SELECT author, description FROM rules_fts WHERE rowid=:id"), {"id": group.id}).one() == (
                author or "",
                description or "",
            )
            for field, term, expected in (("author", "true", author == "true"), ("description", "123", description == "123")):
                hits, _ = search_groups(s, f"{field}:{term}", GroupFilters(include_junk=True), per_family=False)
                assert (group.logic_hash in {hit.logic_hash for hit in hits}) == expected
        for term in ("author:fakeauthor", "description:fakedescription", "author:None", "description:False"):
            assert search_groups(s, term, GroupFilters(include_junk=True), per_family=False)[1] == 0
        inherited = s.scalars(select(LogicGroup).where(LogicGroup.title == "Test inherited")).one()
        assert (inherited.author, inherited.description) == ("Inherited, Writer", "inheritedtext")
        assert search_groups(s, "author:Inherited description:inheritedtext", GroupFilters())[1] == 1
        rebuild(s, workers=1)
        assert list(s.execute(select(RuleVersion.__table__))) == original


def test_index_rebuild_refreshes_planner_statistics(tmp_path: Path) -> None:
    """A freshly filled database has no sqlite_stat1; without it SQLite picks nested scans for the family queries."""
    from sqlalchemy import text

    from sigharvest.index import rebuild

    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    sync_all(ws)
    with open_db(ws)() as s:
        assert not s.execute(text("SELECT 1 FROM sqlite_master WHERE name = 'sqlite_stat1'")).first()
        rebuild(s)
        assert s.execute(text("SELECT count(*) FROM sqlite_stat1")).scalar_one() > 0


def test_heartbeat_keepalive_repeats_a_long_step(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import time

    from sigharvest.cli import pipeline

    monkeypatch.setattr(pipeline, "HEARTBEAT_SECONDS", 0.2)
    beat = pipeline.Heartbeat("x")
    beat.tty = False
    with beat.keepalive():
        beat.say("index: identity families")
        beat.remember("ingest: news not printed yet")
        time.sleep(1.5)
        beat.say("index: identity families")
        time.sleep(1.5)
    out = capsys.readouterr().out
    lines = [line.rsplit(" (", 1)[0] for line in out.splitlines()]
    assert lines[:2] == ["index: identity families", "ingest: news not printed yet"]  # remembered news comes out once
    assert "index: identity families (still running)" in lines
    assert lines[lines.index("index: identity families (still running)") :] == ["index: identity families (still running)"] * (
        len(lines) - lines.index("index: identity families (still running)")
    )
