"""Self-verifying `sigharvest update`: the run table, the gates, the what-changed report, the lock and index skipping."""

import json
import shlex
import sys
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest import runs
from sigharvest.cli import app
from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.db import get_meta
from sigharvest.index import INDEX_BUILT_AT
from sigharvest.lock import LockHeld, UpdateLock, holder, lock_path
from sigharvest.models import LogicGroup, UpdateRun
from sigharvest.service import open_db
from sigharvest.testing import SCHEMAS, SPEC_COMMIT
from tests.test_pipeline import commit, git

N_RULES = 30  # one removed rule is 3.3% of the unique logic: under the 5% gate
RULE = """title: Rule {n}
id: {uid}
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\{exe}.exe'
    condition: selection
level: medium
"""


def _uid(n: int) -> str:
    return str(uuid.UUID(int=(0x5A17 << 112) + n * 0x9E3779B97F4A7C15 + 0x4000_0000_0000_8000_0000_0000_0000, version=4))


def write_rule(repo: Path, n: int, exe: str | None = None) -> None:
    (repo / "rules" / f"r{n}.yml").write_text(RULE.format(n=n, uid=_uid(n), exe=exe or f"tool{n}"))


def make_workspace(tmp: Path) -> tuple[Path, Workspace]:
    """A git repo with N_RULES rules and a workspace on it, with empty JSON schemas cached (no network)."""
    repo = tmp / "upstream"
    (repo / "rules").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    for n in range(N_RULES):
        write_rule(repo, n)
    (repo / "rules" / "broken.yml").write_text("title: broken\ndetection:\n  sel: [unclosed\n")
    commit(repo, "init")
    ws = Workspace(tmp / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="local", type="git", url=str(repo.resolve()), paths=["rules/*"], priority=10)])
    schemas = ws.cache / "sigma-specification" / SPEC_COMMIT
    schemas.mkdir(parents=True)
    for name in SCHEMAS.values():
        (schemas / name).write_text("{}")
    return repo, ws


def update(ws: Workspace, *args: str) -> tuple[int, str]:
    if not ws.db_path.exists() and not lock_path(ws).exists():
        open_db(ws, migrate=True)  # explicit fixture initialization before running the command
    res = CliRunner().invoke(app, ["update", "-j", "2", *args], env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "200"})
    if res.exception and not isinstance(res.exception, SystemExit):
        raise res.exception
    return res.exit_code, res.output


def latest(ws: Workspace) -> UpdateRun:
    with open_db(ws, migrate=True)() as s:
        run = runs.get_run(s, "latest")
        assert run is not None
        return run


def report(ws: Workspace, run: UpdateRun) -> tuple[str, dict]:
    assert run.report
    md = ws.root / run.report
    return md.read_text(encoding="utf-8"), json.loads(md.with_suffix(".json").read_text(encoding="utf-8"))


# ----------------------------------------------------------------------------- gates


BASE = {
    "unique_logic": 1000,
    "quarantine": 100,
    "sources_enabled": 100,
    "sources_failed": 0,
    "index_groups": 1000,
    "index_missing": 0,
}


def _gates(cur: dict, prev: dict | None = None, **th: float) -> dict[str, str]:
    return {g.name: g.status for g in runs.evaluate({**BASE, **cur}, None if prev is None else {**BASE, **prev}, runs.Thresholds(**th))}


def test_first_run_has_no_baseline() -> None:
    g = _gates({})
    assert g["unique logic"] == g["quarantine"] == "skipped"
    assert "SigmaHQ regression" not in g
    assert g["failed sources"] == g["index complete"] == "pass"


def test_gate_unique_logic_drop() -> None:
    assert _gates({"unique_logic": 960}, {})["unique logic"] == "pass"  # -4%
    assert _gates({"unique_logic": 940}, {})["unique logic"] == "fail"  # -6%
    assert _gates({"unique_logic": 940}, {}, max_logic_drop=10)["unique logic"] == "pass"
    assert _gates({"unique_logic": 5000}, {})["unique logic"] == "pass"  # growth is fine


def test_gate_quarantine_growth() -> None:
    assert _gates({"quarantine": 119}, {})["quarantine"] == "pass"
    assert _gates({"quarantine": 160}, {})["quarantine"] == "fail"  # +60%, +60 documents
    small = {"quarantine": 10}
    assert _gates({"quarantine": 30}, small)["quarantine"] == "pass"  # +200% but only 20 documents
    assert _gates({"quarantine": 30}, small, quarantine_min_growth=5)["quarantine"] == "fail"


def test_gate_failed_sources() -> None:
    assert _gates({"sources_failed": 10})["failed sources"] == "pass"
    assert _gates({"sources_failed": 11})["failed sources"] == "fail"


def test_gate_index_complete() -> None:
    assert _gates({"index_missing": 3})["index complete"] == "fail"


@pytest.mark.slow
def test_update_records_runs_and_reports_changes(tmp_path: Path) -> None:
    repo, ws = make_workspace(tmp_path)
    code, out = update(ws)
    assert code == 0, out
    first = latest(ws)
    assert first.status == "ok" and first.counts["new"] == N_RULES and first.counts["unique_logic"] == N_RULES
    assert first.counts["quarantine"] == 1 and first.counts["sources_ok"] == 1
    assert {"sync", "test", "index", "report"} <= set(first.durations)
    assert (ws.reports / "summary.md").exists()

    # a collection with rule 1 (changes upstream) and rule 2 (removed)
    with open_db(ws, migrate=True)() as s:
        from sigharvest import collections as col

        g1 = s.scalars(select(LogicGroup).where(LogicGroup.title == "Rule 1")).one()
        g2 = s.scalars(select(LogicGroup).where(LogicGroup.title == "Rule 2")).one()
        c = col.create(s, "watch")
        col.add(s, c, [g1, g2])
        s.commit()
        old1 = g1.logic_hash

    write_rule(repo, 1, exe="changed1")  # same id, new detection
    (repo / "rules" / "r2.yml").unlink()  # removed
    write_rule(repo, 99)  # new
    commit(repo, "change")
    code, out = update(ws)
    assert code == 0, out
    run = latest(ws)
    assert run.id == first.id + 1 and run.status == "ok"
    assert (run.counts["new"], run.counts["changed"], run.counts["removed"]) == (1, 1, 1)
    md, data = report(ws, run)
    assert md.startswith(f"# sigharvest update {run.id}: OK")
    assert [x["title"] for x in data["new"]] == ["Rule 99"]
    assert [x["title"] for x in data["removed"]] == ["Rule 2"]
    (ch,) = data["changed"]
    assert ch["rule_id"] == _uid(1) and ch["old"] == old1 and ch["sources"] == ["local"]
    assert any(x.startswith("-") and "tool1.exe" in x for x in ch["diff"]) and any(x.startswith("+") and "changed1.exe" in x for x in ch["diff"])
    assert "```diff" in md and "changed1.exe" in md
    assert data["sources"] == {"local": {"new": 1, "changed": 1, "removed": 1, "error": ""}}
    (affected,) = data["collections"]
    assert affected["collection"] == "watch"
    assert [i["title"] for i in affected["updated"]] == ["Rule 1"] and [i["title"] for i in affected["missing"]] == ["Rule 2"]
    assert data["previous_run"] == first.id and data["previous_counts"]["unique_logic"] == N_RULES

    listing = CliRunner().invoke(app, ["runs"], env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "200"})
    assert listing.exit_code == 0 and "ok" in listing.output
    shown = CliRunner().invoke(app, ["runs", "show", "latest"], env={"SIGHARVEST_HOME": str(ws.root)})
    assert shown.exit_code == 0 and shown.output == md


@pytest.mark.slow
def test_unchanged_update_skips_the_index(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    assert update(ws)[0] == 0
    with open_db(ws, migrate=True)() as s:
        built = get_meta(s, INDEX_BUILT_AT)
    t0 = time.monotonic()
    code, out = update(ws)
    idle = time.monotonic() - t0
    assert code == 0 and "not rebuilt" in out
    run = latest(ws)
    assert "index" not in run.durations and run.counts["new"] == run.counts["changed"] == run.counts["removed"] == 0
    with open_db(ws, migrate=True)() as s:
        assert get_meta(s, INDEX_BUILT_AT) == built
    assert idle < 20  # measured about 1 s on the fixture
    assert update(ws, "--force-index")[0] == 0
    assert "index" in latest(ws).durations
    with open_db(ws, migrate=True)() as s:
        assert get_meta(s, INDEX_BUILT_AT) != built


@pytest.mark.slow
def test_failed_gate_exits_1_reports_and_notifies(tmp_path: Path) -> None:
    repo, ws = make_workspace(tmp_path)
    assert update(ws)[0] == 0
    for n in range(5):  # 5 of 30 rules: -16.7% unique logic
        (repo / "rules" / f"r{n}.yml").unlink()
    commit(repo, "remove many")
    marker = tmp_path / "notified.txt"
    script = tmp_path / "notify.py"
    script.write_text(f"import sys; open({str(marker)!r}, 'w').write(sys.argv[-1])\n")
    code, out = update(ws, "--notify-cmd", f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}")
    assert code == 1, out
    run = latest(ws)
    assert run.status == "failed gate" and run.reasons[0].startswith("gate unique logic")
    md, data = report(ws, run)
    assert md.startswith(f"# sigharvest update {run.id}: FAILED GATE") and "**Needs a look:**" in md
    assert {g["name"]: g["status"] for g in data["gates"]}["unique logic"] == "fail"
    assert marker.read_text() == str(ws.root / run.report)
    assert "did not pass" in (ws.reports / "summary.md").read_text()

    # the failed run is not the baseline: the next update still fails until someone accepts it
    assert update(ws)[0] == 1
    with open_db(ws, migrate=True)() as s:
        assert runs.previous_passed(s).counts["unique_logic"] == N_RULES  # type: ignore[union-attr]
    res = CliRunner().invoke(app, ["runs", "accept", "latest"], env={"SIGHARVEST_HOME": str(ws.root)})
    assert res.exit_code == 0, res.output
    assert update(ws)[0] == 0


@pytest.mark.slow
def test_source_failures_gate_and_allow_failures(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    save_sources(ws, [*load_sources(ws), SourceConfig(name="gone", type="git", url=str(tmp_path / "missing"))])
    code, _ = update(ws, "--allow-failures", "--failed-sources-floor", "0")
    run = latest(ws)
    # Explicitly disable the small-install allowance: the percentage gate still applies.
    assert code == 1 and run.status == "failed gate"
    assert run.counts["sources_failed"] == 1 and any("gone" in r for r in run.reasons)
    _, data = report(ws, run)
    assert data["sources"]["gone"]["error"]
    code, _ = update(ws, "--allow-failures", "--max-failed-sources", "60")
    assert code == 0 and latest(ws).status == "source failures"
    code, _ = update(ws, "--max-failed-sources", "60")
    assert code == 1  # source failures without --allow-failures


def test_report_retention(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    folder = runs.runs_dir(ws)
    folder.mkdir(parents=True)
    for i in range(5):
        (folder / f"2026010{i}T000000Z.md").write_text("x")
        (folder / f"2026010{i}T000000Z.json").write_text("{}")
    assert runs.prune_reports(ws, keep=2) == 3
    assert sorted(p.stem for p in folder.iterdir()) == ["20260103T000000Z"] * 2 + ["20260104T000000Z"] * 2


def test_report_retention_keeps_the_last_accepted_runs(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    assert update(ws)[0] == 0
    folder = runs.runs_dir(ws)
    accepted = latest(ws).report
    for i in range(5):
        (folder / f"2099010{i}T000000Z.md").write_text("x")
        (folder / f"2099010{i}T000000Z.json").write_text("{}")
    runs.prune_reports(ws, keep=2)
    names = sorted(p.name for p in folder.glob("*.md"))
    assert names == sorted([accepted.rsplit("/", 1)[1], "20990103T000000Z.md", "20990104T000000Z.md"])


@pytest.mark.slow
def test_log_file_and_rotation(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    logs = ws.root / "data" / "logs"
    logs.mkdir(parents=True)
    for i in range(20):
        (logs / f"update-2020-01-{i + 1:02d}.log").write_text("old")
    assert update(ws)[0] == 0
    files = sorted(p.name for p in logs.iterdir())
    assert len(files) == runs.KEEP_LOGS and "update-2020-01-01.log" not in files
    text = (logs / files[-1]).read_text()
    assert "update 1 started" in text and "update 1: ok" in text


# ----------------------------------------------------------------------------- lock


def test_lock_excludes_a_second_update(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    with UpdateLock(ws):
        with pytest.raises(LockHeld), UpdateLock(ws):
            pass
        code, out = update(ws)
        assert code == 2 and "workspace is busy" in out
    assert holder(lock_path(ws)) is None


def _write_lock(ws: Workspace, **data: object) -> Path:
    path = lock_path(ws)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


@pytest.mark.slow
def test_metadata_edit_rebuilds_the_index(tmp_path: Path) -> None:
    repo, ws = make_workspace(tmp_path)
    assert update(ws)[0] == 0
    path = repo / "rules" / "r3.yml"
    path.write_text(path.read_text().replace("title: Rule 3", "title: Rule three"))  # same logic hash, new title
    commit(repo, "retitle")
    assert update(ws)[0] == 0
    run = latest(ws)
    assert "index" in run.durations and run.counts["changed"] == run.counts["new"] == 0
    with open_db(ws, migrate=True)() as s:
        assert s.scalars(select(LogicGroup.title).where(LogicGroup.title == "Rule three")).one()


EVIL = "\x1b]8;;http://evil\x1b\\click\x1b]8;;\x1b\\ \x1b[2J"


@pytest.mark.slow
def test_control_characters_never_reach_the_terminal(tmp_path: Path) -> None:
    repo, ws = make_workspace(tmp_path)
    assert update(ws)[0] == 0
    # YAML double-quoted escapes: the title and the detection value really contain ESC characters
    evil_yaml = '"Rule 5 \\e]8;;http://evil\\e\\\\click\\e]8;;\\e\\\\ \\e[2J"'
    path = repo / "rules" / "r5.yml"
    path.write_text(path.read_text().replace("title: Rule 5", f"title: {evil_yaml}").replace("'\\\\tool5.exe'", '"\\\\tool5\\e[2J.exe"'))
    commit(repo, "evil")
    assert update(ws)[0] == 0
    with open_db(ws, migrate=True)() as s:
        assert s.scalars(select(LogicGroup.title).where(LogicGroup.title.startswith("Rule 5"))).one().count("\x1b") == 5
    run = latest(ws)
    md, data = report(ws, run)
    raw_json = (ws.root / run.report).with_suffix(".json").read_text()  # type: ignore[operator]
    assert "\x1b" not in md and "\\u001b" not in raw_json and "\x1b" not in raw_json
    (ch,) = data["changed"]
    assert ch["title"].startswith("Rule 5 \ufffd]8;;http://evil") and any("tool5" in x and "[2J" in x for x in ch["diff"])
    shown = CliRunner().invoke(app, ["runs", "show", "latest"], env={"SIGHARVEST_HOME": str(ws.root)})
    assert shown.exit_code == 0 and "\x1b" not in shown.output
    # an old report written before sanitising is cleaned when shown
    (ws.root / run.report).write_text(f"# old {EVIL}\n")  # type: ignore[operator]
    shown = CliRunner().invoke(app, ["runs", "show", "latest"], env={"SIGHARVEST_HOME": str(ws.root)})
    assert "\x1b" not in shown.output and "http://evil" in shown.output


def test_clean_text() -> None:
    assert runs.clean_text(EVIL + "\ttab\nline\x07\x9b") == EVIL.replace("\x1b", "\ufffd") + "\ttab\nline\ufffd\ufffd"
    assert runs.clean_data({"k\x1b": ["a\x1b", 1, None]}) == {"k\ufffd": ["a\ufffd", 1, None]}


def test_update_sources_file_and_report_file(tmp_path: Path) -> None:
    _repo, ws = make_workspace(tmp_path)
    configured = load_sources(ws)
    external = tmp_path / "list.yaml"
    save_sources(Workspace(tmp_path / "other"), configured)
    external.write_bytes((tmp_path / "other" / "sources.yaml").read_bytes())
    fresh = Workspace(tmp_path / "fresh")  # SIGHARVEST_HOME without sources.yaml or database
    from tests.helpers import seed_schemas

    seed_schemas(fresh)  # offline: the validate stage reads its pinned JSON schemas from the cache
    report_md, report_json = tmp_path / "out" / "run.md", tmp_path / "out" / "run.json"

    def update(ws: Workspace, *args: str) -> tuple[int, str]:
        res = CliRunner().invoke(app, ["update", "-j", "2", *args], env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "200"})
        return res.exit_code, res.output

    code, out = update(fresh, "--sources", str(external), "--report-file", str(report_md))
    assert code == 0, out
    assert load_sources(fresh) == configured and fresh.db_path.exists()
    assert report_md.read_text().startswith("# sigharvest update")
    code, out = update(fresh, "--report-file", str(report_json))
    assert code == 0, out
    assert json.loads(report_json.read_text())["status"] == "ok"
    code, out = update(fresh, "--sources", str(tmp_path / "missing.yaml"))
    assert code == 2


def test_update_converts_on_demand_only_unless_asked(tmp_path: Path) -> None:
    """`update` validates and indexes; conversions are stored only with --convert (the first run stays fast)."""
    from sqlalchemy import func

    from sigharvest.conversion import BACKENDS
    from sigharvest.models import TestResult

    _, ws = make_workspace(tmp_path)
    code, out = update(ws)
    assert code == 0, out
    # Without a terminal, long stages still print progress lines (Rich's live status shows nothing there).
    assert "validate: " in out and "(100%)" in out
    assert "index: " in out

    def stored(stage: str) -> int:
        with open_db(ws)() as s:
            return s.scalar(select(func.count()).select_from(TestResult).where(TestResult.stage == stage)) or 0

    assert stored("validate") >= N_RULES
    assert stored("convert") == 0
    if not BACKENDS:
        return
    code, out = update(ws, "--convert")
    assert code == 0, out
    assert stored("convert") >= N_RULES
    with open_db(ws)() as s:
        assert all(g.converts for g in s.scalars(select(LogicGroup)))


def test_quarantine_gate_scales_with_corpus_growth() -> None:
    prev = {"quarantine": 100, "documents": 10_000}
    # The corpus doubled (new sources): 200 quarantined documents is the same share, 260 is +30% over it.
    assert _gates({"quarantine": 200, "documents": 20_000}, prev)["quarantine"] == "pass"
    assert _gates({"quarantine": 260, "documents": 20_000}, prev)["quarantine"] == "fail"
    assert _gates({"quarantine": 160, "documents": 10_000}, prev)["quarantine"] == "fail"  # same corpus: +60%
    assert _gates({"quarantine": 160, "documents": 5_000}, prev)["quarantine"] == "fail"  # never scaled down


def test_sync_admission_charges_running_fetches_not_every_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The first nightly (1,201 sources) was refused upfront: every source's worst case was charged at once."""
    from sigharvest import space

    ws = Workspace(tmp_path)
    sources = [SourceConfig(name=f"s{i}", type="git", url=f"https://example.invalid/s{i}.git") for i in range(1200)]
    monkeypatch.setattr(space, "capacity", lambda path: space.Capacity(1, 14 * 1024**3, None))
    space.before_sync(ws, sources, workers=4)  # 1,200 x 160 MiB would be refused
    monkeypatch.setenv("SIGHARVEST_DISK_RESERVE_BYTES", str(13 * 1024**3))
    with pytest.raises(space.SpaceError) as refused:
        space.before_sync(ws, sources, workers=4)
    assert str(refused.value).count("corpus") == 1  # labels are listed once


def test_test_stage_admission_is_sized_by_versions_to_test(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A resumed validation on the full corpus was refused for ~180k live versions it would not touch."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from sigharvest import space

    ws = Workspace(tmp_path)
    s = Session(create_engine(f"sqlite:///{tmp_path / 'test.db'}"))
    monkeypatch.setattr(space, "capacity", lambda path: space.Capacity(1, 2 * 1024**3, None))
    space.before_test(ws, s, 1_000, tmp_path / "schemas")
    space.before_test(ws, s, 40_000, tmp_path / "schemas")  # 2 x 625 MiB + reserve fits 2 GiB at 16 KiB a version
    with pytest.raises(space.SpaceError):
        space.before_test(ws, s, 180_000, tmp_path / "schemas")
    s.close()


def test_fetch_budget_counts_running_fetches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import space

    ws = Workspace(tmp_path)
    a, b = (SourceConfig(name=n, type="git", url=f"https://example.invalid/{n}.git") for n in "ab")
    monkeypatch.setattr(space, "capacity", lambda path: space.Capacity(1, 1024**3, None))
    monkeypatch.setenv("SIGHARVEST_DISK_SYNC_SOURCE_BYTES", str(100 * 1024**2))  # 500 MiB per fetch
    budget = space.FetchBudget(ws)
    budget.acquire(a)
    with pytest.raises(space.SpaceError):
        budget.acquire(b)  # 1 GiB < 256 MiB reserve + 2 x 500 MiB
    budget.release("a")
    budget.acquire(b)


@pytest.mark.slow
def test_disk_refusal_defers_sources_and_drops_git_clones(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import space

    repo, ws = make_workspace(tmp_path)
    real = space.FetchBudget.acquire

    def refuse_copy(self: space.FetchBudget, source: SourceConfig) -> None:
        if source.name == "copy":
            raise space.SpaceError("disk admission refused (corpus): test")
        real(self, source)

    copy = tmp_path / "copy"
    git(tmp_path, "clone", "-q", str(repo), str(copy))
    save_sources(ws, [*load_sources(ws), SourceConfig(name="copy", type="git", url=str(copy.resolve()), paths=["rules/*"], priority=20)])
    monkeypatch.setattr(space.FetchBudget, "acquire", refuse_copy)
    monkeypatch.setenv("SIGHARVEST_GIT_CACHE", "drop")
    code, out = update(ws)
    assert code == 0, out
    run = latest(ws)
    assert run.counts["sources_deferred"] == 1 and run.counts["sources_failed"] == 0
    assert "1 sources left for the next run" in out
    assert not any(ws.cache.glob("git/*"))  # ingested clone dropped
    monkeypatch.setattr(space.FetchBudget, "acquire", real)
    code, out = update(ws)
    assert code == 0, out
    assert latest(ws).counts.get("sources_deferred", 0) == 0 and "left for the next run" not in out


@pytest.mark.slow
def test_time_budget_defers_sources_to_the_next_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.cli import pipeline
    from sigharvest.index import canonical_version_ids

    repo, ws = make_workspace(tmp_path)
    copy = tmp_path / "copy"
    git(tmp_path, "clone", "-q", str(repo), str(copy))
    sources = [*load_sources(ws), SourceConfig(name="copy", type="git", url=str(copy.resolve()), paths=["rules/*"], priority=20)]
    save_sources(ws, sources)
    monkeypatch.setattr(pipeline, "_deadline", lambda minutes: 0.0 if minutes else None)  # the budget is already spent
    code, out = update(ws, "--time-budget", "5")
    assert code == 0, out
    run = latest(ws)
    assert run.counts["sources_deferred"] == 2 and run.counts["sources_failed"] == 0 and run.counts["unique_logic"] == 0
    assert "2 sources left for the next run" in out
    _, data = report(ws, run)
    assert any("time budget or disk space reached: 2 sources" in n for n in data["notes"])
    code, out = update(ws, "--time-budget", "0")  # 0 = no budget: everything is synced
    assert code == 0, out
    run = latest(ws)
    assert run.counts["unique_logic"] == N_RULES and "sources_deferred" not in run.counts
    with open_db(ws, migrate=True)() as s:
        # The conversion selection of --convert-scope canonical is the copy the index chose (priority 10 wins).
        assert canonical_version_ids(s) == set(s.scalars(select(LogicGroup.canonical_version_id)))


def test_sources_files_are_joined_and_duplicates_refused(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    one, two = tmp_path / "one.yaml", tmp_path / "two.yaml"
    one.write_text("sources:\n- name: a\n  url: https://example.invalid/a.git\n  enabled: false\n")
    two.write_text("sources:\n- name: b\n  url: https://example.invalid/b.git\n  enabled: false\n")
    code, out = update(ws, "--sources", str(one), "--sources", str(two), "--no-report")
    assert [s.name for s in load_sources(ws)] == ["a", "b"], out
    code, out = update(ws, "--sources", str(one), "--sources", str(one))
    assert code == 2 and "more than once" in out
