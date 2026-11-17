"""`sigharvest doctor`: a healthy workspace passes; each kind of breakage is reported with a fix and the right exit code."""

import json
import os
import socket
import sqlite3
import time
from datetime import timedelta
from io import StringIO
from pathlib import Path

import pytest
from rich.cells import cell_len
from rich.console import Console
from sqlalchemy import select
from sqlalchemy import update as sql_update
from typer.testing import CliRunner

from sigharvest import health
from sigharvest.attack import ATTACK_VERSION
from sigharvest.cli import app
from sigharvest.cli.health import format_doctor
from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.lock import lock_path, mutation_lease
from sigharvest.models import Source, SyncLog, utcnow
from sigharvest.service import open_db, sync_all
from tests.test_pipeline import commit
from tests.test_update_runs import make_workspace, update, write_rule


def render_doctor(items: list[health.Check], width: int = 80, root: Path = Path("/workspace")) -> str:
    output = StringIO()
    Console(file=output, width=width, color_system=None).print(format_doctor(items, root))
    return output.getvalue()


@pytest.mark.parametrize("width", [80, 120])
def test_summary_all_ok(width: int) -> None:
    items = [health.Check("schema", "ok", "current"), health.Check("integrity", "ok", "not checked (use --deep)")]
    text = render_doctor(items, width)
    assert text.splitlines() == [
        "healthy: 2 ok, 0 warnings, 0 failures",
        "Workspace: /workspace",
        "Full results, including passed checks: sigharvest doctor --json",
    ]
    assert "Action" not in text


def test_summary_counts_are_singular_for_one() -> None:
    items = [health.Check("schema", "ok", "current"), health.Check("attack", "warn", "not downloaded yet", "sigharvest coverage")]
    assert render_doctor(items, 120).startswith("healthy, with warnings: 1 ok, 1 warning, 0 failures\n")


@pytest.mark.parametrize("width", [80, 120])
def test_summary_preserves_problems_order_and_exact_actions(width: int) -> None:
    items = [
        health.Check("schema", "ok", "current"),
        health.Check("references", "warn", "stale projection", "sigharvest index"),
        health.Check("index", "fail", "missing groups", "sigharvest index"),
        health.Check("disk", "fail", "almost full", "free disk space"),
        health.Check("updates", "warn", "still running"),
        health.Check("other", "warn", "needs full index", "sigharvest index --full"),
        health.Check("literal", "warn", "different trailing whitespace", "sigharvest index "),
    ]
    before = json.dumps(health.as_json(items), indent=1)
    text = render_doctor(items, width)
    assert text.startswith("not healthy: 1 ok, 4 warnings, 2 failures\n")
    problems = [c for c in items if c.status != "ok"]
    positions = [text.index(f"{c.status.upper()} {c.name}: {c.message}") for c in problems]
    assert positions == sorted(positions)
    assert [line for line in text.splitlines() if line.startswith("Action")] == [
        "Action (references, index): sigharvest index",
        "Action (disk): free disk space",
        "Action (other): sigharvest index --full",
        "Action (literal): sigharvest index ",
    ]
    assert "Action (updates)" not in text
    assert json.dumps(health.as_json(items), indent=1) == before


@pytest.mark.parametrize("width", [80, 120])
def test_summary_literal_unicode_markup_and_long_paths(width: int) -> None:
    root = Path("/workspace/[red]/" + "資料ș" * 80)
    items = [health.Check("[bold]診断[/bold]", "fail", f"missing [red]archive[/red] {root}", f"restore [link=https://example.invalid]ș[/link] {root}")]
    result = format_doctor(items, root)
    assert not any(span.style == "bold" or str(span.style).startswith("link") for span in result.spans)
    output = render_doctor(items, width, root)
    # Folding can split even a path or markup token; compare every non-whitespace character.
    compact = "".join(output.split())
    for value in (str(root), items[0].name, items[0].message, items[0].fix):
        assert "".join(value.split()) in compact
    assert max(cell_len(line) for line in output.splitlines()) <= width
    assert "…" not in output


@pytest.mark.parametrize("status,code", [("ok", 0), ("warn", 0), ("fail", 1)])
@pytest.mark.parametrize("json_output", [False, True])
def test_doctor_summary_exit_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, code: int, json_output: bool) -> None:
    items = [health.Check("例[bold]", status, "message [red] ș", "action" if status != "ok" else "")]
    expected = json.dumps({"status": status, "checks": [{"name": "例[bold]", "status": status, "message": "message [red] ș", "fix": items[0].fix}]})

    def run_checks(ws: Workspace, *, deep: bool, stale_days: int) -> list[health.Check]:
        assert deep and stale_days == 9
        return items

    monkeypatch.setattr(health, "run_checks", run_checks)
    args = ["--deep", "--stale-days", "9", *(["--json"] if json_output else [])]
    actual_code, output = doctor(Workspace(tmp_path), *args)
    assert actual_code == code
    if json_output:
        assert output.encode() == (expected + "\n").encode()
    else:
        assert output.startswith("not healthy" if status == "fail" else "healthy")
        assert "--json" in output
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("json_output", [False, True])
def test_doctor_absent_workspace(tmp_path: Path, json_output: bool) -> None:
    ws = Workspace(tmp_path / "absent")
    expected = json.dumps(health.as_json(health.run_checks(ws))) + "\n"
    code, output = doctor(ws, *(["--json"] if json_output else []))
    assert code == 1
    if json_output:
        assert output == expected
    else:
        assert output.startswith("not healthy: 0 ok, 0 warnings, 1 failure\n")
        assert "FAIL database: no database at" in output
        assert "Action (database): sigharvest init, then sigharvest update" in output
    assert not ws.root.exists()


def doctor(ws: Workspace, *args: str) -> tuple[int, str]:
    res = CliRunner().invoke(app, ["doctor", *args], env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "250"})
    if res.exception and not isinstance(res.exception, SystemExit):
        raise res.exception
    return res.exit_code, res.output


def checks(ws: Workspace, **kw: object) -> dict[str, health.Check]:
    return {c.name: c for c in health.run_checks(ws, **kw)}  # type: ignore[arg-type]


def healthy(tmp: Path) -> tuple[Path, Workspace]:
    repo, ws = make_workspace(tmp)
    assert update(ws)[0] == 0
    attack = ws.cache / "attack" / f"enterprise-{ATTACK_VERSION}.v2.min.json"
    attack.parent.mkdir(parents=True)
    attack.write_text("{}")
    return repo, ws


def test_healthy_workspace(tmp_path: Path) -> None:
    _, ws = healthy(tmp_path)
    c = checks(ws, deep=True)
    for name in ("schema", "updates", "index", "sources", "tests", "ATT&CK data", "lock", "disk", "integrity"):
        assert c[name].status == "ok", c[name]
    assert not any(x.status == "fail" for x in c.values())
    code, out = doctor(ws)
    assert code == 0 and "healthy" in out
    code, out = doctor(ws, "--json")
    data = json.loads(out)
    assert code == 0 and data["status"] in ("ok", "warn") and {x["name"] for x in data["checks"]} >= {"schema", "index", "tests"}


def test_no_database(tmp_path: Path) -> None:
    _, ws = make_workspace(tmp_path)
    (c,) = health.run_checks(ws)
    assert c.status == "fail" and "sigharvest update" in c.fix
    assert doctor(ws)[0] == 0
    assert ws.db_path.is_file()  # doctor explicitly initializes a configured workspace


@pytest.mark.slow
def test_schema_newer_than_code(tmp_path: Path) -> None:
    _, ws = healthy(tmp_path)
    with sqlite3.connect(ws.db_path) as conn:
        conn.execute("UPDATE alembic_version SET version_num = '9999'")
    c = health.schema_check(ws)
    assert c.status == "fail" and "newer than this sigharvest" in c.message
    assert doctor(ws)[0] == 2


@pytest.mark.slow
def test_stale_index_and_untested_versions(tmp_path: Path) -> None:
    repo, ws = healthy(tmp_path)
    write_rule(repo, 77)
    commit(repo, "new rule")
    assert sync_all(ws)[0].status == "ok"  # synced, but neither tested nor indexed
    c = checks(ws)
    assert c["index"].status == "fail" and c["index"].fix == "sigharvest index"
    assert c["tests"].status == "warn" and "1 live versions without validation" in c["tests"].message
    assert doctor(ws)[0] == 1


def test_index_built_before_last_sync(tmp_path: Path) -> None:
    from sigharvest.db import mark_sync_changed

    _, ws = healthy(tmp_path)
    with open_db(ws, migrate=True)() as s:
        mark_sync_changed(s)  # a sync the index has not seen yet
        s.commit()
    c = checks(ws)["index"]
    assert c.status == "warn" and "before the last sync" in c.message


def test_index_sync_freshness_survives_a_backward_clock_step(tmp_path: Path) -> None:
    """The sync finished before the index was built, but the wall clock stepped back in between: still fresh."""
    _, ws = healthy(tmp_path)
    with open_db(ws, migrate=True)() as s:
        s.execute(sql_update(SyncLog).values(finished_at=utcnow() + timedelta(hours=1)))
        assert health.index_check(s).status == "ok", health.index_check(s).message


def test_index_sync_freshness_falls_back_to_timestamps_without_revisions(tmp_path: Path) -> None:
    """A database written by an older sigharvest has no sync revision; timestamps decide."""
    from datetime import datetime

    from sigharvest.db import INDEXED_SYNC_REVISION, SYNC_REVISION, get_meta
    from sigharvest.index import INDEX_BUILT_AT
    from sigharvest.models import Meta

    _, ws = healthy(tmp_path)
    with open_db(ws, migrate=True)() as s:
        s.query(Meta).filter(Meta.key.in_([SYNC_REVISION, INDEXED_SYNC_REVISION])).delete()
        built = datetime.fromisoformat(get_meta(s, INDEX_BUILT_AT) or "")
        s.execute(sql_update(SyncLog).values(finished_at=built - timedelta(hours=1)))  # explicit times: no real clock
        assert health.index_check(s).status == "ok"
        s.execute(sql_update(SyncLog).values(finished_at=built + timedelta(hours=1)))
        c = health.index_check(s)
        assert c.status == "warn" and "before the last sync" in c.message


def test_index_result_freshness_uses_revisions_across_clock_changes(tmp_path: Path) -> None:
    from sigharvest.db import INDEXED_RESULTS_REVISION, RESULTS_REVISION, get_meta, set_meta
    from sigharvest.models import TestRun

    _, ws = healthy(tmp_path)
    with open_db(ws, migrate=True)() as s:
        current = get_meta(s, RESULTS_REVISION)
        assert current and current == get_meta(s, INDEXED_RESULTS_REVISION)
        s.execute(sql_update(TestRun).values(finished_at=utcnow() + timedelta(hours=1)))
        assert health.index_check(s).status == "ok"
        set_meta(s, RESULTS_REVISION, "new-publication")
        s.execute(sql_update(TestRun).values(finished_at=utcnow() - timedelta(hours=1)))
        assert health.index_check(s).status == "warn"
        set_meta(s, INDEXED_RESULTS_REVISION, "new-publication")
        assert health.index_check(s).status == "ok"


def test_failing_and_stale_sources(tmp_path: Path) -> None:
    _, ws = healthy(tmp_path)
    save_sources(ws, [*load_sources(ws), SourceConfig(name="gone", type="git", url=str(tmp_path / "missing"))])
    sync_all(ws)
    with open_db(ws, migrate=True)() as s:
        s.execute(sql_update(Source).where(Source.name == "local").values(last_sync_at=utcnow() - timedelta(days=30)))
        s.commit()
    c = checks(ws)
    assert c["failing sources"].status == "fail" and "gone" in c["failing sources"].message  # 1 of 2 = 50%
    assert c["stale sources"].status == "warn" and "local" in c["stale sources"].message
    assert c["unsynced sources"].status == "warn" and "gone" in c["unsynced sources"].message


@pytest.mark.slow
def test_failed_update_is_reported(tmp_path: Path) -> None:
    repo, ws = healthy(tmp_path)
    for n in range(10):
        (repo / "rules" / f"r{n}.yml").unlink()
    commit(repo, "remove a third")
    assert update(ws)[0] == 1
    c = checks(ws)["updates"]
    assert c.status == "fail" and "failed gate" in c.message and c.fix.startswith("sigharvest runs show")


def test_lock_states(tmp_path: Path) -> None:
    _, ws = healthy(tmp_path)
    path = lock_path(ws)
    path.write_text(json.dumps({"pid": 2**22 + 12345, "host": socket.gethostname(), "started": time.time()}))
    c = health.lock_check(ws)  # what an older version or a crash left in the file does not matter
    assert c.status == "ok" and "no writer holds" in c.message
    with mutation_lease(ws) as owner:
        owner.set_operation("update")
        c = health.lock_check(ws)
    assert c.status == "ok" and "a workspace mutation is running" in c.message and f"pid {os.getpid()}" in c.message and "update" in c.message


def test_discovery_cache_warning_and_clean(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _, ws = healthy(tmp_path)
    disc = ws.cache / "discovery"
    (disc / "someone__rules" / "rules").mkdir(parents=True)
    (disc / "someone__rules" / "rules" / "a.yml").write_bytes(b"x" * 5000)
    (disc / health.VERIFY_CACHE).write_text("{}")
    monkeypatch.setattr(health, "DISCOVERY_WARN", 1000)
    c = checks(ws)["discovery cache"]
    assert c.status == "warn" and c.fix == "sigharvest doctor --clean-cache"
    code, out = doctor(ws, "--clean-cache", "--yes")
    assert code == 0 and "freed" in out
    assert sorted(p.name for p in disc.iterdir()) == [health.VERIFY_CACHE]
    assert "discovery cache" not in checks(ws)


@pytest.mark.slow
def test_disk_thresholds(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _, ws = healthy(tmp_path)
    monkeypatch.setattr(health, "DISK_FAIL", 10**18)
    (c,) = [x for x in health.disk_checks(ws) if x.name == "disk"]
    assert c.status == "fail"


@pytest.mark.slow
def test_doctor_messages_are_cleaned(tmp_path: Path) -> None:
    _, ws = healthy(tmp_path)
    with open_db(ws, migrate=True)() as s:
        (log,) = s.scalars(select(SyncLog)).all()[-1:]
        log.status, log.error = "error", "fatal: \x1b]8;;http://evil\x1b\\repo\x1b[2J gone"
        s.commit()
    c = checks(ws)["failing sources"]
    assert "\x1b" not in c.message and "http://evil" in c.message
    assert "\x1b" not in doctor(ws)[1]
