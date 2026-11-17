"""`sigharvest changes` and the static site's changes.json / feed.xml: new, changed and removed rules since the last
update, or between two release packs."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app, pipeline
from sigharvest.service import open_db
from tests.helpers import set_licence
from tests.test_update_publication import update
from tests.test_update_runs import N_RULES, _uid, commit, make_workspace

WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
         "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee", "zulu"]  # fmt: skip


def _name(n: int) -> str:
    return f"{WORDS[n % 26].title()} {WORDS[(n // 26) % 26].title()}"


def _real_rule(repo: Path, n: int, exe: str = "") -> None:
    """A realistic rule (author, description, references): not flagged as a test fixture or template."""
    name = _name(n)
    (repo / "rules" / f"r{n}.yml").write_text(
        f"title: Suspicious {name} Loader Execution\nid: {_uid(n)}\nstatus: test\n"
        f"description: Detects the {name} loader started from a user folder\nauthor: Jane Analyst\ndate: 2024-05-01\n"
        f"references:\n    - https://example.org/{WORDS[n % 26]}\ntags:\n    - attack.execution\n    - attack.t1204\n"
        f"logsource:\n    product: windows\n    category: process_creation\n"
        f"detection:\n    selection:\n        Image|endswith: '\\\\{WORDS[n % 26]}{exe}{n}.exe'\n        CommandLine|contains: '-{WORDS[(n // 26) % 26]}'\n"
        f"    condition: selection\nlevel: high\n"
    )


ATOM = "{http://www.w3.org/2005/Atom}"


@pytest.fixture
def two_updates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """A workspace after two updates (second: 1 new, 1 changed, 1 removed) and a release built after each."""
    from sigharvest.release import build

    repo, ws = make_workspace(tmp_path)
    for n in range(N_RULES):
        _real_rule(repo, n)
    commit(repo, "realistic rules")
    set_licence(ws, "MIT")
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    open_db(ws, migrate=True)
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    assert update(ws).exit_code == 0
    with open_db(ws)() as s:
        build(s, tmp_path / "rel1")
    _real_rule(repo, 100)  # new
    _real_rule(repo, 1, exe="changed")  # same id, other logic
    (repo / "rules" / "r2.yml").unlink()  # removed
    commit(repo, "second")
    assert update(ws).exit_code == 0
    with open_db(ws)() as s:
        build(s, tmp_path / "rel2")
    return ws, tmp_path / "rel1", tmp_path / "rel2"


def run(ws, *args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, list(args), env={"SIGHARVEST_HOME": str(ws.root), "COLUMNS": "200"})


def _counts(data: dict) -> tuple[int, int, int]:  # type: ignore[type-arg]
    return len(data["new"]), len(data["changed"]), len(data["removed"])


def test_changes_since_the_last_update(two_updates) -> None:  # type: ignore[no-untyped-def]
    ws, _, _ = two_updates
    data = json.loads(run(ws, "changes", "--json").output)
    assert _counts(data) == (1, 1, 1)
    assert data["new"][0]["title"] == f"Suspicious {_name(100)} Loader Execution" and data["changed"][0]["title"] == f"Suspicious {_name(1)} Loader Execution"
    text = run(ws, "changes").output
    assert "1 new, 1 changed, 1 removed" in text and _name(100) in text
    # every update since a date, merged: the first update's new rules minus the removed one, plus the new one
    merged = json.loads(run(ws, "changes", "--since", "2000-01-01", "--json").output)
    assert len(merged["new"]) == N_RULES and len(merged["removed"]) == 0
    assert run(ws, "changes", "--since", "yesterday").exit_code != 0


def test_changes_between_two_releases(two_updates) -> None:  # type: ignore[no-untyped-def]
    ws, rel1, rel2 = two_updates
    data = json.loads(run(ws, "changes", "--from-release", str(rel1), "--to-release", str(rel2), "--json").output)
    assert _counts(data) == (1, 1, 1)
    assert run(ws, "changes", "--from-release", str(rel1)).exit_code != 0


def test_static_site_publishes_changes_json_and_an_atom_feed(two_updates, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from sigharvest.release import build
    from sigharvest.site.build import build_site

    ws, rel1, _ = two_updates
    with open_db(ws)() as s:
        build(s, tmp_path / "rel3", previous=rel1)
    for source, out in ((tmp_path / "rel3", tmp_path / "site-release"), (ws.root, tmp_path / "site-ws")):
        build_site(source, out, collections=[], site_url="https://rules.example.org", base_url="/rules/")
        root = out / "rules"
        data = json.loads((root / "changes.json").read_text())
        assert _counts(data) == (1, 1, 1), source
        feed = ET.fromstring((root / "feed.xml").read_bytes())
        entries = feed.findall(f"{ATOM}entry")
        assert len(entries) == 3 and feed.find(f"{ATOM}updated") is not None
        titles = sorted(e.findtext(f"{ATOM}title") or "" for e in entries)
        assert titles == sorted(f"{k}: Suspicious {_name(n)} Loader Execution" for k, n in (("Changed", 1), ("New", 100), ("Removed", 2)))
        links = [link.get("href") for e in entries for link in e.findall(f"{ATOM}link")]
        assert len(links) == 2 and all(str(h).startswith("https://rules.example.org/rules/") for h in links)
        assert 'type="application/atom+xml"' in (root / "index.html").read_text()


def test_index_reading_refuses_a_gzip_bomb(tmp_path: Path) -> None:
    from sigharvest.release_reader import ReleaseError, read_index

    path = tmp_path / "index.json.gz"
    path.write_bytes(gzip.compress(b'{"rules": [' + b" " * (2 * 1024**2) + b"]}"))
    with pytest.raises(ReleaseError, match="limit"):
        read_index(path, cap=1024**2)
    path.write_bytes(gzip.compress(b'{"rules": [{"logic_hash": "ab"}]}'))
    assert read_index(path) == [{"logic_hash": "ab"}]


def test_a_run_that_failed_its_gates_is_not_reported_as_changes(two_updates, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The failed run kept the published corpus: `changes`, changes.json and the feed still show the last published run."""
    ws, _, _ = two_updates
    repo = ws.root.parent / "upstream"  # make_workspace
    for p in sorted((repo / "rules").glob("r*.yml"))[3:]:
        p.unlink()
    commit(repo, "most rules deleted upstream")
    assert update(ws).exit_code == 1  # unique-logic gate
    data = json.loads(run(ws, "changes", "--json").output)
    assert _counts(data) == (1, 1, 1) and "published corpus did not change" in data["note"]
    assert "published corpus did not change" in run(ws, "changes").output
    from sigharvest.site.build import build_site

    build_site(ws.root, tmp_path / "site", collections=[], site_url="https://rules.example.org", base_url="/")
    feed = ET.fromstring((tmp_path / "site" / "feed.xml").read_bytes())
    assert len([e for e in feed.iter(f"{ATOM}entry") if "Removed" in (e.findtext(f"{ATOM}title") or "")]) == 1


def test_since_converts_an_offset_to_utc(two_updates) -> None:  # type: ignore[no-untyped-def]
    from datetime import UTC, timedelta, timezone

    from sigharvest.models import UpdateRun

    ws, _, _ = two_updates
    with open_db(ws)() as s:
        # Explicit start times an hour apart: the wall clock can step back between two fast updates (WSL, NTP).
        first_run, second_run = s.query(UpdateRun).order_by(UpdateRun.id).all()
        second_run.started_at = first_run.started_at + timedelta(hours=1)
        s.commit()
        first, second = first_run.started_at, second_run.started_at
    between = (first + (second - first) / 2).replace(tzinfo=UTC).astimezone(timezone(timedelta(hours=2)))
    data = json.loads(run(ws, "changes", "--since", between.isoformat(), "--json").output)
    assert _counts(data) == (1, 1, 1)


def test_merge_follows_a_rule_across_runs() -> None:
    from sigharvest.changes import empty, merge

    def part(new=(), changed=(), removed=()):  # type: ignore[no-untyped-def]
        p = empty()
        p["new"] = [{"logic_hash": h, "title": "t"} for h in new]
        p["changed"] = [{"rule_id": "r", "old": a, "new": b, "title": "t"} for a, b in changed]
        p["removed"] = [{"logic_hash": h, "title": "t"} for h in removed]
        return p

    added_then_changed = merge([part(new=["A"]), part(changed=[("A", "B")])])
    assert [x["logic_hash"] for x in added_then_changed["new"]] == ["B"] and not added_then_changed["changed"]
    assert _counts(merge([part(changed=[("A", "B")]), part(changed=[("B", "A")])])) == (0, 0, 0)
    changed_then_removed = merge([part(changed=[("A", "B")]), part(removed=["B"])])
    assert not changed_then_removed["changed"] and [x["logic_hash"] for x in changed_then_removed["removed"]] == ["A"]
    assert merge([part(changed=[("A", "B")]), part(changed=[("B", "C")])])["changed"][0] | {} == {"rule_id": "r", "old": "A", "new": "C", "title": "t"}


def test_untrusted_titles_cannot_escape_the_terminal_or_break_the_feed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from sigharvest import changes

    evil = changes.empty("2026-01-01", "2026-01-02")
    evil["new"] = [{"logic_hash": "a" * 64, "title": "EVIL\x1b]0;pwned\x07\x1b[31mRED", "extra": "<x>"}]
    evil["removed"] = [{"logic_hash": "b\x01" * 4, "title": "gone\x01￾"}]
    monkeypatch.setattr(changes, "between_releases", lambda old, new: evil)
    out = CliRunner().invoke(app, ["changes", "--from-release", str(tmp_path), "--to-release", str(tmp_path)], env={"COLUMNS": "200"}).output
    assert "\x1b" not in out and "\x07" not in out and "EVIL" in out
    clean = changes.normalise(evil)
    assert set(clean["new"][0]) == {"logic_hash", "title"}
    xml = changes.atom(clean, feed_url="https://x.invalid/feed.xml", site_url="https://x.invalid/", title="t", link_for=lambda k: None, updated="")
    titles = [e.findtext(f"{ATOM}title") for e in ET.fromstring(xml).iter(f"{ATOM}entry")]
    assert titles[0].startswith("New: EVIL") and titles[1].startswith("Removed: gone")
    raw = changes.atom(evil, feed_url="https://x.invalid/feed.xml", site_url="https://x.invalid/", title="t", link_for=lambda k: None, updated="")
    ET.fromstring(raw)  # well-formed even without normalise


def test_run_reports_list_every_change_and_flag_old_capped_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A run report lists every new, changed and removed rule (only diffs are capped); a report from an older version
    that kept at most 5,000 rows per list is reported as incomplete with the real total, never as a smaller number."""
    from sigharvest import runs

    monkeypatch.setattr(runs, "JSON_LIMIT", 2)  # was also the cap of every list
    repo, ws = make_workspace(tmp_path)
    for n in range(N_RULES):
        _real_rule(repo, n)
    commit(repo, "realistic rules")
    set_licence(ws, "MIT")
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    open_db(ws, migrate=True)
    monkeypatch.setattr(pipeline, "_test", lambda *args, **kwargs: 0)
    assert update(ws).exit_code == 0
    first = json.loads(run(ws, "changes", "--json").output)
    assert len(first["new"]) == N_RULES > 2 and "incomplete" not in first
    for n in range(3):
        _real_rule(repo, n, exe="changed")
    commit(repo, "three changed")
    assert update(ws).exit_code == 0
    second = json.loads(run(ws, "changes", "--json").output)
    assert len(second["changed"]) == 3 and "incomplete" not in second
    # two runs in the same second get <stamp>.json and <stamp>-2.json: pick the reports by their run id
    reports = {json.loads(p.read_text())["run"]: p for p in (ws.reports / "runs").glob("*.json")}
    data = json.loads(reports[2].read_text())
    assert data["totals"] == {"new": 0, "changed": 3, "removed": 0}
    assert [bool(x["diff"]) and not x["diff"][0].startswith("diff unavailable") for x in data["changed"]] == [True, True, False]
    # a report written by an older version: capped lists and no "totals" (the run counts still have the real numbers)
    first_report = reports[1]
    old = json.loads(first_report.read_text())
    old.pop("totals")
    old["new"] = old["new"][:2]
    first_report.write_text(json.dumps(old))
    data = json.loads(run(ws, "changes", "--run", "1", "--json").output)
    assert len(data["new"]) == 2 and data["incomplete"] == [
        f"run 1: the report lists 2 of {N_RULES} new rules (it was written by an older version that kept at most 5,000 per list)"
    ]
    text = run(ws, "changes", "--run", "1").output
    assert "incomplete:" in text and f"2 of {N_RULES} new rules" in text
    merged = json.loads(run(ws, "changes", "--since", "2000-01-01", "--json").output)
    assert merged["incomplete"] == data["incomplete"]


def test_the_feed_says_when_it_is_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import changes

    monkeypatch.setattr(changes, "FEED_LIMIT", 2)
    data = changes.empty("a", "b") | {"new": [{"logic_hash": f"h{i}", "title": f"t{i}"} for i in range(5)]}
    feed = ET.fromstring(changes.atom(data, feed_url="https://x/feed.xml", site_url="https://x/", title="t", link_for=lambda h: None, updated=""))
    assert len(feed.findall(f"{ATOM}entry")) == 2
    assert feed.findtext(f"{ATOM}subtitle") == "5 new, 0 changed, 0 removed; this feed lists the first 2, changes.json lists all of them"
