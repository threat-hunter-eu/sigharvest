"""Report-only work inside the gated update candidate must never abort the update it describes.

Update 2026-11-01 ran 2 h 40 min, passed every stage, then raised in runs.build_report on a stored rule with a
duplicate YAML key; the candidate rolled back and nothing was published.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, update

from sigharvest import runs
from sigharvest.cli import pipeline
from sigharvest.models import LogicGroup, RuleVersion, UpdateRun
from sigharvest.runs import DIFF_UNAVAILABLE, Changes, Snapshot, detection_diff, diff_unavailable
from sigharvest.service import open_db
from tests.test_update_runs import N_RULES, _uid, commit, latest, make_workspace, report, write_rule
from tests.test_update_runs import update as run_update

GOOD = "title: t\nlogsource:\n    product: windows\ndetection:\n    sel:\n        Image: a.exe\n    condition: sel\n"
GOOD2 = GOOD.replace("a.exe", "b.exe")
DUPLICATE = "title: t\ndetection:\n    sel:\n        Image: a.exe\n    sel:\n        Image: b.exe\n    condition: sel\n"


# ----------------------------------------------------------------------------- detection_diff


def test_diff_of_parsable_rules_is_unchanged() -> None:
    lines = detection_diff(GOOD, GOOD2)
    assert lines == ["-  Image: a.exe", "+  Image: b.exe"]
    assert not diff_unavailable(lines)
    assert detection_diff(GOOD, GOOD) == []


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (DUPLICATE, "duplicate key"),
        ("detection: [unclosed\n", "invalid YAML"),
        ("title: a\n  - b: : :\n", "invalid YAML"),
        ("- just\n- a list\n", "not a mapping"),
        ("plain scalar\n", "not a mapping"),
        ("", "rule text missing"),
        (None, "rule text missing"),
        ("? [a, b]\n: c\ndetection: {}\n", "non-scalar key"),
        ("detection: " + "[" * 200 + "]" * 200 + "\n", "too complex"),
        (
            "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
            + "".join(f"{c}: &{c} [*{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}]\n" for p, c in zip("abcdef", "bcdefg", strict=True)),
            "too complex",
        ),
        ("title: x\ndescription: " + "y" * (2 * 1024 * 1024 + 1) + "\n", "oversize"),
    ],
)
def test_unparsable_side_gives_an_explicit_placeholder(raw: str | None, reason: str) -> None:
    assert detection_diff(raw, GOOD) == [f"{DIFF_UNAVAILABLE}{reason} (old version)"]
    assert detection_diff(GOOD, raw) == [f"{DIFF_UNAVAILABLE}{reason} (new version)"]
    assert diff_unavailable(detection_diff(raw, GOOD))


def test_both_sides_unparsable() -> None:
    assert detection_diff(DUPLICATE, DUPLICATE) == [f"{DIFF_UNAVAILABLE}duplicate key (old and new versions)"]
    assert detection_diff(DUPLICATE, "- x\n") == [f"{DIFF_UNAVAILABLE}duplicate key (old version), not a mapping (new version)"]


def test_oversized_section_is_not_diffed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "MAX_DIFF_SIDE_LINES", 2)
    assert detection_diff(GOOD, GOOD2) == [f"{DIFF_UNAVAILABLE}section too large (old and new versions)"]


def test_unexpected_failure_is_a_reason_not_an_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> object:
        raise KeyError("x")

    monkeypatch.setattr(runs.yaml, "safe_dump", boom)
    assert detection_diff(GOOD, GOOD2) == [f"{DIFF_UNAVAILABLE}internal error (KeyError) (old and new versions)"]


def test_reason_never_quotes_rule_text() -> None:
    raw = "title: t\ndetection:\n    \x1b[31mevil: 1\n    \x1b[31mevil: 2\n"
    (line,) = detection_diff(raw, GOOD)
    assert "evil" not in line and "\x1b" not in line


# ----------------------------------------------------------------------------- build_report and rendering


def _run() -> UpdateRun:
    now = datetime.now(UTC)
    return UpdateRun(id=7, status="ok", started_at=now, finished_at=now, reasons=[], gates=[], durations={"sync": 1.0}, counts={"unique_logic": 1})


class _Rows:
    """A stand-in session: every query yields one RuleVersion-shaped row per requested hash, with the given raw."""

    def __init__(self, raws: dict[str, str]) -> None:
        self.raws = raws

    def execute(self, _q: object) -> list[tuple[str, str, str]]:
        return [(lh, raw, f"title {lh}") for lh, raw in self.raws.items()]

    def scalars(self, _q: object) -> list[object]:
        return []


def test_build_report_with_a_duplicate_key_rule() -> None:
    ch = Changes(changed=[("rid", "old", "new", ["src"])], removed=["gone"])
    data = runs.build_report(_Rows({"old": DUPLICATE, "new": GOOD, "gone": GOOD}), _run(), None, Snapshot({}), Snapshot({}), ch)  # type: ignore[arg-type]
    (row,) = data["changed"]
    assert row["diff"] == [f"{DIFF_UNAVAILABLE}duplicate key (old version)"]
    assert data["report_notes"] == []
    md = runs.render_markdown(data | {"notes": []})
    assert "(diff unavailable: duplicate key (old version))" in md and "```diff" not in md


def test_one_failing_section_becomes_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "_collections", lambda *_a: 1 / 0)
    ch = Changes(changed=[("rid", "old", "new", ["src"])])
    data = runs.build_report(_Rows({"old": GOOD, "new": GOOD2}), _run(), None, Snapshot({}), Snapshot({}), ch)  # type: ignore[arg-type]
    assert data["collections"] == [] and data["changed"][0]["diff"] == ["-  Image: a.exe", "+  Image: b.exe"]
    (note,) = data["report_notes"]
    assert "collections" in note and "ZeroDivisionError" in note


def test_one_bad_changed_row_keeps_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    real = runs.detection_diff

    def flaky(old: str, new: str) -> list[str]:
        if old == DUPLICATE:
            raise RuntimeError("unexpected")
        return real(old, new)

    monkeypatch.setattr(runs, "detection_diff", flaky)
    ch = Changes(changed=[("r1", "bad", "new", ["s"]), ("r2", "old", "new", ["s"])])
    data = runs.build_report(_Rows({"bad": DUPLICATE, "old": GOOD, "new": GOOD2}), _run(), None, Snapshot({}), Snapshot({}), ch)  # type: ignore[arg-type]
    assert [r["diff"] for r in data["changed"]] == [[f"{DIFF_UNAVAILABLE}internal error"], ["-  Image: a.exe", "+  Image: b.exe"]]
    assert "1 changed rules" in data["report_notes"][0]


def test_markdown_rendering_failure_writes_a_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.config import Workspace

    ws = Workspace(tmp_path)
    data = runs.report_skeleton(_run(), None) | {"notes": ["a note"], "gates": [{"name": "g", "status": "pass", "detail": "d"}]}
    data["new"] = [{"logic": None}]  # a row render_markdown cannot handle
    md = runs.write_report(ws, data, datetime.now(UTC))
    text = md.read_text()
    assert "could not be rendered (KeyError)" in text and "a note" in text and "g: pass: d" in text
    assert md.with_suffix(".json").exists()


# ----------------------------------------------------------------------------- the update outcome block


def _change_rule_with_broken_old_raw(repo: Path, ws: object) -> str:
    """After a first update, store the duplicate-key text on rule 1's live version, then change rule 1 upstream."""
    with open_db(ws, migrate=True)() as s:  # type: ignore[arg-type]
        old = s.scalars(select(LogicGroup.logic_hash).where(LogicGroup.title == "Rule 1")).one()
        s.execute(update(RuleVersion).where(RuleVersion.logic_hash == old).values(raw=DUPLICATE))
        s.commit()
    write_rule(repo, 1, exe="changed1")
    write_rule(repo, 99)
    commit(repo, "change")
    return old


def _published(ws: object, title: str) -> bool:
    with open_db(ws)() as s:  # type: ignore[arg-type]
        return s.scalar(select(LogicGroup.logic_hash).where(LogicGroup.title == title)) is not None


def test_duplicate_key_in_a_stored_rule_does_not_roll_back_the_update(tmp_path: Path) -> None:
    """The 2026-11-01 incident, end to end."""
    repo, ws = make_workspace(tmp_path)
    assert run_update(ws)[0] == 0
    old = _change_rule_with_broken_old_raw(repo, ws)
    code, out = run_update(ws)
    assert code == 0, out
    run = latest(ws)
    assert run.status == "ok" and run.counts["changed"] == 1 and run.counts["new"] == 1
    assert _published(ws, "Rule 99")
    md, data = report(ws, run)
    (ch,) = data["changed"]
    assert ch["rule_id"] == _uid(1) and ch["old"] == old
    assert ch["diff"] == [f"{DIFF_UNAVAILABLE}duplicate key (old version)"]
    assert "(diff unavailable: duplicate key (old version))" in md


@pytest.mark.parametrize("where", ["build_report", "summary", "render", "prune"])
def test_report_only_failures_are_notes_and_the_corpus_publishes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str) -> None:
    repo, ws = make_workspace(tmp_path)
    assert run_update(ws)[0] == 0
    write_rule(repo, 99)
    commit(repo, "new")

    def boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("report-only failure")

    if where == "build_report":
        monkeypatch.setattr(runs, "build_report", boom)
    elif where == "summary":
        import sigharvest.report

        monkeypatch.setattr(sigharvest.report, "build_summary", boom)
    elif where == "render":
        monkeypatch.setattr(runs, "render_markdown", boom)
    elif where == "prune":
        monkeypatch.setattr(runs, "prune_reports", boom)
    code, out = run_update(ws)
    run = latest(ws)
    assert run.status == "ok", out
    # Report-only failures never change the exit code of a passed run; the summary failure prints its cause.
    assert code == 0, out
    if where == "summary":
        assert "summary report failed (RuntimeError" in " ".join(out.split()), out
    assert _published(ws, "Rule 99")
    assert run.counts["phase"] == "finished"
    md, data = report(ws, run)
    if where == "render":
        assert "could not be rendered (RuntimeError)" in md
    elif where == "prune":
        assert md.startswith(f"# sigharvest update {run.id}: OK")
    else:
        assert any("RuntimeError" in n or "InternalError" in n for n in data["notes"]), data["notes"]
    if where != "build_report":
        assert [x["title"] for x in data["new"]] == ["Rule 99"]
    assert data["counts"]["unique_logic"] == N_RULES + 1


def test_gate_failures_still_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, ws = make_workspace(tmp_path)
    assert run_update(ws)[0] == 0
    write_rule(repo, 99)
    commit(repo, "new")
    monkeypatch.setattr(runs, "corpus_counts", lambda *_a: (_ for _ in ()).throw(RuntimeError("gate input failed")))
    with pytest.raises(RuntimeError, match="gate input failed"):
        run_update(ws)
    assert latest(ws).status == "error" and not _published(ws, "Rule 99")


def test_report_only_does_not_swallow_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> None:
        raise RuntimeError("cleanup during cancellation")

    notes: list[str] = []
    assert pipeline._report_only("x", notes.append, "default", boom) == "default" and len(notes) == 1
    monkeypatch.setattr(pipeline, "cancellation_requested", lambda: True)
    with pytest.raises(RuntimeError):
        pipeline._report_only("x", notes.append, "default", boom)


def test_cleanup_error_during_cancellation_records_a_cancelled_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An error raised while a cancellation unwinds the gate or report-only path is the
    operator's cancel, as in the stage loop, not an update error."""
    repo, ws = make_workspace(tmp_path)
    assert run_update(ws)[0] == 0
    write_rule(repo, 99)
    commit(repo, "new")
    requested = {"now": False}

    def interrupted(*_a: object) -> None:
        requested["now"] = True
        raise RuntimeError("cleanup during cancellation")

    monkeypatch.setattr(pipeline, "cancellation_requested", lambda: requested["now"])
    monkeypatch.setattr(runs, "build_report", interrupted)
    from sigharvest.job_control import Cancelled

    with pytest.raises(Cancelled):
        run_update(ws)
    assert latest(ws).status == "cancelled" and not _published(ws, "Rule 99")


def test_untrusted_report_text_cannot_add_markdown() -> None:
    # Rule titles, ids, log sources, source names and error text come from upstream; the nightly job publishes the
    # markdown report as its GitHub step summary, which renders links, images and emphasis.
    link = "Update required [re-authenticate](https://attacker.example) ![x](https://attacker.example/i.png) <b>*x*</b>"
    data = runs.report_skeleton(_run(), None) | {
        "reasons": ["error: boom\n\n# Injected heading\n[click](https://attacker.example)"],
        "notes": [],
        "new": [
            {"logic": "a" * 64, "title": link, "level": "[l](https://attacker.example)", "logsource": "win|dows"}
            | {"score": 1.0, "family": 1, "sources": ["s"], "junk": False}
        ],
        "changed": [
            {"rule_id": "[r](https://attacker.example)", "title": link, "old": "b" * 64, "new": "c" * 64, "sources": ["s"]}
            | {"diff": ["+  x: a", " ```", "````", "+[click](https://attacker.example)"]}
        ],
        "removed": [{"logic": "d" * 64, "title": link}],
        "sources": {"[s](https://attacker.example)": {"new": 1, "changed": 0, "removed": 0, "error": "e\n- [click](https://attacker.example)"}},
        "collections": [{"collection": link, "updated": [{"title": link, "old": "e" * 64, "new": "f" * 64}], "missing": []}],
    }
    md = runs.render_markdown(data)
    fence = "`````"  # longer than the longest backtick run in the diff, so " ```" cannot close it
    body, after = md.split(fence + "diff\n", 1)[0], md.split(fence + "diff\n", 1)[1].split("\n" + fence + "\n", 1)[1]
    outside = body + after
    assert "](" not in outside.replace("\\](", "") and "<b>" not in outside and "\n# Injected" not in outside
    assert "**Needs a look:**\n\n- error: boom  \\# Injected heading \\[click\\](https://attacker.example)\n" in md
    assert "| win\\|dows |" in md and "\\!\\[x\\]" in outside and "\\*x\\*" in outside
