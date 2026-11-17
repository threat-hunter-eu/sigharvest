"""Update runs: what one `sigharvest update` did, whether the corpus still looks right, and what changed.

- `snapshot()` reads the live corpus as (source, logic hash, trusted rule id) before and after the run; `changes()`
  compares the two: new rules, rules changed upstream (same rule id in the same source, new logic), removed rules,
  per source.
- `corpus_counts()` are the numbers stored on the `update_runs` row; `evaluate()` compares them with the previous
  run that passed its gates (docs/getting-started.md, step "gates"). A failed gate makes the update exit 1.
- `write_report()` writes reports/runs/<UTC stamp>.md and .json; `prune()` keeps the last N.
"""

from __future__ import annotations

import contextlib
import difflib
import json
import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sigharvest.config import Workspace
from sigharvest.db import IN_CHUNK
from sigharvest.models import (
    Collection,
    LogicGroup,
    Occurrence,
    Quarantine,
    RuleVersion,
    Source,
    TestResult,
    UpdateRun,
    utcnow,
)
from sigharvest.query import live_version_ids

log = logging.getLogger("sigharvest.update")

PASSED = ("ok", "source failures", "accepted")  # statuses that can be the baseline of the next run's gates
KEEP_RUNS = 30
KEEP_LOGS = 14
MD_LIMIT = 50  # rows per section in the markdown report (the JSON report lists every new, changed and removed rule)
JSON_LIMIT = 5000  # changed rules that get a detection diff in the JSON report (the others are listed without one)
DIFF_LINES = 16
# C0 and C1 control characters except tab and newline: upstream text (titles, YAML, git errors) could carry terminal
# escape sequences (ANSI colours, OSC 8 links, screen clears) into reports that people print in a terminal.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_text(text: str) -> str:
    """The text with control characters (except tab and newline) replaced by U+FFFD."""
    from sigharvest.observability import scrub

    return scrub(text, redact_urls=False)


def clean_data(value: Any) -> Any:
    """clean_text applied to every string (keys too) in nested lists and dicts."""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, dict):
        return {clean_data(k): clean_data(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_data(v) for v in value]
    return value


# ----------------------------------------------------------------------------- thresholds and gates


@dataclass
class Thresholds:
    """Gate limits (percentages). Defaults are calibrated on a 1,243-repository corpus."""

    max_logic_drop: float = 5.0  # unique logic may shrink by at most this share of the previous run
    max_quarantine_growth: float = 20.0  # quarantined documents may grow by at most this share...
    quarantine_min_growth: int = 50  # ...and the gate ignores growth below this many documents (small workspaces)
    max_failed_sources: float = 10.0  # failed fetches as a share of enabled sources
    failed_sources_floor: int = 1  # one unavailable source must not block a small installation


@dataclass
class Gate:
    """One check of a finished run: status pass, fail, warn (reported, does not fail the run) or skipped."""

    name: str
    status: str
    detail: str


def _pct(a: float, b: float) -> float:
    return 100.0 * a / b if b else 0.0


def evaluate(cur: dict[str, Any], prev: dict[str, Any] | None, th: Thresholds) -> list[Gate]:
    """The gates of a run with counts `cur`, against the counts of the previous passed run (None for the first)."""
    gates: list[Gate] = []
    if prev and prev.get("unique_logic"):
        drop = _pct(prev["unique_logic"] - cur["unique_logic"], prev["unique_logic"])
        ok = drop <= th.max_logic_drop
        gates.append(
            Gate(
                "unique logic",
                "pass" if ok else "fail",
                f"{prev['unique_logic']:,} -> {cur['unique_logic']:,} ({-drop:+.1f}%, limit -{th.max_logic_drop:g}%)"
                + ("" if ok else ": a source was emptied or rewritten, or ingest/identity regressed; see removed rules below"),
            )
        )
    else:
        gates.append(Gate("unique logic", "skipped", "no previous passed run to compare with"))
    if prev is not None and "quarantine" in prev:
        # A corpus that grew (sources added, a long first update finished over several runs) brings its share of
        # broken YAML: the baseline grows with the documents, so only quarantine growing faster than the corpus counts.
        baseline = float(prev["quarantine"])
        scaled = ""
        if prev.get("documents") and cur.get("documents", 0) > prev["documents"]:
            baseline = prev["quarantine"] * cur["documents"] / prev["documents"]
            scaled = f"; baseline {baseline:,.0f} scaled to the corpus, {prev['documents']:,} -> {cur['documents']:,} documents"
        grown = cur["quarantine"] - baseline
        growth = _pct(grown, baseline) if baseline else (100.0 if grown > 0 else 0.0)
        ok = growth <= th.max_quarantine_growth or grown < th.quarantine_min_growth
        gates.append(
            Gate(
                "quarantine",
                "pass" if ok else "fail",
                f"{prev['quarantine']:,} -> {cur['quarantine']:,} ({growth:+.1f}%, limit +{th.max_quarantine_growth:g}% and "
                f"{th.quarantine_min_growth} documents{scaled})" + ("" if ok else ": a parser regression or a new source full of broken YAML"),
            )
        )
    else:
        gates.append(Gate("quarantine", "skipped", "no previous passed run to compare with"))
    enabled = cur.get("sources_enabled") or 0
    share = _pct(cur.get("sources_failed", 0), enabled)
    ok = share <= th.max_failed_sources or cur.get("sources_failed", 0) <= th.failed_sources_floor
    gates.append(
        Gate(
            "failed sources",
            "pass" if ok else "fail",
            f"{cur.get('sources_failed', 0)}/{enabled} failed ({share:.1f}%, limit {th.max_failed_sources:g}%; "
            f"absolute allowance {th.failed_sources_floor})" + ("" if ok else ": network, GitHub or credentials problem"),
        )
    )
    missing = cur.get("index_missing", 0)
    gates.append(
        Gate(
            "index complete",
            "pass" if not missing else "fail",
            f"{cur.get('index_groups', 0):,} groups for {cur['unique_logic']:,} live logic"
            + (f", {missing} live logic not in the index: run `sigharvest index`" if missing else ""),
        )
    )
    if limited := cur.get("conversion_resource_failures", 0):
        # A warning, not a failure: one oversized rule must not block publishing the corpus.
        gates.append(
            Gate(
                "conversion resource failures",
                "warn",
                f"{limited} conversion results hit the per-worker address-space cap; retry with `sigharvest test --stage convert --retry-resource-failures`",
            )
        )
    return gates


# ----------------------------------------------------------------------------- counts


def corpus_counts(s: Session) -> dict[str, Any]:
    """The corpus numbers stored on every run (the source and change counts are added by the caller)."""
    live = live_version_ids()
    lh_live = select(RuleVersion.logic_hash).where(RuleVersion.id.in_(live)).distinct()
    return {
        "documents": s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) or 0,
        "live_versions": s.scalar(select(func.count()).select_from(live.subquery())) or 0,
        "unique_logic": s.scalar(select(func.count()).select_from(lh_live.subquery())) or 0,
        "index_groups": s.scalar(select(func.count()).select_from(LogicGroup)) or 0,
        "index_missing": s.scalar(select(func.count()).select_from(lh_live.where(RuleVersion.logic_hash.not_in(select(LogicGroup.logic_hash))).subquery()))
        or 0,
        "families": s.scalar(select(func.count(func.distinct(LogicGroup.family_id)))) or 0,
        "junk": s.scalar(select(func.count()).select_from(LogicGroup).where(LogicGroup.junk.is_(True))) or 0,
        "quarantine": s.scalar(select(func.count()).select_from(Quarantine).where(Quarantine.present.is_(True))) or 0,
        "conversion_resource_failures": s.scalar(
            select(func.count())
            .select_from(TestResult)
            .where(
                TestResult.stage == "convert",
                TestResult.dataset == "",
                TestResult.status == "resource_failure",
                TestResult.version_id.in_(live),
            )
        )
        or 0,
    }


# ----------------------------------------------------------------------------- what changed


@dataclass
class Snapshot:
    """The live corpus at one moment: per source id, logic hash -> trusted rule id (None when the id is missing,
    generated or a placeholder)."""

    by_source: dict[int, dict[str, str | None]]

    @property
    def logic(self) -> set[str]:
        return {lh for m in self.by_source.values() for lh in m}


def snapshot(s: Session) -> Snapshot:
    """Read the live corpus (about 1.5 s and 80 MB on 500k (source, logic) pairs)."""

    pool: dict[str, str] = {}
    out: dict[int, dict[str, str | None]] = defaultdict(dict)
    rows = s.execute(
        select(Occurrence.source_id, RuleVersion.logic_hash, RuleVersion.rule_id, RuleVersion.id_flag)
        .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
        .where(Occurrence.present.is_(True))
        .distinct()
    )
    for sid, lh, rid, flag in rows:
        lh = pool.setdefault(lh, lh)
        m = out[sid]
        if m.get(lh) is None:
            m[lh] = pool.setdefault(rid, rid) if flag is None else None
    return Snapshot(dict(out))


@dataclass
class SourceChange:
    """New, changed and removed logic in one source, and its sync error, if any."""

    new: int = 0
    changed: int = 0
    removed: int = 0
    error: str = ""


@dataclass
class Changes:
    """What one run changed: logic hashes per kind, with (rule id, old logic, new logic, sources) for changes."""

    new: list[str] = field(default_factory=list)
    changed: list[tuple[str, str, str, list[str]]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    sources: dict[str, SourceChange] = field(default_factory=dict)

    @property
    def gone(self) -> set[str]:
        """Logic hashes that are no longer live because they changed or were removed."""
        return set(self.removed) | {old for _r, old, _n, _s in self.changed}


def changes(s: Session, before: Snapshot, after: Snapshot) -> Changes:
    """Compare two snapshots. A rule "changed upstream" when a source dropped a logic and added another one with the
    same trusted rule id; other added logic is new, other dropped logic is removed (if no source carries it any more)."""
    names = dict(s.execute(select(Source.id, Source.name)).all())
    out = Changes()
    changed: dict[tuple[str, str], tuple[str, set[str]]] = {}
    new_any: set[str] = set()
    for sid in sorted(set(before.by_source) | set(after.by_source)):
        b, a = before.by_source.get(sid, {}), after.by_source.get(sid, {})
        added, dropped = a.keys() - b.keys(), b.keys() - a.keys()
        if not added and not dropped:
            continue
        old_by_rule = {b[lh]: lh for lh in sorted(dropped) if b[lh]}
        pairs = {(old_by_rule[a[lh]], lh) for lh in sorted(added) if a[lh] and a[lh] in old_by_rule}
        name = names.get(sid, str(sid))
        for old, new in pairs:
            changed.setdefault((old, new), (a[new] or "", set()))[1].add(name)
        new_any |= added
        out.sources[name] = SourceChange(len(added) - len(pairs), len(pairs), len(dropped) - len(pairs))
    after_logic, before_logic = after.logic, before.logic
    out.changed = sorted(((rid, old, new, sorted(srcs)) for (old, new), (rid, srcs) in changed.items()), key=lambda c: (c[0], c[2]))
    changed_new = {new for _r, _o, new, _s in out.changed}
    changed_old = {old for _r, old, _n, _s in out.changed}
    out.new = sorted(new_any - before_logic - changed_new)
    out.removed = sorted(before_logic - after_logic - changed_old)
    return out


DIFF_UNAVAILABLE = "diff unavailable: "
MAX_DIFF_SIDE_LINES = 5000  # difflib is quadratic in the worst case; larger sections are reported as unavailable


def _yaml_failure(exc: BaseException) -> str:
    """The reason class of a parse failure; never the message itself, which can quote upstream text."""
    text = str(exc)
    if isinstance(exc, RecursionError) or "depth or node limit" in text or "expanded node limit" in text:
        return "too complex"
    if text.startswith("duplicate YAML key"):
        return "duplicate key"
    if text.startswith("YAML mapping keys must be scalar"):
        return "non-scalar key"
    return "invalid YAML"


def _detection(raw: str | None) -> list[str] | str:
    """The detection (or correlation / filter) section of a rule as YAML lines, or a reason class (a str) when the
    raw text cannot be shown that way. Never raises: rule text is untrusted upstream content, and a run report must
    not abort the update it describes (update 2026-11-01 was rolled back by a duplicate key here)."""
    from sigharvest.documents import MAX_FILE_BYTES, _load_ingest_yaml

    try:
        if not raw:
            return "rule text missing"
        data_bytes = raw.encode("utf-8", errors="replace")
        if len(data_bytes) > MAX_FILE_BYTES:
            return "oversize"
        try:
            # The bounded ingest loader: duplicate keys, depth, node and alias-expansion limits.
            data = _load_ingest_yaml(data_bytes)
        except (yaml.YAMLError, ValueError, RecursionError, UnicodeError) as exc:
            return _yaml_failure(exc)
        if not isinstance(data, dict):
            return "not a mapping"
        part = data.get("detection") or data.get("correlation") or data.get("filter")
        try:
            lines = yaml.safe_dump(part, sort_keys=False, allow_unicode=True, width=200).splitlines()
        except (yaml.YAMLError, ValueError, TypeError, RecursionError):
            return "unrenderable section"
        return lines if len(lines) <= MAX_DIFF_SIDE_LINES else "section too large"
    except Exception as exc:  # report-only: any other failure is a reason, not an aborted update
        log.warning("detection section unavailable (%s)", type(exc).__name__, exc_info=True)
        return f"internal error ({type(exc).__name__})"


def detection_diff(old_raw: str | None, new_raw: str | None, limit: int = DIFF_LINES) -> list[str]:
    """The changed lines of the detection (or correlation / filter) section, `-` old and `+` new, at most `limit`.

    When either side cannot be parsed the result is one line, "diff unavailable: <reason class> (<side>)", and no
    exception escapes."""
    old, new = _detection(old_raw), _detection(new_raw)
    if isinstance(old, str) or isinstance(new, str):
        if isinstance(old, str) and isinstance(new, str):
            why = f"{old} (old and new versions)" if old == new else f"{old} (old version), {new} (new version)"
        else:
            why = f"{old} (old version)" if isinstance(old, str) else f"{new} (new version)"
        return [DIFF_UNAVAILABLE + why]
    try:
        lines = [ln for ln in difflib.unified_diff(old, new, lineterm="", n=0) if not ln.startswith(("---", "+++", "@@"))]
    except Exception as exc:  # report-only
        log.warning("detection diff failed (%s)", type(exc).__name__, exc_info=True)
        return [DIFF_UNAVAILABLE + f"internal error ({type(exc).__name__})"]
    return lines if len(lines) <= limit else [*lines[:limit], f"... {len(lines) - limit} more lines"]


def diff_unavailable(lines: list[str]) -> bool:
    """True for the single-line placeholder detection_diff returns instead of a diff."""
    return len(lines) == 1 and lines[0].startswith(DIFF_UNAVAILABLE)


def _raw_by_logic(s: Session, hashes: Iterable[str]) -> dict[str, tuple[str, str | None]]:
    """logic hash -> (raw, title) of one version with that logic (the first stored)."""
    out: dict[str, tuple[str, str | None]] = {}
    hs = list(hashes)
    for i in range(0, len(hs), IN_CHUNK):
        for lh, raw, title in s.execute(
            select(RuleVersion.logic_hash, RuleVersion.raw, RuleVersion.title).where(RuleVersion.logic_hash.in_(hs[i : i + IN_CHUNK])).order_by(RuleVersion.id)
        ):
            out.setdefault(lh, (raw, title))
    return out


def _groups(s: Session, hashes: Iterable[str]) -> dict[str, LogicGroup]:
    hs = list(hashes)
    out: dict[str, LogicGroup] = {}
    for i in range(0, len(hs), IN_CHUNK):
        out.update({g.logic_hash: g for g in s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.in_(hs[i : i + IN_CHUNK])))})
    return out


def _rule_row(g: LogicGroup) -> dict[str, Any]:
    return {
        "logic": g.logic_hash,
        "title": g.title,
        "level": g.level,
        "logsource": "/".join(x for x in (g.product, g.category, g.service) if x),
        "score": round(g.score, 1),
        "family": g.family_id,
        "sources": g.sources,
        "junk": g.junk,
    }


def _new_rules(s: Session, hashes: list[str]) -> list[dict[str, Any]]:
    """New logic as index rows, grouped by family (families ordered by their best score), best first in a family."""
    groups = _groups(s, hashes)
    fams: dict[int, list[LogicGroup]] = defaultdict(list)
    for g in groups.values():
        fams[g.family_id].append(g)
    ordered = sorted(fams.values(), key=lambda gs: (-max(g.score for g in gs), min(g.title or "" for g in gs)))
    return [_rule_row(g) for gs in ordered for g in sorted(gs, key=lambda g: -g.score)]


def _collections(s: Session, gone: set[str]) -> list[dict[str, Any]]:
    """Collections with items that were updated upstream or went missing in this run."""
    from sigharvest.collections import resolve

    out = []
    for c in s.scalars(select(Collection).order_by(Collection.name)):
        items = [r for r in resolve(s, c) if r.item.logic_hash in gone]
        if items:
            out.append(
                {
                    "collection": c.name,
                    "updated": [{"title": r.item.title, "old": r.item.logic_hash, "new": r.group.logic_hash} for r in items if r.group is not None],
                    "missing": [{"title": r.item.title, "old": r.item.logic_hash} for r in items if r.group is None],
                }
            )
    return out


def stamp(when: datetime) -> str:
    """UTC timestamp used as the report file name, e.g. 20261026T043000Z."""
    return when.strftime("%Y%m%dT%H%M%SZ")


def runs_dir(ws: Workspace) -> Path:
    return ws.reports / "runs"


def _guarded(name: str, notes: list[str], default: Any, fn: Any, *args: Any) -> Any:
    """Run one report-only section; a failure becomes a note (exception type only, no upstream text) and `default`."""
    try:
        return fn(*args)
    except Exception as exc:  # report sections must not abort the update they describe
        log.warning("run report section %s unavailable", name, exc_info=True)
        notes.append(f"run report section '{name}' unavailable ({type(exc).__name__}); the corpus update is not affected")
        return default


def _changed_rows(s: Session, ch: Changes, gone_raw: dict[str, tuple[str, str | None]], notes: list[str]) -> list[dict[str, Any]]:
    """Every changed rule; the first JSON_LIMIT carry a detection diff (the rule text of the others is not read)."""
    new_raw = _guarded("changed rule text", notes, {}, _raw_by_logic, s, [new for _r, _o, new, _s in ch.changed[:JSON_LIMIT]])
    groups = _guarded("changed rule titles", notes, {}, _groups, s, [new for _r, _o, new, _s in ch.changed])
    changed = []
    failed = 0
    for i, (rid, old, new, srcs) in enumerate(ch.changed):
        row: dict[str, Any] = {"rule_id": rid, "title": None, "old": old, "new": new, "sources": srcs}
        try:
            g = groups.get(new)
            row["title"] = (g.title if g else None) or new_raw.get(new, ("", None))[1] or gone_raw.get(old, ("", None))[1]
            if i < JSON_LIMIT:
                row["diff"] = detection_diff(gone_raw.get(old, ("", None))[0], new_raw.get(new, ("", None))[0])
            else:
                row["diff"] = [DIFF_UNAVAILABLE + f"only the first {JSON_LIMIT:,} changed rules of a run get a diff"]
        except Exception:  # one bad row must not drop the others
            log.warning("changed rule %s: report row incomplete", rid, exc_info=True)
            failed += 1
            row["diff"] = [DIFF_UNAVAILABLE + "internal error"]
        changed.append(row)
    if failed:
        notes.append(f"{failed} changed rules have an incomplete report row; the corpus update is not affected")
    return changed


def report_skeleton(run: UpdateRun, prev: UpdateRun | None) -> dict[str, Any]:
    """The run fields of a report with every what-changed section empty (also the fallback of build_report)."""
    return {
        "run": run.id,
        "started": run.started_at.isoformat() if run.started_at else None,
        "finished": run.finished_at.isoformat() if run.finished_at else None,
        "status": run.status,
        "reasons": run.reasons,
        "previous_run": prev.id if prev else None,
        "gates": run.gates,
        "durations": run.durations,
        "counts": run.counts,
        "previous_counts": prev.counts if prev else None,
        "new": [],
        "changed": [],
        "removed": [],
        "sources": {},
        "collections": [],
    }


def build_report(s: Session, run: UpdateRun, prev: UpdateRun | None, before: Snapshot, after: Snapshot, ch: Changes) -> dict[str, Any]:
    """Everything the run report shows, as JSON-ready data.

    Report-only: each what-changed section is computed under its own guard, so untrusted rule text or one bad row
    yields a note in data["report_notes"] (and an empty or partial section) instead of an exception. The run
    fields (status, reasons, gates, counts) are copied from the run, never recomputed here."""
    notes: list[str] = []
    data = report_skeleton(run, prev)
    gone_raw = _guarded("old rule text", notes, {}, _raw_by_logic, s, [old for _r, old, _n, _s in ch.changed] + ch.removed)
    # Every new, changed and removed rule is listed. Older reports stopped at 5,000 rows per list; "totals" (and the
    # run counts) let readers tell that such a list is incomplete.
    data["totals"] = {"new": len(ch.new), "changed": len(ch.changed), "removed": len(ch.removed)}
    data["new"] = _guarded("new rules", notes, [], lambda: _new_rules(s, ch.new))
    data["changed"] = _guarded("changed upstream", notes, [], _changed_rows, s, ch, gone_raw, notes)
    data["removed"] = _guarded("removed rules", notes, [], lambda: [{"logic": lh, "title": gone_raw.get(lh, ("", None))[1]} for lh in ch.removed])
    data["sources"] = _guarded("sources", notes, {}, lambda: {k: asdict(v) for k, v in sorted(ch.sources.items())})
    data["collections"] = _guarded("collections", notes, [], _collections, s, ch.gone)
    data["report_notes"] = notes
    return data


def _esc(text: Any) -> str:
    return clean_text(str(text if text is not None else "")).replace("|", "\\|").replace("\n", " ")


def _num(v: Any) -> str:
    return "" if v is None else f"{v:,}" if isinstance(v, int) else str(v)


def render_markdown(r: dict[str, Any]) -> str:
    """The run report as markdown: verdict first, then gates, counts, and what changed."""
    status = r["status"]
    head = {"ok": "OK", "source failures": "OK, some sources failed", "failed gate": "FAILED GATE", "error": "ERROR"}.get(status, status.upper())
    out = [f"# sigharvest update {r['run']}: {head}", "", f"Started {r['started']} UTC, finished {r['finished']} UTC.", ""]
    if r["reasons"]:
        out += ["**Needs a look:**", "", *[f"- {x}" for x in r["reasons"]], ""]
    if r.get("notes"):
        out += ["**Notes:**", "", *[f"- {_esc(x)}" for x in r["notes"]], ""]
    out += ["## Gates", "", "| gate | result | detail |", "|---|---|---|"]
    out += [f"| {g['name']} | {g['status']} | {_esc(g['detail'])} |" for g in r["gates"]]
    prev = r["previous_counts"] or {}
    out += ["", "## Counts", "", f"Compared with run {r['previous_run'] or '-'} (the last run that passed its gates).", ""]
    out += ["| metric | previous | now | change |", "|---|---:|---:|---:|"]
    visible = {
        "documents",
        "live_versions",
        "unique_logic",
        "index_groups",
        "index_missing",
        "families",
        "junk",
        "quarantine",
        "sources_enabled",
        "sources_ok",
        "sources_failed",
        "new",
        "changed",
        "removed",
    }
    for k, v in r["counts"].items():
        if k not in visible or not isinstance(v, int):
            continue
        p = prev.get(k)
        delta = f"{v - p:+,}" if isinstance(v, int) and isinstance(p, int) else ""
        out.append(f"| {k.replace('_', ' ')} | {_num(p)} | {_num(v)} | {delta} |")
    out += ["", "Step durations: " + ", ".join(f"{k} {v:.0f} s" for k, v in r["durations"].items()), ""]

    def cap(rows: list[Any]) -> list[Any]:
        return rows[:MD_LIMIT]

    def more(rows: list[Any]) -> list[str]:
        return ["", f"... and {len(rows) - MD_LIMIT} more (see the .json report)"] if len(rows) > MD_LIMIT else []

    out += [f"## New rules ({len(r['new'])})", ""]
    if r["new"]:
        out += [
            "Grouped by family, best family first.",
            "",
            "| logic | title | level | log source | score | family | sources |",
            "|---|---|---|---|---:|---:|---|",
        ]
        for x in cap(r["new"]):
            title = _esc(x["title"]) + (" (junk)" if x["junk"] else "")
            srcs = _esc(", ".join(x["sources"][:3])) + (" ..." if len(x["sources"]) > 3 else "")
            out.append(f"| {x['logic'][:10]} | {title} | {x['level'] or ''} | {x['logsource']} | {x['score']} | {x['family']} | {srcs} |")
        out += more(r["new"])
    out += ["", f"## Changed upstream ({len(r['changed'])})", ""]
    for x in cap(r["changed"]):
        out += [f"**{_esc(x['title'])}** (rule {x['rule_id']}, {x['old'][:10]} -> {x['new'][:10]}, in {_esc(', '.join(x['sources'][:3]))})", ""]
        if diff_unavailable(x["diff"]):
            out += [f"({_esc(x['diff'][0])})", ""]
        else:
            out += ["```diff", *x["diff"], "```", ""] if x["diff"] else ["(metadata only: the detection is identical)", ""]
    out += more(r["changed"])
    out += ["", f"## Removed rules ({len(r['removed'])})", ""]
    out += [f"- {x['logic'][:10]} {_esc(x['title'])}" for x in cap(r["removed"])] + more(r["removed"])
    out += ["", "## Sources", ""]
    if r["sources"]:
        out += ["| source | new | changed | removed | error |", "|---|---:|---:|---:|---|"]
        rows = sorted(r["sources"].items(), key=lambda kv: (not kv[1]["error"], -(kv[1]["new"] + kv[1]["changed"] + kv[1]["removed"]), kv[0]))
        out += [f"| {n} | {v['new']} | {v['changed']} | {v['removed']} | {_esc(v['error'][:160])} |" for n, v in rows[: MD_LIMIT * 2]]
    else:
        out.append("No source changed.")
    out += ["", "## Collections affected", ""]
    for c in r["collections"]:
        out.append(f"- **{_esc(c['collection'])}**: {len(c['updated'])} updated upstream, {len(c['missing'])} missing")
        out += [f"  - updated: {_esc(i['title'])} ({i['old'][:10]} -> {i['new'][:10]})" for i in c["updated"][:10]]
        out += [f"  - missing: {_esc(i['title'])} ({i['old'][:10]})" for i in c["missing"][:10]]
    if not r["collections"]:
        out.append("None.")
    return "\n".join(out) + "\n"


def render_fallback(r: dict[str, Any], exc: BaseException) -> str:
    """A minimal markdown report (status, reasons, gates, notes) when render_markdown fails on unexpected data."""
    out = [f"# sigharvest update {_esc(r.get('run'))}: {_esc(str(r.get('status', '')).upper())}", ""]
    out += [f"The full markdown report could not be rendered ({type(exc).__name__}); see the .json report.", ""]
    out += [f"- {_esc(x)}" for x in (r.get("reasons") or [])]
    out += [f"- note: {_esc(x)}" for x in (r.get("notes") or [])]
    out += ["", "## Gates", ""]
    for g in r.get("gates") or []:
        if isinstance(g, dict):
            out.append(f"- {_esc(g.get('name'))}: {_esc(g.get('status'))}: {_esc(g.get('detail'))}")
    return "\n".join(out) + "\n"


def write_report(ws: Workspace, data: dict[str, Any], started: datetime) -> Path:
    """Write reports/runs/<stamp>.md and .json; returns the markdown path."""
    data = clean_data(data)
    folder = runs_dir(ws)
    folder.mkdir(parents=True, exist_ok=True)
    md = folder / f"{stamp(started)}.md"
    if md.exists() and data.get("run") is not None:
        # Two runs that started in the same second must not share (and overwrite) one report.
        previous = md.with_suffix(".json")
        try:
            same = json.loads(previous.read_text(encoding="utf-8")).get("run") == data.get("run")
        except (OSError, ValueError, AttributeError):
            same = False
        if not same:
            md = folder / f"{stamp(started)}-{data['run']}.md"
    try:
        text = render_markdown(data)
    except Exception as exc:  # the JSON report and the run row stay complete
        log.warning("run report markdown rendering failed", exc_info=True)
        text = render_fallback(data, exc)
    md.write_text(text, encoding="utf-8")
    md.with_suffix(".json").write_text(json.dumps(data, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    return md


def prune(folder: Path, pattern: str, keep: int, protected: set[Path] | None = None) -> list[Path]:
    """Delete all but the newest `keep` files matching the pattern (names sort by time); returns the deleted ones."""
    if keep < 0:
        raise ValueError("retention count must be nonnegative")
    files = sorted(folder.glob(pattern)) if folder.exists() else []
    gone = [p for p in files[: max(0, len(files) - keep)] if p not in (protected or set())]
    for p in gone:
        p.unlink(missing_ok=True)
    return gone


def prune_reports(ws: Workspace, keep: int = KEEP_RUNS) -> int:
    """Delete all but the newest `keep` report pairs (.md + .json) in reports/runs. The reports of the last two runs
    that passed their gates are always kept: `runs show` and the change baseline read them."""
    import sqlite3

    from sigharvest.config import workspace_relative

    if keep < 0:
        raise ValueError("retention count must be nonnegative")
    accepted: set[str] = set()
    if ws.db_path.exists():
        with contextlib.suppress(sqlite3.Error), contextlib.closing(sqlite3.connect(f"{ws.db_path.resolve().as_uri()}?mode=ro", uri=True)) as db:
            q = "SELECT report FROM update_runs WHERE status IN ('ok', 'accepted', 'source failures') AND report IS NOT NULL ORDER BY id DESC LIMIT 2"
            accepted = {r for (r,) in db.execute(q)}
    folder = runs_dir(ws)
    if folder.is_symlink():
        return 0
    pairs = sorted(p for p in folder.glob("*.md") if p.is_file() and not p.is_symlink() and p.with_suffix(".json").is_file()) if folder.exists() else []
    removed = [p for p in pairs[: max(0, len(pairs) - keep)] if workspace_relative(p, ws.root) not in accepted]
    for p in removed:
        p.unlink(missing_ok=True)
        p.with_suffix(".json").unlink(missing_ok=True)
    return len(removed)


# ----------------------------------------------------------------------------- the run table


def previous_passed(s: Session, before_id: int | None = None) -> UpdateRun | None:
    """The newest finished run that passed its gates (or was accepted), older than `before_id` if given."""
    q = select(UpdateRun).where(UpdateRun.status.in_(PASSED))
    if before_id is not None:
        q = q.where(UpdateRun.id < before_id)
    return s.scalars(q.order_by(UpdateRun.id.desc()).limit(1)).first()


INCOMPLETE = ("failed gate", "error", "interrupted", "cancelled")  # a first update that ended so leaves a partial corpus


def incomplete_corpus(s: Session) -> UpdateRun | None:
    """The run that left the visible corpus incomplete, or None.

    The first update of a workspace has no previous corpus a gate could keep, so its stages commit as they finish
    (update_publication.candidate). When no update has passed its gates yet (or been accepted) and the newest
    finished one failed a gate, errored or was interrupted, what the CLI, web UI and publishers see is that partial
    result: it must be shown as incomplete, not as a normal corpus. A later passing run or `runs accept` clears it."""
    if s.scalar(select(UpdateRun.id).where(UpdateRun.status.in_(PASSED)).limit(1)) is not None:
        return None
    # The newest run, finished or not: a first update that is still running, or whose process was killed (SIGKILL,
    # out of memory, power loss) before it could record an outcome, has also left only part of the corpus.
    run = s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(1)).first()
    if run is None:
        return None
    return run if run.finished_at is None or run.status in INCOMPLETE else None


def publish_refusal(s: Session) -> str | None:
    """Why the workspace corpus must not be published (release, static site), or None.

    An incomplete first update, an index that does not cover the live logic (doctor's index failure) and an empty
    index all refuse: publishers would otherwise ship a partial or empty pack with exit 0."""
    if (partial := incomplete_corpus(s)) is not None:
        return incomplete_text(partial)
    c = corpus_counts(s)
    if c["index_missing"] or c["index_groups"] != c["unique_logic"]:
        return f"index out of date: {c['index_groups']:,} groups for {c['unique_logic']:,} live logic. Run `sigharvest index` (or `sigharvest update`) first."
    if not c["index_groups"]:
        return "the index is empty: nothing to publish. Run `sigharvest update` first."
    return None


ABANDONED = "the process ended before the run finished (killed, out of memory or power loss)"


def close_abandoned(s: Session) -> int:
    """Mark runs that never finished as interrupted. Only call while holding the workspace mutation lease: then no
    other process can be running an update, so every unfinished run belongs to a process that is gone."""
    abandoned = list(s.scalars(select(UpdateRun).where(UpdateRun.finished_at.is_(None))))
    for run in abandoned:
        run.status = "interrupted"
        run.reasons = [ABANDONED, *(run.reasons or [])]
        run.finished_at = utcnow()
    return len(abandoned)


def incomplete_text(run: UpdateRun) -> str:
    """One line for every surface (CLI, doctor, web banner, publishers)."""
    if run.finished_at is None:
        return (
            f"corpus incomplete: the first update (run {run.id}) has not finished (still running, or its process was killed). "
            "Wait for it, or run `sigharvest update` again."
        )
    why = f": {clean_text(run.reasons[0])[:160]}" if run.reasons else ""
    keep = f", or keep this corpus with `sigharvest runs accept {run.id}`" if run.status == "failed gate" else ""
    return f"corpus incomplete: the first update (run {run.id}) ended with '{run.status}'{why}. Fix the cause and run `sigharvest update` again{keep}."


def get_run(s: Session, key: str) -> UpdateRun | None:
    """A run by id, or the newest one for "latest"."""
    if key == "latest":
        return s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(1)).first()
    return s.get(UpdateRun, int(key)) if key.isdigit() else None


def finish(run: UpdateRun, gates: list[Gate], source_failures: list[str], error: str | None = None) -> None:
    """Set the run's gates, status and reasons."""
    run.gates = [asdict(g) for g in gates]
    failed = [g for g in gates if g.status == "fail"]
    reasons = [f"gate {g.name}: {g.detail}" for g in failed]
    if error:
        reasons.insert(0, f"error: {error}")
    if source_failures:
        reasons.append(f"{len(source_failures)} sources failed to sync: {', '.join(source_failures[:15])}{' ...' if len(source_failures) > 15 else ''}")
    run.reasons = [clean_text(r) for r in reasons]
    run.status = "error" if error else "failed gate" if failed else "source failures" if source_failures else "ok"
    run.finished_at = utcnow()


def open_log(ws: Workspace, keep: int = KEEP_LOGS) -> logging.Handler:
    """Log the update to data/logs/update-<date>.log (appending; files beyond the newest `keep` are deleted).
    Returns the handler, to be removed with close_log()."""
    import os

    from sigharvest.observability import FileHandler, Formatter

    folder = ws.root / "data" / "logs"
    structured = os.environ.get("SIGHARVEST_LOG_FORMAT", "text") == "json"
    path = folder / f"update-{utcnow():%Y-%m-%d}.{'jsonl' if structured else 'log'}"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = FileHandler(path, encoding="utf-8")
    except OSError:
        import sys

        print("sigharvest: log file unavailable; continuing with stderr", file=sys.stderr)
        handler = logging.StreamHandler()
    handler.setFormatter(Formatter(structured))
    log.setLevel(logging.INFO)
    log.propagate = False
    log.addHandler(handler)
    logging.getLogger("sigharvest").addHandler(handler)  # warnings of every module
    protected = {path}
    job = os.environ.get("SIGHARVEST_UPDATE_JOB", "")
    if re.fullmatch(r"[A-Za-z0-9-]{1,80}", job):
        protected.add(folder / f"update-{job}.log")
    try:
        prune(folder, "update-*.log", keep, protected)
        prune(folder, "update-*.jsonl", keep, {path})
    except OSError:
        log.warning("log retention failed; files retained")
    return handler


def close_log(handler: logging.Handler) -> None:
    log.removeHandler(handler)
    logging.getLogger("sigharvest").removeHandler(handler)
    handler.close()
