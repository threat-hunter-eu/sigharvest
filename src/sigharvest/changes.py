"""What is new, changed or removed: since the last update(s) of a workspace, or between two release packs.

One shape for every consumer (the `changes` command, the static site's changes.json and Atom feed):

    {"since": label, "until": label, "new": [{"logic_hash", "title"}], "changed": [{"rule_id", "old", "new", "title"}],
     "removed": [{"logic_hash", "title"}]}

Workspace changes come from the run reports `sigharvest update` writes (reports/runs/<stamp>.json); release changes
compare the verified index.json.gz of two packs (the same rules as release.py's changes.json).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError

KINDS = ("new", "changed", "removed")
FEED_LIMIT = 200
# Not allowed in XML 1.0 even when escaped (C0 controls other than tab/newline/CR, surrogates, U+FFFE/U+FFFF).
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def safe_text(value: Any) -> str:
    """One line of printable text: terminal escape sequences and XML-invalid characters cannot pass (titles and
    hashes can come from an untrusted release pack)."""
    from sigharvest.runs import clean_text

    return _XML_INVALID.sub("\ufffd", " ".join(clean_text(str(value)).split()))


def normalise(changes: dict[str, Any]) -> dict[str, Any]:
    """Only the documented shape, with every value a clean string (a release's changes.json is untrusted input)."""

    def text(v: Any) -> str | None:
        return None if v is None else safe_text(v)

    out = empty(text(changes.get("since")) or "", text(changes.get("until")) or "")
    for kind in KINDS:
        rows = changes.get(kind)
        for x in rows if isinstance(rows, list) else []:
            if not isinstance(x, dict):
                continue
            if kind == "changed":
                out[kind].append({"rule_id": text(x.get("rule_id")), "old": text(x.get("old")), "new": text(x.get("new")), "title": text(x.get("title"))})
            else:
                out[kind].append({"logic_hash": text(x.get("logic_hash")) or "", "title": text(x.get("title"))})
    return out


def empty(since: str = "", until: str = "") -> dict[str, Any]:
    return {"since": since, "until": until, "new": [], "changed": [], "removed": []}


def report_totals(report: dict[str, Any]) -> dict[str, int]:
    """How many rules of each kind a run report covers: its "totals", else the run counts (older reports), else the
    listed rows. A total larger than the list means the list is incomplete (older reports stopped at 5,000 rows)."""
    out: dict[str, int] = {}
    for source in (report.get("totals"), report.get("counts")):
        if isinstance(source, dict):
            for kind in KINDS:
                if kind not in out and isinstance(source.get(kind), int) and not isinstance(source.get(kind), bool):
                    out[kind] = int(source[kind])
    rows = {kind: len(report.get(kind) or []) for kind in KINDS}
    return {kind: max(out.get(kind, 0), rows[kind]) for kind in KINDS}


def from_report(report: dict[str, Any]) -> dict[str, Any]:
    """The changes of one update run report."""
    out = empty(str(report.get("started") or ""), str(report.get("finished") or ""))
    out["run"] = report.get("run")
    totals = report_totals(report)
    out["new"] = [{"logic_hash": str(x.get("logic") or ""), "title": x.get("title")} for x in report.get("new") or [] if isinstance(x, dict)]
    out["changed"] = [
        {"rule_id": x.get("rule_id"), "old": x.get("old"), "new": x.get("new"), "title": x.get("title")}
        for x in report.get("changed") or []
        if isinstance(x, dict)
    ]
    out["removed"] = [{"logic_hash": str(x.get("logic") or ""), "title": x.get("title")} for x in report.get("removed") or [] if isinstance(x, dict)]
    missing = {kind: totals[kind] - len(out[kind]) for kind in KINDS if totals[kind] > len(out[kind])}
    if missing:
        out["incomplete"] = [
            f"run {report.get('run')}: the report lists {len(out[kind]):,} of {totals[kind]:,} {kind} rules (it was written by an older "
            "version that kept at most 5,000 per list)"
            for kind in missing
        ]
    return out


def merge(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Several consecutive runs (oldest first) as one change set: a rule added then removed is in neither list."""
    if not parts:
        return empty()
    out = empty(parts[0]["since"], parts[-1]["until"])
    new: dict[str, dict[str, Any]] = {}
    removed: dict[str, dict[str, Any]] = {}
    changed: dict[str, dict[str, Any]] = {}  # rule id -> change with the oldest "old" and the newest "new"
    for p in parts:
        for x in p["new"]:
            if removed.pop(x["logic_hash"], None) is None:
                new[x["logic_hash"]] = x
        for x in p["changed"]:
            if x.get("old") in new:  # added in an earlier run, changed since: new with its current logic
                del new[x["old"]]
                new[str(x.get("new"))] = {"logic_hash": str(x.get("new")), "title": x.get("title")}
                continue
            key = str(x.get("rule_id") or x.get("new"))
            first = changed.get(key)
            merged = x | ({"old": first["old"]} if first else {})
            if merged.get("old") == merged.get("new"):  # changed back: no change over the whole span
                changed.pop(key, None)
            else:
                changed[key] = merged
        for x in p["removed"]:
            if new.pop(x["logic_hash"], None) is not None:
                continue
            was = next((k for k, c in changed.items() if c.get("new") == x["logic_hash"]), None)
            if was is not None:  # changed, then removed: the rule that existed before the span is gone
                x = x | {"logic_hash": str(changed.pop(was)["old"])}
            removed[x["logic_hash"]] = x
    out["new"], out["changed"], out["removed"] = list(new.values()), list(changed.values()), list(removed.values())
    out["runs"] = [p.get("run") for p in parts]
    incomplete = [line for p in parts for line in p.get("incomplete") or []]
    if incomplete:
        out["incomplete"] = incomplete
    return out


def since_update(s: Session, ws_root: Path, *, run: str | None = None, since: str | None = None) -> dict[str, Any]:
    """Changes of the latest published update (default), of one run id, or of every published update started since
    an ISO date (a time without an offset is UTC).

    Only runs that passed their gates (or were accepted) changed the published corpus; a run that failed a gate kept
    the previous corpus, so its candidate changes are not reported unless asked for by id."""
    from sigharvest.models import UpdateRun
    from sigharvest.runs import PASSED
    from sigharvest.web.present import run_report

    q = select(UpdateRun).where(UpdateRun.finished_at.is_not(None)).order_by(UpdateRun.id)
    if run not in (None, "latest"):
        if not str(run).isdigit():
            raise SigharvestError("--run takes a run id or latest")
        q = q.where(UpdateRun.id == int(str(run)))
    else:
        q = q.where(UpdateRun.status.in_(PASSED))
    if since:
        try:
            start = datetime.fromisoformat(since)
        except ValueError:
            raise SigharvestError("--since takes a date (YYYY-MM-DD) or an ISO time") from None
        if start.tzinfo is not None:
            start = start.astimezone(UTC)
        q = q.where(UpdateRun.started_at >= start.replace(tzinfo=None))
    runs = list(s.scalars(q))
    if not since:
        runs = runs[-1:]
    parts = [from_report(r) for r in (run_report(ws_root, x) for x in runs) if r]
    out = merge(parts)
    if run in (None, "latest"):
        newest = s.scalars(select(UpdateRun).where(UpdateRun.finished_at.is_not(None)).order_by(UpdateRun.id.desc()).limit(1)).first()
        if newest is not None and newest.status not in PASSED:
            out["note"] = f"the latest update (run {newest.id}) ended with '{newest.status}': the published corpus did not change"
    return out


def _index(folder: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from sigharvest.release_reader import ReleaseError, open_release, read_index

    try:
        with open_release(folder) as reader:
            path = reader.folder / "index.json.gz"
            if not path.is_file():
                raise SigharvestError(f"{folder}: the release has no index.json.gz")
            return read_index(path), reader.manifest
    except ReleaseError as exc:
        raise SigharvestError(f"{folder}: {exc}") from None


def between_releases(old: Path, new: Path) -> dict[str, Any]:
    """What `new` adds, changes (same rule id, other logic) and removes compared with `old`; both are verified."""
    old_rows, old_manifest = _index(old)
    new_rows, new_manifest = _index(new)
    old_logic = {r["logic_hash"]: r for r in old_rows}
    new_logic = {r["logic_hash"]: r for r in new_rows}
    old_by_id = {r.get("rule_id"): r["logic_hash"] for r in old_rows if r.get("rule_id")}
    added = sorted(h for h in new_logic if h not in old_logic)
    changed = [
        {"rule_id": new_logic[h]["rule_id"], "old": old_by_id[new_logic[h]["rule_id"]], "new": h, "title": new_logic[h].get("title")}
        for h in added
        if new_logic[h].get("rule_id") in old_by_id and old_by_id[new_logic[h]["rule_id"]] not in new_logic
    ]
    changed_new, changed_old = {c["new"] for c in changed}, {c["old"] for c in changed}
    out = empty(str(old_manifest.get("created") or ""), str(new_manifest.get("created") or ""))
    out["new"] = [{"logic_hash": h, "title": new_logic[h].get("title")} for h in added if h not in changed_new]
    out["changed"] = changed
    out["removed"] = [{"logic_hash": h, "title": old_logic[h].get("title")} for h in sorted(old_logic) if h not in new_logic and h not in changed_old]
    return out


def atom(changes: dict[str, Any], *, feed_url: str, site_url: str, title: str, link_for: Any, updated: str) -> str:
    """An Atom 1.0 feed (RFC 4287): one entry per new, changed or removed rule, at most FEED_LIMIT; the subtitle gives
    the full counts and says when the feed is cut."""
    ns = "http://www.w3.org/2005/Atom"
    ET.register_namespace("", ns)
    feed = ET.Element(f"{{{ns}}}feed")

    def sub(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
        el = ET.SubElement(parent, f"{{{ns}}}{tag}", attrs)
        if text is not None:
            el.text = text
        return el

    stamp = _atom_time(updated)
    sub(feed, "id", safe_text(feed_url))
    sub(feed, "title", safe_text(title))
    sub(feed, "updated", stamp)
    sub(feed, "link", rel="self", href=feed_url)
    sub(feed, "link", href=site_url)
    total = sum(len(changes.get(kind) or []) for kind in KINDS)
    counts = ", ".join(f"{len(changes.get(kind) or []):,} {kind}" for kind in KINDS)
    more = f"; this feed lists the first {FEED_LIMIT}, changes.json lists all of them" if total > FEED_LIMIT else ""
    sub(feed, "subtitle", f"{counts}{more}")
    author = sub(feed, "author")
    sub(author, "name", "sigharvest")
    n = 0
    for kind in KINDS:
        for x in changes.get(kind) or []:
            if n >= FEED_LIMIT:
                break
            key = safe_text(x.get("new") if kind == "changed" else x.get("logic_hash") or "")
            entry = sub(feed, "entry")
            sub(entry, "id", f"{feed_url}#{kind}-{key}")
            label = {"new": "New", "changed": "Changed", "removed": "Removed"}[kind]
            sub(entry, "title", f"{label}: {safe_text(x.get('title') or '(untitled)')[:200]}")
            sub(entry, "updated", stamp)
            if kind != "removed" and (href := link_for(key)):
                sub(entry, "link", href=href)
            sub(entry, "summary", f"{label} rule, logic {key[:12]}" + (f" (was {safe_text(x.get('old') or '')[:12]})" if kind == "changed" else ""))
            n += 1
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(feed, encoding="unicode") + "\n"


def _atom_time(value: str) -> str:
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00")) if value else datetime.now(UTC)
    except ValueError:
        t = datetime.now(UTC)
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
