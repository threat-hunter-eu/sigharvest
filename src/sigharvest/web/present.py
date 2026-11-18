"""Presentation helpers shared by the web routes: licence badges, source health, the sidebar status line,
heat and width classes (the CSP forbids inline styles), relative times and the update-run reports behind Changes.

Everything here is read-only and returns plain data; templates do the markup with autoescaping.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from sigharvest.licensing import licence_class, normalise
from sigharvest.models import LogicGroup, Source, SyncLog, UpdateRun
from sigharvest.models import utcnow as now

STALE_AFTER = timedelta(days=30)

# ----------------------------------------------------------------------------- licences

LIC_WORDS = {"permissive": "permissive", "copyleft": "copyleft", "restricted": "restricted", "none": "no licence"}
LIC_TITLES = {
    "permissive": "Permissive: free to reuse and share with credit (DRL, MIT, Apache, BSD, CC0)",
    "copyleft": "Copyleft: share it, or a changed version, under the same licence (GPL family, CC-BY-SA)",
    "restricted": "Restricted: limits on use or sharing (non-commercial, no-derivatives or custom terms)",
    "none": "No licence: you may read it at the source, not redistribute it",
}
LIC_MEANING = {
    "permissive": "free to share, keep the author credit",
    "copyleft": "share under the same licence",
    "restricted": "read the terms before sharing",
    "none": "link only, do not redistribute",
}
LIC_SENTENCE = {
    "permissive": "You may use, change and share this rule, including commercially, if you keep the author credit and the licence notice. "
    "Exports include the author and a NOTICE file automatically.",
    "copyleft": "You may use and change this rule. If you share it, or a changed version, share it under the same licence. "
    "Exports keep copyleft rules in their own folder with the licence text.",
    "restricted": "This licence limits how the rule may be used or shared (for example non-commercial only). Read its terms first; "
    "exports leave these rules out unless you choose to include them.",
    "none": "No licence was stated, so nobody else may redistribute the text. Read it at the source; exports list it in SKIPPED.md "
    "with a link instead of a copy.",
}
LIC_EXAMPLES = {
    "permissive": "DRL, MIT, Apache-2.0, BSD, CC0, CC-BY",
    "copyleft": "GPL-2.0, GPL-3.0, AGPL, LGPL, MPL, CC-BY-SA",
    "restricted": "CC-BY-NC, Elastic License, BUSL, custom terms",
    "none": "no LICENSE file and no license: field",
}
LIC_NAMES = {
    "drl-1.1": "Detection Rule License 1.1",
    "drl-1.0": "Detection Rule License 1.0",
    "mit": "MIT License",
    "apache-2.0": "Apache License 2.0",
    "cc0-1.0": "Creative Commons Zero 1.0",
    "cc-by-4.0": "Creative Commons Attribution 4.0",
    "cc-by-sa-4.0": "Creative Commons Attribution-ShareAlike 4.0",
    "gpl-2.0": "GNU General Public License 2.0",
    "gpl-3.0": "GNU General Public License 3.0",
    "agpl-3.0": "GNU Affero General Public License 3.0",
    "lgpl-3.0": "GNU Lesser General Public License 3.0",
    "bsd-3-clause": "BSD 3-Clause License",
    "bsd-2-clause": "BSD 2-Clause License",
    "mpl-2.0": "Mozilla Public License 2.0",
    "unlicense": "The Unlicense",
}


def licence_info(licence: str | None) -> dict[str, str]:
    """Badge data for a licence name or SPDX id: label (as stated), class, title (tooltip), full name and meaning."""
    cls = licence_class(licence)
    stated = (licence or "").strip()[:200]
    label = stated or LIC_WORDS["none"]  # a long id ends in an ellipsis in CSS; the title keeps it whole
    key = normalise(licence) or ""
    return {
        "label": label,
        "cls": cls,
        "title": f"{stated}: {LIC_TITLES[cls]}" if len(stated) > 24 else LIC_TITLES[cls],
        "name": LIC_NAMES.get(key, label),
        "meaning": LIC_MEANING[cls],
        "sentence": LIC_SENTENCE[cls],
    }


def source_licences(s: Session) -> dict[str, str | None]:
    """Source licences as sources.yaml states them now, over the database copy (source_metadata)."""
    from sigharvest.source_metadata import source_licences as current

    return current(s)


def sources_by_class(s: Session) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, lic in source_licences(s).items():
        out.setdefault(licence_class(lic), []).append(name)
    return {k: sorted(v) for k, v in out.items()}


def licence_counts(s: Session) -> list[dict[str, Any]]:
    """Unique rules per licence class of their effective licence (the canonical source's licence; the rule's own
    license: field only when narrower), with the licence ids seen in each class."""
    from sigharvest.licensing import shipped_licence

    current = source_licences(s)
    grouped = s.execute(
        text(
            "SELECT nullif(v.rule_license, '') AS own, g.canonical_source AS src, count(*) FROM logic_groups g "
            "JOIN rule_versions v ON v.id = g.canonical_version_id "
            "WHERE g.junk = 0 AND coalesce(g.status, '') NOT IN ('deprecated', 'unsupported') GROUP BY own, src"
        )
    )
    rows = [(shipped_licence(own, current.get(src)), n) for own, src, n in grouped]
    classes: dict[str, dict[str, Any]] = {}
    for lic, n in rows:
        cls = licence_class(lic)
        entry = classes.setdefault(cls, {"cls": cls, "word": LIC_WORDS[cls], "title": LIC_TITLES[cls], "n": 0, "ids": [], "by_id": {}})
        entry["n"] += int(n)
        if lic:
            entry["by_id"][str(lic)] = entry["by_id"].get(str(lic), 0) + int(n)
    for entry in classes.values():
        # The most common licence ids first; the long tail is summarised so the overview stays readable.
        ranked = sorted(entry.pop("by_id").items(), key=lambda kv: (-kv[1], kv[0]))
        entry["ids"] = [lic.removeprefix("LicenseRef-") for lic, _ in ranked[:5]]
        if len(ranked) > 5:
            entry["ids"].append(f"{len(ranked) - 5} more")
    order = ["permissive", "copyleft", "restricted", "none"]
    return [classes[c] for c in order if c in classes]


# ----------------------------------------------------------------------------- sources: health


def _naive(t: datetime | None) -> datetime | None:
    return t.replace(tzinfo=None) if t is not None and t.tzinfo is not None else t


def source_health(s: Session) -> dict[str, dict[str, Any]]:
    """Per enabled source: synced / stale (no sync for 30 days) / failing (the last sync attempt failed) / not synced,
    with the error of a failing source (shown as a tooltip; the old rules are kept)."""
    last = select(SyncLog.source_id, func.max(SyncLog.id).label("id")).group_by(SyncLog.source_id).subquery()
    logs = {
        sid: (status, error) for sid, status, error in s.execute(select(SyncLog.source_id, SyncLog.status, SyncLog.error).join(last, last.c.id == SyncLog.id))
    }
    out: dict[str, dict[str, Any]] = {}
    current = now()
    for sid, name, enabled, last_sync in s.execute(select(Source.id, Source.name, Source.enabled, Source.last_sync_at)):
        status, error = logs.get(sid, (None, None))
        if not enabled:
            state, label = "idle", "disabled"
        elif status not in (None, "ok"):
            state, label = "failing", "skipped"
        elif last_sync is None:
            state, label = "idle", "not synced"
        elif current - (_naive(last_sync) or current) > STALE_AFTER:
            state, label = "stale", "stale"
        else:
            state, label = "synced", "synced"
        out[name] = {"state": state, "label": label, "error": friendly_error(error)[:300], "last_sync": last_sync}
    return out


def friendly_error(error: str | None) -> str:
    """A sync error as a reader sees it: without the Python exception class in front ("SyncError: ...")."""
    text = (error or "").strip()
    return re.sub(r"^[A-Z][A-Za-z]*(?:Error|Exception): ", "", text)


def health_counts(health: dict[str, dict[str, Any]]) -> dict[str, int]:
    out = {"synced": 0, "stale": 0, "failing": 0, "idle": 0}
    for h in health.values():
        out[h["state"]] += 1
    return out


# ----------------------------------------------------------------------------- times, heat, widths


def reltime(t: datetime | None) -> str:
    """'just now', '5 min ago', '2 h ago', '3 days ago', '4 months ago'."""
    if t is None:
        return "never"
    delta = now() - (_naive(t) or now())
    secs = max(delta.total_seconds(), 0)
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    days = int(secs // 86400)
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return f"{days // 30} months ago"


def fulltime(t: datetime | None) -> str:
    return t.strftime("%d %b %Y %H:%M UTC") if t else ""


def heat(n: int, peak: int) -> int:
    """0..5 on a log scale relative to the peak (0 only for no rules)."""
    if n <= 0 or peak <= 0:
        return 0
    return max(1, min(5, math.ceil(5 * math.log1p(n) / math.log1p(peak))))


def width(n: float, peak: float) -> str:
    """A .wNN class (2..100) for a bar of n out of peak; '' for nothing."""
    if n <= 0 or peak <= 0:
        return ""
    return f"w{max(2, min(100, round(100 * n / peak)))}"


def pips(n_sources: int) -> list[bool]:
    """Five pips: how widely a rule is copied (1, 2, 3-4, 5-9, 10+ sources)."""
    on = 1 if n_sources <= 1 else 2 if n_sources == 2 else 3 if n_sources <= 4 else 4 if n_sources <= 9 else 5
    return [i < on for i in range(5)]


# ----------------------------------------------------------------------------- update runs (Changes)


def runs(s: Session, limit: int = 20) -> list[UpdateRun]:
    return list(s.scalars(select(UpdateRun).where(UpdateRun.finished_at.is_not(None)).order_by(UpdateRun.id.desc()).limit(limit)))


def run_report(ws_root: Path, run: UpdateRun | None) -> dict[str, Any] | None:
    """The JSON report of an update run (written by `sigharvest update`), or None. Only files under the workspace
    reports folder are read."""
    if run is None or not run.report:
        return None
    root = (ws_root / "reports").resolve()
    path = (ws_root / run.report).with_suffix(".json").resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def change_summary(report: dict[str, Any] | None) -> dict[str, int]:
    if not report:
        return {"new": 0, "changed": 0, "removed": 0}
    return {k: len(report.get(k) or []) for k in ("new", "changed", "removed")}


def logsource_of(g: Any) -> str:
    return " / ".join(x for x in (g.product, g.category, g.service) if x)


def technique_count(s: Session) -> int:
    """Distinct ATT&CK technique ids (attack.tNNNN[.NNN]) tagged by at least one live rule."""
    return int(
        s.scalar(
            text("SELECT count(DISTINCT lower(t.value)) FROM logic_groups g, json_each(g.tags) t WHERE g.junk = 0 AND lower(t.value) GLOB 'attack.t[0-9]*'")
        )
        or 0
    )


def live_rules(s: Session) -> int:
    return int(s.scalar(select(func.count()).select_from(LogicGroup)) or 0)


# ----------------------------------------------------------------------------- the sidebar status line


def sidebar(ws_root: Path, s: Session) -> dict[str, Any]:
    """Every page shows it: rules, sources, the last sync, failing sources and the new-rules badge of Changes."""
    from sigharvest.source_status import counts

    n_rules = live_rules(s)
    _total, enabled = counts(s)
    health = source_health(s)
    failing = sorted(name for name, h in health.items() if h["state"] == "failing")
    last = runs(s, 1)
    report = run_report(ws_root, last[0]) if last else None
    new = len(report.get("new") or []) if report else 0
    first = report is not None and not report.get("previous_run")
    from sigharvest.runs import incomplete_corpus, incomplete_text

    partial = incomplete_corpus(s)
    return {
        "incomplete": incomplete_text(partial) if partial is not None else "",
        "empty": n_rules == 0,
        "n_rules": n_rules,
        "n_sources": enabled,
        "last_sync": (last[0].finished_at if last else None) or s.scalar(select(func.max(Source.last_sync_at))),
        "failing": failing,
        "new_badge": 0 if first else new,
    }


def mark(text_value: Any, terms: list[str]) -> Any:
    """Escape text and wrap case-insensitive matches of the search terms in <mark> (no other markup)."""
    import re

    from markupsafe import Markup, escape

    value = str(text_value or "")
    words = sorted({t for t in terms if len(t) >= 2}, key=len, reverse=True)[:12]
    if not words:
        return escape(value)
    pattern = re.compile("(" + "|".join(re.escape(w) for w in words) + ")", re.I)
    pieces = pattern.split(value)
    return Markup("".join(f"<mark>{escape(p)}</mark>" if i % 2 else str(escape(p)) for i, p in enumerate(pieces)))  # noqa: S704 - every piece is escaped


def query_terms(q: str) -> list[str]:
    """Words of a search worth highlighting: no operators, exclusions or field:value filters."""
    import re

    out = []
    for phrase, word in re.findall(r'"([^"]+)"|(\S+)', q or ""):
        token = phrase or word
        if not token or token.upper() in ("AND", "OR", "NOT") or token.startswith("-") or (":" in token and not phrase):
            continue
        out.append(token.strip("()*"))
    return [t for t in out if t]


def display_path(path: object) -> str:
    """A local path as the UI shows it: `~/...` under the home directory, else only its last part (the workspace
    name), so absolute machine paths never reach a page or a screenshot."""
    from pathlib import Path

    p = Path(str(path)).expanduser()
    try:
        return "~/" + p.resolve().relative_to(Path.home().resolve()).as_posix()
    except (ValueError, OSError, RuntimeError):
        return p.name or str(p)


# ----------------------------------------------------------------------------- overview charts


def age_chart(by_year: dict[int, int], unknown: int, recent: int, total: int, this_year: int, span: int = 10) -> dict[str, Any]:
    """Columns for "when the rules were last changed": one per year for the last `span` years, older years in one
    first column. Geometry in a 0..100 x 0..100 box (the template draws it as SVG, no inline style under the CSP)."""
    first = this_year - span + 1
    cols: list[dict[str, Any]] = []
    older = sum(n for y, n in by_year.items() if y < first)
    if older:
        cols.append({"label": f"before {first}", "short": "older", "n": older, "now": False})
    for y in range(first, this_year + 1):
        cols.append({"label": str(y), "short": f"'{y % 100:02d}" if y != this_year else str(y), "n": by_year.get(y, 0), "now": y == this_year})
    peak = max((c["n"] for c in cols), default=0)
    n = len(cols)
    slot = 100 / n if n else 100
    for i, c in enumerate(cols):
        h = 0.0 if not peak or not c["n"] else max(2.0, 96 * c["n"] / peak)
        c.update(x=round(i * slot + slot * 0.14, 3), w=round(slot * 0.72, 3), y=round(100 - h, 3), h=round(h, 3))
    dated = sum(by_year.values())
    return {"cols": cols, "dated": dated, "unknown": unknown, "recent": recent, "share": round(100 * recent / total) if total else 0, "peak": peak}


def spark(values: list[int]) -> dict[str, Any] | None:
    """A sparkline (polyline points in a 0..100 x 0..30 box) of a count over the last updates, oldest first; None for
    fewer than two points."""
    if len(values) < 2:
        return None
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1
    step = 100 / (len(values) - 1)
    pts = [(round(i * step, 2), round(27 - 24 * (v - lo) / rng, 2) if hi > lo else 15.0) for i, v in enumerate(values)]
    return {
        "points": " ".join(f"{x},{y}" for x, y in pts),
        "area": "0,30 " + " ".join(f"{x},{y}" for x, y in pts) + " 100,30",
        "last": pts[-1],
        "n": len(values),
        "delta": values[-1] - values[0],
    }


def rule_ages(s: Session) -> dict[str, Any]:
    """Live rules by the year of their last change (modified, else date), for the overview chart."""
    from sigharvest.models import RuleVersion

    when = func.replace(func.coalesce(LogicGroup.modified, RuleVersion.date), "/", "-")
    rows = s.execute(
        select(func.substr(when, 1, 4), func.count())
        .select_from(LogicGroup)
        .join(RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id)
        .where(LogicGroup.junk.is_(False))
        .group_by(func.substr(when, 1, 4))
    ).all()
    today = now()
    cutoff = (today - timedelta(days=365)).strftime("%Y-%m-%d")
    recent = s.scalar(
        select(func.count())
        .select_from(LogicGroup)
        .join(RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id)
        .where(LogicGroup.junk.is_(False), when >= cutoff, when <= today.strftime("%Y-%m-%d") + "~")
    )
    by_year: dict[int, int] = {}
    unknown = total = 0
    for y, n in rows:
        total += n
        if y and str(y).isdigit() and 1990 <= int(y) <= today.year:
            by_year[int(y)] = by_year.get(int(y), 0) + n
        else:
            unknown += n
    return age_chart(by_year, unknown, int(recent or 0), total, today.year)


def corpus_trend(s: Session, limit: int = 24) -> dict[str, Any] | None:
    """Unique rules after each of the last finished updates (oldest first), as a sparkline."""
    values = [int((r.counts or {}).get("unique_logic") or 0) for r in reversed(runs(s, limit))]
    values = [v for v in values if v > 0]
    return spark(values)


def composition(counts: list[tuple[str, int]], order: tuple[str, ...], href: Any, cls_prefix: str) -> list[dict[str, Any]]:
    """Parts of a 100% bar in a fixed order (never by rank): label, count, percent, .wNN width class, colour class."""
    by = dict(counts)
    total = sum(by.get(k, 0) for k in order)
    parts: list[dict[str, Any]] = []
    for k in order:
        n = by.get(k, 0)
        if n and total:
            pct = 100 * n / total
            parts.append(
                {
                    "label": k,
                    "n": n,
                    "pct": round(pct) if pct >= 1 else "<1",
                    "w": f"w{max(2, min(100, round(pct)))}",
                    "cls": f"{cls_prefix}{k}",
                    "href": href(k),
                }
            )
    return parts
