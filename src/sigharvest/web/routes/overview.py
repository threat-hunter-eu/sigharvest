"""Overview: the state of the index (hero numbers, ATT&CK tactic strip, recent changes, top sources, licences) and
where to start."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.web import present, queries
from sigharvest.web.deps import Web, WebDep

router = APIRouter()

# The 14 Enterprise tactics in matrix order; ATT&CK v19 split defense-evasion into stealth and defense-impairment,
# so the Evasion cell counts (and searches) all three tags.
STRIP = (
    ("reconnaissance", "Recon", "Reconnaissance", ("reconnaissance",)),
    ("resource-development", "Resource dev.", "Resource Development", ("resource-development",)),
    ("initial-access", "Initial access", "Initial Access", ("initial-access",)),
    ("execution", "Execution", "Execution", ("execution",)),
    ("persistence", "Persistence", "Persistence", ("persistence",)),
    ("privilege-escalation", "Privilege esc.", "Privilege Escalation", ("privilege-escalation",)),
    ("defense-evasion", "Evasion", "Defense Evasion", ("defense-evasion", "stealth", "defense-impairment")),
    ("credential-access", "Credentials", "Credential Access", ("credential-access",)),
    ("discovery", "Discovery", "Discovery", ("discovery",)),
    ("lateral-movement", "Lateral mov.", "Lateral Movement", ("lateral-movement",)),
    ("collection", "Collection", "Collection", ("collection",)),
    ("command-and-control", "C2", "Command and Control", ("command-and-control",)),
    ("exfiltration", "Exfiltration", "Exfiltration", ("exfiltration",)),
    ("impact", "Impact", "Impact", ("impact",)),
)
STARTING_POINTS = (
    ("Stable rules of high level", {"level": "high", "status": "stable"}, None),
    ("Critical rules", {"level": "critical"}, None),
    ("Windows process creation rules", {"product": "windows", "category": "process_creation"}, None),
    ("Found in one source only", {"source_only": "1"}, None),
)


def top_sources(s: Session, limit: int = 7) -> list[dict[str, Any]]:
    from sigharvest.models import SourceSummary

    lic = present.source_licences(s)
    rows = list(s.scalars(select(SourceSummary).order_by(SourceSummary.only.desc(), SourceSummary.logic.desc(), SourceSummary.name).limit(limit)))
    peak = max((r.only for r in rows), default=0)
    return [
        {"name": r.name, "logic": r.logic, "only": r.only, "licence": present.licence_info(lic.get(r.name)), "w": present.width(r.only, peak)} for r in rows
    ]


def strip_heat(n: int, peak: int) -> int:
    """0..5 by share of the busiest tactic (the same steps as the suriharvest protocol strip)."""
    if n <= 0 or peak <= 0:
        return 0
    r = n / peak
    return 5 if r > 0.5 else 4 if r > 0.25 else 3 if r > 0.08 else 2 if r > 0.02 else 1


def tactic_strip(c: queries.Corpus) -> list[dict[str, Any]]:
    counts = {tag.removeprefix("attack."): n for tag, n in c.tactics}
    cells: list[dict[str, Any]] = []
    for key, short, name, tags in STRIP:
        n = sum(counts.get(t, 0) for t in tags)
        cells.append({"key": key, "short": short, "name": name, "n": n, "href": "/search?" + urlencode({"tactic": ",".join(tags)})})
    peak = max((int(x["n"]) for x in cells), default=0)
    for x in cells:
        x["heat"] = strip_heat(int(x["n"]), peak)
    return cells


def starting_points(s: Session) -> list[dict[str, Any]]:
    from sigharvest.web.routes.search import count_for

    return [{"label": label, "href": "/search?" + urlencode(params), "n": count_for(s, params)} for label, params, _ in STARTING_POINTS]


def recent_changes(web: Web, s: Session) -> dict[str, Any]:
    """Up to 6 rows of the last update (new first, then changed, then removed), from its run report."""
    last = present.runs(s, 1)
    report = present.run_report(web.ws.root, last[0]) if last else None
    if not report:
        return {"rows": [], "counts": {"new": 0, "changed": 0, "removed": 0}, "when": None, "first": False}
    first = not report.get("previous_run")
    hashes = [r.get("logic") for r in (report.get("new") or [])[:6]] + [r.get("new") for r in (report.get("changed") or [])[:6]]
    from sigharvest.models import LogicGroup

    groups = {g.logic_hash: g for g in s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.in_([h for h in hashes if h])))}
    rows: list[dict[str, Any]] = []

    def add(kind: str, logic: str | None, title: str | None, level: str | None = None) -> None:
        g = groups.get(logic or "")
        rows.append(
            {
                "kind": kind,
                "title": (g.title if g else None) or title or "(untitled)",
                "href": f"/rule/{logic[:16]}" if g is not None and logic else "",
                "meta": " · ".join(x for x in ((present.logsource_of(g) if g else ""), (g.canonical_source if g else "")) if x),
                "level": (g.level if g else level) or "",
            }
        )

    for r in (report.get("new") or [])[: 3 if report.get("changed") else 6]:
        add("new", r.get("logic"), r.get("title"), r.get("level"))
    for r in (report.get("changed") or [])[: 6 - len(rows) - (1 if report.get("removed") else 0)]:
        add("changed", r.get("new"), r.get("title"))
    for r in (report.get("removed") or [])[: max(0, 6 - len(rows))]:
        add("removed", None, r.get("title"))
    return {"rows": rows, "counts": present.change_summary(report), "when": last[0].finished_at, "first": first}


def overview_data(web: Web, s: Session) -> dict[str, Any]:
    c = queries.corpus(s)
    health = present.source_health(s)
    return {
        "c": c,
        "copies": max(c.documents - c.logic, 0),
        "techniques": present.technique_count(s),
        "strip": tactic_strip(c),
        "health": present.health_counts(health),
        "top_sources": top_sources(s),
        "n_sources": len(health),
        "licences": present.licence_counts(s),
        "starts": starting_points(s),
        "recent": recent_changes(web, s),
        "ages": present.rule_ages(s),
        "trend": present.corpus_trend(s),
        "levels": present.composition(c.levels, ("critical", "high", "medium", "low", "informational"), lambda k: "/search?" + urlencode({"level": k}), "seg-"),
    }


@router.get("/", response_class=HTMLResponse)
def home(request: Request, web: WebDep) -> Response:
    if request.query_params.get("q") is not None:
        return RedirectResponse("/search?" + str(request.query_params), status_code=307)
    with web.read_session() as s:
        data = queries.cached(web.cache, "overview", s, lambda session: overview_data(web, session), size=1)
    return web.render(request, "overview.html", data)


@router.get("/overview")
def overview() -> Response:
    """Old address of the overview."""
    return RedirectResponse("/", status_code=301)
