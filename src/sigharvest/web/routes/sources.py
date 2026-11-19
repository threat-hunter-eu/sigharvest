"""Sources: repository contribution, licence, sync state and directional overlap (precomputed at index time)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from sigharvest.index import GroupFilters, search_groups
from sigharvest.models import LogicGroup, Source, SourceOverlap, SourceSummary
from sigharvest.sources import public_url
from sigharvest.web import queries
from sigharvest.web.deps import Web, WebDep

router = APIRouter()
PAGE = 20  # unique rules per page on a source page
SORT_KEYS = {"only": "only", "docs": "docs", "logic": "logic", "valid": "valid_pct", "score": "avg_score", "name": "name"}
HEALTH_STATES = ("synced", "stale", "failing")
STATUSES = ("active", "added, waiting for the next update", "not synced", "no Sigma rules", "disabled", "removed from config")


def top_overlaps(s: Session) -> dict[str, list[dict[str, Any]]]:
    """Read the top five peers for every repository in one bounded result set."""
    rows = s.execute(
        text("""
        SELECT ranked.name, ranked.other, ranked.exact, ranked.near, summary.logic
        FROM (
            SELECT name, other, exact, near,
                   row_number() OVER (PARTITION BY name ORDER BY exact DESC, near DESC, other) AS rank
            FROM source_overlaps
        ) ranked JOIN source_summaries summary ON summary.name = ranked.name
        WHERE ranked.rank <= 5 ORDER BY ranked.name, ranked.rank
    """)
    )
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for name, other, exact, near, logic in rows:
        out[name].append({"name": other, "exact": exact, "near": near, "pct": round(100 * exact / logic, 1) if logic else 0})
    return dict(out)


def source_inputs(s: Session) -> dict[str, Any]:
    """Every source row the Sources page shows (JSON-ready except `last_sync`); published with the index."""
    from sigharvest.source_status import configured, documents, pending, status

    config = configured(s)
    quality = queries.source_quality(s)
    needs_index = not quality and s.scalar(select(LogicGroup.id).limit(1)) is not None
    docs_of = documents(s)
    overlaps = top_overlaps(s)
    rows = []
    for name, url, licence, priority, enabled, last_sync, commit in s.execute(
        select(Source.name, Source.url, Source.licence, Source.priority, Source.enabled, Source.last_sync_at, Source.last_commit)
    ):
        q = quality.get(name, {})
        rows.append(
            {
                "name": name,
                "url": public_url(url),
                "licence": licence,
                "priority": priority,
                "enabled": enabled,
                "status": status(name, enabled, docs_of.get(name, 0), last_sync, config),
                "last_sync": last_sync,
                "commit": commit,
                "docs": docs_of.get(name, 0),
                **{k: q.get(k, 0) for k in ("logic", "families", "only", "avg_score")},
                "valid_pct": q.get("valid_pct"),
                "overlaps": overlaps.get(name, []),
            }
        )
    return {"rows": rows + pending(s), "needs_index": needs_index}


def render_sources(
    templates: Jinja2Templates,
    inputs: dict[str, Any],
    sort: str,
    *,
    name: str = "",
    state: str = "",
    health: dict[str, dict[str, Any]] | None = None,
    health_state: str = "",
) -> str:
    from sigharvest.web import present

    rows = [r | {"lic": present.licence_info(r.get("licence")), "health": (health or {}).get(r["name"])} for r in inputs["rows"]]
    sort = sort if sort in SORT_KEYS else "only"
    k = SORT_KEYS[sort]
    rows.sort(key=lambda r: (r[k] is None, r[k] if k == "name" else -(r[k] or 0)))
    configured_count = sum(r["status"] != "removed from config" for r in rows)
    counts = present.health_counts({r["name"]: r["health"] for r in rows if r["health"]}) if health else None
    rows = [row for row in rows if name.casefold() in row["name"].casefold() and (not state or row["status"] == state)]
    if health_state:
        rows = [row for row in rows if row["health"] and row["health"]["state"] == health_state]
    peak = max((r["logic"] or 0 for r in rows), default=0)
    for r in rows:
        r["w"] = present.width(r["logic"] or 0, peak)
    return templates.get_template("sources_content.html").render(
        rows=rows,
        health_counts=counts,
        sort=sort,
        needs_index=inputs["needs_index"],
        configured_count=configured_count,
        filters={"name": name, "status": state, "health": health_state},
        statuses=STATUSES,
    )


def stored_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    """Undo the JSON date encoding of published inputs; every other field is JSON-native."""
    rows = [r | {"last_sync": datetime.fromisoformat(r["last_sync"]) if r.get("last_sync") else None} for r in inputs["rows"]]
    return {**inputs, "rows": rows}


def source_content(web: Web, s: Session, sort: str, *, name: str = "", state: str = "", health_state: str = "") -> str:
    """The table, from the inputs published with the index (or computed live), with the current sync health."""
    from sigharvest.page_summaries import read
    from sigharvest.web import present

    inputs = read(s, "source_inputs")
    rows = stored_inputs(inputs) if inputs is not None else source_inputs(s)
    return render_sources(web.templates, rows, sort, name=name, state=state, health=present.source_health(s), health_state=health_state)


@router.get("/sources", response_class=HTMLResponse)
def sources_page(
    request: Request,
    web: WebDep,
    sort: str = Query("only"),
    name: str = Query("", max_length=200),
    status: str = Query(""),
    health: str = Query(""),
) -> HTMLResponse:
    sort = sort if sort in SORT_KEYS else "only"
    if status and status not in STATUSES:
        raise HTTPException(400, "Unknown source status")
    if health and health not in HEALTH_STATES:
        raise HTTPException(400, "Unknown source health")
    with web.read_session() as s:
        content = queries.cached(
            web.cache,
            "sources_html",
            s,
            lambda s: source_content(web, s, sort, name=name, state=status, health_state=health),
            key=(sort, name, status, health),
            size=12,
        )
    return web.render(request, "sources.html", {"content": Markup(content)})  # noqa: S704 - autoescaped read-only fragment


@router.get("/api/sources")
def api_sources(web: WebDep) -> list[dict[str, Any]]:
    """Every configured source with its contribution counts and top overlaps."""
    with web.read_session() as s:
        rows = source_inputs(s)["rows"]
    return [r | {"last_sync": r["last_sync"].isoformat() if isinstance(r["last_sync"], datetime) else r["last_sync"]} for r in rows]


@router.get("/sources/{name:path}", response_class=HTMLResponse)
def source_page(request: Request, web: WebDep, name: str, page: int = Query(1, ge=1, le=100000)) -> HTMLResponse:
    from sigharvest.source_status import configured, documents, pending, status

    with web.read_session() as s:
        source = s.scalar(select(Source).where(Source.name == name))
        if source is None:
            registration = next((row for row in pending(s) if row["name"] == name), None)
            if registration is None:
                raise HTTPException(404, "repository not found")
            from sigharvest.web import present

            context = {"source": registration, "source_status": registration["status"], "pending": True, "summary": None}
            extra: dict[str, Any] = {"licinfo": present.licence_info(registration.get("licence")), "health": None, "rows": [], "link": ""}
            return web.render(request, "source.html", context | extra | {"overlaps": [], "groups": [], "total": 0, "page": page, "pages": 1})
        source_status = status(source.name, source.enabled, documents(s).get(source.name, 0), source.last_sync_at, configured(s))
        summary = s.get(SourceSummary, name)
        overlaps = list(
            s.scalars(
                select(SourceOverlap).where(SourceOverlap.name == name).order_by(SourceOverlap.exact.desc(), SourceOverlap.near.desc(), SourceOverlap.other)
            )
        )
        groups, total = search_groups(
            s,
            None,
            GroupFilters(source=name, source_only=True, include_deprecated=True, include_junk=True),
            limit=PAGE,
            offset=(page - 1) * PAGE,
            sort="title",
        )
        from sigharvest.web import present
        from sigharvest.web.routes.search import cards

        rows = cards(s, groups)
        health = present.source_health(s).get(source.name)
    return web.render(
        request,
        "source.html",
        {
            "source": source,
            "source_status": source_status,
            "pending": False,
            "summary": summary,
            "overlaps": overlaps,
            "groups": groups,
            "total": total,
            "page": page,
            "pages": max(1, (total + PAGE - 1) // PAGE),
            "rows": rows,
            "health": health,
            "licinfo": present.licence_info(source.licence),
            "link": public_url(source.url).removesuffix(".git") if source.url.startswith("https://") else "",
        },
    )
