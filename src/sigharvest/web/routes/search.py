"""Find rules: full-text search with facets, cards or table, selection for export, and the JSON search API.

The page always lists one row per detection logic (duplicates are already merged); the family size is on the card.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from sigharvest.errors import SigharvestError
from sigharvest.index import GroupFilters, match_counts, search_groups
from sigharvest.licensing import shipped_licence
from sigharvest.models import LogicGroup, RuleVersion
from sigharvest.query_limits import check_query
from sigharvest.search_options import SORTS
from sigharvest.title_relevance import default_sort
from sigharvest.web import present, queries
from sigharvest.web.deps import PER_PAGE_CHOICES, Params, SameOrigin, Web, WebDep, chips, filters_for, per_page, search_params

router = APIRouter()
FACETS = ("level", "status", "validation", "product", "category", "service", "datasource", "tactic", "technique", "source")
LEVELS = ("critical", "high", "medium", "low", "informational")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
VALIDATION = (("ok", "valid"), ("warning", "warnings"), ("error", "invalid"))
SORT_LABELS = (
    ("relevance", "Best match"), ("sources", "Most sources"), ("level", "Level"), ("modified", "Recently changed"), ("title", "Title A-Z"),
    ("score", "Quality score"),
)  # fmt: skip
EXAMPLES = ("certutil OR bitsadmin", "T1003.001", '"net user" -powershell', "level:high category:ps_script", 'author:"Nasreddine"')
TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development", "initial-access": "Initial Access",
    "execution": "Execution", "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion", "stealth": "Stealth", "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access", "discovery": "Discovery", "lateral-movement": "Lateral Movement",
    "collection": "Collection", "command-and-control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact",
}  # fmt: skip


def _sort(params: Params, q: str) -> str:
    sort = str(params.get("sort") or "")
    return sort if sort in SORTS else default_sort(q)


def per_family(params: Params) -> bool:
    """The API keeps view=family; the pages always show every logic."""
    return params.get("view") == "family"


def run_search(s: Session, params: Params, limit: int, offset: int, *, family: bool | None = None) -> tuple[list[LogicGroup], int]:
    q = str(params.get("q") or "").strip()
    check_query(q)
    return search_groups(
        s,
        q or None,
        filters_for(s, params),
        limit=limit,
        offset=offset,
        sort=_sort(params, q),
        per_family=per_family(params) if family is None else family,
    )


def count_for(s: Session, params: dict[str, str]) -> int:
    """Rules matching a search (used for counts next to links)."""
    try:
        return run_search(s, Params(params), 0, 0, family=False)[1]
    except SigharvestError:
        return 0


class Row(dict[str, Any]):
    """A card's fields, readable as keys or attributes (conversion.statuses_of reads attributes)."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def cards(s: Session, groups: list[LogicGroup]) -> list[Row]:
    """What a result card or table row shows, for a page of groups (two batched reads: licences, rule licences)."""
    from sigharvest.attack import session_matrix, tag_metadata

    if not groups:
        return []
    lic = present.source_licences(s)
    own = dict(s.execute(select(RuleVersion.id, RuleVersion.rule_license).where(RuleVersion.id.in_([g.canonical_version_id for g in groups]))).all())
    matrix = session_matrix(s)
    cache: dict[str, Any] = {}
    out = []
    for g in groups:
        techniques: list[tuple[str, str]] = []
        for item in tag_metadata([t for t in g.tags or [] if str(t).lower().startswith("attack.t")], matrix, cache):
            tid = item.get("original_id") or ""
            if tid and tid.upper() not in (x[0] for x in techniques):
                tech = matrix.techniques.get(str(item.get("current_id") or "")) if matrix is not None else None
                techniques.append((tid.upper(), tech.name if tech is not None else ""))
        licence = shipped_licence(own.get(g.canonical_version_id), lic.get(g.canonical_source))
        out.append(
            Row(
                {
                    "logic_hash": g.logic_hash,
                    "rule_id": g.rule_id,
                    "title": g.title,
                    "description": g.description,
                    "level": g.level,
                    "status": g.status,
                    "product": g.product,
                    "category": g.category,
                    "service": g.service,
                    "copies": g.copies,
                    "n_sources": g.n_sources,
                    "pips": present.pips(g.n_sources),
                    "family_size": g.family_size,
                    "validation": g.validation,
                    "canonical_source": g.canonical_source,
                    "author": g.author,
                    "modified": g.modified,
                    "techniques": techniques,
                    "licence": present.licence_info(licence),
                    "conversion": g.conversion,
                    "converts": g.converts,
                }
            )
        )
    return out


def cached_search(web: Web, s: Session, params: Params, size: int, page: int) -> dict[str, Any]:
    def compute(session: Session) -> dict[str, Any]:
        groups, total = run_search(session, params, size, (page - 1) * size)
        return {"rows": cards(session, groups), "total": total}

    key = (tuple(sorted(search_params(params).items())), params.get("view", ""), params.get("sort", ""), size, page)
    return queries.cached(web.cache, "search", s, compute, key=key, size=32)


def copies_total(s: Session, params: Params) -> int:
    """Rule files behind the matching rules (sum of copies)."""
    from sigharvest.index import _base

    q = str(params.get("q") or "").strip() or None
    base, _rel, bind = _base(q, filters_for(s, params), session=s)
    return int(s.execute(text(f"SELECT total(g.copies) {base}"), bind).scalar_one() or 0)


def logsource_facet(s: Session, params: Params) -> list[dict[str, Any]]:
    """(product, category, service) value counts for the search without its own log source filters."""
    from sigharvest.index import _base

    q = str(params.get("q") or "").strip() or None
    f = replace(filters_for(s, params), product=None, category=None, service=None)
    base, _rel, bind = _base(q, f, session=s)
    rows = s.execute(text(f"SELECT g.product, g.category, g.service, count(*) AS n {base} GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 400"), bind)
    out = []
    for product, category, service, n in rows:
        label = " / ".join(x for x in (product, category, service) if x) or "no log source"
        values = {"product": product or "", "category": category or "", "service": service or ""}
        active = all(str(params.get(k) or "") == v for k, v in values.items()) and any(values.values())
        out.append({"label": label, "n": int(n), "values": values, "active": active})
    return out


def licence_facet(s: Session, params: Params) -> list[tuple[str, int]]:
    """Rules with a copy in a source of each licence class (the search without its own licence filter)."""
    from sigharvest.index import _base

    q = str(params.get("q") or "").strip() or None
    rest = Params({k: v for k, v in params.items() if k != "licence"})
    base, _rel, bind = _base(q, filters_for(s, rest), session=s)
    lic = {name: present.licence_info(value)["cls"] for name, value in present.source_licences(s).items()}
    counts: dict[str, int] = {}
    for (sources,) in s.execute(text(f"SELECT g.sources {base}"), bind):
        names = json.loads(sources) if isinstance(sources, str) else sources or []
        for cls in {lic.get(n, "none") for n in names}:
            counts[cls] = counts.get(cls, 0) + 1
    order = ["permissive", "copyleft", "restricted", "none"]
    return [(c, counts.get(c, 0)) for c in order if c in counts or c in ("permissive", "copyleft")]


def cached_facets(web: Web, s: Session, params: Params) -> dict[str, Any]:
    from sigharvest.search_summary import counts

    def compute(session: Session) -> dict[str, Any]:
        q = str(params.get("q") or "").strip() or None
        out: dict[str, Any] = dict(counts(session, q, filters_for(session, params), False))
        out["logsource"] = logsource_facet(session, params)
        out["licence"] = licence_facet(session, params)
        out["documents"] = copies_total(session, params)
        return out

    key = (tuple(sorted(search_params(params).items())),)
    return queries.cached(web.cache, "facets", s, compute, key=key, size=32)


def facet_values(facets: dict[str, Any], params: Params) -> dict[str, Any]:
    """Facet rows for the template: (value, label, count, active), with the fixed-vocabulary facets in their order."""
    out: dict[str, Any] = {}
    by = {name: dict(facets.get(name, [])) for name in ("level", "status", "validation", "tactic", "source")}
    out["level"] = [(v, v, by["level"].get(v, 0)) for v in LEVELS]
    out["status"] = [(v, v, by["status"].get(v, 0)) for v in STATUSES if by["status"].get(v) or v in ("stable", "test", "experimental")]
    out["validation"] = [(v, label, by["validation"].get(v, 0)) for v, label in VALIDATION]
    out["tactic"] = sorted(((v, TACTIC_NAMES[v], n) for v, n in by["tactic"].items() if v in TACTIC_NAMES), key=lambda x: -x[2])
    out["source"] = sorted(((v, v, n) for v, n in by["source"].items()), key=lambda x: (-x[2], x[0]))
    out["licence"] = [(v, v, n) for v, n in facets.get("licence", [])]
    out["logsource"] = facets.get("logsource", [])
    return out


def search_page(request: Request, web: WebDep) -> HTMLResponse:
    params = Params(request.query_params)
    # view=table|cards picks the page layout (the shared name, docs/conventions.md); layout=table is the old alias.
    # The API's view=logic|family does not apply here: the pages always show every logic.
    table = params.get("view") == "table" or params.get("layout") == "table"
    for key in ("view", "layout", "added", "to", "already", "error"):
        params.pop(key, None)
    q = str(params.get("q") or "").strip()
    page = max(int(params["page"]), 1) if str(params.get("page", "")).isdigit() and len(str(params["page"])) < 7 else 1
    size = per_page(params)
    status_code = 200
    hints: list[str] = []
    error = ""
    with web.read_session() as s:
        try:
            found = cached_search(web, s, params, size, page)
            facets = cached_facets(web, s, params)
            if q:
                from sigharvest.attack_search import search_hints

                hints = search_hints(s, q)
            text_only = 0
            if not found["total"] and q and any(k != "q" for k in search_params(params)):
                text_only = count_for(s, {"q": q})
        except SigharvestError as exc:
            error = str(exc)
            status_code = 400
            found, facets, text_only = {"rows": [], "total": 0}, {}, 0
    total = found["total"]
    base = (
        {k: v for k, v in search_params(params).items()}
        | {k: str(params[k]) for k in ("sort", "per_page") if params.get(k)}
        | ({"view": "table"} if table else {})
    )

    def href(**changes: Any) -> str:
        merged = {**base, **{k: v for k, v in changes.items()}}
        return "/search?" + urlencode({k: v for k, v in merged.items() if v not in (None, "")})

    active_chips = ([{"key": "q", "label": "text", "value": q, "href": href(q="", page="")}] if q else []) + chips(params)
    documents = int(facets.get("documents") or 0) if facets else 0
    families = 0
    if total and not error:
        with web.read_session() as counting:
            # The CLI lists one row per family by default and the pages one per rule: show both numbers.
            families = match_counts(counting, q or None, filters_for(counting, params))[1]
    return web.render(
        request,
        "search.html",
        {
            "rows": found["rows"],
            "total": total,
            "documents": documents,
            "families": families,
            "q": q,
            "terms": present.query_terms(q),
            "effective_sort": _sort(params, q),
            "sort_labels": SORT_LABELS,
            "params": params,
            "base": base,
            "href": href,
            "page": page,
            "pages": max((total + size - 1) // size, 1),
            "per_page": size,
            "per_page_choices": PER_PAGE_CHOICES,
            "view": "table" if table else "cards",
            "facets": facet_values(facets, params) if facets else {},
            "chips": active_chips,
            "hints": hints,
            "error": error,
            "text_only": text_only,
            "examples": EXAMPLES,
            "export_qs": urlencode(search_params(params)),
        },
        status_code=status_code,
    )


@router.get("/search", response_class=HTMLResponse)
def search(request: Request, web: WebDep) -> HTMLResponse:
    with web.search_slot():
        return search_page(request, web)


@router.get("/search/export", dependencies=[SameOrigin])
def search_export(request: Request, web: WebDep, format: str = Query("zip", max_length=40)) -> Response:
    """Download every rule of a search (kept for scripts; the Export page uses /export/download)."""
    from sigharvest.web.routes.export import download_response

    return download_response(web, Params(request.query_params), format, scope="search")


@router.get("/api/search", dependencies=[SameOrigin])
def api_search(request: Request, web: WebDep, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000)) -> JSONResponse:
    """Search with the same parameters as /search (q, view=logic|family, sort and every filter)."""
    params = Params(request.query_params)
    family = params.get("view") == "family"
    with web.search_slot(), web.read_session() as s:
        try:
            groups, total = run_search(s, params, limit, offset, family=family)
            q = str(params.get("q") or "").strip()
            rules, families = match_counts(s, q or None, filters_for(s, params))
        except SigharvestError as exc:
            raise HTTPException(400, str(exc)) from exc
    # `total` counts what `results` pages through (rules, or families with view=family), like `sigharvest search
    # --json`; total_rules and total_families are both always given.
    return JSONResponse(
        {
            "view": "family" if family else "logic",
            "total": total,
            "total_rules": rules,
            "total_families": families,
            "offset": offset,
            "limit": limit,
            "results": [api_record(g) for g in groups],
        }
    )


@router.get("/api/facets", dependencies=[SameOrigin])
def api_facets(request: Request, web: WebDep) -> JSONResponse:
    """Facet counts (value, count) for a search, with the same parameters as /api/search."""
    from sigharvest.search_summary import counts

    params = Params(request.query_params)
    with web.search_slot(), web.read_session() as s:
        try:
            check_query(str(params.get("q") or ""))
            q = str(params.get("q") or "").strip() or None
            facets = counts(s, q, filters_for(s, params), per_family(params))
        except SigharvestError as exc:
            raise HTTPException(400, str(exc)) from exc
    return JSONResponse({name: [list(row) for row in rows] for name, rows in facets.items()})


def api_record(g: Any) -> dict[str, Any]:
    return {
        "logic_hash": g.logic_hash,
        "rule_id": g.rule_id,
        "title": g.title,
        "level": g.level,
        "status": g.status,
        "logsource": {"product": g.product, "category": g.category, "service": g.service},
        "tags": g.tags,
        "copies": g.copies,
        "sources": g.sources,
        "n_sources": g.n_sources,
        "family_id": g.family_id,
        "family_size": g.family_size,
        "validation": g.validation,
        "converts": g.converts,
        "conversion": g.conversion or {},
        "quality_flags": g.quality_flags,
        "score": g.score,
    }


__all__ = ["GroupFilters", "api_record", "cards", "count_for", "run_search", "search_page"]
