"""ATT&CK coverage: rule families per technique (from declared rule tags), as a matrix and as a Navigator layer."""

from __future__ import annotations

from dataclasses import astuple
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from sigharvest.web import present, queries
from sigharvest.web.deps import SEARCH_KEYS, Params, Web, WebDep, filters_for

router = APIRouter()
FILTER_KEYS = tuple(key for key in SEARCH_KEYS if key != "q")
PRODUCTS = ["windows", "linux", "macos", "aws", "azure", "gcp", "m365", "okta", "github", "kubernetes"]


def source_names(web: Web) -> list[str]:
    from sqlalchemy import select

    from sigharvest.models import Source

    with web.read_session() as s:
        return sorted(s.scalars(select(Source.name)))


def coverage_for(web: Web, params: Params) -> Any:
    """Counts for the complete selection; the unfiltered matrix is read from the index publication when current.

    Never downloads: the ATT&CK catalog is fetched by `sigharvest coverage` (or `sigharvest update`)."""
    from sigharvest.attack import compute, coverage_key, stored_coverage
    from sigharvest.index import GroupFilters

    with web.read_session() as s0:
        filters = filters_for(s0, params)

    def calculate(s: Any) -> Any:
        if filters == GroupFilters():
            stored = stored_coverage(web.ws, s)
            if stored is not None:
                return stored
        return compute(web.ws, s, filters, acquire=False)

    with web.read_session() as s:
        return queries.cached(web.cache, "coverage", s, calculate, key=(astuple(filters), coverage_key(web.ws)))


@router.get("/coverage", response_class=HTMLResponse)
async def coverage_page(request: Request, web: WebDep) -> HTMLResponse:
    from sigharvest.attack import ATTRIBUTION, AttackCacheError, coverage_tag_sets

    params = Params(request.query_params)
    try:
        cov = await run_in_threadpool(coverage_for, web, params)
    except AttackCacheError as exc:
        return web.render(request, "coverage.html", {"missing": str(exc), "params": params})
    m = cov.matrix
    peak = max(cov.tagged_rules.values(), default=1)
    scope = {k: params[k] for k in FILTER_KEYS if params.get(k)}

    def link(**extra: str) -> str:
        return "/search?" + urlencode({**scope, **extra})

    columns = []
    tag_sets = coverage_tag_sets(m)
    for short, name, ta in m.tactics:
        techs = sorted((t for t in m.techniques.values() if short in t.tactics), key=lambda t: t.id)
        cells = []
        for t in techs:
            # Include revoked tag aliases and sub-techniques in the exact tag union.
            cells.append(
                {
                    "id": t.id,
                    "name": t.name,
                    "n": cov.tagged_rules.get(t.id, 0),
                    "families": cov.families.get(t.id, 0),
                    "heat": present.heat(cov.tagged_rules.get(t.id, 0), peak),
                    "tag_url": link(coverage_tags=",".join(tag_sets[t.id])),
                    "parent": t.parent,
                    "subs": [],
                }
            )
        # Collapse sub-techniques under their parent when the parent is in the same tactic.
        by_id = {c["id"]: c for c in cells}
        top = []
        for c in cells:
            if c["parent"] and c["parent"] in by_id:
                by_id[c["parent"]]["subs"].append(c)
            else:
                top.append(c)
        columns.append({"short": short, "name": name, "id": ta, "cells": top})
    stats = {
        "tagged": cov.rules_with_tags,
        "rules": cov.rules_total,
        "covered": cov.covered(),
        "techniques": len(m.techniques),
        "version": m.version,
        "rules_url": link(),
    }
    return web.render(
        request,
        "coverage.html",
        {
            "missing": "",
            "columns": columns,
            "stats": stats,
            "params": params,
            "scope": scope,
            "attribution": ATTRIBUTION,
            "products": PRODUCTS,
            "licence_classes": ("permissive", "copyleft", "restricted", "none"),
            "sources": source_names(web),
            "normalisation": [entry for entry in cov.normalisation.values() if entry["status"] != "current"],
            "unknown": list(cov.unknown.items())[:50],
        },
    )


@router.get("/coverage/navigator.json")
async def coverage_navigator(request: Request, web: WebDep) -> JSONResponse:
    """ATT&CK Navigator layer for the selection (same filters as /coverage); score = rule families per technique."""
    from sigharvest.attack import navigator_layer

    cov = await run_in_threadpool(coverage_for, web, Params(request.query_params))
    return JSONResponse(navigator_layer(cov), headers={"Content-Disposition": 'attachment; filename="sigharvest-coverage-layer.json"'})
