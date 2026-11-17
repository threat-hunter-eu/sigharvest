"""Collections: saved sets of rules, built from searches or rule pages, and exported as a unit."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from sigharvest import collections as col
from sigharvest.index import search_groups
from sigharvest.models import LogicGroup
from sigharvest.web.deps import PAGE, Params, SameOrigin, Web, WebDep, back, col_url, filters_from, groups_for_keys, local_path, with_params

router = APIRouter()


def _col_or_404(s: Session, name: str) -> Any:
    c = col.get(s, name)
    if c is None:
        raise HTTPException(404, "collection not found")
    return c


@contextmanager
def writer(web: Web) -> Iterator[Session]:
    """A writable session holding the workspace lease (an update or index rebuild is not running)."""
    from sigharvest.lock import mutation_lease

    with mutation_lease(web.ws), web.Session_() as s:
        yield s


@router.get("/collections", response_class=HTMLResponse)
def collections_page(request: Request, web: WebDep) -> Response:
    with web.read_session() as s:
        rows = col.summaries(s)
    return web.render(request, "collections.html", {"rows": rows, "params": Params(request.query_params)})


@router.post("/collections", dependencies=[SameOrigin])
def collections_create(web: WebDep, name: str = Form(..., max_length=80), description: str = Form("", max_length=500)) -> RedirectResponse:
    with writer(web) as s:
        try:
            c = col.create(s, name, description)
        except col.CollectionError as exc:
            return back("/collections", error=str(exc))
        s.commit()
        return back(col_url(c.name))


@router.get("/collections/{name}", response_class=HTMLResponse)
def collection_page(request: Request, web: WebDep, name: str, page: int = Query(1, ge=1, le=100000)) -> HTMLResponse:
    with web.read_session() as s:
        c = _col_or_404(s, name)
        rows = col.resolve(s, c)
        counts = {state: sum(1 for r in rows if r.state == state) for state in ("current", "updated", "missing")}
        total = len(rows)
        visible = rows[(page - 1) * PAGE : page * PAGE]
        return web.render(
            request,
            "collection.html",
            {
                "c": c,
                "rows": visible,
                "counts": counts,
                "total": total,
                "page": page,
                "pages": max(1, (total + PAGE - 1) // PAGE),
                "params": Params(request.query_params),
                "formats": ("zip", "jsonl", "csv"),
            },
        )


@router.post("/collections/add", dependencies=[SameOrigin])
async def collection_add(request: Request, web: WebDep) -> RedirectResponse:
    """Add rules by logic hash (`keys`) or every result of a search (the search parameters), up to `max_rules`.
    Creates the collection when it does not exist."""
    form = Params(await request.form())
    name = str(form.get("name") or "")
    keys = str(form.get("keys") or "")
    back_to = local_path(str(form.get("back") or ""))
    max_rules = int(form["max_rules"]) if str(form.get("max_rules") or "").isdigit() else 1000
    with writer(web) as s:
        found: list[LogicGroup] = groups_for_keys(s, keys)
        if not keys.strip():
            limit = min(max(max_rules, 1), web.limits.collection_add)
            q = str(form.get("q") or "").strip() or None
            found += search_groups(s, q, filters_from(form), limit=limit, sort="score", per_family=form.get("view") != "logic")[0]
        try:
            c = col.ensure(s, name)
        except col.CollectionError as exc:
            return back(back_to or "/collections", error=str(exc))
        n = col.add(s, c, found)
        s.commit()
        target = back_to or col_url(c.name)
        return RedirectResponse(with_params(target, added=n, to=c.name, already=len({g.logic_hash for g in found}) - n), status_code=303)


@router.post("/collections/{name}/remove", dependencies=[SameOrigin])
def collection_remove(web: WebDep, name: str, key: str = Form(..., max_length=64)) -> RedirectResponse:
    if not re.fullmatch(r"[0-9a-f]{6,64}", key):
        raise HTTPException(400, "bad key")
    with writer(web) as s:
        c = _col_or_404(s, name)
        n = col.remove(s, c, [key])
        s.commit()
        return back(col_url(c.name), removed=str(n))


@router.post("/collections/{name}/update", dependencies=[SameOrigin])
def collection_update(web: WebDep, name: str) -> RedirectResponse:
    """Point items whose rule changed upstream at the rule's current logic."""
    with writer(web) as s:
        c = _col_or_404(s, name)
        n = col.follow_updates(s, c)
        s.commit()
        return back(col_url(c.name), moved=str(n))


@router.post("/collections/{name}/edit", dependencies=[SameOrigin])
def collection_edit(web: WebDep, name: str, new_name: str = Form(..., max_length=80), description: str = Form("", max_length=500)) -> RedirectResponse:
    with writer(web) as s:
        c = _col_or_404(s, name)
        try:
            col.rename(s, c.name, new_name)
        except col.CollectionError as exc:
            return back(col_url(c.name), error=str(exc))
        c.description = description.strip() or None
        s.commit()
        return back(col_url(c.name))


@router.post("/collections/{name}/delete", dependencies=[SameOrigin])
def collection_delete(web: WebDep, name: str) -> RedirectResponse:
    with writer(web) as s:
        c = _col_or_404(s, name)
        col.remove_collection(s, c.name)
        s.commit()
    return back("/collections")


@router.get("/collections/{name}/export", dependencies=[SameOrigin])
def collection_export(web: WebDep, name: str, format: str = Query("zip", max_length=40)) -> Response:
    """zip: YAML tree + manifest.jsonl; jsonl: one object per rule; csv; or a backend name: converted queries.
    Same-origin only and through the bounded download queue, like every other download."""
    from sigharvest.web.downloads import download
    from sigharvest.web.routes.export import held_download

    def build() -> Response:
        with web.read_session() as s:
            c = _col_or_404(s, name)
            return download(s, col.groups(s, c), format, c.name)

    return held_download(build)


@router.get("/api/collections")
def api_collections(web: WebDep) -> list[dict[str, Any]]:
    """Every collection with its number of rules."""
    with web.read_session() as s:
        return [{"name": c.name, "description": c.description, "rules": n, "created_at": c.created_at.isoformat()} for c, n in col.summaries(s)]


@router.get("/api/collections/{name}")
def api_collection(web: WebDep, name: str) -> dict[str, Any]:
    """The rules of one collection and how each resolves now (current, updated upstream or missing)."""
    with web.read_session() as s:
        c = _col_or_404(s, name)
        items = [
            {
                "logic_hash": r.group.logic_hash if r.group is not None else r.item.logic_hash,
                "stored_logic_hash": r.item.logic_hash,
                "rule_id": r.item.rule_id,
                "title": r.group.title if r.group is not None else r.item.title,
                "state": r.state,
                "note": r.item.note,
            }
            for r in col.resolve(s, c)
        ]
    return {"name": c.name, "description": c.description, "rules": items}
