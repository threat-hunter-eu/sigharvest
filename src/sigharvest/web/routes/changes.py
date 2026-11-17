"""Changes: what an update added, changed upstream or removed, read from the run reports `sigharvest update` writes
(reports/runs/<stamp>.json). Read-only: updating is a terminal command (`sigharvest update`)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select

from sigharvest.changes import from_report
from sigharvest.models import LogicGroup
from sigharvest.web import present
from sigharvest.web.deps import WebDep

router = APIRouter()
PAGE = 20  # rules per page (changed rules carry a diff)
KINDS = ("new", "changed", "removed")


@router.get("/changes", response_class=HTMLResponse)
def changes_page(
    request: Request, web: WebDep, run: int | None = Query(None, ge=1), kind: str = Query("new"), page: int = Query(1, ge=1, le=100000)
) -> HTMLResponse:
    from sigharvest.web.routes.search import cards

    kind = kind if kind in KINDS else "new"
    with web.read_session() as s:
        runs = present.runs(s)
        chosen = next((r for r in runs if r.id == run), runs[0] if runs else None)
        report = present.run_report(web.ws.root, chosen)
        counts = present.change_summary(report)
        incomplete = from_report(report).get("incomplete") or [] if report else []
        items = list((report or {}).get(kind) or [])
        total = len(items)
        visible = items[(page - 1) * PAGE : page * PAGE]
        rows: list[dict[str, Any]] = []
        if kind in ("new", "changed"):
            key = "logic" if kind == "new" else "new"
            hashes = [str(x.get(key) or "") for x in visible]
            groups = {g.logic_hash: g for g in s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.in_(hashes)))}
            by_hash = {c["logic_hash"]: c for c in cards(s, [groups[h] for h in hashes if h in groups])}
            for x in visible:
                h = str(x.get(key) or "")
                rows.append(
                    {
                        "card": by_hash.get(h),
                        "title": x.get("title") or "(untitled)",
                        "diff": [str(d) for d in (x.get("diff") or [])][:16],
                        "sources": x.get("sources") or [],
                    }
                )
        else:
            rows = [{"card": None, "title": x.get("title") or "(untitled)", "diff": [], "sources": []} for x in visible]
        per_source = sorted(((name, v) for name, v in ((report or {}).get("sources") or {}).items() if isinstance(v, dict)), key=lambda kv: kv[0])
    return web.render(
        request,
        "changes.html",
        {
            "runs": runs,
            "chosen": chosen,
            "report": report,
            "first": report is not None and not report.get("previous_run"),
            "counts": counts,
            "kind": kind,
            "rows": rows,
            "total": total,
            "page": page,
            "pages": max(1, (total + PAGE - 1) // PAGE),
            "per_source": per_source,
            "incomplete": incomplete,
        },
    )


@router.get("/new")
def old_new(request: Request) -> Response:
    """Old address of the changes page."""
    query = str(request.query_params)
    return RedirectResponse("/changes" + (f"?{query}" if query else ""), status_code=301)
