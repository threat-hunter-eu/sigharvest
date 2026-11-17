"""Family page: every variant of a rule family (same rule identity or equivalent detection, same log source route)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select

from sigharvest.models import LogicGroup
from sigharvest.web.deps import WebDep, group_or_404

router = APIRouter()
MAX_FAMILY = 2000


@router.get("/family/{logic}", response_class=HTMLResponse)
def family_page(request: Request, web: WebDep, logic: str) -> HTMLResponse:
    """`logic` is the logic hash (or a 6+ character prefix) of any member."""
    with web.read_session() as s:
        anchor = group_or_404(s, logic)
        members = list(
            s.scalars(
                select(LogicGroup)
                .where(LogicGroup.family_id == anchor.family_id)
                .order_by(LogicGroup.score.desc(), LogicGroup.logic_hash)
                .limit(MAX_FAMILY + 1)
            )
        )
    return web.render(request, "family.html", {"anchor": anchor, "members": members[:MAX_FAMILY], "truncated": len(members) > MAX_FAMILY})


@router.get("/family/{logic}/variants")
def family_variants(logic: str) -> Response:
    """Old address of the family page."""
    return RedirectResponse(f"/family/{logic}", status_code=301)
