"""Old addresses of pages that were merged or renamed in the public edition: each redirects to its new home, so
bookmarks keep working. The private features they belonged to are not part of sigharvest."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import RedirectResponse, Response

router = APIRouter()

MOVED = {
    "/hunt": "/search",
    "/library": "/search",
    "/find": "/search",
    "/triage": "/search",
    "/workbench": "/search",
    "/playbooks": "/export",
    "/quality": "/search?validation=error",
    "/more": "/about",
    "/coverage/threats": "/coverage",
    "/coverage/cves": "/coverage",
    "/actor-matrix": "/coverage",
    "/updates": "/changes",
    "/runs": "/changes",
}


def _redirect(target: str) -> Response:
    return RedirectResponse(target, status_code=301)


for _old, _new in MOVED.items():
    router.add_api_route(_old, (lambda new=_new: _redirect(new)), methods=["GET"], include_in_schema=False)
