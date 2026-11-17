"""Phone layout: no page of the web UI scrolls sideways at 390 px (light and dark), and none logs a JS error.

Runs in a real browser (Playwright Chromium); skipped when Playwright or its browser is not installed. CI runs it in
the `layout` job (uv sync --group browser; playwright install chromium). The pages are served by the TestClient of
tests/test_web.py through request interception, so no server or port is needed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from tests.test_web import client, logic  # noqa: F401 (the fixture is shared with the HTML tests)

# The CI layout job sets SIGHARVEST_REQUIRE_BROWSER=1: there a missing Playwright or Chromium fails instead of skipping.
REQUIRED = os.environ.get("SIGHARVEST_REQUIRE_BROWSER") == "1"
if REQUIRED:
    import playwright.sync_api as sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

BASE = "http://127.0.0.1"
PAGES = [
    "/",
    "/search",
    "/search?q=mimikatz",
    "/search?q=mimikatz&view=table",
    "/search?q=zzzqqqxxx",
    "/rule/{logic}",
    "/family/{logic}",
    "/compare",
    "/export",
    "/export?q=mimikatz",
    "/coverage",
    "/changes",
    "/sources",
    "/sources/local-rules",
    "/collections",
    "/about",
    "/guide",
    "/rule/ffffffffffffffff",
]
# Elements wider than the viewport are fine inside a scroll container (tables, code blocks); the page itself must not
# be wider than the viewport.
OVERFLOW_JS = """() => {
  const W = document.documentElement.clientWidth, out = [];
  for (const el of document.querySelectorAll('body *')) {
    const b = el.getBoundingClientRect();
    if (!b.width || b.right <= W + 1) continue;
    let p = el.parentElement, clipped = false;
    while (p) { if (/(auto|scroll|hidden)/.test(getComputedStyle(p).overflowX)) { clipped = true; break; } p = p.parentElement; }
    if (!clipped) out.push(el.tagName + '.' + el.className + ' right=' + Math.round(b.right) + ' ' + (el.textContent || '').slice(0, 40));
  }
  return {scrollWidth: document.documentElement.scrollWidth, width: W, over: out.slice(0, 5)};
}"""


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # browser binary missing: playwright install chromium
            if REQUIRED:
                raise
            pytest.skip(f"Chromium for Playwright is not installed: {exc}")
        yield b
        b.close()


def _serve(client: TestClient):  # noqa: F811
    def handler(route: Any) -> None:
        req = route.request
        parts = urlsplit(req.url)
        if parts.netloc != "127.0.0.1":
            route.abort()
            return
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        r = client.get(path, headers={"accept": req.headers.get("accept", "*/*")})
        route.fulfill(status=r.status_code, headers={k: v for k, v in r.headers.items() if k.lower() != "content-length"}, body=r.content)

    return handler


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_no_page_scrolls_sideways_on_a_phone(browser: Any, client: TestClient, scheme: str) -> None:  # noqa: F811
    key = logic(client)[:16]
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, color_scheme=scheme)
    ctx.route("**/*", _serve(client))
    problems: list[str] = []
    try:
        for path in PAGES:
            url = path.format(logic=key)
            page = ctx.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e, errs=errors: errs.append(str(e)))
            page.goto(BASE + url, wait_until="load")
            m = page.evaluate(OVERFLOW_JS)
            if m["scrollWidth"] > m["width"]:
                problems.append(f"{url}: page is {m['scrollWidth']} px wide at {m['width']} px: {m['over']}")
            problems += [f"{url}: JS error {e}" for e in errors]
            page.close()
    finally:
        ctx.close()
    assert not problems, "\n".join(problems)


def test_keyboard_j_k_and_enter_open_a_result(browser: Any, client: TestClient) -> None:  # noqa: F811
    """j / k move through the results and Enter opens the rule, with no JS error. A `var cur` added for the phone
    navigation shadowed the cursor: j threw "Cannot read properties of undefined (reading 'classList')"."""
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    ctx.route("**/*", _serve(client))
    try:
        for view in ("", "&view=table"):
            page = ctx.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda e, errs=errors: errs.append(str(e)))
            page.goto(f"{BASE}/search?q=mimikatz{view}", wait_until="load")
            page.keyboard.press("j")
            page.keyboard.press("j")
            page.keyboard.press("k")
            focused = page.locator("#results .is-focused, #results tr.cur")
            assert focused.count() == 1, (view, errors)
            with page.expect_navigation():
                page.keyboard.press("Enter")
            assert "/rule/" in page.url and not errors, (view, page.url, errors)
            page.close()
    finally:
        ctx.close()
