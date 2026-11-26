"""Web UI: every page renders, rule text is escaped, collections and exports work, cross-site POSTs are refused,
old addresses redirect and the Content-Security-Policy is strict (no inline script or style, nothing from a CDN)."""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.service import open_db, sync_all

MIMIKATZ = """title: Mimikatz Command Line
id: 5f8c7ef7-8b54-4b1f-9a33-6d6e4b0c7f11
status: test
description: Detects mimikatz <script>alert(1)</script> usage
author: Tester
date: 2024-01-02
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - sekurlsa::logonpasswords
      - lsadump::sam
  condition: selection
level: high
"""
VARIANT = MIMIKATZ.replace("Mimikatz Command Line", "Mimikatz Command Line Variant").replace(
    "      - lsadump::sam\n", "      - lsadump::sam\n      - privilege::debug\n"
)
CERTUTIL = """title: Certutil Download
id: 0f3e2a1b-1111-4c2d-9e8f-123456789abc
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: selection
level: medium
tags:
  - attack.command-and-control
  - attack.t1105
"""
HTML = {"accept": "text/html"}


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    root: Path = tmp_path_factory.mktemp("web")
    rules = root / "rules" / "win"
    rules.mkdir(parents=True)
    (rules / "mimikatz.yml").write_text(MIMIKATZ)
    (rules / "mimikatz2.yml").write_text(VARIANT)
    (rules / "certutil.yml").write_text(CERTUTIL)
    ws = Workspace(root / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="local-rules", type="local", url=str(root / "rules"), licence="MIT", redistributable=True)])
    sessions = open_db(ws, migrate=True)
    sync_all(ws, workers=1)
    from sigharvest.index import rebuild
    from sigharvest.lock import mutation_lease

    with mutation_lease(ws), sessions() as s:
        assert rebuild(s, workers=1) == 3
    from sigharvest.web.app import create_app

    with TestClient(create_app(ws, sessions), base_url="http://127.0.0.1") as c:
        yield c


def logic(client: TestClient, q: str = "mimikatz") -> str:
    return str(client.get(f"/api/search?q={q}&view=logic").json()["results"][0]["logic_hash"])


@pytest.mark.parametrize(
    "url",
    [
        "/",
        "/search",
        "/search?q=mimikatz",
        "/search?q=mimikatz&view=table",
        "/search?licence=permissive",
        "/search?q=mimikatz&licence=none",
        "/search?level=high&tactic=credential-access",
        "/search?technique=T1003",
        "/search?q=a+OR+b+-c",
        "/sources",
        "/sources/local-rules",
        "/coverage",
        "/coverage?licence=permissive&level=high",
        "/changes",
        "/changes?kind=removed",
        "/export",
        "/export?q=mimikatz",
        "/export?scope=all&format=siem",
        "/about",
        "/collections",
        "/api/sources",
        "/api/facets?q=mimikatz",
        "/api/collections",
        "/api/docs",
        "/static/app.js",
        "/static/style.css",
    ],
)
def test_pages_render(client: TestClient, url: str) -> None:
    assert client.get(url, headers=HTML).status_code == 200


def test_search_table_view_and_old_layout_alias(client: TestClient) -> None:
    """view=table is the shared name (docs/conventions.md); layout=table, the old one, still works."""
    for url in ("/search?q=mimikatz&view=table", "/search?q=mimikatz&layout=table"):
        page = client.get(url, headers=HTML).text
        assert '<table class="rows">' in page
        assert "view=table" in page and "layout=table" not in page
    assert '<table class="rows">' not in client.get("/search?q=mimikatz", headers=HTML).text


def test_rule_text_is_escaped(client: TestClient) -> None:
    page = client.get("/search?q=mimikatz", headers=HTML).text
    assert "Mimikatz" in page
    assert "<script>alert(1)" not in page
    rule = client.get(f"/rule/{logic(client)[:16]}", headers=HTML)
    assert rule.status_code == 200
    assert "<script>alert(1)" not in rule.text


def test_rule_family_api_and_conversion(client: TestClient) -> None:
    key = logic(client)[:16]
    for url in (f"/rule/{key}/yaml", f"/family/{key}", f"/api/rule/{key}", f"/api/convert/{key}?target=splunk"):
        assert client.get(url, headers=HTML).status_code == 200, url
    assert client.get("/rule/zzzz", headers=HTML).status_code == 404
    assert client.get("/nope", headers=HTML).status_code == 404


def test_technique_filter_matches_sub_techniques(client: TestClient) -> None:
    found = client.get("/api/search?technique=T1003&view=logic").json()["results"]
    assert {r["title"] for r in found} >= {"Mimikatz Command Line"}
    assert all("Certutil" not in r["title"] for r in found)


@pytest.mark.backend("lucene")
def test_collection_lifecycle_and_exports(client: TestClient) -> None:
    key = logic(client)
    assert client.post("/collections", data={"name": "creds", "description": "test"}, follow_redirects=False).status_code in (303, 302)
    assert client.post("/collections/add", data={"name": "creds", "keys": key}, follow_redirects=False).status_code in (303, 302)
    assert client.get("/collections/creds", headers=HTML).status_code == 200
    items = client.get("/api/collections/creds").json()
    assert key in json.dumps(items)
    zipped = client.get("/collections/creds/export?format=zip")
    assert zipped.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(zipped.content)).namelist()
    assert any(n.endswith(".yml") for n in names)
    for fmt in ("jsonl", "csv", "splunk"):
        assert client.get(f"/collections/creds/export?format={fmt}").status_code == 200, fmt
    for fmt in ("zip", "jsonl", "csv", "lucene"):
        assert client.get(f"/search/export?q=mimikatz&format={fmt}").status_code == 200, fmt
    assert client.post("/collections/creds/remove", data={"key": key[:16]}, follow_redirects=False).status_code in (303, 302)
    assert client.post("/collections/creds/delete", follow_redirects=False).status_code in (303, 302)


def test_cross_site_post_is_refused(client: TestClient) -> None:
    response = client.post("/collections", data={"name": "x"}, headers={"origin": "http://evil.example"})
    assert response.status_code == 403


@pytest.mark.parametrize(("old", "new"), [("/overview", "/"), ("/guide", "/about"), ("/new", "/changes"), ("/hunt", "/search"), ("/quality", "/search")])
def test_removed_routes_redirect(client: TestClient, old: str, new: str) -> None:
    response = client.get(old, follow_redirects=False)
    assert response.status_code in (301, 307, 308)
    assert response.headers["location"].startswith(new)


def test_sidebar_has_the_seven_sections(client: TestClient) -> None:
    page = client.get("/about", headers=HTML).text
    nav = page.split('<ul class="nav">', 1)[1].split("</ul>", 1)[0]
    labels = re.findall(r"<span>([^<]+)</span>", nav)
    assert labels == ["Overview", "Search", "ATT&amp;CK coverage", "Sources", "Changes", "Export", "About &amp; licences"]


STRICT_CSP = "default-src 'self'; script-src 'self'; style-src 'self'"


@pytest.mark.parametrize("url", ["/", "/search?q=mimikatz", "/coverage", "/sources", "/changes", "/export", "/about", "/rule/{key}", "/family/{key}", "/nope"])
def test_csp_is_strict_and_pages_have_no_inline_code(client: TestClient, url: str) -> None:
    response = client.get(url.format(key=logic(client)[:16]), headers=HTML)
    csp = response.headers["content-security-policy"]
    assert csp.startswith(STRICT_CSP) and "unsafe-inline" not in csp and "object-src 'none'" in csp
    page = response.text
    assert not re.search(r"\sstyle\s*=", page), "inline style attribute"
    assert not re.search(r"<style", page), "inline <style>"
    assert not re.search(r"<script(?![^>]*\ssrc=\"/static/)", page), "inline or external script"
    assert not re.search(r"\son[a-z]+\s*=", page), "inline event handler"
    assert not re.search(r"(src|href)=\"(https?:)?//(?!github\.com/)[^\"]+\.(js|css)", page), "script or style from another site"


def test_rule_page_has_summary_needs_licence_and_tabs(client: TestClient) -> None:
    from sigharvest.conversion import BACKENDS

    page = client.get(f"/rule/{logic(client)[:16]}", headers=HTML).text
    assert "Alerts on <b>process creation</b> events where" in page
    assert "<b>You need:</b> Sysmon event 1, or Security event 4688" in page
    assert 'class="badge lic lic-permissive"' in page and "MIT" in page
    for target in BACKENDS:
        assert f'id="t-{target}"' in page
    if not BACKENDS:
        assert "sigharvest[convert]" in page


def test_rule_page_without_backends_explains_the_extra(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.web import app as web_app

    monkeypatch.setitem(web_app._templates().env.globals, "backends", [])
    from sigharvest.web.routes import rules

    monkeypatch.setattr(rules, "BACKENDS", [])
    page = client.get(f"/rule/{logic(client)[:16]}", headers=HTML).text
    assert 'uv tool install --reinstall "sigharvest[convert]"' in page.replace("&#34;", '"')
    assert 'id="t-splunk"' not in page


def test_install_hints_use_the_published_pypi_package(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """sigharvest is on PyPI: every hint installs the published package with its extra, through conversion.install_command."""
    from sigharvest import conversion

    assert conversion.install_command("convert-legacy") == 'uv tool install --reinstall "sigharvest[convert-legacy]"'
    assert "git+https://" not in (conversion.backend_error("lucene") or "") and "git+https://" not in conversion.INSTALL_HINT
    monkeypatch.setattr(conversion, "INSTALL_SOURCE", "git+https://github.com/threat-hunter-eu/sigharvest")
    assert conversion.install_command() == 'uv tool install --reinstall "sigharvest[convert] @ git+https://github.com/threat-hunter-eu/sigharvest"'
    templates = Path(conversion.__file__).parent / "web" / "templates"
    for t in templates.rglob("*.html"):
        assert "pipx install" not in t.read_text(encoding="utf-8"), t


def test_about_names_the_extra_of_each_missing_backend(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """lucene/esql/opensearch/microsoft365defender come from [convert-legacy], splunk/loki/sqlite from [convert]."""
    from sigharvest.web.routes import about

    groups = dict(about.missing_by_extra(["lucene", "splunk", "esql", "opensearch", "microsoft365defender", "loki"]))
    assert groups == {"convert": ["splunk", "loki"], "convert-legacy": ["lucene", "esql", "opensearch", "microsoft365defender"]}
    from sigharvest import conversion

    monkeypatch.setattr(conversion, "BACKENDS", ["splunk", "loki", "sqlite"])
    page = client.get("/about", headers=HTML).text.replace("&#34;", '"')
    assert 'Missing backends (lucene, esql, opensearch, microsoft365defender): <code>uv tool install --reinstall "sigharvest[convert-legacy]' in page
    assert '"sigharvest[convert] @' not in page.split("Missing backends")[1]


def test_export_downloads(client: TestClient) -> None:
    key = logic(client)
    zipped = client.get(f"/export/download?h={key}&format=zip")
    assert zipped.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(zipped.content)).namelist()
    assert any(n.endswith(".yml") and "/permissive/MIT/" in n for n in names)
    assert {n.split("/", 1)[1] for n in names} >= {"NOTICE.md", "LICENSES.md", "manifest.jsonl", "provenance.json", "SKIPPED.md"}
    layer = client.get("/export/download?q=mimikatz&format=navigator").json()
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1003.001"}
    assert client.get("/export/download?scope=all&format=yaml").text.count("\n---\n") + 1 >= 3
    for fmt in ("jsonl", "csv"):
        assert client.get(f"/export/download?q=mimikatz&format={fmt}").status_code == 200, fmt
    assert client.post("/export/download", data={"h": key, "format": "csv"}).status_code == 200
    assert client.post("/export/download", data={"h": key}, headers={"origin": "http://evil.example"}).status_code == 403
    assert client.get("/export/download?h=ffffffffffff&format=zip").status_code == 404


def test_unlicensed_rules_are_linked_not_copied(client: TestClient) -> None:
    from sigharvest.web.downloads import _included

    assert not _included("none", "all") and not _included("restricted", "split") and _included("copyleft", "split")
    assert not _included("copyleft", "permissive")


@pytest.mark.parametrize("url", ["/search?page=99999999999999999999", "/api/search?offset=99999999999999999999", "/api/search?offset=1000001"])
def test_huge_page_numbers_are_not_server_errors(client: TestClient, url: str) -> None:
    assert client.get(url).status_code in (200, 400, 422)


def test_downloads_address_redirects_to_export(client: TestClient) -> None:
    r = client.get("/downloads?q=x", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/export?q=x"


def test_web_and_cli_zip_are_the_same_layout_and_private_copy_is_explicit(tmp_path, client: TestClient) -> None:
    import io
    import zipfile

    page = client.get("/export?private=1").text
    assert "Private copy" in page and "--include-private-sources" in page
    web = zipfile.ZipFile(io.BytesIO(client.get("/export/download?format=zip&scope=all").content))
    names = web.namelist()
    top = names[0].split("/", 1)[0]
    assert {f"{top}/{n}" for n in ("NOTICE.md", "LICENSES.md", "ATTRIBUTION.md", "manifest.jsonl", "provenance.json", "SKIPPED.md")} <= set(names)
    assert any(n.startswith(f"{top}/permissive/MIT/") and n.endswith(".yml") for n in names)


def test_api_and_cli_json_name_both_totals(client: TestClient) -> None:
    """`total` follows the view; total_rules and total_families are the same numbers in /api/search and the CLI."""
    import json

    from typer.testing import CliRunner

    from sigharvest.cli import app as cli

    ws = client.app.state.web.ws  # type: ignore[attr-defined]
    api = client.get("/api/search?q=mimikatz").json()
    fam = client.get("/api/search?q=mimikatz&view=family").json()
    assert (api["view"], api["total"], api["total_rules"], api["total_families"]) == ("logic", 2, 2, 1)
    assert (fam["view"], fam["total"], fam["total_rules"], fam["total_families"]) == ("family", 1, 2, 1)
    env = {"SIGHARVEST_HOME": str(ws.root)}
    out = json.loads(CliRunner().invoke(cli, ["search", "mimikatz", "--json"], env=env).output)
    per_logic = json.loads(CliRunner().invoke(cli, ["search", "mimikatz", "--json", "--per-logic"], env=env).output)
    assert {k: out[k] for k in ("view", "total", "total_rules", "total_families")} == {k: fam[k] for k in ("view", "total", "total_rules", "total_families")}
    assert {k: per_logic[k] for k in ("view", "total", "total_rules", "total_families")} == {
        k: api[k] for k in ("view", "total", "total_rules", "total_families")
    }


@pytest.mark.backend("splunk")
def test_web_query_export_states_selected_and_written_and_ships_the_conversion_report(client: TestClient) -> None:
    import io
    import zipfile

    zipped = zipfile.ZipFile(io.BytesIO(client.get("/export/download?scope=all&format=siem&target=splunk").content))
    names = {n.split("/", 1)[1]: n for n in zipped.namelist()}
    query = next(n for n in names if n.endswith(".splunk.txt"))
    assert f"{query}.conversion.jsonl" in names
    head = zipped.read(names[query]).decode().splitlines()
    assert head[0] == "# sigharvest export for splunk: 3 selected -> 3 written for splunk"
    assert f"# details: {query}.conversion.jsonl" in head


def test_export_page_never_opens_on_a_download_it_cannot_make(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Above the web limit, /export starts from SigmaHQ's core profile; Everything explains the limit and the way out."""
    monkeypatch.setattr(client.app.state.web.limits, "export_rules", 2)  # type: ignore[attr-defined]
    first = client.get("/export?format=sheet", headers=HTML, follow_redirects=False)
    assert first.status_code == 303 and first.headers["location"].startswith("/export?profile=core&scope=search&big=1")
    page = client.get(first.headers["location"], headers=HTML).text
    assert "<b>core</b> profile (2 rules, one per logic; " in page and " families, the unit <code>sigharvest export</code> uses by default)" in page
    assert 'type="submit" disabled' not in page and "sigharvest export --profile core --unit logic" in page
    everything = client.get("/export?scope=all", headers=HTML).text
    assert "more than the 2 rules a web download can hold" in everything and "core profile (2 rules, one per logic; " in everything
    assert "sigharvest export --unit logic --format zip --out sigharvest-all.zip" in everything
    monkeypatch.setattr(client.app.state.web.limits, "export_rules", 20_000)
    assert client.get("/export", headers=HTML, follow_redirects=False).status_code == 200


@pytest.mark.parametrize(("q", "hint"), [("mimikatz prodct:windows", "did you mean product:?"), ("level:hgh", "did you mean level:high?")])
def test_inline_filter_typo_is_a_400_with_a_suggestion(client: TestClient, q: str, hint: str) -> None:
    api = client.get("/api/search", params={"q": q})
    assert api.status_code == 400 and hint in api.text
    page = client.get("/search", params={"q": q}, headers=HTML)
    assert page.status_code == 400 and hint in page.text.replace("&#39;", "'")


@pytest.mark.parametrize("host", ["testserver", "evil.example", "localhost.", ""])
def test_only_loopback_host_headers_are_served(client: TestClient, host: str) -> None:
    """`testserver` is only Starlette's TestClient name: in production it would be a DNS-rebinding opening."""
    assert client.get("/about", headers={**HTML, "host": host}).status_code == 400
    assert client.get("/about", headers={**HTML, "host": "localhost:8000"}).status_code == 200


def test_short_prefixes_are_refused_and_repeats_count_once(client: TestClient) -> None:
    from sigharvest.index import fts_query

    assert fts_query("process process process") == ('"process"*', "")
    assert fts_query("ps exec") == ('"ps" AND "exec"*', "")  # two letters: exact, not a prefix of half the index
    r = client.get("/api/search", params={"q": " ".join(["a*"] * 64)})
    assert r.status_code == 400 and "at least 3 characters before *" in r.text
    assert client.get("/api/search", params={"q": "mim*"}).json()["total_rules"] >= 1


def test_a_search_over_the_time_budget_is_a_503_not_a_500(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """The reader's progress handler stops a statement after WEB_STATEMENT_SECONDS (15 s by default)."""
    from sigharvest import db_reads
    from sigharvest.db_reads import DeadlineConnection
    from sigharvest.web.app import create_app

    web = client.app.state.web  # type: ignore[attr-defined]
    monkeypatch.setattr(DeadlineConnection, "expired", lambda self: True)  # every statement is over its budget
    monkeypatch.setattr(db_reads, "PROGRESS_STEPS", 1)
    with TestClient(create_app(web.ws, web.Session_), base_url="http://127.0.0.1") as fresh:
        r = fresh.get("/api/search", params={"q": "mimikatz"})
    assert r.status_code == 503 and "too expensive" in r.text and r.headers["retry-after"] == "5"


def test_web_readers_default_to_a_small_pool_and_a_short_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest.db_reads import WEB_STATEMENT_SECONDS, ReadSettings

    monkeypatch.delenv("SIGHARVEST_READ_POOL", raising=False)
    monkeypatch.delenv("SIGHARVEST_READ_STATEMENT_SECONDS", raising=False)
    web = ReadSettings.from_env(statement_default=WEB_STATEMENT_SECONDS)
    assert web.pool_size <= 2 and web.statement_seconds == 15
    assert ReadSettings.from_env().statement_seconds == 60  # the CLI keeps its longer budget


def test_expensive_searches_cannot_starve_light_pages(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Searches run in a bounded number of slots (pool size - 1), so a reader stays free for every other page; a
    search that finds every slot busy for SEARCH_WAIT_SECONDS gets a 503 with Retry-After, not an endless queue."""
    import threading
    import time

    from sigharvest.web import deps
    from sigharvest.web.routes import search as search_routes

    web = client.app.state.web  # type: ignore[attr-defined]
    key = logic(client)[:16]
    monkeypatch.setattr(deps, "SEARCH_WAIT_SECONDS", 0.2)
    release, started = threading.Event(), threading.Event()
    original = search_routes.run_search

    def slow(*args, **kwargs):  # type: ignore[no-untyped-def]
        started.set()
        release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(search_routes, "run_search", slow)
    busy: list[int] = []
    worker = threading.Thread(target=lambda: busy.append(client.get("/api/search", params={"q": "mimikatz"}).status_code))
    worker.start()
    try:
        assert started.wait(5)
        t = time.monotonic()
        assert client.get("/about", headers=HTML).status_code == 200  # light page: not behind the search
        assert client.get(f"/rule/{key}", headers=HTML).status_code == 200
        assert time.monotonic() - t < 3
        refused = client.get("/api/search", params={"q": "certutil"})
        assert refused.status_code == 503 and refused.headers["retry-after"] == "5" and "Too many searches" in refused.text
        assert client.get("/search", params={"q": "certutil"}, headers=HTML).status_code == 503
    finally:
        release.set()
        worker.join(10)
    assert busy == [200]
    assert web.search_slots.acquire(timeout=1)  # the slot was given back
    web.search_slots.release()


def test_copy_paste_command_keeps_a_leading_dash_query_a_query():
    """The CLI line shown on the Export page ends options with `--` before the search text."""
    from sigharvest.web.routes.export import cli_command

    line = cli_command({"q": "--out=/tmp/x"}, "search", "zip", "", "sel")
    assert line.endswith("-- --out=/tmp/x")
    assert line.index("--out sel.zip") < line.index(" -- ")
    nav = cli_command({"q": "-mimikatz"}, "search", "navigator", "", "sel")
    assert nav.endswith("-- -mimikatz") and "--navigator sel.layer.json" in nav


def test_api_errors_are_json_detail(client: TestClient) -> None:
    """docs/conventions.md: every `/api/*` error is JSON {"detail": "..."}, the request guards' refusals included."""
    from sigharvest.web.security import refusal

    missing = client.get("/api/nope")
    assert missing.status_code == 404 and set(missing.json()) == {"detail"}
    bad = client.get("/api/search", params={"q": "level:hgh"})
    assert bad.status_code == 400 and "did you mean" in bad.json()["detail"]
    invalid = client.get("/api/search", params={"limit": "many"})  # FastAPI's own validation error: a string here too
    assert invalid.status_code == 400 and set(invalid.json()) == {"detail"} and isinstance(invalid.json()["detail"], str)
    guard = client.post("/api/search", headers={"origin": "http://evil.example"})
    assert guard.status_code == 403 and guard.json() == {"detail": "cross-site request refused"}
    auth = refusal({"path": "/api/search"}, "authentication required", 401, {"WWW-Authenticate": "Basic"})
    assert auth.status_code == 401 and auth.body == b'{"detail":"authentication required"}' and auth.headers["www-authenticate"] == "Basic"
    assert refusal({"path": "/search"}, "authentication required", 401).body == b"authentication required"


@pytest.mark.parametrize("path", ["/search?min_sources=99999999999999999999", "/api/search?q=x&min_sources=99999999999999999999"])
def test_a_number_beyond_sqlite_integers_is_a_400_not_a_500(client: TestClient, path: str) -> None:
    """Found crawling the UI with hostile URLs: SQLite's OverflowError on a 20-digit number reached the user as a 500."""
    r = client.get(path)
    assert r.status_code == 400 and "out of range" in r.text, (r.status_code, r.text[:200])


def test_overview_headline_counts_the_rules_search_shows(tmp_path: Path) -> None:
    """The big number links to search, so it leaves junk out like search does; the junk count stays one click away."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "mimikatz.yml").write_text(MIMIKATZ)
    (rules / "certutil.yml").write_text(CERTUTIL)
    marker = (
        CERTUTIL.replace("Certutil Download", "Simulator Marker")
        .replace("0f3e2a1b-1111", "0f3e2a1b-2222")
        .replace("  category: process_creation\n  product: windows\n", "  category: test\n")
        .replace("urlcache", "marker-42")
    )
    (rules / "marker.yml").write_text(marker)  # a placeholder log source: junk
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    save_sources(ws, [SourceConfig(name="local-rules", type="local", url=str(rules), licence="MIT", redistributable=True)])
    sessions = open_db(ws, migrate=True)
    sync_all(ws, workers=1)
    from sigharvest.index import rebuild
    from sigharvest.lock import mutation_lease
    from sigharvest.web.app import create_app

    with mutation_lease(ws), sessions() as s:
        assert rebuild(s, workers=1) == 3
    with TestClient(create_app(ws, sessions), base_url="http://127.0.0.1") as c:
        page = c.get("/", headers=HTML).text
    assert re.search(r'class="yield-n" href="/search">2</a>', page), page
    assert '<a href="/search?junk=1">1 more</a> set aside as junk.' in page
    assert "1 source &middot; 2 rules" in page
