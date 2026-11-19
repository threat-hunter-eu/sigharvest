"""What docs/conventions.md promises (shared with suriharvest): command names, errors, exit codes, JSON envelopes,
UI authentication off loopback, the shared stylesheet and the file names."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sigharvest.cli import app
from tests.test_web import HTML, client, logic  # noqa: F401 (shared fixtures)

ROOT = Path(__file__).resolve().parents[1]
# SHA-256 of src/sigharvest/web/static/harvest-base.css. The same file (and this value) is in suriharvest: change both.
HARVEST_BASE_SHA256 = "446063cf64875c7599ba2c1d960519851f4c281fc86c2d5b0d4401c217ce083e"


def test_harvest_base_is_the_shared_copy() -> None:
    data = (ROOT / "src/sigharvest/web/static/harvest-base.css").read_bytes()
    assert hashlib.sha256(data).hexdigest() == HARVEST_BASE_SHA256, "harvest-base.css changed: copy it to suriharvest and update both hashes"
    assert b"sigharvest" not in data.split(b"*/", 1)[1], "product-specific rules belong in style.css"


def test_conventions_doc_and_renamed_files_exist() -> None:
    text = (ROOT / "docs/conventions.md").read_text(encoding="utf-8")
    assert text.startswith("# Conventions shared by sigharvest and suriharvest")
    for name in ("web.md", "releases.md", "site.md", "scheduling.md", "concepts.md", "conventions.md"):
        assert (ROOT / "docs" / name).is_file(), name
    assert (ROOT / ".github/workflows/nightly.yml").is_file() and not (ROOT / ".github/workflows/update.yml").exists()
    assert (ROOT / ".github/ISSUE_TEMPLATE/config.yml").is_file()
    assert "## [Unreleased]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_pypi_variable_has_the_shared_name_and_the_old_one_still_works() -> None:
    text = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    assert "vars.SIGHARVEST_PYPI_ENABLED == 'true' || vars.SIGHARVEST_PYPI_PUBLISH == 'true'" in text
    assert "deprecated" in text
    pages = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    assert "vars.SIGHARVEST_AUTOMATION_ENABLED == 'true' && vars.SIGHARVEST_PAGES_ENABLED == 'true'" in pages


# ------------------------------------------------------------------ command line


def test_version_command_and_python_dash_m(tmp_path: Path) -> None:
    env = os.environ | {"SIGHARVEST_HOME": str(tmp_path)}
    out = subprocess.run([sys.executable, "-m", "sigharvest", "version"], capture_output=True, text=True, check=True, env=env, timeout=60).stdout
    first = out.splitlines()[0]
    assert first.startswith("sigharvest ") and ", schema " in first and "pySigma " in out
    assert not list(tmp_path.iterdir())  # needs no workspace


def test_web_is_a_hidden_alias_of_serve() -> None:
    runner = CliRunner(env={"COLUMNS": "120"})
    assert not re.search(r"^\W*web\s", runner.invoke(app, ["--help"], prog_name="sigharvest").output, flags=re.M)
    help_text = runner.invoke(app, ["web", "--help"], prog_name="sigharvest").output
    assert "Alias of serve" in help_text and "--token-env" in help_text


def test_errors_start_with_error_and_go_to_stderr(tmp_path: Path) -> None:
    env = os.environ | {"SIGHARVEST_HOME": str(tmp_path / "nothing"), "COLUMNS": "300"}
    result = subprocess.run([sys.executable, "-m", "sigharvest", "stats"], capture_output=True, text=True, env=env, timeout=60)
    assert result.returncode == 2
    assert result.stderr.startswith("error: not a sigharvest workspace") and "sigharvest init DIR" in result.stderr
    assert result.stdout == ""


@pytest.fixture
def fresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A workspace right after `init` (curated preset, nothing synced)."""
    root = tmp_path / "ws"
    assert CliRunner().invoke(app, ["init", str(root)]).exit_code == 0
    monkeypatch.setenv("SIGHARVEST_HOME", str(root))
    return root


def test_not_found_is_exit_1(fresh: Path) -> None:
    show = CliRunner().invoke(app, ["show", "0123456789abcdef"])
    assert show.exit_code == 1 and show.stderr.startswith("error: no rule matches that key")
    run = CliRunner().invoke(app, ["runs", "show", "999"])
    assert run.exit_code == 1 and run.stderr.startswith("error: no update run 999")


def test_json_lists_share_one_envelope(fresh: Path) -> None:
    for args in (["search", "x", "--json"], ["stats", "--json"], ["runs", "list", "--json"], ["sources", "list", "--json"], ["quarantine", "list", "--json"]):
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, (args, result.output)
        assert len(result.stdout.strip().splitlines()) == 1, args  # one compact document
        doc = json.loads(result.stdout)
        assert {"total", "offset", "limit", "results"} <= set(doc), args
        assert isinstance(doc["results"], list)
    sources = json.loads(CliRunner().invoke(app, ["sources", "list", "--json"]).stdout)
    assert sources["total"] == len(sources["results"]) > 0


def test_update_waits_for_a_busy_workspace(fresh: Path) -> None:
    import threading

    from sigharvest.config import Workspace
    from sigharvest.lock import mutation_lease

    assert (fresh / "data" / "sigharvest.lock").name == "sigharvest.lock"
    held, release = threading.Event(), threading.Event()

    def hold() -> None:
        with mutation_lease(Workspace(fresh)):
            held.set()
            release.wait(10)

    thread = threading.Thread(target=hold)
    thread.start()
    held.wait(10)
    try:
        busy = CliRunner().invoke(app, ["update", "--source", "nothing-such", "--wait", "0.2"])
        assert busy.exit_code == 2 and "busy" in busy.output
    finally:
        release.set()
        thread.join()
    assert (fresh / "data" / "sigharvest.lock").exists()


def test_sources_yaml_uses_redistribute() -> None:
    from sigharvest.config import SourceConfig

    assert SourceConfig(name="a", url="u", redistributable=True).to_dict()["redistribute"] == "yes"
    assert SourceConfig(name="a", url="u", redistributable="unknown").to_dict()["redistribute"] == "unknown"
    assert "redistributable" not in SourceConfig(name="a", url="u", redistributable=False).to_dict()
    assert SourceConfig.from_dict({"name": "a", "url": "u", "redistribute": "no"}).redistributable is False
    assert SourceConfig.from_dict({"name": "a", "url": "u", "redistributable": True}).redistributable is True  # old name


# ------------------------------------------------------------------ web UI


def test_serve_refuses_a_network_address_without_a_token(fresh: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("must not start"))
    refused = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"])
    assert refused.exit_code == 2 and refused.stderr.startswith("error: binding to 0.0.0.0") and "--token-env" in refused.stderr
    monkeypatch.setenv("SHORT_TOKEN", "short")
    short = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0", "--token-env", "SHORT_TOKEN"])
    assert short.exit_code == 2 and "at least 16 characters" in short.stderr
    started: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda application, **k: started.update(k, app=application))
    monkeypatch.setenv("UI_TOKEN", "x" * 24)
    ok = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0", "--token-env", "UI_TOKEN", "--port", "8123"])
    assert ok.exit_code == 0, ok.output
    assert started["host"] == "0.0.0.0" and started["port"] == 8123
    assert "Ctrl+C stops it" in ok.stdout and str(fresh) in ok.stdout


def test_token_is_required_on_every_request(client: TestClient) -> None:  # noqa: F811
    from sigharvest.web.app import create_app

    web = client.app.state.web  # type: ignore[attr-defined]
    token = "t" * 20
    with TestClient(create_app(web.ws, web.Session_, token=token), base_url="http://127.0.0.1") as guarded:
        assert guarded.get("/about").status_code == 401
        assert guarded.get("/static/app.js").status_code == 401
        assert guarded.get("/about").headers["www-authenticate"].startswith("Basic")
        assert guarded.get("/about", headers={"authorization": "Bearer " + "u" * 20}).status_code == 401
        assert guarded.get("/about", headers={"authorization": "Basic !!!"}).status_code == 401
        assert guarded.get("/about", headers={"authorization": "Bearer " + token}).status_code == 200
        basic = base64.b64encode(f"anyone:{token}".encode()).decode()
        assert guarded.get("/api/search", params={"q": "mimikatz"}, headers={"authorization": "Basic " + basic}).status_code == 200


def test_token_auth_throttles_wrong_tokens_per_peer() -> None:
    """After too many wrong tokens a peer is refused (429), the right token included, until the window passes."""
    from fastapi.responses import PlainTextResponse

    from sigharvest.web.security import TokenAuth

    token, now = "t" * 20, [1000.0]
    guarded = TokenAuth(PlainTextResponse("ok"), token=token, clock=lambda: now[0])
    good, bad = {"authorization": "Bearer " + token}, {"authorization": "Bearer " + "u" * 20}
    attacker = TestClient(guarded, base_url="http://127.0.0.1", client=("10.0.0.9", 5000))  # type: ignore[arg-type]
    other = TestClient(guarded, base_url="http://127.0.0.1", client=("10.0.0.7", 5000))  # type: ignore[arg-type]
    for _ in range(TokenAuth.MAX_FAILURES * 2):
        assert attacker.get("/about").status_code == 401  # the browser's first, header-less request never counts
    for _ in range(TokenAuth.MAX_FAILURES - 1):
        assert attacker.get("/about", headers=bad).status_code == 401
    assert attacker.get("/about", headers=good).status_code == 200  # a success does not reset the count
    assert attacker.get("/about", headers=bad).status_code == 401
    blocked = attacker.get("/api/search", headers=good)
    assert blocked.status_code == 429 and blocked.json() == {"detail": "too many failed logins"}
    assert 0 < int(blocked.headers["retry-after"]) <= TokenAuth.WINDOW_SECONDS
    assert other.get("/about", headers=good).status_code == 200  # another address is not affected
    now[0] += TokenAuth.WINDOW_SECONDS + 1
    assert attacker.get("/about", headers=good).status_code == 200


def test_unknown_pages_render_the_html_error_page(client: TestClient) -> None:  # noqa: F811
    page = client.get("/no-such-page")
    assert page.status_code == 404 and page.headers["content-type"].startswith("text/html") and "Not found" in page.text
    api = client.get("/api/no-such-thing")
    assert api.status_code == 404 and api.json() == {"detail": "Not Found"}
    assert client.get("/no-such-page", headers={"accept": "application/json"}).json() == {"detail": "Not Found"}


def test_api_search_has_the_shared_envelope(client: TestClient) -> None:  # noqa: F811
    doc = client.get("/api/search", params={"q": "mimikatz", "limit": 5}).json()
    assert doc["limit"] == 5 and doc["offset"] == 0 and isinstance(doc["results"], list) and doc["total"] >= 1


def test_sources_page_on_a_fresh_workspace(fresh: Path) -> None:
    """After `init`, before the first update: every source is still pending (it was a 500)."""
    from sigharvest.config import Workspace
    from sigharvest.service import open_db
    from sigharvest.web.app import create_app

    ws = Workspace(fresh)
    with TestClient(create_app(ws, open_db(ws)), base_url="http://127.0.0.1") as fresh_client:
        page = fresh_client.get("/sources", headers=HTML)
        assert page.status_code == 200, page.text[:500]
        assert fresh_client.get("/", headers=HTML).status_code == 200
