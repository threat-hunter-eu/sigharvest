"""Credentials in a source URL (https://user:token@host/...) never reach the web UI, the API or a release."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.models import Source
from sigharvest.service import open_db, sync_all
from sigharvest.sources import public_url

RULE = """title: Redaction Test Rule
id: 7d2f0c1e-3a4b-4c5d-8e9f-0a1b2c3d4e5f
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: redaction-test
  condition: selection
level: low
"""
SECRET = "not-a-real-secret"
SYNCED = f"https://alice:{SECRET}@git.example.test/org/rules.git"
PENDING = f"https://{SECRET}@git.example.test/org/private.git"
HTML = {"accept": "text/html"}


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        (SYNCED, "https://git.example.test/org/rules.git"),
        (PENDING, "https://git.example.test/org/private.git"),  # a token given as the user name
        ("http://u:p@a@host:8080/x?q=1", "http://host:8080/x?q=1"),
        ("ssh://git:pw@host/org/r.git", "ssh://git@host/org/r.git"),
        ("https://u:p@[::1/x", "https://[::1/x"),  # malformed: the userinfo still goes
        # a secret in the query string or fragment: the value goes, the name stays
        ("https://host/rules.zip?private_token=SECRET", "https://host/rules.zip?private_token=REDACTED"),
        (
            "https://bucket/rules.zip?X-Amz-Signature=SECRET&X-Amz-Credential=AK&ref=main",
            "https://bucket/rules.zip?X-Amz-Signature=REDACTED&X-Amz-Credential=REDACTED&ref=main",
        ),
        ("https://host/rules.zip?a=1&API_KEY=SECRET#x", "https://host/rules.zip?a=1&API_KEY=REDACTED#x"),
        ("https://host/rules.zip#access_token=SECRET&state=1", "https://host/rules.zip#access_token=REDACTED&state=1"),
        ("https://alice:pw@host/rules.zip?password=SECRET", "https://host/rules.zip?password=REDACTED"),  # both at once
        ("https://u:p@[::1/x?token=SECRET", "https://[::1/x?token=REDACTED"),  # malformed URL, query still redacted
    ],
)
def test_public_url_drops_credentials(url: str, shown: str) -> None:
    assert public_url(url) == shown


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/a/b.git",
        "ssh://git@host/org/r.git",
        "git@github.com:a/b.git",
        "/srv/rules",
        "file:///srv/rules",
        "https://[::1",
        "https://host/rules.zip?ref=main",  # a parameter that is not a secret stays
        "https://host/rules.zip?ref=main#L10-L20",
    ],
)
def test_public_url_keeps_urls_without_secrets(url: str) -> None:
    assert public_url(url) == url


def test_web_and_release_do_not_show_source_credentials(tmp_path: Path) -> None:
    from sigharvest.index import rebuild
    from sigharvest.lock import mutation_lease
    from sigharvest.release import build
    from sigharvest.web.app import create_app

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(RULE)
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir()
    local = SourceConfig(name="local-rules", type="local", url=str(rules), licence="MIT", redistributable=True)
    save_sources(ws, [local])
    sessions = open_db(ws, migrate=True)
    sync_all(ws, workers=1)
    with mutation_lease(ws), sessions() as s:
        assert rebuild(s, workers=1) == 1
        # As if the source had been registered with credentials in its URL instead of `auth`.
        s.execute(update(Source).where(Source.name == "local-rules").values(url=SYNCED))
        s.commit()
    save_sources(ws, [local, SourceConfig(name="private", url=PENDING)])  # registered, not synced yet

    with TestClient(create_app(ws, sessions), base_url="http://127.0.0.1") as client:
        api = client.get("/api/sources")
        assert api.status_code == 200
        urls = {row["name"]: row["url"] for row in api.json()}
        assert urls == {"local-rules": "https://git.example.test/org/rules.git", "private": "https://git.example.test/org/private.git"}
        for page in ("/sources", "/sources/local-rules", "/sources/private"):
            response = client.get(page, headers=HTML)
            assert response.status_code == 200 and SECRET not in response.text, page
        for page in ("/sources", "/sources/local-rules"):  # the URL itself is still shown
            assert "git.example.test/org/rules" in client.get(page, headers=HTML).text, page

    with sessions() as s:
        manifest = build(s, tmp_path / "rel")
    assert [row["url"] for row in manifest["sources"]] == ["https://git.example.test/org/rules.git"]
    for name in ("manifest.json", "ATTRIBUTION.md"):
        text = (tmp_path / "rel" / name).read_text(encoding="utf-8")
        assert SECRET not in text and "https://git.example.test/org/rules.git" in text, name
    assert SECRET not in json.dumps(manifest)
