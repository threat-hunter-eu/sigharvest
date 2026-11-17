"""Non-git adapters use local fixtures and MockTransport; no test reaches the network."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml
from sqlalchemy import select
from typer.testing import CliRunner

import sigharvest.remote_documents as documents
import sigharvest.sync_remote as remote
from sigharvest.cli import app
from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.identity import sha256_hex
from sigharvest.models import Occurrence, RuleVersion, Source
from sigharvest.remote_documents import complete_yaml, dataset_rows, html_blocks, parse_json, text_blocks
from sigharvest.service import fetch_source, open_db, sync_all
from sigharvest.sync import SyncError
from tests.test_sync_http import serve, ws_for

FIXTURES = Path(__file__).parent / "fixtures" / "non_git"
SHA = "a" * 40
SHA2 = "b" * 40
REPO = "https://huggingface.co/datasets/example/rules"
URL = "https://example.org/rule.txt"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def manifest(ws: Workspace, name: str = "remote") -> dict:
    return json.loads((ws.cache / "non-git" / name / "manifest.json").read_bytes())


def test_text_and_html_only_extract_complete_blocks() -> None:
    raw = fixture("rule.txt")
    assert text_blocks(raw.decode()) == [("document", raw)]
    blocks = text_blocks(fixture("article.txt").decode())
    assert len(blocks) == 2
    assert [yaml.safe_load(b)["title"] for _, b in blocks] == ["Fenced rule", "Indented rule"]
    assert yaml.safe_load(blocks[0][1])["detection"]["selection"]["Image"] == r"C:\new\tool.exe"
    html = html_blocks(fixture("page.html").decode())
    assert len(html) == 1
    assert yaml.safe_load(html[0][1])["detection"]["selection"]["CommandLine|contains"] == "<script>&"


@pytest.mark.parametrize(
    "text",
    [
        "prose\n" + fixture("rule.txt").decode(),
        "```yaml\n" + fixture("rule.txt").decode(),
        "```python\n" + fixture("rule.txt").decode() + "```\n",
        "title: Incomplete\nlogsource: {product: windows}\ndetection: {}\n",
        "```yaml\nlogsource: {product: windows}\n```\n```yaml\ndetection: {condition: selection}\n```\n",
    ],
)
def test_text_does_not_guess_fragments(text: str) -> None:
    assert text_blocks(text) == []


def test_multidocument_crlf_and_nested_html() -> None:
    raw = fixture("rule.txt").replace(b"\n", b"\r\n")
    combined = raw + b"---\r\n" + raw
    assert text_blocks(combined.decode()) == [("document", combined)]
    assert len(html_blocks("<pre><code>" + raw.decode() + "</code></pre>")) == 1
    assert html_blocks("<pre>" + raw.decode()) == []
    assert html_blocks("<script><pre>" + raw.decode() + "</pre></script>") == []


def test_dataset_formats_preserve_metadata_paths_and_escapes() -> None:
    rows = dataset_rows(fixture("rules.jsonl"), True)
    assert len(rows) == 2
    data = yaml.safe_load(rows[0][1])
    assert data["title"] == "Structured rule" and data["author"] == "Fixture author" and data["license"] == "MIT"
    assert data["detection"]["selection"]["Image"] == r"C:\new\notepad.exe"
    assert data["detection"]["selection"]["CommandLine|re"] == r"\n.*"
    assert "id" not in data and "raw_yaml" not in data and "rule_id" not in data
    assert rows[1][1] == fixture("rule.txt")
    assert dataset_rows(fixture("rules.json"), False)[0][1] == fixture("rule.txt")
    assert dataset_rows(json.dumps({"raw_yaml": fixture("rule.txt").decode()}).encode(), False)[0][1] == fixture("rule.txt")


def test_escaped_raw_only_is_refused_without_corrupting_windows_paths() -> None:
    row = {"raw_yaml": fixture("rule.txt").decode().replace("\n", r"\n")}
    with pytest.raises(SyncError, match="structured fields"):
        dataset_rows(json.dumps([row]).encode(), False)


@pytest.mark.parametrize("raw", [b'{"x": 1, "x": 2}', b'{"x": NaN}', b"{broken", b"[" * 1000])
def test_invalid_json_is_rejected(raw: bytes) -> None:
    with pytest.raises(SyncError, match="JSON"):
        parse_json(raw)


def test_aliases_duplicate_keys_unsafe_tags_and_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    base = fixture("rule.txt").decode()
    assert complete_yaml(base + "title: Duplicate\n") is None
    assert complete_yaml(base + "extra: &a [*a]\n") is None
    assert complete_yaml(base + "extra: !!python/object/apply:os.system ['false']\n") is None
    monkeypatch.setattr(documents, "MAX_DEPTH", 3)
    assert complete_yaml(base) is None
    with pytest.raises(SyncError, match="complexity"):
        parse_json(b"[[[[[1]]]]]")
    monkeypatch.setattr(documents, "MAX_FILE_BYTES", 10)
    with pytest.raises(SyncError, match="size limit"):
        complete_yaml(base)


def test_http_validators_hashes_and_partial_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="http-files", url="https://example.org/article", urls=[URL])
    state = {"body": fixture("rule.txt"), "etag": '"v1"', "fail": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["fail"]:
            return httpx.Response(503)
        if request.headers.get("if-none-match") == state["etag"]:
            return httpx.Response(304)
        return httpx.Response(200, content=state["body"], headers={"ETag": str(state["etag"])})

    seen = serve(monkeypatch, handler)
    first = fetch_source(ws, src, None, {})
    assert first.full_scan and len(first.added) == 1
    saved = manifest(ws)
    assert saved["resources"][URL]["sha256"] == sha256_hex(fixture("rule.txt"))
    assert saved["resources"][URL]["etag"] == '"v1"'
    assert next(iter(saved["outputs"].values()))["url"] == URL
    ingested = {path: sha256_hex((first.root / path).read_bytes()) for path in first.added}
    second = fetch_source(ws, src, first.new_commit, ingested)
    assert seen[-1].headers["if-none-match"] == '"v1"'
    assert not second.added | second.changed | second.removed and not second.full_scan
    state.update(body=fixture("rule.txt").replace(b"Example remote", b"Changed remote"), etag='"v2"')
    third = fetch_source(ws, src, second.new_commit, {})
    assert third.changed == first.added and third.new_commit != first.new_commit
    prior_tree = {p: (third.root / p).read_bytes() for p in third.changed}
    prior_manifest = manifest(ws)
    state["fail"] = True
    with pytest.raises(SyncError, match="503"):
        fetch_source(ws, src, third.new_commit, {})
    assert manifest(ws) == prior_manifest
    assert {p: (third.root / p).read_bytes() for p in third.changed} == prior_tree


def test_missing_or_corrupt_blob_refetches_without_validator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="html", url=URL)
    seen = serve(monkeypatch, lambda r: httpx.Response(200, content=fixture("page.html"), headers={"ETag": '"same"'}))
    first = fetch_source(ws, src, None, {})
    blob = ws.cache / "non-git" / "remote" / f"{sha256_hex(fixture('page.html'))}.bin"
    blob.write_bytes(b"bad cache")
    second = fetch_source(ws, src, first.new_commit, {})
    assert "if-none-match" not in seen[-1].headers
    assert not second.changed
    assert blob.read_bytes() == fixture("page.html")


def test_multiple_urls_colliding_basenames_removal_and_ingestion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    urls = [URL, "https://example.net/rule.txt"]
    src = SourceConfig(name="remote", type="http-files", url=URL, urls=urls)
    serve(monkeypatch, lambda r: httpx.Response(200, content=fixture("rule.txt")))
    save_sources(ws, [src])
    open_db(ws, migrate=True)  # initialize the offline workspace explicitly
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as session:
        occurrences = list(session.scalars(select(Occurrence).where(Occurrence.present.is_(True))))
        assert len(occurrences) == 2
        assert len({o.path for o in occurrences}) == 2
    src.urls = [urls[1]]
    save_sources(ws, [src])
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok" and outcome.log.files_removed == 1
    with open_db(ws, migrate=True)() as session:
        assert len(list(session.scalars(select(Occurrence).where(Occurrence.present.is_(True))))) == 1
        assert session.scalar(select(Source.last_commit)) == manifest(ws)["revision"]
    # A disappearing extraction target is a failed fetch, not a mass deletion.
    serve(monkeypatch, lambda r: httpx.Response(200, content=b"login page"))
    assert sync_all(ws)[0].status == "error"
    with open_db(ws, migrate=True)() as session:
        assert len(list(session.scalars(select(Occurrence).where(Occurrence.present.is_(True))))) == 1


def test_huggingface_pins_downloads_and_reuses_immutable_blobs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="huggingface", url=REPO, files=["data/rules.jsonl", "rules.json"])
    state = {"sha": SHA}

    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/datasets/" in request.url.path:
            return httpx.Response(200, json={"sha": state["sha"], "siblings": [{"rfilename": n} for n in src.files]})
        assert f"/resolve/{state['sha']}/" in request.url.path
        return httpx.Response(200, content=fixture("rules.jsonl" if request.url.path.endswith(".jsonl") else "rules.json"))

    seen = serve(monkeypatch, handler)
    save_sources(ws, [src])
    open_db(ws, migrate=True)  # initialize the offline workspace explicitly
    first = sync_all(ws)[0]
    assert first.status == "ok" and first.log.new_commit == SHA and first.log.files_added == 3
    assert len(seen) == 3
    second = sync_all(ws)[0]
    assert second.status == "ok" and second.log.files_added == second.log.files_changed == 0
    assert len(seen) == 4  # API only; file downloads are SHA-pinned and cached.
    state["sha"] = SHA2
    third = sync_all(ws)[0]
    assert third.status == "ok" and third.log.new_commit == SHA2 and len(seen) == 7
    with open_db(ws, migrate=True)() as session:
        assert len(list(session.scalars(select(RuleVersion)))) == 2
    assert manifest(ws)["revision"] == SHA2


@pytest.mark.parametrize("file", ["../rules.json", "/rules.json", "a/../../rules.json", r"a\rules.json"])
def test_hf_rejects_unsafe_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, file: str) -> None:
    serve(monkeypatch, lambda r: httpx.Response(200, json={"sha": SHA, "siblings": [{"rfilename": file}]}))
    src = SourceConfig(name="remote", type="huggingface", url=REPO, files=[file])
    with pytest.raises(SyncError, match="unsafe"):
        fetch_source(ws_for(tmp_path), src, None, {})


@pytest.mark.parametrize("metadata", [{"sha": "main", "siblings": []}, {"sha": SHA}, {"sha": SHA, "siblings": []}])
def test_hf_requires_sha_and_existing_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, metadata: dict) -> None:
    serve(monkeypatch, lambda r: httpx.Response(200, json=metadata))
    src = SourceConfig(name="remote", type="huggingface", url=REPO, files=["rules.json"])
    with pytest.raises(SyncError):
        fetch_source(ws_for(tmp_path), src, None, {})


def test_download_caps_and_https_redirect_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    monkeypatch.setenv("FIXTURE_TOKEN", "fixture-value")
    src = SourceConfig(name="remote", type="http-files", url=URL, auth="FIXTURE_TOKEN")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.org":
            assert request.headers["Authorization"] == "Bearer fixture-value"
            return httpx.Response(302, headers={"Location": "https://cdn.example.net/rule.txt"})
        assert "authorization" not in request.headers
        return httpx.Response(200, content=fixture("rule.txt"))

    seen = serve(monkeypatch, handler)
    fetch_source(ws, src, None, {})
    assert len(seen) == 2
    assert "fixture-value" not in json.dumps(manifest(ws))
    serve(monkeypatch, lambda r: httpx.Response(302, headers={"Location": "http://example.net/rule.txt"}))
    with pytest.raises(SyncError, match="HTTPS"):
        fetch_source(ws, src, None, {})
    serve(monkeypatch, lambda r: httpx.Response(200, content=b"x" * 100))
    monkeypatch.setattr(remote, "MAX_FILE_BYTES", 50)
    with pytest.raises(SyncError, match="size limit"):
        fetch_source(ws, src, None, {})
    monkeypatch.setattr(remote, "MAX_FILE_BYTES", 1000)
    monkeypatch.setattr(remote, "MAX_SOURCE_BYTES", 50)
    with pytest.raises(SyncError, match="total download"):
        fetch_source(ws, src, None, {})


@pytest.mark.parametrize("url", ["http://example.org/r.txt", "file:///etc/passwd", "https://user:pass@example.org/r.txt"])
def test_invalid_remote_urls_never_requested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    seen = serve(monkeypatch, lambda r: httpx.Response(500))
    with pytest.raises(SyncError, match="HTTPS"):
        fetch_source(ws_for(tmp_path), SourceConfig(name="remote", type="http-files", url=url), None, {})
    assert not seen


def test_cli_configuration_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    monkeypatch.setenv("SIGHARVEST_HOME", str(ws.root))
    runner = CliRunner()
    for kind, url, options in [
        ("http-files", URL, ["--url", URL, "--url", "https://example.net/rule.txt"]),
        ("html", "https://example.org/page", []),
        ("huggingface", REPO, ["--file", "rules.jsonl", "--ref", SHA]),
    ]:
        result = runner.invoke(app, ["sources", "add", kind, url, "--type", kind, "--disabled", *options])
        assert result.exit_code == 0, result.output
    configs = load_sources(ws)
    assert len(configs) == 3 and not any(s.enabled for s in configs)
    assert configs[0].urls == [URL, "https://example.net/rule.txt"]
    assert configs[2].files == ["rules.jsonl"] and configs[2].ref == SHA


def test_recovery_after_fetch_without_ingest_at_same_hf_revision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="huggingface", url=REPO, files=["first.json"])

    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/datasets/" in request.url.path:
            return httpx.Response(200, json={"sha": SHA, "siblings": [{"rfilename": "first.json"}, {"rfilename": "second.json"}]})
        raw = fixture("rule.txt").decode().replace("Example remote rule", request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json=[{"raw_yaml": raw}])

    serve(monkeypatch, handler)
    save_sources(ws, [src])
    open_db(ws, migrate=True)  # initialize the offline workspace explicitly
    assert sync_all(ws)[0].status == "ok"
    with open_db(ws, migrate=True)() as session:
        ingested = {o.path: o.file_hash for o in session.scalars(select(Occurrence))}
    src.files = ["second.json"]
    save_sources(ws, [src])
    interrupted = fetch_source(ws, src, SHA, ingested)  # Simulate process exit before ingest.
    assert interrupted.removed == {"first.json/row-000001.yml"}
    outcome = sync_all(ws)[0]
    assert outcome.status == "ok" and outcome.log.new_commit == SHA
    with open_db(ws, migrate=True)() as session:
        current = list(session.scalars(select(Occurrence).where(Occurrence.present.is_(True))))
        assert len(current) == 1 and current[0].path == "second.json/row-000001.yml"
        assert len(list(session.scalars(select(RuleVersion)))) == 2


def test_prose_changes_update_revision_without_rule_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="html", url=URL)
    body = {"raw": fixture("page.html")}
    serve(monkeypatch, lambda r: httpx.Response(200, content=body["raw"]))
    save_sources(ws, [src])
    open_db(ws, migrate=True)  # initialize the offline workspace explicitly
    first = sync_all(ws)[0]
    body["raw"] = body["raw"].replace(b"<h1>Example</h1>", b"<h1>Updated article</h1>")
    second = sync_all(ws)[0]
    assert second.status == "ok" and second.log.new_commit != first.log.new_commit
    assert second.log.files_added == second.log.files_changed == second.log.files_removed == 0


def test_last_modified_and_unexpected_304(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="http-files", url=URL)
    stamp = "Mon, 26 Oct 2026 10:00:00 GMT"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("if-modified-since") == stamp:
            return httpx.Response(304)
        return httpx.Response(200, content=fixture("rule.txt"), headers={"Last-Modified": stamp})

    seen = serve(monkeypatch, handler)
    first = fetch_source(ws, src, None, {})
    second = fetch_source(ws, src, first.new_commit, {})
    assert seen[-1].headers["if-modified-since"] == stamp and not second.changed
    serve(monkeypatch, lambda r: httpx.Response(304))
    with pytest.raises(SyncError, match="without a verified"):
        fetch_source(ws, SourceConfig(name="new", type="http-files", url=URL), None, {})


def test_failed_second_url_keeps_the_entire_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="http-files", url=URL, urls=[URL, "https://example.net/rule.txt"])
    state = {"fail": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["fail"] and request.url.host == "example.net":
            return httpx.Response(404)
        body = fixture("rule.txt") + (b"# updated\n" if state["fail"] else b"")
        return httpx.Response(200, content=body)

    serve(monkeypatch, handler)
    first = fetch_source(ws, src, None, {})
    saved = manifest(ws)
    state["fail"] = True
    with pytest.raises(SyncError, match="404"):
        fetch_source(ws, src, first.new_commit, {})
    assert manifest(ws) == saved
    assert all((first.root / path).read_bytes() == fixture("rule.txt") for path in first.added)


def test_hf_sha_mismatch_and_default_file_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="remote", type="huggingface", url=REPO, ref=SHA)

    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/datasets/" in request.url.path:
            return httpx.Response(200, json={"sha": SHA2, "siblings": [{"rfilename": "rules.json"}, {"rfilename": "metrics.json"}]})
        return httpx.Response(200, content=fixture("rules.json") if request.url.path.endswith("rules.json") else b'{"count": 42}')

    serve(monkeypatch, handler)
    with pytest.raises(SyncError, match="different revision"):
        fetch_source(ws, src, None, {})
    src.ref = "main"
    result = fetch_source(ws, src, None, {})
    assert result.added == {"rules.json/row-000001.yml"}


def test_generated_path_filters_and_config_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    serve(monkeypatch, lambda r: httpx.Response(200, content=fixture("article.txt")))
    src = SourceConfig(name="remote", type="http-files", url=URL, paths=["*/fence-*.yml"])
    result = fetch_source(ws, src, None, {})
    assert len(result.added) == 1 and "fence-" in next(iter(result.added))
    for kwargs in ({"urls": [URL]}, {"files": ["rules.json"]}):
        with pytest.raises(ValueError):
            SourceConfig(name="bad", type="local", url="/tmp", **kwargs)
    with pytest.raises(ValueError):
        SourceConfig(name="..\\escape", type="local", url="/tmp")
