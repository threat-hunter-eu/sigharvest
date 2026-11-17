"""Bounded HTTPS sources with cached validators, raw hashes and pinned dataset revisions.

The existing http adapter owns ZIP/tar extraction. These adapters only consume explicit
text/page URLs or data files enumerated by the Hugging Face API, never dataset code.
"""

from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from sigharvest.config import SourceConfig, Workspace
from sigharvest.documents import MAX_FILE_BYTES
from sigharvest.identity import sha256_hex
from sigharvest.remote_documents import dataset_rows, html_blocks, parse_json, text_blocks
from sigharvest.retry import RetryBudget, http_category
from sigharvest.source_selection import path_selected
from sigharvest.sync import SyncError, SyncResult, _diff_trees, _hash_tree

MAX_REMOTE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_REMOTE_FILES = 1000
MAX_REDIRECTS = 5
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _https(url: str) -> httpx.URL:
    try:
        parsed = httpx.URL(url)
        if parsed.scheme != "https" or not parsed.host or parsed.userinfo or parsed.fragment:
            raise ValueError
        return parsed
    except (httpx.InvalidURL, ValueError):
        raise SyncError("remote sources require HTTPS URLs without credentials or fragments") from None


def _download(
    client: httpx.Client, url: str, token: str | None, previous: dict[str, Any], cached: bytes | None, limit: int, immutable: bool = False
) -> tuple[bytes, dict[str, Any]]:
    """Retry safe GETs only; keep the last-good source until every download succeeds."""
    budget = RetryBudget(max_attempts=3)
    while True:
        budget.attempts += 1
        try:
            return _download_once(client, url, token, previous, cached, limit, immutable)
        except SyncError as exc:
            delay = budget.delay(exc.category, getattr(exc, "retry_headers", {}))
            if delay is None:
                raise
            time.sleep(delay)


def _download_once(
    client: httpx.Client, url: str, token: str | None, previous: dict[str, Any], cached: bytes | None, limit: int, immutable: bool = False
) -> tuple[bytes, dict[str, Any]]:
    original = _https(url)
    if immutable and cached is not None:
        return cached, previous
    headers = {}
    if cached is not None:
        if previous.get("etag"):
            headers["If-None-Match"] = previous["etag"]
        elif previous.get("last_modified"):
            headers["If-Modified-Since"] = previous["last_modified"]
    current = original
    try:
        for _ in range(MAX_REDIRECTS + 1):
            same_origin = (current.scheme, current.host, current.port) == (original.scheme, original.host, original.port)
            auth = {"Authorization": f"Bearer {token}"} if token and same_origin else {}
            with client.stream("GET", current, headers=headers | auth) as response:
                if response.status_code == 304:
                    if cached is None:
                        raise SyncError("HTTP 304 without a verified cached body")
                    return cached, previous
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise SyncError("redirect without a location")
                    current = _https(str(current.join(location)))
                    continue
                if response.status_code != 200:
                    exc = SyncError(
                        f"remote download failed (HTTP {response.status_code}, {http_category(response.status_code, response.headers)})",
                        category=http_category(response.status_code, response.headers),
                    )
                    exc.retry_headers = dict(response.headers)  # type: ignore[attr-defined]
                    raise exc
                size = response.headers.get("content-length", "")
                if size.isdigit() and int(size) > limit:
                    raise SyncError("remote download exceeds the size limit")
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    body.extend(chunk)
                    if len(body) > limit:
                        raise SyncError("remote download exceeds the size limit")
                metadata: dict[str, Any] = {"sha256": sha256_hex(bytes(body))}
                for header, key in (("etag", "etag"), ("last-modified", "last_modified")):
                    value = response.headers.get(header)
                    if value and len(value) <= 1024 and not any(ord(c) < 32 for c in value) and (not token or token not in value):
                        metadata[key] = value
                return bytes(body), metadata
    except httpx.HTTPError:
        # HTTP exceptions can contain signed URLs or upstream responses; do not log them.
        raise SyncError("remote HTTPS request failed (transient)", category="transient") from None
    raise SyncError("too many HTTPS redirects")


def _dataset_id(url: str) -> str:
    _https(url)
    parsed = urlsplit(url)
    match = re.fullmatch(r"/datasets/([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)/?", parsed.path)
    if parsed.netloc != "huggingface.co" or parsed.query or not match:
        raise SyncError("huggingface URL must be https://huggingface.co/datasets/OWNER/DATASET")
    return match[1]


def _dataset_path(path: str) -> str:
    parts = PurePosixPath(path).parts
    if not path or path.startswith("/") or "\\" in path or any(p in (".", "..") for p in path.split("/")) or any(ord(c) < 32 for c in path):
        raise SyncError("unsafe dataset file path")
    if not parts or not path.lower().endswith((".json", ".jsonl")):
        raise SyncError("dataset files must be JSON or JSONL")
    return path


def _load_manifest(cache: Path) -> dict[str, Any]:
    path = cache / "manifest.json"
    if not path.exists() or path.stat().st_size > MAX_MANIFEST_BYTES:
        return {}
    try:
        data = json.loads(path.read_bytes())
        return data if isinstance(data, dict) and isinstance(data.get("resources"), dict) else {}
    except (ValueError, RecursionError):
        return {}


def sync_remote(src: SourceConfig, ws: Workspace, last_commit: str | None, ingested_files: dict[str, str]) -> SyncResult:
    """Fetch all resources before publishing; failures preserve the previous corpus and manifest."""
    dest = ws.source_dir(src.name)
    before = _hash_tree(dest) if dest.exists() else {}
    cache = ws.cache / "non-git" / src.name
    cache.mkdir(parents=True, exist_ok=True)
    old = _load_manifest(cache)
    resources: dict[str, Any] = {}
    outputs: dict[str, Any] = {}
    total = 0
    written = 0
    with TemporaryDirectory(prefix="snapshot-", dir=cache) as staging, httpx.Client(follow_redirects=False, timeout=120) as client:
        stage = Path(staging)
        corpus = stage / "corpus"
        corpus.mkdir()

        def fetch(url: str, limit: int, immutable: bool = False) -> bytes:
            nonlocal total
            if len(resources) >= MAX_REMOTE_FILES:
                raise SyncError("too many remote files")
            previous = old.get("resources", {}).get(url, {})
            if not isinstance(previous, dict):
                previous = {}
            digest = previous.get("sha256", "")
            cached = None
            if isinstance(digest, str) and _DIGEST.fullmatch(digest):
                blob = cache / f"{digest}.bin"
                if blob.is_file() and blob.stat().st_size <= limit:
                    candidate = blob.read_bytes()
                    if sha256_hex(candidate) == digest:
                        cached = candidate
            raw, metadata = _download(client, url, src.token(), previous, cached, limit, immutable)
            total += len(raw)
            if total > MAX_SOURCE_BYTES:
                raise SyncError("source exceeds the total download size limit")
            resources[url] = metadata
            (stage / f"{metadata['sha256']}.bin").write_bytes(raw)
            return raw

        revision = None
        downloads: list[tuple[str, str]] = []
        if src.type == "huggingface":
            repo = _dataset_id(src.url)
            ref = src.ref or "main"
            if not re.fullmatch(r"[A-Za-z0-9._/+-]{1,200}", ref) or ".." in ref or ref.startswith("-"):
                raise SyncError("invalid dataset revision")
            api_url = f"https://huggingface.co/api/datasets/{repo}/revision/{quote(ref, safe='')}"
            info = parse_json(fetch(api_url, MAX_FILE_BYTES))
            if not isinstance(info, dict) or not isinstance(info.get("sha"), str) or not _SHA.fullmatch(info["sha"]):
                raise SyncError("dataset API did not return a revision SHA")
            revision = info["sha"]
            if _SHA.fullmatch(ref) and ref != revision:
                raise SyncError("dataset API returned a different revision than the requested SHA")
            siblings = info.get("siblings")
            if not isinstance(siblings, list):
                raise SyncError("dataset API did not enumerate files")
            available = {item["rfilename"] for item in siblings if isinstance(item, dict) and isinstance(item.get("rfilename"), str)}
            names = src.files or sorted(p for p in available if p.lower().endswith((".json", ".jsonl")))
            if not names or len(names) > MAX_REMOTE_FILES:
                raise SyncError("dataset has no JSON/JSONL files or too many files; set files explicitly")
            for name in dict.fromkeys(names):
                _dataset_path(name)
                if name not in available:
                    raise SyncError("configured dataset file is missing at this revision")
                downloads.append((name, f"https://huggingface.co/datasets/{repo}/resolve/{revision}/{quote(name, safe='/')}"))
        else:
            urls = list(dict.fromkeys(src.urls or [src.url]))
            if len(urls) > MAX_REMOTE_FILES:
                raise SyncError("too many remote files")
            downloads = [(sha256_hex(url.encode()), url) for url in urls]

        for name, url in downloads:
            raw = fetch(url, MAX_REMOTE_BYTES if revision else MAX_FILE_BYTES, immutable=revision is not None)
            if revision:
                blocks = dataset_rows(raw, name.lower().endswith(".jsonl"))
            else:
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeError:
                    raise SyncError("remote document is not UTF-8") from None
                blocks = html_blocks(text) if src.type == "html" else text_blocks(text)
            if not blocks:
                if revision and not src.files:
                    continue
                raise SyncError("remote resource contains no complete Sigma documents; previous corpus kept")
            for block, content in blocks:
                rel = f"{name}/{block}.yml"
                if not path_selected(rel, src):
                    continue
                written += len(content)
                if written > MAX_SOURCE_BYTES:
                    raise SyncError("extracted rules exceed the total size limit")
                target = corpus / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                outputs[rel] = {"url": url, "block": block, "sha256": sha256_hex(content)}

        if not outputs and src.paths == ["**/*"] and not src.exclude:
            raise SyncError("source contains no complete Sigma documents; previous corpus kept")

        # HTTP identity includes raw resource hashes, so even prose-only edits are traceable.
        digest_data = {url: meta["sha256"] for url, meta in sorted(resources.items())}
        commit = revision or sha256_hex(json.dumps(digest_data, sort_keys=True).encode())
        manifest = {"version": 1, "type": src.type, "revision": commit, "resources": resources, "outputs": outputs}
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise SyncError("source manifest exceeds the size limit")
        after = _hash_tree(corpus)
        result = _diff_trees(before, after, SyncResult(last_commit, commit, dest))
        result.full_scan = last_commit is None or last_commit != old.get("revision") or not dest.exists() or before != ingested_files
        for blob in stage.glob("*.bin"):
            blob.replace(cache / blob.name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        backup = stage / "previous"
        if dest.exists():
            dest.rename(backup)
        try:
            corpus.rename(dest)
            temporary = stage / "manifest.json"
            temporary.write_bytes(manifest_bytes)
            temporary.replace(cache / "manifest.json")
        except OSError:
            if dest.exists():
                shutil.rmtree(dest)
            if backup.exists():
                backup.rename(dest)
            raise
        return result
