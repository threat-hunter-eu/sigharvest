"""Immutable fetched source inventories, independent of the DB's accepted generation.

A canonical manifest names bounded SHA-256 blobs. Generation trees hard-link those
blobs for existing file consumers; neither blobs nor generations are ever edited.
The fetched pointer is only a recovery hint. Acceptance lives in the same SQLite
transaction as source membership, under the workspace mutation lease.
"""

from __future__ import annotations

import json
import os
import platform
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from sigharvest.config import SourceConfig, Workspace
from sigharvest.documents import MAX_FILE_BYTES, looks_like_sigma
from sigharvest.fingerprints import digest, package_version, source_digest
from sigharvest.identity import sha256_hex
from sigharvest.source_selection import path_selected
from sigharvest.sync import SyncError, SyncResult, _list_files

MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024
MAX_SNAPSHOT_FILES = 200_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}")
ACTIVE_PREFIX = "source-active:"
CONFIG_PREFIX = "sync-config:"


def origin_fingerprint(cfg: SourceConfig) -> str:
    """Hash acquisition identity without persisting URLs or credential values."""
    return digest([cfg.type, cfg.url, cfg.ref, cfg.urls, cfg.files])


# Modules whose code decides the stored rows (rule_versions, occurrences, quarantine)
# for given file bytes: parsing and Sigma detection (documents.py, always added by
# implementation()), identity hashes, logsource normalization, the ingest writes,
# quarantine records and path selection. Fetch, snapshot I/O, locks, progress and the
# sync orchestration only decide which bytes are fetched and when; those bytes are
# content-addressed, so a changed adapter output reaches ingestion as changed files.
INGEST_MODULES = ("ingest.py", "identity.py", "normalize.py", "quarantine.py", "source_selection.py")
# Bump when plumbing changes which bytes reach ingestion for an unchanged upstream
# (for example what snapshot capture retains); that forces one full re-ingest.
INGEST_POLICY_REVISION = 1


def _components(stage: str, modules: dict[str, str], options: Any) -> dict[str, Any]:
    """The implementation() layout, without its implicit fingerprints.py digest.

    fingerprints.py holds cache-key helpers for every stage and changes often; it
    decides no stored row, so editing it must not re-ingest every source.
    """
    return {
        "contract": "sigharvest-results-v1",
        "stage": stage,
        "python": platform.python_version(),
        "packages": {p: package_version(p) for p in ("pyparsing", "pysigma", "pyyaml")},
        "modules": modules,
        "options": options,
    }


def ingest_policy() -> str:
    modules = {m: source_digest(m) for m in sorted(("documents.py", *INGEST_MODULES))}
    return digest(_components("source-ingest-rows", modules, INGEST_POLICY_REVISION))


def _marker(cfg: SourceConfig, policy: str) -> str:
    return digest([origin_fingerprint(cfg), cfg.paths, cfg.exclude, policy])


def config_fingerprint(cfg: SourceConfig) -> str:
    """Selection and parser policy changes invalidate even an unchanged upstream ref."""
    return _marker(cfg, ingest_policy())


def policy_current(cfg: SourceConfig, stored: str | None) -> bool:
    """True when rows (or a snapshot) accepted under `stored` match what ingestion would now produce."""
    if stored is None:
        return False
    return stored == config_fingerprint(cfg)


def _safe_path(rel: str) -> None:
    if not rel or rel.startswith("/") or "\\" in rel or any(p in ("", ".", "..") for p in rel.split("/")) or "\0" in rel:
        raise SyncError("unsafe source snapshot path")


def read_regular(path: Path, limit: int) -> bytes:
    """Read a bounded regular file without following its final symlink."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise SyncError("source snapshot file is not regular or exceeds its size limit")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise SyncError("source snapshot file exceeds its size limit")
        return raw


def _cache(ws: Workspace, cfg: SourceConfig) -> Path:
    return ws.cache / "source-snapshots" / cfg.name


@dataclass
class Snapshot:
    generation: str
    root: Path
    manifest: dict[str, Any]

    @property
    def hashes(self) -> dict[str, str]:
        return {rel: item["sha256"] for rel, item in self.manifest["files"].items()}


def load_snapshot(ws: Workspace, cfg: SourceConfig, generation: str | None = None) -> Snapshot:
    """Validate the complete retained inventory before a rescan or acknowledgement."""
    cache = _cache(ws, cfg)
    if generation is None:
        try:
            generation = read_regular(cache / "fetched", 64).decode("ascii")
        except (OSError, UnicodeError) as exc:
            raise SyncError("no cached source snapshot; run a normal sync first") from exc
    if not _HEX.fullmatch(generation):
        raise SyncError("invalid source snapshot generation")
    directory = cache / "generations" / generation
    if directory.is_symlink():
        raise SyncError("source snapshot generation must not be a symlink")
    raw = read_regular(directory / "manifest.json", MAX_MANIFEST_BYTES)
    if sha256_hex(raw) != generation:
        raise SyncError("source snapshot manifest checksum mismatch")
    try:
        manifest = json.loads(raw)
        if manifest["format"] != 1 or manifest["origin"] != origin_fingerprint(cfg):
            raise SyncError("cached snapshot belongs to another URL/ref/file list; run a normal sync first")
        files = manifest["files"]
        if not isinstance(files, dict) or len(files) > MAX_SNAPSHOT_FILES:
            raise ValueError
        root = directory / "files"
        if root.is_symlink() or not root.is_dir():
            raise SyncError("source snapshot inventory must be a directory, not a symlink")
        total = 0
        for rel, item in files.items():
            _safe_path(rel)
            if not isinstance(item, dict) or not isinstance(item.get("sha256"), str) or not _HEX.fullmatch(item["sha256"]):
                raise ValueError
            if type(item.get("size")) is not int or not 0 <= item["size"] <= MAX_FILE_BYTES:
                raise ValueError
            total += item["size"]
            if total > MAX_SNAPSHOT_BYTES:
                raise ValueError
            path = root / rel
            if not path.resolve().is_relative_to(root.resolve()):
                raise SyncError("source snapshot path escapes its generation")
            body = read_regular(path, MAX_FILE_BYTES)
            if len(body) != item["size"] or sha256_hex(body) != item["sha256"]:
                raise SyncError("source snapshot blob checksum mismatch")
        if not isinstance(manifest["config"], str) or not _HEX.fullmatch(manifest["config"]):
            raise ValueError
        revision = manifest["revision"]
        if revision is not None and (not isinstance(revision, str) or len(revision) > 64):
            raise ValueError
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SyncError("invalid source snapshot manifest") from exc
    return Snapshot(generation, root, manifest)


def capture(ws: Workspace, cfg: SourceConfig, result: SyncResult) -> Snapshot:
    """Freeze the adapter inventory before ingestion. Never overwrite retained bytes."""
    cache = _cache(ws, cfg)
    generations = cache / "generations"
    blobs = cache / "blobs"
    generations.mkdir(parents=True, exist_ok=True)
    blobs.mkdir(exist_ok=True)
    files: dict[str, dict[str, Any]] = {}
    total = 0
    with TemporaryDirectory(prefix=".stage-", dir=cache) as temporary:
        stage = Path(temporary)
        root = stage / "files"
        root.mkdir()
        for rel in sorted(_list_files(result.root)):
            try:
                _safe_path(rel)
            except SyncError:
                # An upstream name that is legal on POSIX but not a portable snapshot
                # path (a backslash): skip that file, unread, instead of the source.
                result.skipped_unsafe_path += 1
                continue
            path = result.root / rel
            # Local sources may contain links or large non-rule assets. They are not
            # eligible documents; never dereference or buffer them.
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_size > MAX_FILE_BYTES:
                result.skipped_large += 1
                continue
            if not path.resolve().is_relative_to(result.root.resolve()):
                raise SyncError("source file escapes its root")
            raw = read_regular(path, MAX_FILE_BYTES)
            if not looks_like_sigma(raw):
                if Path(rel).suffix.lower() in {".yaml", ".yml"}:
                    result.skipped_non_sigma += 1
                continue
            total += len(raw)
            if total > MAX_SNAPSHOT_BYTES or len(files) >= MAX_SNAPSHOT_FILES:
                raise SyncError("source snapshot exceeds its byte/file budget")
            checksum = sha256_hex(raw)
            blob = blobs / checksum
            if blob.exists():
                if sha256_hex(read_regular(blob, MAX_FILE_BYTES)) != checksum:
                    raise SyncError("retained source blob checksum mismatch")
            else:
                pending = stage / "blob"
                pending.write_bytes(raw)
                pending.replace(blob)
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(blob, target)
            files[rel] = {"sha256": checksum, "size": len(raw)}
        if cfg.type == "local":
            # Describe the bytes actually frozen, not the earlier discovery scan.
            result.new_commit = sha256_hex("".join(f"{p}:{item['sha256']}\n" for p, item in sorted(files.items())).encode("utf-8", "surrogatepass"))
        manifest = {"format": 1, "origin": origin_fingerprint(cfg), "config": config_fingerprint(cfg), "revision": result.new_commit, "files": files}
        raw_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        if len(raw_manifest) > MAX_MANIFEST_BYTES:
            raise SyncError("source snapshot manifest exceeds its size limit")
        generation = sha256_hex(raw_manifest)
        (stage / "manifest.json").write_bytes(raw_manifest)
        destination = generations / generation
        if not destination.exists():
            stage.rename(destination)
        snapshot = load_snapshot(ws, cfg, generation)
        # Pointer publication follows complete verification. A crash before this
        # replace leaves at most an unreferenced, complete generation.
        pending_pointer = cache / ".fetched.tmp"
        pending_pointer.write_text(generation, encoding="ascii")
        pending_pointer.replace(cache / "fetched")
    return snapshot


def attach(result: SyncResult, snapshot: Snapshot, cfg: SourceConfig) -> SyncResult:
    """Make ingestion consume the immutable bytes, while preserving adapter deltas."""
    result.root = snapshot.root
    result.snapshot_id = snapshot.generation
    result.file_hashes = snapshot.hashes
    result.added = {p for p in result.added if p in result.file_hashes and path_selected(p, cfg)}
    result.changed = {p for p in result.changed if p in result.file_hashes and path_selected(p, cfg)}
    result.removed = {p for p in result.removed if path_selected(p, cfg)}
    return result


def rescan(ws: Workspace, cfg: SourceConfig, last_commit: str | None) -> SyncResult:
    """Replay the latest complete fetch, including an unaccepted one, without I/O upstream."""
    snapshot = load_snapshot(ws, cfg)
    result = SyncResult(last_commit, snapshot.manifest["revision"], snapshot.root, full_scan=True)
    # The new configuration/parser gets its own immutable manifest, sharing blobs.
    return attach(result, capture(ws, cfg, result), cfg)
