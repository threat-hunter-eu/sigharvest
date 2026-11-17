"""Snapshot reads on the steady-state sync path, without per-file path resolution.

`source_snapshots.load_snapshot` resolves every file path and the generation root
(one lstat per path component) to reject symlink escapes. On an unchanged source
that was more than half of a sync: about 1.2 million lstat calls for 45k files.
`verified_snapshot` performs the same checks, but proves containment with one
non-following directory walk; any path the walk does not show as a plain regular
file goes through the original per-file check, so errors are unchanged.

This lives outside source_snapshots.py on purpose: that module's source bytes are
part of every source's ingest policy fingerprint, so editing it forces a full
re-ingest of the whole corpus on the next sync.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from sigharvest import source_snapshots as snapshots
from sigharvest.config import SourceConfig, Workspace
from sigharvest.documents import MAX_FILE_BYTES
from sigharvest.identity import sha256_hex
from sigharvest.sync import SyncError


def _plain_files(root: Path) -> set[str]:
    """Regular files reachable from root through real directories only."""
    found: set[str] = set()
    stack = [("", str(root))]
    while stack:
        prefix, directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                rel = prefix + entry.name
                if entry.is_dir(follow_symlinks=False):
                    stack.append((rel + "/", entry.path))
                elif entry.is_file(follow_symlinks=False):
                    found.add(rel)
    return found


def _read_manifest(ws: Workspace, cfg: SourceConfig, generation: str) -> tuple[Path, bytes]:
    if not snapshots._HEX.fullmatch(generation):
        raise SyncError("invalid source snapshot generation")
    directory = snapshots._cache(ws, cfg) / "generations" / generation
    if directory.is_symlink():
        raise SyncError("source snapshot generation must not be a symlink")
    raw = snapshots.read_regular(directory / "manifest.json", snapshots.MAX_MANIFEST_BYTES)
    if sha256_hex(raw) != generation:
        raise SyncError("source snapshot manifest checksum mismatch")
    return directory, raw


def verified_snapshot(ws: Workspace, cfg: SourceConfig, generation: str | None = None) -> snapshots.Snapshot:
    """Same contract and errors as `source_snapshots.load_snapshot`.

    Twin of `source_snapshots.load_snapshot`: any check added to or changed in one
    must be mirrored in the other (test_fast_snapshot_verification_matches_load_snapshot
    compares them). That module is not edited here because it is fingerprinted.
    """
    if generation is None:
        try:
            generation = snapshots.read_regular(snapshots._cache(ws, cfg) / "fetched", 64).decode("ascii")
        except (OSError, UnicodeError) as exc:
            raise SyncError("no cached source snapshot; run a normal sync first") from exc
    directory, raw = _read_manifest(ws, cfg, generation)
    try:
        manifest = json.loads(raw)
        if manifest["format"] != 1 or manifest["origin"] != snapshots.origin_fingerprint(cfg):
            raise SyncError("cached snapshot belongs to another URL/ref/file list; run a normal sync first")
        files = manifest["files"]
        if not isinstance(files, dict) or len(files) > snapshots.MAX_SNAPSHOT_FILES:
            raise ValueError
        root = directory / "files"
        if root.is_symlink() or not root.is_dir():
            raise SyncError("source snapshot inventory must be a directory, not a symlink")
        plain = _plain_files(root)
        resolved_root = root.resolve()
        total = 0
        for rel, item in files.items():
            snapshots._safe_path(rel)
            if not isinstance(item, dict) or not isinstance(item.get("sha256"), str) or not snapshots._HEX.fullmatch(item["sha256"]):
                raise ValueError
            if type(item.get("size")) is not int or not 0 <= item["size"] <= MAX_FILE_BYTES:
                raise ValueError
            total += item["size"]
            if total > snapshots.MAX_SNAPSHOT_BYTES:
                raise ValueError
            path = root / rel
            # _safe_path excludes "..", so a walked plain file is inside root.
            if rel not in plain and not path.resolve().is_relative_to(resolved_root):
                raise SyncError("source snapshot path escapes its generation")
            body = snapshots.read_regular(path, MAX_FILE_BYTES)
            if len(body) != item["size"] or sha256_hex(body) != item["sha256"]:
                raise SyncError("source snapshot blob checksum mismatch")
        if not isinstance(manifest["config"], str) or not snapshots._HEX.fullmatch(manifest["config"]):
            raise ValueError
        revision = manifest["revision"]
        if revision is not None and (not isinstance(revision, str) or len(revision) > 64):
            raise ValueError
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SyncError("invalid source snapshot manifest") from exc
    return snapshots.Snapshot(generation, root, manifest)


def manifest_hashes(ws: Workspace, cfg: SourceConfig, generation: str) -> dict[str, str]:
    """Path checksums of a retained generation, from its checksummed manifest only.

    Enough to diff a previously accepted inventory against a new, fully verified
    one: no byte of the old generation is ingested, so its blobs are not reread.
    """
    _, raw = _read_manifest(ws, cfg, generation)
    try:
        manifest = json.loads(raw)
        if manifest["format"] != 1 or manifest["origin"] != snapshots.origin_fingerprint(cfg):
            raise SyncError("cached snapshot belongs to another URL/ref/file list; run a normal sync first")
        files = manifest["files"]
        if not isinstance(files, dict) or len(files) > snapshots.MAX_SNAPSHOT_FILES:
            raise ValueError
        hashes: dict[str, str] = {}
        for rel, item in files.items():
            snapshots._safe_path(rel)
            if not isinstance(item, dict) or not isinstance(item.get("sha256"), str) or not snapshots._HEX.fullmatch(item["sha256"]):
                raise ValueError
            hashes[rel] = item["sha256"]
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SyncError("invalid source snapshot manifest") from exc
    return hashes
