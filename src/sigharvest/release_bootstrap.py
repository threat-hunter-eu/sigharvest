"""`sigharvest init --from-release`: a workspace from a published release pack, without cloning any repository.

The pack's rules.jsonl.gz holds every rule whose licence allows redistribution as YAML, with its source, licence
and the path of its canonical copy. Those rules are written to data/release/<content id>/<source>/<original path>
and registered as one local source per original source, named `release-<source>`, with the source's licence from
manifest.json; the source's own licence files from LICENSES.zip go to data/licences/. Then the normal ingest and
index run (the same code as `update`), so search, export, the web UI and the static site work at once.
Validation is left for a later `sigharvest update` (doctor reports it). Metadata-only rules (no licence, restricted)
have no text in the pack and are not in the workspace; the pack's rules.jsonl.gz still lists them.

Switch to live sources at any time: `sigharvest init --force` (curated preset) then `sigharvest update`.
"""

from __future__ import annotations

import errno
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from sigharvest.config import SourceConfig, Workspace
from sigharvest.errors import SigharvestError

# The rule packs live in a separate public data repository (releases rules-YYYY-MM-DD only); the code stays in
# threat-hunter-eu/sigharvest. SIGHARVEST_RELEASE_REPO overrides it (a fork, a mirror).
DEFAULT_REPO = "threat-hunter-eu/sigharvest-rules"
# Until the data repository has its first rules-* release, `latest` falls back to the packs in the tool repository.
FALLBACK_REPO = "threat-hunter-eu/sigharvest"
PREFIX = "release-"
_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
CONTENT_ID = re.compile(r"[0-9a-f]{16,128}")
# LICENSES.zip of an untrusted pack: bounded however its headers look.
MAX_ZIP_MEMBERS = 2000
MAX_ZIP_BYTES = 8 * 1024**2
# The archive itself, checked before zipfile reads its central directory (a real pack's is a few KiB).
MAX_ZIP_FILE = 16 * 1024**2
MAX_PART = 150  # characters per path component of a rule written from the pack
MAX_FILES_PER_SOURCE = 8


class BootstrapError(SigharvestError):
    """The release cannot be used to start a workspace."""


class NoRelease(BootstrapError):
    """The repository does not exist (or is not reachable) or has no rules-* release yet."""


@dataclass
class Bootstrap:
    content_id: str
    created: str
    sources: list[SourceConfig] = field(default_factory=list)
    rules: int = 0
    metadata_only: int = 0
    folder: Path | None = None
    incomplete: bool = False  # the pack was built with --allow-incomplete from a partial corpus


def latest_url(repo: str = DEFAULT_REPO) -> str:
    """Download base URL of the newest `rules-*` release of a GitHub repository (package releases are skipped)."""
    import os

    import httpx

    headers = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = httpx.get(f"https://api.github.com/repos/{repo}/releases?per_page=50", headers=headers, timeout=60, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise BootstrapError(f"cannot list the releases of {repo}: {type(exc).__name__}") from None
    if r.status_code == 404:
        raise NoRelease(
            f"cannot list the releases of {repo}: HTTP 404 (the repository is private, renamed or does not exist). "
            "Pass a release download URL or a local release folder instead of latest."
        )
    if r.status_code != 200:
        raise BootstrapError(f"cannot list the releases of {repo}: HTTP {r.status_code}")
    for item in r.json():
        tag = str(item.get("tag_name") or "")
        if tag.startswith("rules-") and not item.get("draft"):
            return f"https://github.com/{repo}/releases/download/{tag}/"
    raise NoRelease(f"{repo} has no rules-* release yet; pass a release download URL or a local release folder")


def resolve(location: str, note: Callable[[str], None] | None = None) -> str:
    """`latest` (or empty) -> the newest rules-* release URL; a URL or a local release folder as given.

    Without SIGHARVEST_RELEASE_REPO, `latest` tries the data repository first and, when it does not exist yet or has
    no rules-* release, the tool repository (FALLBACK_REPO), saying so in one line through `note`."""
    if location in ("", "latest"):
        import os

        if chosen := os.environ.get("SIGHARVEST_RELEASE_REPO"):
            return latest_url(chosen)
        try:
            return latest_url(DEFAULT_REPO)
        except NoRelease:
            if note is not None:
                note(f"no rules-* release in {DEFAULT_REPO} yet; using the latest one from {FALLBACK_REPO}")
            return latest_url(FALLBACK_REPO)
    return location


def _safe_rel(path: str | None, fallback: str) -> str:
    """A relative POSIX path inside the source folder (no absolute paths, no '..', no odd characters)."""
    # The root anchor is "/" or, for exactly two leading slashes, "//" (POSIX keeps it): drop either.
    parts = [p for p in PurePosixPath(path or "").parts if p.strip("/") not in ("", ".")]
    if not parts or any(p == ".." or p.startswith(".") or "\\" in p or "\0" in p or len(p) > MAX_PART for p in parts) or len(parts) > 20:
        return fallback
    rel = "/".join(parts)
    if not rel.lower().endswith((".yml", ".yaml")):
        rel += ".yml"
    return rel


def source_name(name: str) -> str:
    return PREFIX + (_NAME.sub("-", name).strip("-.") or "source")[:150]


class _Names:
    """Workspace source names for the pack's sources: sanitised, and unique even when two original names differ
    only in characters the sanitising replaces (`up stream`, `up-stream`): later ones get a short hash suffix."""

    def __init__(self) -> None:
        self.of: dict[str, str] = {}
        self._taken: set[str] = set()

    def __call__(self, original: str) -> str:
        if original not in self.of:
            name = source_name(original)
            if name.casefold() in self._taken:
                name = f"{name[: len(PREFIX) + 140]}-{hashlib.sha256(original.encode('utf-8', 'surrogatepass')).hexdigest()[:8]}"
            self._taken.add(name.casefold())
            self.of[original] = name
        return self.of[original]


def _write_rule(folder: Path, rel: str, text: str, logic_hash: str, used: set[str]) -> None:
    """Write one rule at `rel` inside `folder`, or at a name from its logic hash when that path cannot be used (taken,
    a file where a folder is needed or the reverse, a name the file system refuses)."""
    candidates = [rel, f"{logic_hash[:16]}.yml", f"{logic_hash}.yml"]
    for i, candidate in enumerate(candidates):
        if candidate in used:
            continue
        out = (folder / candidate).resolve()
        if not out.is_relative_to(folder.resolve()):
            raise BootstrapError("a rule path of the release points outside its folder")
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("x", encoding="utf-8", errors="surrogatepass") as fh:
                fh.write(text)
        except (FileExistsError, NotADirectoryError, IsADirectoryError):
            continue
        except OSError as exc:
            if exc.errno in (errno.ENAMETOOLONG, errno.EINVAL, errno.EILSEQ) and i + 1 < len(candidates):
                continue
            raise BootstrapError(f"cannot write a rule of the release: {exc.strerror or type(exc).__name__}") from None
        used.add(candidate)
        return
    raise BootstrapError(f"the release has several rules with logic {logic_hash[:16]} at conflicting paths")


def _release_folder(ws: Workspace, content_id: str) -> Path:
    """data/release/<content id prefix>/, refused unless it resolves inside data/release/ (the id comes from an
    untrusted manifest; it is also checked to be hexadecimal)."""
    if not CONTENT_ID.fullmatch(content_id):
        raise BootstrapError("invalid release content_id")
    base = (ws.root / "data" / "release").resolve()
    target = (base / content_id[:16]).resolve()
    if target.parent != base:
        raise BootstrapError("release folder outside the workspace")
    return target


def _upstream_licences(path: Path, sources: dict[str, str], name_rx: re.Pattern[str], max_file: int) -> dict[str, dict[str, bytes]]:
    """LICENSES/<folder>/<file> members of the pack's LICENSES.zip ({folder: source}, licence_texts.licence_folder),
    for the sources actually used only, keyed by source. Bounded
    regardless of the zip headers: members examined, files per source, bytes per file (read with a cap) and in all."""
    out: dict[str, dict[str, bytes]] = defaultdict(dict)
    if not path.is_file():
        return out
    if path.stat().st_size > MAX_ZIP_FILE:
        raise BootstrapError(f"LICENSES.zip is larger than {MAX_ZIP_FILE // 1024**2} MiB; a release pack's is a few KiB")
    total = 0
    with zipfile.ZipFile(path) as zf:
        for n, member in enumerate(zf.infolist()):
            if n >= MAX_ZIP_MEMBERS:
                break
            parts = PurePosixPath(member.filename).parts
            if len(parts) != 3 or parts[0] != "LICENSES" or parts[1] not in sources or not name_rx.fullmatch(parts[2]):
                continue
            source = sources[parts[1]]
            if len(out[source]) >= MAX_FILES_PER_SOURCE or member.is_dir():
                continue
            with zf.open(member) as fh:
                data = fh.read(max_file + 1)
            if len(data) > max_file:
                continue
            total += len(data)
            if total > MAX_ZIP_BYTES:
                break
            out[source][parts[2]] = data
    return out


def materialise(release_folder: Path, ws: Workspace, *, sums_sha256: str | None = None) -> Bootstrap:
    """Verify the release (SHA256SUMS, and its own digest when given), write its redistributable rules into the
    workspace and return the sources."""
    from sigharvest.licence_texts import LICENCE_FILE, MAX_LICENCE_BYTES, licence_folder, store_upstream
    from sigharvest.release_reader import ReleaseError, open_release

    names = _Names()
    try:
        with open_release(release_folder, sums_sha256) as reader:
            manifest = reader.manifest
            content_id = str(manifest.get("content_id") or "")
            if not CONTENT_ID.fullmatch(content_id):
                raise BootstrapError("the release manifest has no valid content_id")
            target = _release_folder(ws, content_id)
            if target.exists():
                shutil.rmtree(target)
            boot = Bootstrap(content_id, str(manifest.get("created") or ""), folder=target, incomplete=manifest.get("incomplete") is True)
            used: dict[str, set[str]] = defaultdict(set)
            for row in reader.rows():
                text = row.get("yaml")
                if not text:
                    boot.metadata_only += 1
                    continue
                canonical = row.get("canonical") or {}
                source = str(canonical.get("source") or "unknown")
                rel = _safe_rel(canonical.get("path"), f"{row['logic_hash'][:16]}.yml")
                if rel in used[source]:  # another document of the same multi-document file
                    stem, n = rel.rsplit(".", 1)[0], 0
                    while rel in used[source]:
                        rel = f"{stem}__{row['logic_hash'][:8]}{f'_{n}' if n else ''}.yml"
                        n += 1
                _write_rule(target / names(source), rel, text, str(row["logic_hash"]), used[source])
                boot.rules += 1
            upstream = _upstream_licences(reader.folder / "LICENSES.zip", {licence_folder(s): s for s in used}, LICENCE_FILE, MAX_LICENCE_BYTES)
    except (ReleaseError, zipfile.BadZipFile) as exc:
        raise BootstrapError(f"release check failed: {exc}") from None
    except OSError as exc:
        raise BootstrapError(f"cannot write the release into the workspace: {exc.strerror or type(exc).__name__}") from None
    by_name = {str(s.get("name")): s for s in manifest.get("sources") or [] if isinstance(s, dict)}
    for original in sorted(used):
        info = by_name.get(original, {})
        name = names(original)
        boot.sources.append(
            SourceConfig(
                name=name,
                url=str(target / name),
                type="local",
                licence=info.get("licence"),
                priority=int(info.get("priority") or 50) if str(info.get("priority") or "").isdigit() else 50,
                redistributable=True,  # the pack shipped its text, so its licence and source allow it
                notes=f"from sigharvest release {content_id[:16]} ({boot.created[:10]}); upstream {info.get('url') or 'unknown'}",
            )
        )
        if original in upstream:
            store_upstream(ws, name, upstream[original])
    return boot


def bootstrap(
    ws: Workspace,
    location: str,
    *,
    progress: Any = None,
    workers: int = 8,
    sums_sha256: str | None = None,
    counts: Any = None,
    note: Callable[[str], None] | None = None,
) -> Bootstrap:
    """Download (or open) a release, materialise it, register its sources, ingest and index. Returns the summary.

    `sums_sha256` (the SHA-256 of the pack's SHA256SUMS, published out of band) pins the pack: without it the
    checksums only prove the files are intact, not who made them. sources.yaml is only replaced once every rule is
    written, and put back as it was when ingesting fails, so a failed start never leaves an unusable workspace."""
    import httpx

    from sigharvest.config import load_sources, save_sources
    from sigharvest.release_reader import ReleaseError, fetch_release

    say = progress or (lambda _msg: None)
    url = resolve(location, note or say)
    ws.root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sigharvest-release-", dir=ws.root) as tmp:
        say(f"fetching {url}")
        try:
            folder = fetch_release(url, Path(tmp))
        except ReleaseError as exc:
            raise BootstrapError(str(exc)) from None
        except httpx.HTTPError as exc:
            raise BootstrapError(f"cannot download the release: {type(exc).__name__}") from None
        except OSError as exc:
            raise BootstrapError(f"cannot download the release: {exc.strerror or type(exc).__name__}") from None
        say("verifying checksums and writing rules")
        boot = materialise(folder, ws, sums_sha256=sums_sha256)
    if not boot.sources:
        raise BootstrapError("the release has no redistributable rule text to start from")
    previous = ws.sources_file.read_bytes() if ws.sources_file.is_file() else None
    save_sources(ws, boot.sources)
    try:
        try:
            load_sources(ws)  # the file every later command reads must load
        except ValueError as exc:
            raise BootstrapError(f"the release's sources cannot be registered: {exc}") from None
        _ingest(ws, boot, url, say, workers, counts)
    except BaseException:
        if previous is None:
            ws.sources_file.unlink(missing_ok=True)
        else:
            ws.sources_file.write_bytes(previous)
        raise
    return boot


# Local pack folders: snapshotting them is Python work, so more threads only take the GIL from the single ingest
# writer. One snapshot thread still overlaps the ingest (19,444 rules: ingest 1m43s with 22 threads, 55 s with 2, 35 s with 1).
SNAPSHOT_THREADS = 1


def _ingest(ws: Workspace, boot: Bootstrap, url: str, say: Any, workers: int, counts: Any = None) -> None:
    """Ingest and index. `say` gets each step ("ingest: <source>: 500/2,000 files", "index: identity families", ...);
    `counts` (done, total) the semantic-hash progress."""
    from sigharvest.service import open_db, sync_all

    sessions = open_db(ws, migrate=True)
    say(f"ingesting {boot.rules:,} rules from {len(boot.sources)} sources")
    failed = [o.name for o in sync_all(ws, workers=SNAPSHOT_THREADS, progress=lambda m: say(f"ingest: {m}")) if o.status != "ok"]
    if failed:
        raise BootstrapError(f"ingest failed for {', '.join(failed[:5])}")
    from sigharvest.db import set_meta
    from sigharvest.index import rebuild
    from sigharvest.semantic import backfill

    say("indexing")
    with sessions() as s:
        backfill(s, workers=workers, progress=counts)
        rebuild(s, progress=say, workers=workers)
        set_meta(s, "bootstrap_release", json.dumps({"content_id": boot.content_id, "created": boot.created, "url": url, "incomplete": boot.incomplete}))
        s.commit()
