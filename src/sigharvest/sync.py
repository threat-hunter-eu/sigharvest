"""Fetch sources into corpus/<name>/ and report which files changed.

git sources: shallow clone, then `git fetch --depth 1` + diff between the previous and the new commit.
http sources: download a file or archive; change detection by content hash.
local sources: read in place; change detection by content hash.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
import time
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from sigharvest.config import SourceConfig, Workspace
from sigharvest.documents import MAX_FILE_BYTES
from sigharvest.identity import sha256_hex
from sigharvest.retry import RetryBudget, git_category
from sigharvest.source_selection import path_selected


class SyncError(RuntimeError):
    """A source cannot be fetched (bad URL or ref, refused input, size limit, git failure)."""

    def __init__(self, message: str, *, category: str | None = None) -> None:
        super().__init__(message)
        self.category = category or git_category(RuntimeError(message))


MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_GIT_ERROR_CHARS = 500  # of git's stderr kept in a SyncError
ALLOWED_GIT_URL = ("https://", "ssh://", "git@", "file://")
_SAFE_REF = re.compile(r"^[A-Za-z0-9._/+-]{1,200}$")


def _check_git_inputs(url: str, ref: str | None) -> None:
    if url.startswith("-") or (not url.startswith(ALLOWED_GIT_URL) and not Path(url).is_absolute()):
        raise SyncError(f"refusing git url {url!r}: only https, ssh and local absolute paths are allowed")
    if ref is not None and (ref.startswith("-") or not _SAFE_REF.match(ref) or ".." in ref):
        raise SyncError(f"refusing git ref {ref!r}")


@dataclass
class SyncResult:
    """What a fetch found: the old and new commit (or tree digest), the files on disk and what changed."""

    old_commit: str | None
    new_commit: str | None
    root: Path
    added: set[str] = field(default_factory=set)
    changed: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    full_scan: bool = False
    skipped_non_sigma: int = 0
    skipped_large: int = 0
    skipped_unsafe_path: int = 0
    snapshot_id: str | None = None
    file_hashes: dict[str, str] | None = None


STALL_BYTES_PER_SECOND = 1000
STALL_SECONDS = 60
# A stalled or cut clone/fetch (transient) is tried again, twice at most, after a short backoff. Many parallel clones
# from one runner can stall for a minute; the same repository then clones in seconds.
NETWORK_RETRIES = 2
NETWORK_RETRY_WAIT = 30.0


def _auth_header(token: str, url: str) -> str:
    """GitLab accepts a token over git HTTP as Basic oauth2:<token>; GitHub and most others accept Bearer."""
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    if host == "gitlab.com" or host.startswith("gitlab."):
        import base64

        return "Authorization: Basic " + base64.b64encode(f"oauth2:{token}".encode()).decode()
    return f"Authorization: Bearer {token}"


def _git(args: list[str], cwd: Path | None = None, token: str | None = None, url: str = "", timeout: int = 1800) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    # A stalled HTTP transfer (seen on first clones: one source hung for 10 minutes before failing) aborts after
    # STALL_SECONDS below STALL_BYTES_PER_SECOND instead of holding the whole update; retries handle the rest.
    env.setdefault("GIT_HTTP_LOW_SPEED_LIMIT", str(STALL_BYTES_PER_SECOND))
    env.setdefault("GIT_HTTP_LOW_SPEED_TIME", str(STALL_SECONDS))
    cmd = [
        "git",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.ssh.allow=always",
        "-c",
        "protocol.file.allow=always",
        "-c",
        "core.hooksPath=/dev/null",
    ]
    if token:
        # The header goes through the environment (GIT_CONFIG_*), not argv, so it is not visible in `ps` or
        # /proc/*/cmdline, and it is never written to .git/config.
        env |= {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader", "GIT_CONFIG_VALUE_0": _auth_header(token, url)}
    budget = RetryBudget(max_attempts=NETWORK_RETRIES, max_wait=NETWORK_RETRY_WAIT) if args[0] in ("clone", "fetch") else None
    while True:
        proc = subprocess.run([*cmd, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return proc.stdout
        category = "missing_ref" if args[0] == "ls-remote" and proc.returncode == 2 else git_category(RuntimeError(proc.stderr))
        delay = budget.delay(category) if budget is not None else None
        if budget is None or delay is None:
            raise SyncError(f"git {args[0]} failed ({category})", category=category)
        budget.attempts += 1
        if args[0] == "clone" and Path(args[-1]).exists():
            # git removes a clone target it created, but a half-written one must not make the retry refuse it.
            shutil.rmtree(args[-1], ignore_errors=True)
        time.sleep(delay)


def _list_files(root: Path) -> list[str]:
    out = []

    def failed(exc: OSError) -> None:
        raise exc

    for dirpath, dirnames, filenames in os.walk(root, onerror=failed):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for f in filenames:
            out.append(str((Path(dirpath) / f).relative_to(root)).replace(os.sep, "/"))
    # os.walk follows the filesystem's directory order (hash order on ext4): sorted, a full scan ingests files in the
    # same order as an incremental one, so row ids do not depend on the disk.
    return sorted(out)


_PROMISOR_KEYS = ("remote.origin.promisor", "extensions.partialclone", "remote.origin.partialclonefilter")


def _drop_promisor(repo: Path) -> None:
    """Make filtered-out blobs read as missing instead of being downloaded lazily."""
    for key in _PROMISOR_KEYS:
        subprocess.run(["git", "config", "--unset", key], cwd=repo, capture_output=True, check=False)


def _git_bytes(args: list[str], cwd: Path, stdin: bytes | None = None, *, offline: bool = False) -> bytes:
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        timeout=1800,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", **({"GIT_ALLOW_PROTOCOL": "", "GIT_NO_LAZY_FETCH": "1"} if offline else {})},
    )
    if proc.returncode != 0:
        raise SyncError(f"git {' '.join(args[:2])} failed: {proc.stderr.decode(errors='replace').strip()[:MAX_GIT_ERROR_CHARS]}")
    return proc.stdout


# Git stores a tree once however often it is referenced, so a 2 KiB repository can list billions of paths
# (a tree of 40 entries pointing at a tree of 40 entries...). The listing is read as a stream and refused past this.
MAX_TREE_ENTRIES = 500_000


def ls_tree_entries(cmd: list[str], cwd: Path, env: dict[str, str] | None = None, max_entries: int | None = None) -> Iterator[bytes]:
    """The NUL-separated entries of a `git ls-tree -r -z` command, streamed; SyncError past max_entries."""
    limit = MAX_TREE_ENTRIES if max_entries is None else max_entries
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    count, rest, ok = 0, b"", False
    try:
        while chunk := proc.stdout.read(1 << 20):
            *entries, rest = (rest + chunk).split(b"\0")
            for entry in entries:
                if entry:
                    count += 1
                    if count > limit:
                        raise SyncError(f"repository tree lists more than {limit} files; refusing it", category="refusing_input")
                    yield entry
        ok = True
    finally:
        if not ok:
            proc.kill()
        proc.stdout.close()
        stderr = proc.stderr.read() if proc.stderr else b""
        if proc.stderr:
            proc.stderr.close()
        code = proc.wait()
    if code != 0:
        raise SyncError(f"git ls-tree failed: {stderr.decode(errors='replace').strip()[:MAX_GIT_ERROR_CHARS]}")
    if rest:
        count += 1
        if count > limit:
            raise SyncError(f"repository tree lists more than {limit} files; refusing it", category="refusing_input")
        yield rest


def _tree(repo: Path, commit: str) -> dict[str, tuple[str, int]]:
    """path -> (blob oid, size) for every regular file of a commit. Size is -1 for blobs that are not present."""
    out: dict[str, tuple[str, int]] = {}
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "ls-tree", "-r", "-l", "-z", commit]
    for entry in ls_tree_entries(cmd, repo, {**os.environ, "GIT_TERMINAL_PROMPT": "0"}):
        meta, _, path = entry.partition(b"\t")
        parts = meta.split()
        if len(parts) == 4 and parts[1] == b"blob" and parts[0] in (b"100644", b"100755"):
            size = int(parts[3]) if parts[3].isdigit() else -1
            out[path.decode("utf-8", "surrogateescape")] = (parts[2].decode(), size)
    return out


def _read_blobs(repo: Path, oids: list[str]) -> dict[str, bytes]:
    """Read many blobs with one `git cat-file --batch`; missing (filtered) blobs are left out."""
    if not oids:
        return {}
    data = _git_bytes(["cat-file", "--batch"], repo, stdin="".join(f"{o}\n" for o in oids).encode())
    out: dict[str, bytes] = {}
    pos = 0
    for oid in oids:
        nl = data.index(b"\n", pos)
        header = data[pos:nl].split()
        pos = nl + 1
        if len(header) == 2 and header[1] == b"missing":
            continue
        size = int(header[2])
        out[oid] = data[pos : pos + size]
        pos += size + 1
    return out


BATCH_BYTES = 64 * 1024 * 1024


def _byte_chunks(paths: list[str], tree: dict[str, tuple[str, int]]) -> list[list[str]]:
    """Split paths so that one `cat-file --batch` call never buffers more than BATCH_BYTES of blob data."""
    chunks: list[list[str]] = [[]]
    size = 0
    for p in paths:
        blob = max(tree[p][1], 0)
        if chunks[-1] and size + blob > BATCH_BYTES:
            chunks.append([])
            size = 0
        chunks[-1].append(p)
        size += blob
    return [c for c in chunks if c]


def _materialise(repo: Path, commit: str, paths: list[str], dest: Path, tree: dict[str, tuple[str, int]], result: SyncResult | None = None) -> set[str]:
    """Write the files that look like Sigma into dest; remove the others. Returns the paths written."""
    from sigharvest.documents import looks_like_sigma

    root = dest.resolve()
    # A `.git` component (a blob named .git at the root, or a .git/ folder committed by mistake) would make the next
    # sync mistake corpus/<name>/ for an old work-tree layout and rebuild it every run.
    wanted = [p for p in paths if p in tree and 0 <= tree[p][1] <= MAX_FILE_BYTES and ".git" not in p.split("/")]
    from sigharvest.source_snapshots import MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_FILES

    written: set[str] = set()
    written_bytes = 0
    for chunk in _byte_chunks(wanted, tree):
        blobs = _read_blobs(repo, list(dict.fromkeys(tree[p][0] for p in chunk)))
        for p in chunk:
            target = (root / p).resolve()
            if not target.is_relative_to(root):
                continue
            content = blobs.get(tree[p][0])
            if content is None:
                raise SyncError("eligible Git blob is missing; rebuild the source Git cache and retry")
            if content is not None and looks_like_sigma(content):
                written_bytes += len(content)
                if len(written) >= MAX_SNAPSHOT_FILES or written_bytes > MAX_SNAPSHOT_BYTES:
                    raise SyncError(
                        f"source has more than {MAX_SNAPSHOT_FILES} rule files or {MAX_SNAPSHOT_BYTES} bytes; refusing it", category="refusing_input"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                written.add(p)
            else:
                if result is not None and Path(p).suffix.lower() in {".yaml", ".yml"}:
                    result.skipped_non_sigma += 1
                if target.is_file():
                    target.unlink()
    for p in set(paths) - set(wanted):
        target = (root / p).resolve()
        if target.is_relative_to(root) and target.is_file():
            target.unlink()
    return written


def remote_commit(src: SourceConfig) -> str:
    """Resolve the selected remote HEAD, branch or tag without cloning (60-second timeout).

    Exact ref matching avoids ls-remote's suffix matches. Annotated tags use their peeled commit.
    Ambiguous short names fail closed; use refs/heads/... or refs/tags/... to disambiguate.
    """
    _check_git_inputs(src.url, src.ref)
    ref = src.ref or "HEAD"
    refs = [ref] if ref == "HEAD" or ref.startswith("refs/") else [f"refs/heads/{ref}", f"refs/tags/{ref}"]
    patterns = [p for r in refs for p in (r, r + "^{}")]
    output = _git(["ls-remote", "--exit-code", "--", src.url, *patterns], token=src.token(), url=src.url, timeout=60)
    found = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in patterns and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", parts[0]):
            found[parts[1]] = parts[0]
    matches = [r for r in refs if r in found]
    if len(matches) != 1:
        raise SyncError("remote ref is missing or ambiguous; select an explicit branch or tag")
    selected = matches[0]
    return found.get(selected + "^{}", found[selected])


def sync_git(src: SourceConfig, ws: Workspace, last_commit: str | None, remote_check: bool = False, cached_files: dict[str, str] | None = None) -> SyncResult:
    """Bare, shallow, blob-filtered (<= 2 MiB) clone in data/cache/git/<name>.git; only files that look like Sigma are
    written to corpus/<name>/. Incremental runs fetch the new commit and diff it against the previous one."""
    dest = ws.source_dir(src.name)
    repo = ws.git_repo(src.name)
    token = src.token()
    _check_git_inputs(src.url, src.ref)
    if remote_check and remote_commit(src) == last_commit:
        # The DB contains the documents and is authoritative, even on a runner without a git/corpus cache.
        return SyncResult(last_commit, last_commit, dest)
    ref = src.ref or "HEAD"
    if (dest / ".git").exists():
        # Older layout (full work tree in corpus/): start over with the compact layout.
        shutil.rmtree(dest)
    fresh = not (repo / "HEAD").exists()
    if not fresh:
        # A repository without the synced marker was interrupted during its first clone: start over.
        marker = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "refs/sigharvest/synced"], cwd=repo, capture_output=True, text=True, check=False)
        fresh = marker.returncode != 0
    if fresh:
        if repo.exists():
            shutil.rmtree(repo)
        repo.parent.mkdir(parents=True, exist_ok=True)
        args = ["clone", "--bare", "--depth", "1", "--filter=blob:limit=2m", "--no-tags", "--single-branch"]
        if src.ref and src.ref != "HEAD":
            args += ["--branch", src.ref.removeprefix("refs/heads/").removeprefix("refs/tags/")]
        _git([*args, "--", src.url, str(repo)], token=token, url=src.url)
        if src.ref and src.ref.startswith("refs/"):
            # clone --branch accepts short names and prefers a branch over a same-named tag.
            # Fetch the exact ref so an explicitly selected tag cannot ingest that branch instead.
            _git(["fetch", "--depth", "1", "--filter=blob:limit=2m", "--no-tags", "--", src.url, src.ref], cwd=repo, token=token, url=src.url)
        _drop_promisor(repo)
        old = None
        new = _git(["rev-parse", "FETCH_HEAD^{commit}" if src.ref and src.ref.startswith("refs/") else "HEAD"], cwd=repo).strip()
    else:
        old = _git(["rev-parse", "--verify", "--quiet", "refs/sigharvest/synced"], cwd=repo).strip() or None
        # Keep the cached remote consistent with the configured source, including
        # subsequent tooling that uses origin rather than our explicit fetch URL.
        _git(["remote", "set-url", "origin", src.url], cwd=repo)
        _git(["fetch", "--depth", "1", "--filter=blob:limit=2m", "--no-tags", "--", src.url, ref], cwd=repo, token=token, url=src.url)
        _drop_promisor(repo)
        new = _git(["rev-parse", "FETCH_HEAD^{commit}"], cwd=repo).strip()
    result = SyncResult(old, new, dest)
    tree = _tree(repo, new)
    result.skipped_large = sum(size < 0 or size > MAX_FILE_BYTES for _, size in tree.values())
    if any(tree[p][1] < 0 for p in tree.keys() & (cached_files or {}).keys()):
        # A previously retained path must not disappear merely because Git can no
        # longer report its object size. Filtered-out new large assets remain ineligible.
        raise SyncError("previously eligible Git blob is missing; rebuild the source Git cache and retry")
    full = fresh or old is None or last_commit != old or not dest.exists()
    if not full and cached_files is not None and _portable(_hash_tree(dest)) != cached_files:
        full = True  # A damaged materialized cache is not an upstream deletion.
    if full:
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        selected = [p for p in tree if path_selected(p, src)]
        written = _materialise(repo, new, selected, dest, tree, result)
        result.added, result.full_scan = written, True
    elif new != old:
        raw = _git_bytes(["diff", "--name-status", "--no-renames", "-z", old, new, "--"], repo)  # type: ignore[list-item]
        fields = raw.split(b"\0")
        for status, path_b in zip(fields[0::2], fields[1::2], strict=False):
            path = path_b.decode("utf-8", "surrogateescape")
            if not path_selected(path, src):
                continue
            {"A": result.added, "D": result.removed}.get(status.decode()[:1], result.changed).add(path)
        _materialise(repo, new, sorted(result.added | result.changed | result.removed), dest, tree, result)
    _store_licence_files(ws, src.name, repo, tree)
    _git(["update-ref", "refs/sigharvest/synced", new], cwd=repo)
    if new == old:
        return result  # nothing fetched, nothing to prune
    # Keep the object store small: drop everything not reachable from the synced commit.
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "gc", "--quiet", "--prune=now"], cwd=repo, capture_output=True, check=False)
    return result


def _store_licence_files(ws: Workspace, name: str, repo: Path, tree: dict[str, tuple[str, int]]) -> None:
    """Keep the LICENSE / COPYING / NOTICE files at the root of the synced commit (data/licences/<name>/): releases
    and exports ship them with the source's rules (copyright lines, Apache NOTICE). Only root-level files whose name
    says what they are; nothing else of the repository is copied."""
    from sigharvest.licence_texts import LICENCE_FILE, MAX_LICENCE_BYTES, store_upstream

    wanted = {p: oid for p, (oid, size) in tree.items() if "/" not in p and LICENCE_FILE.fullmatch(p) and 0 <= size <= MAX_LICENCE_BYTES}
    blobs = _read_blobs(repo, sorted(set(wanted.values())))
    store_upstream(ws, name, {p: blobs[oid] for p, oid in wanted.items() if oid in blobs})


def _hash_tree(root: Path) -> dict[str, str]:
    from sigharvest.source_snapshots import read_regular

    return {
        rel: sha256_hex(read_regular(root / rel, MAX_FILE_BYTES))
        for rel in _list_files(root)
        if not (root / rel).is_symlink() and (root / rel).is_file() and (root / rel).stat().st_size <= MAX_FILE_BYTES
    }


def _portable(files: dict[str, str]) -> dict[str, str]:
    """Only the paths a source snapshot retains: capture skips non-portable names (a backslash),
    so they are never in the cached manifest and must not read as a damaged cache."""
    from sigharvest.source_snapshots import _safe_path

    out = {}
    for rel, digest in files.items():
        try:
            _safe_path(rel)
        except SyncError:
            continue
        out[rel] = digest
    return out


def _diff_trees(before: dict[str, str], after: dict[str, str], result: SyncResult) -> SyncResult:
    result.added = set(after) - set(before)
    result.removed = set(before) - set(after)
    result.changed = {p for p in set(after) & set(before) if after[p] != before[p]}
    return result


def sync_http(src: SourceConfig, ws: Workspace) -> SyncResult:
    """Download an archive or a single file over http(s) into corpus/<name>/ and diff it with the previous run."""
    dest = ws.source_dir(src.name)
    before = _hash_tree(dest) if dest.exists() else {}
    token = src.token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if not src.url.startswith(("https://", "http://")):
        raise SyncError(f"http source must use http(s): {src.url!r}")
    if token and not src.url.startswith("https://"):
        raise SyncError(f"refusing to send the {src.auth} token over plain http: {src.url!r}; use https")
    skipped_large = 0
    buf = bytearray()
    with httpx.Client(follow_redirects=True, timeout=120, headers=headers) as client, client.stream("GET", src.url) as resp:
        resp.raise_for_status()
        for chunk in resp.iter_bytes():
            buf.extend(chunk)
            if len(buf) > MAX_DOWNLOAD_BYTES:
                raise SyncError(f"download larger than {MAX_DOWNLOAD_BYTES} bytes: {src.url}")
    data = bytes(buf)
    from sigharvest.publication import staged_directory

    with staged_directory(dest) as tmp:
        url = src.url.lower().split("?")[0]
        root = tmp.resolve()
        total = 0

        def _target(name: str, size: int) -> Path | None:
            nonlocal total, skipped_large
            if size > MAX_FILE_BYTES:
                skipped_large += 1
                return None
            parts = Path(name).parts
            if not name or Path(name).is_absolute() or ".." in parts or size > MAX_FILE_BYTES:
                return None
            target = (root / name).resolve()
            if not target.is_relative_to(root):
                return None
            total += size
            if total > MAX_EXTRACTED_BYTES:
                raise SyncError("archive expands beyond the size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            return target

        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    target = _target(member.filename, member.file_size)
                    if target is not None:
                        with zf.open(member) as fh:
                            target.write_bytes(fh.read(MAX_FILE_BYTES + 1)[:MAX_FILE_BYTES])
        elif url.endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for tmember in tf:
                    if not tmember.isfile():
                        continue
                    target = _target(tmember.name, tmember.size)
                    tfh = tf.extractfile(tmember) if target is not None else None
                    if target is not None and tfh is not None:
                        target.write_bytes(tfh.read(MAX_FILE_BYTES))
        else:
            (tmp / Path(url).name).write_bytes(data)
    after = _hash_tree(dest)
    digest = sha256_hex(data)
    return _diff_trees(before, after, SyncResult(None, digest, dest, skipped_large=skipped_large))


def sync_local(src: SourceConfig, ws: Workspace, previous: dict[str, str]) -> SyncResult:
    """Use a local folder as is; changes are found by comparing file hashes with the last ingest."""
    root = Path(src.url).expanduser().resolve()
    if not root.is_dir():
        raise SyncError(f"local source path does not exist: {root}")
    after = _hash_tree(root)
    digest = sha256_hex("".join(f"{k}:{v}\n" for k, v in sorted(after.items())).encode("utf-8", "surrogatepass"))
    return _diff_trees(previous, after, SyncResult(None, digest, root))


def selected_files(result: SyncResult, src: SourceConfig) -> list[str]:
    """The files to ingest: every selected file on a full scan, else only the added and changed ones."""
    files = _list_files(result.root) if result.full_scan else sorted(result.added | result.changed)
    return [f for f in files if path_selected(f, src)]
