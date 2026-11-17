"""One bounded format-1 boundary for release consumers.

Checksums detect corruption. Authenticity requires a separately supplied digest or
an explicit offline signature policy; keys inside a release are never trusted.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, BinaryIO, TypedDict

from sigharvest.conversion import STATUSES as CONVERSION_STATUSES
from sigharvest.errors import SigharvestError

FILES = ("manifest.json", "rules.jsonl.gz", "ATTRIBUTION.md")
HEX = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")
STATUSES = CONVERSION_STATUSES


class ReleaseError(SigharvestError, RuntimeError):
    """A release failed verification, schema validation or a resource budget."""


@dataclass(frozen=True)
class ReleaseLimits:
    file_bytes: int = 2 * 1024**3
    total_bytes: int = 4 * 1024**3
    manifest_bytes: int = 16 * 1024**2
    sums_bytes: int = 64 * 1024
    expanded_bytes: int = 4 * 1024**3
    line_bytes: int = 16 * 1024**2
    rows: int = 1_000_000
    depth: int = 32

    def __post_init__(self) -> None:
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise ValueError("release limits must be positive integers")


@dataclass(frozen=True)
class SignaturePolicy:
    """Offline OpenSSL SHA-256 detached signature, with an operator-selected PEM key.

    Both paths are explicit local inputs, never discovered in the release. The
    public key is the trust anchor; distribute and review it separately.
    """

    public_key: Path
    signature: Path

    def verify(self, sums: Path) -> None:
        executable = shutil.which("openssl")
        if executable is None:
            raise ReleaseError("offline signature verification requires openssl")
        with tempfile.TemporaryDirectory(prefix="sigharvest-signature-") as tmp:
            root = Path(tmp)
            for name, path in (("key.pem", self.public_key), ("signature", self.signature)):
                (root / name).write_bytes(read_bounded(path, 64 * 1024))
            try:
                result = subprocess.run(
                    [executable, "dgst", "-sha256", "-verify", str(root / "key.pem"), "-signature", str(root / "signature"), str(sums)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ReleaseError("offline signature verification failed") from exc
            if result.returncode:
                raise ReleaseError("offline signature verification failed")


class ConversionSummary(TypedDict):
    status: str
    covered_sources: list[str]
    sources: dict[str, str]


def conversion_summary(value: Any) -> ConversionSummary:
    """Accept legacy status strings and current per-source summaries without stringifying objects."""
    if isinstance(value, str):
        value = {"status": value}
    if not isinstance(value, dict) or not isinstance(value.get("status"), str) or value["status"] not in STATUSES:
        raise ReleaseError("invalid conversion status")
    covered = value.get("covered_sources", [])
    sources = value.get("sources", {})
    if not isinstance(covered, list) or not all(isinstance(x, str) for x in covered):
        raise ReleaseError("invalid conversion covered_sources")
    if not isinstance(sources, dict) or not all(isinstance(k, str) and isinstance(v, str) and v in STATUSES for k, v in sources.items()):
        raise ReleaseError("invalid conversion sources")
    if any(sources.get(x) != "ok" for x in covered):
        raise ReleaseError("covered conversion sources must have status ok")
    return {"status": value["status"], "covered_sources": covered, "sources": sources}


@contextmanager
def _regular_file(path: Path) -> Iterator[BinaryIO]:
    """Open without following a final symlink or blocking on a substituted FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    if path.is_symlink():
        raise ReleaseError(f"{path.name}: expected a regular file")
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ReleaseError(f"{path.name}: expected a regular file")
            yield stream
    except OSError as exc:
        raise ReleaseError(f"{path.name}: missing or unreadable regular file") from exc


def read_bounded(path: Path, cap: int) -> bytes:
    with _regular_file(path) as stream:
        body = stream.read(cap + 1)
    if len(body) > cap:
        raise ReleaseError(f"{path.name}: byte limit exceeded")
    return body


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("duplicate JSON key")
        result[key] = value
    return result


def _json(body: bytes, depth: int) -> dict[str, Any]:
    # Check nesting before the JSON parser allocates a nested graph.
    nesting, quoted, escaped = 0, False, False
    for char in body:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            nesting += 1
            if nesting > depth:
                raise ReleaseError("JSON depth limit exceeded")
        elif char in (93, 125):
            nesting -= 1
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: _invalid_number())
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReleaseError("invalid JSON in release") from exc
    if not isinstance(value, dict):
        raise ReleaseError("release JSON must be an object")
    return value


def _invalid_number() -> None:
    raise ReleaseError("non-finite JSON number")


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def _manifest(value: dict[str, Any]) -> None:
    if type(value.get("format")) is not int or value["format"] != 1:
        raise ReleaseError(f"release format {value.get('format')} is not supported (expected 1)")
    if not isinstance(value.get("sources", []), list) or not all(isinstance(x, dict) for x in value.get("sources", [])):
        raise ReleaseError("invalid manifest sources")
    names = [x.get("name") for x in value.get("sources", [])]
    if not all(isinstance(x, str) for x in names) or len(set(names)) != len(names):
        raise ReleaseError("invalid or duplicate manifest source name")
    for source in value.get("sources", []):
        for key in ("type", "url", "commit", "licence"):
            if source.get(key) is not None and not isinstance(source[key], str):
                raise ReleaseError(f"invalid source {key}")
        for key in ("paths", "exclude"):
            if source.get(key) is not None and not _strings(source[key]):
                raise ReleaseError(f"invalid source {key}")
    counts = value.get("counts", {})
    if not isinstance(counts, dict) or any(type(x) is not int or x < 0 for x in counts.values()):
        raise ReleaseError("invalid manifest counts")
    if value.get("created") is not None and not isinstance(value["created"], str):
        raise ReleaseError("invalid manifest created time")
    if "redistributed_classes" in value and not _strings(value["redistributed_classes"]):
        raise ReleaseError("invalid redistributed_classes")


def _row(row: dict[str, Any]) -> None:
    if not isinstance(row.get("logic_hash"), str) or not HEX.fullmatch(row["logic_hash"]):
        raise ReleaseError("invalid rule logic_hash")
    for key in (
        "rule_id",
        "title",
        "description",
        "kind",
        "level",
        "status",
        "author",
        "modified",
        "yaml",
        "licence",
        "licence_from",
        "licence_class",
        "validation",
    ):
        if row.get(key) is not None and not isinstance(row[key], str):
            raise ReleaseError(f"invalid rule {key}")
    for key in ("tags", "sources", "quality_flags"):
        if row.get(key) is not None and not _strings(row[key]):
            raise ReleaseError(f"invalid rule {key}")
    for key in ("logsource", "canonical"):
        if row.get(key) is not None and (not isinstance(row[key], dict) or any(v is not None and not isinstance(v, str) for v in row[key].values())):
            raise ReleaseError(f"invalid rule {key}")
    if row.get("validation") not in (None, "", "ok", "warning", "error", "timeout"):
        raise ReleaseError("invalid validation status")
    if row.get("family") is not None and type(row["family"]) not in (str, int):
        raise ReleaseError("invalid rule family")
    for key in ("score", "n_independent"):
        if row.get(key) is not None and (type(row[key]) not in (int, float) or not math.isfinite(row[key]) or row[key] < 0):
            raise ReleaseError(f"invalid rule {key}")
    if row.get("conversion") is not None:
        if not isinstance(row["conversion"], dict):
            raise ReleaseError("invalid conversion summary")
        for target, value in row["conversion"].items():
            if not NAME.fullmatch(target) or len(target) > 60:
                raise ReleaseError("invalid conversion target")
            conversion_summary(value)


@dataclass
class ReleaseReader:
    """Verified snapshot. Consume rows fully, including when selecting a preview."""

    folder: Path
    manifest: dict[str, Any]
    limits: ReleaseLimits

    def rows(self) -> Iterator[dict[str, Any]]:
        total, count = 0, 0
        seen: set[str] = set()
        try:
            with gzip.open(self.folder / "rules.jsonl.gz", "rb") as stream:
                while line := stream.readline(min(self.limits.line_bytes, self.limits.expanded_bytes - total) + 1):
                    total += len(line)
                    count += 1
                    if len(line) > self.limits.line_bytes or total > self.limits.expanded_bytes or count > self.limits.rows:
                        raise ReleaseError("release expanded-byte, line or row limit exceeded")
                    row = _json(line, self.limits.depth)
                    _row(row)
                    if row["logic_hash"] in seen:
                        raise ReleaseError("duplicate rule logic_hash")
                    seen.add(row["logic_hash"])
                    yield row
        except (OSError, EOFError, zlib.error) as exc:
            raise ReleaseError("invalid or truncated gzip release") from exc
        expected = self.manifest.get("counts", {}).get("rules")
        if expected is not None and count != expected:
            raise ReleaseError("release row count does not match manifest")


@contextmanager
def open_release(
    folder: Path, sums_sha256: str | None = None, *, limits: ReleaseLimits | None = None, trust: SignaturePolicy | None = None
) -> Iterator[ReleaseReader]:
    """Copy, hash and parse the same bounded bytes, avoiding verify/reopen races."""
    limits = limits or ReleaseLimits()
    with tempfile.TemporaryDirectory(prefix="sigharvest-release-reader-") as tmp:
        dest = Path(tmp)
        if not (folder / "SHA256SUMS").exists():
            raise ReleaseError("SHA256SUMS missing: refusing an unverifiable release")
        sums = read_bounded(folder / "SHA256SUMS", limits.sums_bytes)
        (dest / "SHA256SUMS").write_bytes(sums)
        if sums_sha256 and hashlib.sha256(sums).hexdigest() != sums_sha256.strip().lower():
            raise ReleaseError("SHA256SUMS does not match the digest given with --sums-sha256")
        if trust:
            trust.verify(dest / "SHA256SUMS")
        expected = checksum_entries(sums)
        all_bytes = 0
        # Extra signed files (CI run reports) are also verified, never interpreted as paths.
        for name, digest in expected.items():
            cap = limits.manifest_bytes if name == "manifest.json" else limits.file_bytes
            try:
                path = folder / name
                with _regular_file(path) as source, (dest / name).open("wb") as target:
                    total = 0
                    h = hashlib.sha256()
                    while block := source.read(min(1024 * 1024, cap - total + 1)):
                        total += len(block)
                        all_bytes += len(block)
                        if total > cap or all_bytes > limits.total_bytes:
                            raise ReleaseError(f"{name}: byte limit exceeded")
                        h.update(block)
                        target.write(block)
                if h.hexdigest() != digest:
                    raise ReleaseError(f"{name}: SHA-256 does not match SHA256SUMS")
            except OSError as exc:
                raise ReleaseError(f"{name}: missing or unreadable") from exc
        manifest = _json(read_bounded(dest / "manifest.json", limits.manifest_bytes), limits.depth)
        _manifest(manifest)
        yield ReleaseReader(dest, manifest, limits)


def checksum_entries(sums: bytes) -> dict[str, str]:
    """Parse bounded checksum text; accept only flat filenames, including CI report assets."""
    expected = {}
    try:
        for line in sums.decode("utf-8").splitlines():
            digest, sep, name = line.partition("  ")
            if not sep or not HEX.fullmatch(digest) or not NAME.fullmatch(name) or name in expected or name == "SHA256SUMS":
                raise ReleaseError("invalid or duplicate SHA256SUMS entry")
            expected[name] = digest
    except UnicodeError as exc:
        raise ReleaseError("invalid SHA256SUMS encoding") from exc
    for name in FILES:
        if name not in expected:
            raise ReleaseError(f"SHA256SUMS does not list {name}")
    return expected


def read_json(path: Path, cap: int = 16 * 1024**2) -> dict[str, Any]:
    """Bounded object JSON for explicit ancillary site inputs."""
    return _json(read_bounded(path, cap), 32)


INDEX_BYTES = 256 * 1024**2  # index.json.gz expanded


def read_index(path: Path, cap: int = INDEX_BYTES) -> list[dict[str, Any]]:
    """The rules of a release index.json.gz, refusing more than `cap` expanded bytes (a gzip bomb) or a bad shape."""
    try:
        with gzip.open(path, "rb") as fh:
            body = fh.read(cap + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise ReleaseError("invalid or truncated index.json.gz") from exc
    if len(body) > cap:
        raise ReleaseError("index.json.gz is larger than the expanded-size limit")
    try:
        rules = json.loads(body).get("rules", [])
    except (ValueError, AttributeError) as exc:
        raise ReleaseError("invalid index.json.gz") from exc
    if not isinstance(rules, list) or not all(isinstance(r, dict) and isinstance(r.get("logic_hash"), str) for r in rules):
        raise ReleaseError("invalid index.json.gz rules")
    return rules


MAX_DOWNLOAD = 2 * 1024**3  # 2 GiB per file


def fetch_release(location: str, dest: Path) -> Path:
    """A local release folder as is, or the files of a remote one downloaded into dest (checksums verified on open)."""
    if not location.startswith(("https://", "http://")):
        folder = Path(location)
        if not (folder / "manifest.json").is_file():
            raise ReleaseError(f"{location}: no manifest.json (not a release folder)")
        return folder
    if location.startswith("http://"):
        raise ReleaseError("refusing plain http; use https")
    import httpx

    base = location.rstrip("/") + "/"
    budget = ReleaseLimits()
    names = ["SHA256SUMS"]
    total = 0

    def https_only(request: httpx.Request) -> None:
        if request.url.scheme != "https":
            raise ReleaseError("release redirected to a non-https URL")

    with httpx.Client(follow_redirects=True, timeout=120, trust_env=False, event_hooks={"request": [https_only]}) as client:
        for name in names:
            with client.stream("GET", base + name) as r:
                if r.url.scheme != "https":  # a redirect must not downgrade the transport
                    raise ReleaseError(f"{name}: redirected to a non-https URL")
                if r.status_code != 200:
                    raise ReleaseError(f"{name}: HTTP {r.status_code}")
                size = 0
                with (dest / name).open("wb") as fh:
                    for chunk in r.iter_bytes():
                        size += len(chunk)
                        total += len(chunk)
                        cap = min(MAX_DOWNLOAD, budget.sums_bytes if name == "SHA256SUMS" else budget.file_bytes)
                        if size > cap or total > budget.total_bytes:
                            raise ReleaseError(f"{name} is larger than the release download limit")
                        fh.write(chunk)
            if name == "SHA256SUMS":
                names.extend(checksum_entries((dest / name).read_bytes()))
    return dest
