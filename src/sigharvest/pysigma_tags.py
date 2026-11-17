"""MITRE ATT&CK and D3FEND tag catalogues for pySigma's tag validators: fetched once, shared with every worker.

pySigma (1.5 and 2.x alike) loads these catalogues lazily, on the first tag it validates: each process downloads the
full STIX bundle (ATT&CK is about 45 MB) into ~/.cache/pysigma, without a lock. On a fresh machine every worker of the
validate stage therefore started its own download, and on a slow network the stage stalled for hours.

The validate stage instead calls `prepare` once, in the parent process:

- a reduced copy kept in the workspace cache (`cache/pysigma/<name>.json`) is used while younger than `TTL`;
- otherwise the source is downloaded once, within the bounded ATT&CK transport (attack_io.fetch_bundle: one
  300-second budget, 128 MiB cap), and reduced by pySigma's own loader in a short isolated subprocess;
- when that fails, an older copy is used if there is one; with none, that tag check is skipped for this run with
  one note (`Prepared.notes`) and the run continues. Skipping is part of the validation key, so those versions are
  validated again once the catalogue is available.

Workers receive the reduced data in their initializer (`install`), which sets the module attributes pySigma's lazy
loader would otherwise fetch; a skipped catalogue's validator is left out instead, so no worker ever opens a socket.
ATT&CK uses the release pinned for coverage (attack.ATTACK_URL), so validation and coverage agree.
"""

from __future__ import annotations

import importlib
import json
import logging
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TTL = 30 * 24 * 3600  # seconds; a stale copy is still used when the refresh fails
FORMAT = 1
REDUCE_SECONDS = 180  # pySigma parsing the downloaded bundle in the helper subprocess
D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"


@dataclass(frozen=True)
class Catalog:
    name: str
    label: str
    module: str
    validator: str  # pySigma validator class that reads it
    keys: tuple[str, ...]

    @property
    def url(self) -> str:
        if self.name == "attack":
            from sigharvest.attack import ATTACK_URL

            return ATTACK_URL
        return D3FEND_URL


CATALOGS = (
    Catalog(
        "attack",
        "MITRE ATT&CK",
        "sigma.data.mitre_attack",
        "ATTACKTagValidator",
        (
            "mitre_attack_version",
            "mitre_attack_tactics",
            "mitre_attack_techniques",
            "mitre_attack_techniques_tactics_mapping",
            "mitre_attack_intrusion_sets",
            "mitre_attack_software",
            "mitre_attack_datasources",
            "mitre_attack_mitigations",
        ),
    ),
    Catalog(
        "d3fend",
        "MITRE D3FEND",
        "sigma.data.mitre_d3fend",
        "D3FENDTagValidator",
        ("mitre_d3fend_version", "mitre_d3fend_tactics", "mitre_d3fend_techniques", "mitre_d3fend_artifacts"),
    ),
)


# Not read by the tag validators: may be absent when a caller set the catalogues on pySigma's modules itself.
_OPTIONAL: dict[str, Any] = {"mitre_attack_version": "unknown", "mitre_d3fend_version": "unknown", "mitre_attack_techniques_tactics_mapping": {}}


@dataclass
class Prepared:
    """Catalogue data per name (None: unavailable, its check is skipped) and the notes to show once."""

    data: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def skipped(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, d in self.data.items() if d is None))


# Runs in `python -I`: pySigma's public API only (set_cache_dir, set_url, the lazy module attributes), on a local file.
_REDUCE = """
import importlib, json, sys
module, source, cache, keys = sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4])
m = importlib.import_module(module)
m.set_cache_dir(cache)
m.set_url(source)
json.dump({k: getattr(m, k) for k in keys}, sys.stdout)
"""


def _path(cache: Path, c: Catalog) -> Path:
    return cache / "pysigma" / f"{c.name}.json"


def _well_formed(c: Catalog, data: object) -> bool:
    return isinstance(data, dict) and set(data) == set(c.keys) and all(isinstance(data[k], dict) for k in c.keys if not k.endswith("_version"))


def _read(cache: Path, c: Catalog) -> tuple[dict[str, Any], float, str] | None:
    """(data, fetched_at, url) of the stored copy, or None when absent or unreadable."""
    try:
        doc = json.loads(_path(cache, c).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT or not _well_formed(c, doc.get("data")):
        return None
    fetched = doc.get("fetched_at")
    return doc["data"], float(fetched) if isinstance(fetched, int | float) else 0.0, str(doc.get("url"))


def _reduce(c: Catalog, raw: bytes, work: Path) -> dict[str, Any]:
    """The catalogue as pySigma's loader reads it from `raw`, without touching ~/.cache or the network."""
    source = work / "source.json"
    source.write_bytes(raw)
    r = subprocess.run(
        [sys.executable, "-I", "-c", _REDUCE, c.module, str(source), str(work / "diskcache"), json.dumps(c.keys)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=REDUCE_SECONDS,
        check=False,
    )
    if r.returncode:
        last = (r.stderr.decode("utf-8", "replace").strip().splitlines() or ["no output"])[-1]
        raise ValueError(f"pySigma could not read it: {last[:200]}")
    data = json.loads(r.stdout)
    if not _well_formed(c, data):
        raise ValueError("pySigma returned an unexpected catalogue")
    return data


def _download(cache: Path, c: Catalog, fetch: Callable[[str], bytes]) -> dict[str, Any]:
    from sigharvest.attack_io import publish

    try:
        raw = fetch(c.url)
    except (OSError, ValueError) as exc:  # the transport's messages name ATT&CK, whatever the URL
        raise ValueError("no network, or the download failed or timed out") from exc
    folder = cache / "pysigma"
    folder.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="reduce-", dir=folder) as work:
        data = _reduce(c, raw, Path(work))
    doc = {"format": FORMAT, "url": c.url, "fetched_at": time.time(), "data": data}
    publish(_path(cache, c), json.dumps(doc, sort_keys=True).encode("utf-8"))
    return data


def _reason(exc: BaseException) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return "reading it took too long"
    text = str(exc).strip()
    return text[:160] if text else type(exc).__name__


def _fetch(url: str) -> bytes:
    from sigharvest.attack_io import fetch_bundle

    return fetch_bundle(url)


def prepare(cache: Path, *, fetch: Callable[[str], bytes] | None = None, now: Callable[[], float] = time.time) -> Prepared:
    """Make every catalogue available for the validate stage; at most one download each, never a hang.

    `fetch(url) -> bytes` defaults to the bounded ATT&CK transport. Catalogues already set on pySigma's modules in
    this process are used as they are (no file, no network)."""
    out = Prepared()
    for c in CATALOGS:
        try:
            module = importlib.import_module(c.module)
        except ImportError:
            continue  # this pySigma has no such catalogue, nor the validator that reads it
        loaded = vars(module)
        if all(k in loaded for k in c.keys if k not in _OPTIONAL):  # what the tag validators read
            out.data[c.name] = {k: loaded[k] if k in loaded else _OPTIONAL[k] for k in c.keys}
            continue
        stored = _read(cache, c)
        if stored is not None and stored[2] == c.url and 0 <= now() - stored[1] < TTL:
            out.data[c.name] = stored[0]
            continue
        try:
            out.data[c.name] = _download(cache, c, fetch or _fetch)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            if stored is not None:
                out.data[c.name] = stored[0]
                day = time.strftime("%Y-%m-%d", time.gmtime(stored[1]))
                out.notes.append(f"{c.label} tags: could not refresh the catalogue ({_reason(exc)}); using the copy from {day}.")
            else:
                out.data[c.name] = None
                out.notes.append(
                    f"{c.label} tag check skipped this run: the catalogue could not be downloaded ({_reason(exc)}). "
                    "Everything else is validated; the next run with network access adds the check."
                )
    for note in out.notes:
        log.info("%s", note)
    return out


def install(data: dict[str, dict[str, Any] | None]) -> set[str]:
    """In a worker: set the prepared catalogues on pySigma's modules; returns the validator classes to leave out."""
    excluded = set()
    for c in CATALOGS:
        if c.name not in data:
            continue
        values = data[c.name]
        if values is None:
            excluded.add(c.validator)
            continue
        vars(importlib.import_module(c.module)).update(values)
    return excluded
