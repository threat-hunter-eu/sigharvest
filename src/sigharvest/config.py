"""Workspace layout and sources.yaml handling."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePath
from typing import Any

import yaml

SOURCE_TYPES = ("git", "http", "local", "http-files", "html", "huggingface")


@dataclass
class SourceConfig:
    """One entry of sources.yaml."""

    name: str
    url: str
    type: str = "git"
    ref: str | None = None
    paths: list[str] = field(default_factory=lambda: ["**/*"])
    exclude: list[str] = field(default_factory=list)
    licence: str | None = None
    priority: int = 50
    enabled: bool = True
    auth: str | None = None  # name of the env var holding a token
    notes: str | None = None
    urls: list[str] = field(default_factory=list)  # explicit files/pages; otherwise use url
    files: list[str] = field(default_factory=list)  # exact dataset paths for Hugging Face
    # Whether the source licence allows redistributing rule text (releases ship metadata and a link otherwise).
    # true / false / "unknown"; None means not stated, which ships metadata and a link only (licensing.redistributable).
    # In sources.yaml: `redistribute: yes|no|unknown` (the older `redistributable: true|false` is still read).
    redistributable: bool | str | None = None
    tier: str | None = None  # curated / extended (informational)
    # The publisher's copyright line, e.g. "Copyright (c) 2022 Example Labs" (MIT, BSD, Apache and CC-BY need it in
    # every copy). Releases also read it from the source's own LICENSE / NOTICE files (licence_texts.py).
    copyright: str | None = None

    def __post_init__(self) -> None:
        import re

        if self.auth and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.auth):
            raise ValueError("Source auth must be an environment variable name")
        if self.type not in SOURCE_TYPES:
            raise ValueError(f"source {self.name}: type must be one of {SOURCE_TYPES}")
        if not self.name or any(c in self.name for c in "/\\\0") or self.name.startswith("."):
            raise ValueError(f"invalid source name: {self.name!r}")
        if self.urls and self.type not in ("http-files", "html"):
            raise ValueError("urls is only supported for http-files and html sources")
        if self.files and self.type != "huggingface":
            raise ValueError("files is only supported for huggingface sources")
        if isinstance(self.redistributable, str):
            # Fail closed: only an explicit yes/true allows shipping rule text; any other string means "unknown".
            word = self.redistributable.strip().lower()
            self.redistributable = True if word in ("true", "yes", "1") else False if word in ("false", "no", "0") else "unknown"

    def token(self) -> str | None:
        """The token from the environment variable named by `auth`, if any."""
        return os.environ.get(self.auth) if self.auth else None

    def to_dict(self) -> dict[str, Any]:
        """The entry as written to sources.yaml (empty optional fields left out)."""
        d = asdict(self)
        # `v not in (None, [], False)` would also drop `priority: 0`, because 0 == False.
        out = {k: v for k, v in d.items() if (v is not None and v is not False and v != []) or k in ("paths", "enabled")}
        out.pop("redistributable", None)
        if self.redistributable is not None:
            # Written as `redistribute: yes|no|unknown`, the field name and values shared with suriharvest.
            out["redistribute"] = "yes" if self.redistributable is True else "no" if self.redistributable is False else "unknown"
        if out.get("type") == "git":
            del out["type"]
        return out

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> SourceConfig:
        """Build from a sources file entry; unknown keys are ignored so newer files stay readable."""
        known = set(cls.__dataclass_fields__)
        values = {k: v for k, v in item.items() if k in known}
        if "redistribute" in item:  # the shared name (docs/conventions.md); `redistributable` is still read
            values["redistributable"] = item["redistribute"]
        return cls(**values)


@dataclass
class Workspace:
    """Paths of a workspace: sources.yaml, corpus/, data/ (database and caches) and reports/."""

    root: Path

    @property
    def sources_file(self) -> Path:
        return self.root / "sources.yaml"

    @property
    def corpus(self) -> Path:
        return self.root / "corpus"

    @property
    def db_path(self) -> Path:
        return self.root / "data" / "sigharvest.db"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def cache(self) -> Path:
        return self.root / "data" / "cache"

    def source_dir(self, name: str) -> Path:
        """corpus/<name>/: the files of a source that look like Sigma, at their original paths."""
        return self.corpus / name

    def git_repo(self, name: str) -> Path:
        """data/cache/git/<name>.git: the bare clone of a git source."""
        return self.cache / "git" / f"{name}.git"


def find_workspace(start: Path | None = None) -> Workspace:
    """SIGHARVEST_HOME if set, else the nearest folder (from `start` or the current one) with a sources.yaml, else that folder."""
    env = os.environ.get("SIGHARVEST_HOME")
    if env:
        return Workspace(Path(env).resolve())
    here = (start or Path.cwd()).resolve()
    for p in [here, *here.parents]:
        if (p / "sources.yaml").exists():
            return Workspace(p)
    return Workspace(here)


def _read_sources(path: Path) -> list[SourceConfig]:
    """The sources of a sources file. A file a hand edit broke (not UTF-8, not YAML, `sources:` not a list of
    mappings) is a SigharvestError naming the file and the line: one error line, not a traceback."""
    from sigharvest.errors import SigharvestError

    if not path.exists():
        return []
    fix = "fix it or restore it from a backup"
    try:
        # The libyaml safe loader builds the same objects about six times faster.
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)) or {}  # noqa: S506 - safe loader
    except UnicodeDecodeError as e:
        raise SigharvestError(f"{path} is not UTF-8 text ({e.reason} at byte {e.start}): {fix}") from e
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
        problem = getattr(e, "problem", None) or str(e).splitlines()[0]
        raise SigharvestError(f"{path} is not valid YAML{where}: {problem}; {fix}") from e
    items = data.get("sources", []) if isinstance(data, dict) else []
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise SigharvestError(f"{path}: `sources:` must be a list of sources (name:, url: ...); {fix}")
    return [SourceConfig.from_dict(item) for item in items]


def read_sources_file(path: Path) -> list[SourceConfig]:
    """Sources of any sources file (same format as sources.yaml); ValueError on duplicate names."""
    sources = _read_sources(path)
    names = [s.name for s in sources]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate source names in {path.name}: {sorted(dupes)}")
    return sources


def load_sources(ws: Workspace) -> list[SourceConfig]:
    """The sources in sources.yaml ([] when there are none). ValueError on duplicate names."""
    sources = _read_sources(ws.sources_file)
    names = [s.name for s in sources]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate source names in sources.yaml: {sorted(dupes)}")
    return sources


def save_sources(ws: Workspace, sources: list[SourceConfig]) -> None:
    """Write sources.yaml."""
    header = (
        "# sigharvest rule sources. Edit by hand or with `sigharvest sources add/remove/enable/disable`.\n"
        "# priority: lower number wins when the same logic appears in several sources (canonical copy).\n"
    )
    body = yaml.safe_dump({"sources": [s.to_dict() for s in sources]}, sort_keys=False, allow_unicode=True, width=120)
    ws.root.mkdir(parents=True, exist_ok=True)
    ws.sources_file.write_text(header + body, encoding="utf-8")


PRESETS = ("curated", "all", "sigmahq")


# Bundled lists (src/sigharvest/presets/<file>.yaml, copies of sources/<file>.yaml): `all` is curated + extended.
PRESET_FILES = {"curated": ("curated",), "all": ("curated", "extended"), "sigmahq": ("sigmahq",)}


def preset_sources(name: str) -> list[SourceConfig]:
    """Sources of a bundled preset: curated (default), all (curated + extended), or sigmahq only."""
    if name not in PRESETS:
        raise ValueError(f"preset must be one of {', '.join(PRESETS)}")
    out: list[SourceConfig] = []
    for file in PRESET_FILES[name]:
        path = Path(__file__).parent / "presets" / f"{file}.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out += [SourceConfig.from_dict(item) for item in data.get("sources", [])]
    return out


def workspace_relative(path: PurePath, root: PurePath) -> str:
    """A workspace path as stored in the database (update_runs.report): relative, with "/" on every OS."""
    return path.relative_to(root).as_posix()
