"""Discover public repositories that contain Sigma rules, verify them by content and register them.

Pipeline:

1. collect candidates (GitHub code search, repository search by topic/keyword, awesome lists,
   the SigmaHQ README and site, GitLab project search, and the seed list from the brief);
2. enrich GitHub candidates with repository metadata (stars, size, licence, fork parent, last push);
3. verify every candidate by content: shallow partial clone, read every blob <= 2 MiB, count the
   YAML documents that are Sigma (rule/correlation/filter) and compute a logic hash without error;
4. score, classify (auto_added / manual_review / rejected) and write discovery/candidates.yaml;
5. add verified repos to sources.yaml (never removing anything) and write discovery/top100.md.

All HTTP responses are cached on disk (ws.cache / "github") keyed by URL, revalidated with ETag /
If-None-Match, so reruns are cheap. The API token is read from GITHUB_TOKEN or `gh auth token` and is
never printed or logged.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.discovery_coverage import QueryCoverage
from sigharvest.discovery_http import CLOCK_STEP_TOLERANCE, MAX_CACHE_BYTES
from sigharvest.discovery_http import ApiError as ApiError
from sigharvest.discovery_http import CachedClient as CachedClient
from sigharvest.documents import MAX_FILE_BYTES, load_documents, looks_like_sigma
from sigharvest.identity import logic_hash
from sigharvest.retry import RetryBudget, git_category
from sigharvest.sync import SyncError, _check_git_inputs, ls_tree_entries

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
GITLAB_API = "https://gitlab.com/api/v4"
# Large reference corpora; a repository whose logic is >= 90% contained in their union is marked as a mirror.
REFERENCE_REPOS = {"github.com/sigmahq/sigma": "SigmaHQ/sigma", "github.com/yamato-security/hayabusa-rules": "Yamato-Security/hayabusa-rules"}
REFERENCE_VERSION = "refs-v2"  # bump when REFERENCE_REPOS or the overlap rule changes, to refresh cached verifications
MIRROR_THRESHOLD = 0.9

STATUS_AUTO = "auto_added"
STATUS_REVIEW = "manual_review"
STATUS_REJECTED = "rejected"

PRIORITY_SEED = 20
MIN_FREE_BYTES = 25 * 1024**3  # clones are deleted after counting when free disk space drops below this
PRIORITY_DISCOVERED = 50

# Seed list from the product brief: (owner/repo, note).
SEEDS: list[tuple[str, str]] = [
    ("SigmaHQ/sigma", "reference repository"),
    ("Yamato-Security/hayabusa-rules", ""),
    ("The-DFIR-Report/Sigma-Rules", ""),
    ("mdecrevoisier/SIGMA-detection-rules", ""),
    ("P4T12ICK/Sigma-Rule-Repository", ""),
    ("joesecurity/sigma-rules", ""),
    ("tsale/Sigma_rules", ""),
    ("mbabinski/Sigma-Rules", ""),
    ("anil-yelken/sigma-rules", ""),
    ("mthcht/ThreatHunting-Keywords-sigma-rules", ""),
    ("magicsword-io/LOLDrivers", "sigma rules under detections/sigma"),
    ("delivr-to/detections", "sigma rules under sigma-rules"),
    ("center-for-threat-informed-defense/cloud-analytics", ""),
    ("elastic/detection-rules", "only if it holds Sigma-format files"),
    ("splunk/security_content", "only if it holds Sigma-format files"),
]

AWESOME_LISTS = ["jatrost/awesome-detection-rules", "mthcht/awesome-lists", "SigmaHQ/sigma"]
SIGMAHQ_SITE_FILES = [".vitepress/theme/layouts/Resources.vue", "resources/index.md", "README.md"]

TOPICS = ["sigma", "sigma-rules", "detection-rules", "sigmahq", "detection-engineering", "sigma-rule", "sigma-detection"]
REPO_KEYWORDS = ['"sigma rules"', '"sigma rule"', '"sigma detection"', "sigma-rules", "sigma detections", '"sigma" "detection rules"']
GITLAB_QUERIES = ["sigma rules", "sigma-rules", "sigma detection", "sigma rule"]

CODE_BASE = "logsource detection condition"
CODE_EXTENSIONS = ["yml", "yaml"]
CODE_KEYWORDS = [
    "",
    "product windows",
    "category process_creation",
    "service security",
    "service sysmon",
    "service powershell",
    "category ps_script",
    "category file_event",
    "category registry_set",
    "category network_connection",
    "category image_load",
    "category dns_query",
    "category proxy",
    "category webserver",
    "product linux",
    "service auditd",
    "product macos",
    "product aws",
    "service cloudtrail",
    "product azure",
    "product gcp",
    "product m365",
    "product okta",
    "product github",
    "product zeek",
    "correlation",
    "author tags attack",
]
CODE_PATHS = ["", "path:rules", "path:sigma", "path:detections", "path:hunting"]
# Size slices (bytes) used when a query reports more than 1000 results.
CODE_SIZE_SLICES = ["<800", "800..1200", "1201..1600", "1601..2000", "2001..2600", "2601..3500", "3501..5000", ">5000"]

_GH_LINK = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9_.-]{1,100})")
_GL_LINK = re.compile(r"https?://(?:www\.)?gitlab\.com/((?:[A-Za-z0-9_.-]+/){1,4}[A-Za-z0-9_.-]+)")
_GH_RESERVED_OWNERS = {
    "about",
    "apps",
    "collections",
    "contact",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "issues",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "pulls",
    "search",
    "settings",
    "site",
    "sponsors",
    "topics",
    "trending",
    "users",
}
_GL_RESERVED = {"explore", "users", "help", "dashboard", "-", "api"}


# --------------------------------------------------------------------------- small helpers


def normalise_url(url: str) -> str:
    """Canonical key for a repository URL: 'host/owner/repo', lower-case, no scheme, no .git, no trailing slash.

    Handles https://, http://, ssh://git@host/..., git@host:owner/repo and bare 'host/owner/repo'.
    Anything after the repository part of a GitHub link (/tree/main/x, /blob/...) is dropped.
    """
    u = url.strip()
    m = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", u)
    if m:
        u = f"{m.group(1)}/{m.group(2)}"
    u = re.sub(r"^[a-z+]+://", "", u, flags=re.IGNORECASE)
    u = re.sub(r"^[^/@]+@", "", u)  # user@ in ssh:// urls
    u = u.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    host, _, path = u.partition("/")
    host = host.lower().removeprefix("www.")
    parts = [p for p in path.split("/") if p]
    if host == "github.com":
        parts = parts[:2]
    elif host == "gitlab.com" and "-" in parts:
        parts = parts[: parts.index("-")]
    if parts:
        parts[-1] = parts[-1].removesuffix(".git")
    return "/".join([host, *parts]).lower()


def source_name(full_name: str) -> str:
    """sources.yaml name for a repo: '<owner>__<repo>' lower-case with only [a-z0-9_-]."""
    parts = [p for p in full_name.strip("/").split("/") if p]
    clean = [re.sub(r"[^a-z0-9_-]+", "-", p.lower()).strip("-_") for p in parts]
    return "__".join(p for p in clean if p) or "repo"


def extract_repo_links(text: str) -> tuple[list[str], list[str]]:
    """Return (github 'owner/repo' list, gitlab 'group/.../project' list) found in a markdown/html text, in order, unique."""
    gh: dict[str, None] = {}
    for owner, repo in _GH_LINK.findall(text):
        repo = repo.removesuffix(".git").rstrip(".")
        if owner.lower() in _GH_RESERVED_OWNERS or not repo or repo.startswith("."):
            continue
        gh.setdefault(f"{owner}/{repo}", None)
    gl: dict[str, None] = {}
    for path in _GL_LINK.findall(text):
        parts = [p for p in path.split("/") if p]
        if "-" in parts:
            parts = parts[: parts.index("-")]
        if len(parts) < 2 or parts[0].lower() in _GL_RESERVED:
            continue
        parts[-1] = parts[-1].removesuffix(".git").rstrip(".")
        gl.setdefault("/".join(parts), None)
    return list(gh), list(gl)


def sigma_paths(rule_files: Iterable[str], max_groups: int = 25) -> list[str]:
    """fnmatch globs (as used by SourceConfig.paths, '*' crosses '/') covering the folders that hold rules.

    Files are grouped by top-level folder; each group becomes '<deepest common folder>/*'. Rules at the
    repository root (or too many groups) give ['**/*'].
    """
    groups: dict[str, list[PurePosixPath]] = {}
    for f in rule_files:
        p = PurePosixPath(f)
        if len(p.parts) < 2:
            return ["**/*"]
        groups.setdefault(p.parts[0], []).append(p.parent)
    if not groups or len(groups) > max_groups:
        return ["**/*"]
    out = []
    for parents in groups.values():
        common = parents[0].parts
        for par in parents[1:]:
            n = 0
            for a, b in zip(common, par.parts, strict=False):
                if a != b:
                    break
                n += 1
            common = common[:n]
        out.append("/".join(common) + "/*")
    return sorted(set(out))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- candidates


@dataclass
class Candidate:
    url: str  # clone url (https)
    full_name: str  # owner/repo (GitHub) or group/.../project (GitLab)
    host: str = "github"
    strategies: list[str] = field(default_factory=list)
    code_hits: int = 0
    stars: int | None = None
    size_kb: int | None = None
    default_branch: str | None = None
    pushed_at: str | None = None
    licence: str | None = None
    fork: bool = False
    parent: str | None = None
    archived: bool = False
    description: str | None = None
    seed: bool = False
    verified: bool = False
    head: str | None = None
    valid_rule_count: int = 0
    rule_files: int = 0
    yaml_files: int = 0
    unique_logic: int = 0
    sigmahq_overlap: float | None = None
    reference_overlap: float | None = None  # share of unique logic found in the union of REFERENCE_REPOS
    mirror_of: str | None = None
    sigma_paths: list[str] = field(default_factory=list)
    confidence: float = 0.0
    status: str = STATUS_REVIEW
    reason: str | None = None
    source: str | None = None  # name in sources.yaml once registered
    provider_id: str | None = None
    aliases: list[str] = field(default_factory=list)
    error_category: str | None = None
    stale: bool = False

    @property
    def key(self) -> str:
        return normalise_url(self.url)

    def add_strategy(self, strategy: str) -> None:
        if strategy not in self.strategies:
            self.strategies.append(strategy)

    def to_record(self) -> dict[str, Any]:
        d = asdict(self)
        order = [
            "provider_id",
            "aliases",
            "error_category",
            "stale",
            "full_name",
            "url",
            "host",
            "status",
            "reason",
            "confidence",
            "valid_rule_count",
            "unique_logic",
            "rule_files",
            "yaml_files",
            "sigma_paths",
            "sigmahq_overlap",
            "reference_overlap",
            "mirror_of",
            "stars",
            "size_kb",
            "default_branch",
            "pushed_at",
            "licence",
            "fork",
            "parent",
            "archived",
            "seed",
            "strategies",
            "code_hits",
            "head",
            "source",
            "description",
            "verified",
        ]
        return {k: d[k] for k in order if d[k] not in (None, [], "")}


def github_candidate(full_name: str, strategy: str) -> Candidate:
    return Candidate(url=f"https://github.com/{full_name}.git", full_name=full_name, host="github", strategies=[strategy])


def merge_candidate(pool: dict[str, Candidate], new: Candidate) -> Candidate:
    """Insert `new` into `pool` (keyed by normalised URL) or merge it into the existing entry.

    Strategies are unioned, code hits summed, and metadata fields filled where the existing entry has none.
    """
    cur = pool.get(new.key)
    if cur is None and new.provider_id:
        cur = next((c for c in pool.values() if c.host == new.host and c.provider_id == new.provider_id), None)
        if cur is not None and cur.key != new.key:
            old_key = cur.key
            pool.pop(old_key, None)
            cur.aliases = sorted(set([*cur.aliases, old_key]))
            cur.full_name, cur.url = new.full_name, new.url
            pool[cur.key] = cur
    if cur is None:
        pool[new.key] = new
        return new
    for s in new.strategies:
        cur.add_strategy(s)
    cur.provider_id = new.provider_id or cur.provider_id
    cur.aliases = sorted(set([*cur.aliases, *new.aliases]))
    cur.code_hits += new.code_hits
    cur.seed = cur.seed or new.seed
    for name in ("stars", "size_kb", "default_branch", "pushed_at", "licence", "parent", "description"):
        if getattr(cur, name) is None and getattr(new, name) is not None:
            setattr(cur, name, getattr(new, name))
    cur.fork = cur.fork or new.fork
    cur.archived = cur.archived or new.archived
    return cur


def confidence_score(c: Candidate, now: datetime | None = None) -> float:
    """Confidence (0-1) that a candidate is a useful Sigma rule source.

    score = 0.45 * volume + 0.20 * purity + 0.10 * corroboration + 0.10 * licence + 0.15 * activity

    - volume        = min(1, log10(valid_rule_count + 1) / 2)      (1 rule -> 0.15, 10 -> 0.52, 99+ -> 1)
    - purity        = rule_files / yaml_files                     (share of YAML files that hold valid Sigma)
    - corroboration = min(1, (number of discovery strategies - 1) / 2)
    - licence       = 1 if the repository declares an SPDX licence (not NOASSERTION), else 0
    - activity      = 1 if pushed in the last 365 days, 0.5 within 3 years, 0.2 older, 0 unknown

    GitLab candidates (unauthenticated, fewer signals) are multiplied by 0.85. A repository with
    no valid rule scores 0. The result is rounded to 3 decimals.
    """
    if c.valid_rule_count <= 0:
        return 0.0
    now = now or datetime.now(UTC)
    volume = min(1.0, math.log10(c.valid_rule_count + 1) / 2)
    purity = min(1.0, c.rule_files / c.yaml_files) if c.yaml_files else 0.0
    corroboration = min(1.0, max(0, len(c.strategies) - 1) / 2)
    licence = 1.0 if c.licence and c.licence.upper() not in ("NOASSERTION", "OTHER") else 0.0
    pushed = _parse_time(c.pushed_at)
    if pushed is None:
        activity = 0.0
    else:
        age_days = (now - pushed).days
        activity = 1.0 if age_days <= 365 else 0.5 if age_days <= 3 * 365 else 0.2
    score = 0.45 * volume + 0.20 * purity + 0.10 * corroboration + 0.10 * licence + 0.15 * activity
    if c.host == "gitlab":
        score *= 0.85
    return round(min(1.0, score), 3)


def classify(c: Candidate, min_rules: int) -> None:
    """Set status/reason from the verification result."""
    if c.stale or c.archived:
        c.status, c.reason = STATUS_REVIEW, ("stale last-good verification" if c.stale else "archived repository; review required")
    elif not c.verified:
        c.status = STATUS_REJECTED if c.reason and c.reason.startswith(("not found", "duplicate")) else STATUS_REVIEW
        c.reason = c.reason or "not verified"
    elif c.valid_rule_count >= min_rules:
        c.status = STATUS_AUTO
        c.reason = None
    elif c.valid_rule_count > 0:
        c.status = STATUS_REVIEW
        c.reason = f"only {c.valid_rule_count} valid Sigma rule(s), threshold is {min_rules}"
    else:
        c.status = STATUS_REJECTED
        c.reason = "empty repository" if c.reason == "empty repository" else "no valid Sigma rules"


# --------------------------------------------------------------------------- HTTP with cache + rate limits


def github_token() -> str | None:
    """GITHUB_TOKEN, else `gh auth token`; None if neither is available. The value is never logged."""
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok.strip()
    try:
        proc = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


# --------------------------------------------------------------------------- collection strategies


def _q(params: dict[str, Any]) -> str:
    return str(httpx.QueryParams(params))


def _search_data(client: CachedClient, url: str, evidence: QueryCoverage) -> Any:
    try:
        return client.get(url)
    except ApiError as exc:
        evidence.error(exc.category)
        return None


def _github_page(data: Any, evidence: QueryCoverage) -> tuple[list[dict[str, Any]], int] | None:
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("items"), list)
        or not isinstance(data.get("total_count"), int)
        or data["total_count"] < 0
        or any(not isinstance(item, dict) for item in data["items"])
    ):
        evidence.error("invalid_response")
        return None
    items, total = data["items"], data["total_count"]
    ids = []
    for item in items:
        if evidence.strategy == "repos":
            key = item.get("id") or item.get("full_name")
        else:
            repo = item.get("repository")
            if repo is not None and not isinstance(repo, dict):
                evidence.error("invalid_response")
                return None
            key = f"{(repo or {}).get('full_name')}/{item['path']}" if item.get("path") else None
        if key is not None:
            ids.append(str(key))
    evidence.page(len(items), total=total, incomplete=bool(data.get("incomplete_results")), ids=ids)
    return items, total


def search_code(client: CachedClient, pool: dict[str, Candidate], max_requests: int, progress: Callable[[str], None]) -> int:
    """Search configured slices. Failed calls consume the query budget too."""
    queue = []
    for path in CODE_PATHS:
        for kw in CODE_KEYWORDS:
            if path and kw:
                continue
            for ext in CODE_EXTENSIONS:
                q = " ".join(x for x in (CODE_BASE, kw, f"extension:{ext}", path) if x)
                queue.append((q, True, client.coverage.start("code", q)))
    used = 0
    while queue:
        q, can_split, evidence = queue.pop(0)
        weak_pages = 0
        for page in range(1, 11):
            if used >= max_requests:
                evidence.finish("budget_exhausted")
                break
            used += 1
            url = f"{GITHUB_API}/search/code?{_q({'q': q, 'per_page': 100, 'page': page})}"
            data = _search_data(client, url, evidence)
            if data is None:
                break
            parsed = _github_page(data, evidence)
            if parsed is None:
                break
            items, total = parsed
            before = len(pool)
            for it in items:
                repo = it.get("repository") or {}
                fn = repo.get("full_name")
                if not fn:
                    continue
                c = github_candidate(fn, "code_search")
                c.provider_id = str(repo["id"]) if repo.get("id") is not None else None
                c.code_hits, c.fork, c.description = 1, bool(repo.get("fork")), repo.get("description")
                merge_candidate(pool, c)
            if page == 1:
                progress(f"code search: {q!r} -> {total} files, {len(pool)} candidates")
                if total > 1000 and can_split:
                    for size in CODE_SIZE_SLICES:
                        sliced = f"{q} size:{size}"
                        queue.append((sliced, False, client.coverage.start("code", sliced)))
            weak_pages = weak_pages + 1 if len(pool) - before < 3 else 0
            if len(items) < 100 or page * 100 >= total:
                evidence.finish()
                break
            if page == 10 or weak_pages >= 2:
                evidence.finish("result_cap" if page == 10 else "low_yield")
                break
    return used


def _add_repo_items(pool: dict[str, Candidate], items: Iterable[dict[str, Any]], strategy: str) -> int:
    n = 0
    for repo in items:
        fn = repo.get("full_name")
        if not fn:
            continue
        c = github_candidate(fn, strategy)
        _apply_repo_meta(c, repo)
        merge_candidate(pool, c)
        n += 1
    return n


def search_repos(client: CachedClient, pool: dict[str, Candidate], progress: Callable[[str], None]) -> None:
    queries = [(f"topic:{t}", "topic") for t in TOPICS] + [(f"{k} in:name,description", "keyword") for k in REPO_KEYWORDS]
    for q, strategy in queries:
        evidence = client.coverage.start("repos", q)
        for page in range(1, 11):
            url = f"{GITHUB_API}/search/repositories?{_q({'q': q, 'per_page': 100, 'page': page})}"
            data = _search_data(client, url, evidence)
            if data is None:
                break
            parsed = _github_page(data, evidence)
            if parsed is None:
                break
            items, total = parsed
            _add_repo_items(pool, items, strategy)
            if page == 1:
                progress(f"repo search: {q!r} -> {total} repos, {len(pool)} candidates")
            if len(items) < 100 or page * 100 >= total:
                evidence.finish()
                break
            if page == 10:
                evidence.finish("result_cap")


def mine_awesome(client: CachedClient, pool: dict[str, Candidate], progress: Callable[[str], None]) -> None:
    urls = [(f"awesome:{repo}", f"{GITHUB_API}/repos/{repo}/readme") for repo in AWESOME_LISTS]
    urls += [(f"sigmahq_site:{path}", f"{GITHUB_API}/repos/SigmaHQ/sigmahq.github.io/contents/{path}") for path in SIGMAHQ_SITE_FILES]
    for query, url in urls:
        evidence = client.coverage.start("awesome", query)
        try:
            body = client.get(url, accept="application/vnd.github.raw")
        except ApiError as exc:
            evidence.error(exc.category)
            continue
        if not isinstance(body, str):
            evidence.error("invalid_response")
            continue
        gh, gl = extract_repo_links(body)
        evidence.page(len(gh) + len(gl))
        evidence.finish()
        for fn in gh:
            merge_candidate(pool, github_candidate(fn, "awesome_list" if query.startswith("awesome") else "sigmahq_site"))
        for path in gl:
            merge_candidate(pool, Candidate(url=f"https://gitlab.com/{path}.git", full_name=path, host="gitlab", strategies=["awesome_list"]))
        progress(f"{query}: {len(gh)} github + {len(gl)} gitlab links, {len(pool)} candidates")


def search_gitlab(client: CachedClient, pool: dict[str, Candidate], progress: Callable[[str], None]) -> None:
    queries = [("search", q, 3) for q in GITLAB_QUERIES] + [("topic", t, 3) for t in ("sigma", "sigma-rules", "detection-rules")]
    for kind, q, max_pages in queries:
        evidence = client.coverage.start("gitlab", f"{kind}:{q}")
        for page in range(1, max_pages + 1):
            url = f"{GITLAB_API}/projects?{_q({kind: q, 'per_page': 100, 'page': page, 'order_by': 'star_count'})}"
            items = _search_data(client, url, evidence)
            if items is None:
                break
            if not isinstance(items, list) or any(not isinstance(p, dict) for p in items):
                evidence.error("invalid_response")
                break
            evidence.page(len(items), ids=[str(p.get("id") or p["path_with_namespace"]) for p in items if p.get("id") or p.get("path_with_namespace")])
            for project in items:
                path = project.get("path_with_namespace")
                if not path:
                    continue
                c = Candidate(url=f"https://gitlab.com/{path}.git", full_name=path, host="gitlab", strategies=["gitlab_search"])
                _apply_gitlab_meta(c, project)
                merge_candidate(pool, c)
            if len(items) < 100:
                evidence.finish()
                break
            if page == max_pages:
                evidence.finish("page_cap")
    progress(f"gitlab: {sum(1 for c in pool.values() if c.host == 'gitlab')} candidates")


def _apply_gitlab_meta(c: Candidate, project: dict[str, Any]) -> None:
    c.provider_id = str(project["id"]) if project.get("id") is not None else c.provider_id
    old_key = c.key
    c.full_name = project.get("path_with_namespace") or c.full_name
    c.url = f"https://gitlab.com/{c.full_name}.git"
    if c.key != old_key:
        c.aliases = sorted(set([*c.aliases, old_key]))
    c.stars = project.get("star_count", c.stars)
    c.default_branch = project.get("default_branch", c.default_branch)
    c.pushed_at = project.get("last_activity_at", c.pushed_at)
    c.description = (project.get("description") or c.description or "")[:300] or None
    c.archived = bool(project.get("archived", c.archived))
    forked = project.get("forked_from_project") or {}
    if forked:
        c.fork, c.parent = True, forked.get("path_with_namespace")
    c.licence = ((project.get("license") or {}).get("key") or c.licence or "").upper() or None


def add_seeds(pool: dict[str, Candidate]) -> None:
    for fn, _note in SEEDS:
        c = github_candidate(fn, "seed")
        c.seed = True
        merge_candidate(pool, c)


def _apply_repo_meta(c: Candidate, repo: dict[str, Any]) -> None:
    old_key = c.key
    c.provider_id = str(repo["id"]) if repo.get("id") is not None else c.provider_id
    c.full_name = repo.get("full_name") or c.full_name
    c.url = f"https://github.com/{c.full_name}.git"
    if c.key != old_key:
        c.aliases = sorted(set([*c.aliases, old_key]))
    c.stars = repo.get("stargazers_count", c.stars)
    c.size_kb = repo.get("size", c.size_kb)
    c.default_branch = repo.get("default_branch", c.default_branch)
    c.pushed_at = repo.get("pushed_at", c.pushed_at)
    lic = repo.get("license") or {}
    from sigharvest.licensing import current_spdx

    c.licence = current_spdx(lic.get("spdx_id")) or c.licence
    c.fork = bool(repo.get("fork", c.fork))
    parent = repo.get("parent") or {}
    c.parent = parent.get("full_name") or c.parent
    c.archived = bool(repo.get("archived", c.archived))
    desc = repo.get("description")
    c.description = desc[:300] if isinstance(desc, str) and desc else c.description


def enrich(client: CachedClient, pool: dict[str, Candidate], cands: list[Candidate]) -> None:
    """Fetch /repos metadata for GitHub candidates (follows renames and re-keys merged duplicates)."""
    for c in cands:
        if c.host != "github":
            if c.host == "gitlab":
                old_key = c.key
                try:
                    meta = client.get(f"{GITLAB_API}/projects/{quote(c.full_name, safe='')}?license=true")
                except ApiError as exc:
                    c.error_category, c.reason = exc.category, f"metadata error {exc.status}"
                else:
                    if isinstance(meta, dict):
                        _apply_gitlab_meta(c, meta)
                        if c.key != old_key:
                            pool.pop(old_key, None)
                            merge_candidate(pool, c)
                    else:
                        c.error_category, c.reason = "invalid_response", "invalid metadata"
            continue
        if c.pushed_at is not None and c.size_kb is not None and not (c.fork and c.parent is None):
            continue  # full metadata already came with a repository search result
        old_key = c.key
        try:
            repo = client.get(f"{GITHUB_API}/repos/{c.full_name}")
        except ApiError as exc:
            c.error_category = exc.category
            c.reason = "not found (deleted, renamed away or private)" if exc.status in (404, 410, 451) else f"metadata error {exc.status}"
            continue
        if not isinstance(repo, dict):
            c.error_category, c.reason = "invalid_response", "invalid metadata"
            continue
        _apply_repo_meta(c, repo)
        if c.key != old_key:
            pool.pop(old_key, None)
            merged = merge_candidate(pool, c)
            if merged is not c:
                c.reason = f"duplicate of {merged.full_name}"


# --------------------------------------------------------------------------- verification


GIT_BASE = [
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


def _git_env() -> dict[str, str]:
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "/bin/true"}


def _git(args: list[str], cwd: Path | None = None, timeout: int = 900) -> str:
    proc = subprocess.run([*GIT_BASE, *args], cwd=cwd, env=_git_env(), capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise SyncError(f"git {args[0]} failed: {proc.stderr.strip()[-300:]}")
    return proc.stdout


class EmptyRepository(SyncError):
    """The repository has no commits."""


def clone(url: str, dest: Path, timeout: int = 900) -> str:
    """Shallow, blob-filtered, no-checkout clone. Returns the HEAD commit.

    After cloning the promisor settings are removed so that reading a filtered-out blob reports it as
    missing instead of lazily downloading it.
    """
    _check_git_inputs(url, None)
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git(
        ["clone", "--quiet", "--depth", "1", "--filter=blob:limit=2m", "--no-checkout", "--no-tags", "--single-branch", "--", url, str(dest)],
        timeout=timeout,
    )
    for key in ("remote.origin.promisor", "extensions.partialclone", "remote.origin.partialclonefilter"):
        subprocess.run([*GIT_BASE, "config", "--unset", key], cwd=dest, env=_git_env(), capture_output=True, check=False)
    try:
        return _git(["rev-parse", "--verify", "HEAD"], cwd=dest).strip()
    except SyncError as exc:
        raise EmptyRepository(url) from exc


def iter_blobs(repo: Path) -> Iterator[tuple[list[str], bytes]]:
    """Yield (paths, content) for every blob of HEAD that is present locally and <= MAX_FILE_BYTES."""
    by_oid: dict[str, list[str]] = {}
    for entry in ls_tree_entries([*GIT_BASE, "ls-tree", "-r", "-z", "HEAD"], repo, _git_env()):
        meta, _, path = entry.partition(b"\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == b"blob":
            by_oid.setdefault(parts[2].decode(), []).append(path.decode("utf-8", "replace"))
    if not by_oid:
        return
    proc = subprocess.Popen(
        [*GIT_BASE, "cat-file", "--batch"], cwd=repo, env=_git_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    assert proc.stdin is not None and proc.stdout is not None

    def _feed() -> None:
        assert proc.stdin is not None
        with contextlib.suppress(BrokenPipeError):
            proc.stdin.write("".join(f"{oid}\n" for oid in by_oid).encode())
        with contextlib.suppress(BrokenPipeError):
            proc.stdin.close()

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()
    try:
        for _ in range(len(by_oid)):
            header = proc.stdout.readline()
            if not header:
                break
            fields = header.split()
            if len(fields) < 3:  # "<oid> missing"
                continue
            oid, size = fields[0].decode(), int(fields[2])
            content = proc.stdout.read(size)
            proc.stdout.read(1)
            if size <= MAX_FILE_BYTES:
                yield by_oid.get(oid, []), content
    finally:
        proc.stdout.close()
        proc.kill()
        proc.wait()
        feeder.join(timeout=5)


@dataclass
class RepoCount:
    valid_rule_count: int = 0
    rule_files: int = 0
    yaml_files: int = 0
    logic: set[str] = field(default_factory=set)
    files: list[str] = field(default_factory=list)


def count_rules(blobs: Iterable[tuple[list[str], bytes]]) -> RepoCount:
    """Count valid Sigma documents: YAML documents whose kind is not None and whose logic hash computes."""
    out = RepoCount()
    for paths, raw in blobs:
        is_yaml = sum(1 for p in paths if p.lower().endswith((".yml", ".yaml")))
        out.yaml_files += is_yaml
        if not looks_like_sigma(raw):
            continue
        n = 0
        try:
            docs = load_documents(raw)
        except Exception:  # noqa: BLE001, S112 - arbitrary repository content
            continue
        for d in docs:
            if d.kind is None or not isinstance(d.data, dict):
                continue
            try:
                out.logic.add(logic_hash(d.data))
            except Exception:  # noqa: BLE001, S112 - malformed rule body: not counted
                continue
            n += 1
        if n:
            out.valid_rule_count += n * len(paths)
            out.rule_files += len(paths)
            out.yaml_files += len(paths) - is_yaml  # content-detected Sigma files count as YAML whatever their name
            out.files.extend(paths)
    return out


def _reusable_clone(url: str, dest: Path) -> str | None:
    """HEAD of an existing clone in `dest` if it still matches the remote HEAD (checked with ls-remote)."""
    if not (dest / ".git").is_dir():
        return None
    try:
        local = _git(["rev-parse", "--verify", "HEAD"], cwd=dest).strip()
        remote = _git(["ls-remote", "--", url, "HEAD"], timeout=120).split()
    except (SyncError, subprocess.SubprocessError, OSError):
        return None
    return local if remote and remote[0] == local else None


def mirror_of(logic: set[str], references: dict[str, set[str]]) -> tuple[float | None, str | None]:
    """(overlap with the union of references, mirror label or None).

    The label lists every reference that contributes at least 10% of the repository's logic, largest first.
    """
    union = set().union(*references.values()) if references else set()
    if not logic or not union:
        return None, None
    overlap = round(len(logic & union) / len(logic), 3)
    if overlap < MIRROR_THRESHOLD:
        return overlap, None
    shares = sorted(((len(logic & ref) / len(logic), name) for name, ref in references.items()), reverse=True)
    return overlap, " + ".join(name for share, name in shares if share >= 0.1) or None


def verify(c: Candidate, clone_root: Path, references: dict[str, set[str]] | None, timeout: int = 900) -> tuple[Candidate, set[str]]:
    """Clone (or reuse an up-to-date clone) and count one candidate.

    `references` maps reference repo names (e.g. 'SigmaHQ/sigma') to their logic-hash sets, used for the
    overlap/mirror fields. Clones without rules are deleted; others are kept for reuse.
    """
    dest = clone_root / source_name(c.full_name)
    try:
        _check_git_inputs(c.url, None)
        budget = RetryBudget(max_attempts=3)
        while True:
            budget.attempts += 1
            try:
                c.head = _reusable_clone(c.url, dest) or clone(c.url, dest, timeout=timeout)
                counted = count_rules(iter_blobs(dest))
                break
            except (SyncError, subprocess.SubprocessError, OSError) as exc:
                delay = budget.delay(git_category(exc))
                if delay is None:
                    raise
                time.sleep(delay)
    except EmptyRepository:
        shutil.rmtree(dest, ignore_errors=True)
        c.verified, c.reason, c.valid_rule_count = True, "empty repository", 0
        return c, set()
    except (SyncError, subprocess.SubprocessError, OSError) as exc:
        c.verified = False
        c.error_category = git_category(exc)
        c.reason = f"clone/verify failed: {c.error_category}"
        shutil.rmtree(dest, ignore_errors=True)
        return c, set()
    c.verified = True
    c.valid_rule_count = counted.valid_rule_count
    c.rule_files = counted.rule_files
    c.yaml_files = counted.yaml_files
    c.unique_logic = len(counted.logic)
    c.sigma_paths = sigma_paths(counted.files) if counted.files else []
    refs = {name: logic for name, logic in (references or {}).items() if REFERENCE_REPOS.get(c.key) != name}
    if counted.logic and "SigmaHQ/sigma" in refs:
        c.sigmahq_overlap = round(len(counted.logic & refs["SigmaHQ/sigma"]) / len(counted.logic), 3)
    if c.key not in REFERENCE_REPOS:
        c.reference_overlap, c.mirror_of = mirror_of(counted.logic, refs)
    if counted.valid_rule_count == 0 or shutil.disk_usage(clone_root).free < MIN_FREE_BYTES:
        shutil.rmtree(dest, ignore_errors=True)
    return c, counted.logic


# --------------------------------------------------------------------------- orchestration


@dataclass
class DiscoveryOptions:
    max_repos: int = 1000  # candidates to verify (seeds always included); 0 = all
    min_rules: int = 5
    auto_add: bool = True
    top: int = 100
    workers: int = 6
    max_code_requests: int = 400
    max_repo_kb: int = 3_000_000  # skip cloning repositories larger than this (GitHub size, KiB)
    cache_max_age: float = 7 * 86400
    reverify: bool = False
    strategies: tuple[str, ...] = ("code", "repos", "awesome", "gitlab")
    max_http_requests: int = 2000
    verify: bool = True  # clone and count rules; without it only already-verified (cached) results are used
    output: Path | None = None  # write discovered sources here (all disabled) instead of editing sources.yaml
    known: Path | list[Path] | None = None  # sources file(s) whose repositories are already known (left out of `output`)
    denylist: Path | None = None  # YAML list (or sources file) of names/URLs never to propose
    cache_dir: Path | None = None  # default: <workspace>/data/cache
    report_file: Path | None = None  # also write the candidates report (markdown) here
    # Two-step runs (CI keeps the API token away from the step that clones untrusted repositories):
    collect_only: bool = False  # search and enrich with the API, write discovery/candidates.yaml, clone nothing
    candidates: Path | None = None  # verify the candidates of a collect-only run instead of searching (no API calls)


@dataclass
class DiscoveryReport:
    candidates: list[Candidate]
    per_strategy: dict[str, int]
    verified: int
    added: list[str]
    top: list[Candidate]
    requests: int = 0
    cache_hits: int = 0
    completeness: dict[str, Any] = field(default_factory=dict)


_VERIFY_FIELDS = (
    "head",
    "valid_rule_count",
    "rule_files",
    "yaml_files",
    "unique_logic",
    "sigma_paths",
    "sigmahq_overlap",
    "reference_overlap",
    "mirror_of",
    "reason",
)


def _load_verify_cache(path: Path) -> dict[str, dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CACHE_BYTES + 1)
        data = json.loads(raw) if len(raw) <= MAX_CACHE_BYTES else None
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    valid = {}
    for key, hit in data.items():
        if not isinstance(hit, dict):
            continue
        if any(not isinstance(hit.get(n), int) or hit[n] < 0 for n in ("valid_rule_count", "rule_files", "yaml_files", "unique_logic")):
            continue
        if not isinstance(hit.get("sigma_paths"), list):
            continue
        try:
            when = float(hit.get("verified_at", 0))
        except (TypeError, ValueError, OverflowError):
            continue
        if not math.isfinite(when) or when < 0 or when > time.time() + CLOCK_STEP_TOLERANCE:
            continue
        hit["verified_at"] = when
        valid[key] = hit
    return valid


def _verify_order(c: Candidate) -> tuple[int, int, int, int]:
    return (0 if c.seed else 1, -c.code_hits, -len(c.strategies), -(c.stars or 0))


def strategy_counts(cands: Iterable[Candidate]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for c in cands:
        counts.update(set(c.strategies))
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def register_sources(ws: Workspace, cands: list[Candidate], force: set[str], auto_add: bool, today: str) -> list[str]:
    """Add auto_added candidates (and those whose key is in `force`) to sources.yaml. Never removes sources.

    Only seeds and `force` (the top-N) are enabled; other auto-added repositories are registered disabled.

    Existing sources are matched by normalised URL and rename aliases; disabled sources stay disabled.
    Returns the names that were added.
    """
    sources = load_sources(ws)
    by_url = {normalise_url(s.url): s for s in sources}
    names = {s.name for s in sources}
    added: list[str] = []
    for c in cands:
        wanted = not c.stale and (c.key in force or (auto_add and c.status == STATUS_AUTO))
        if not wanted or not c.verified or c.valid_rule_count <= 0:
            continue
        existing = by_url.get(c.key) or next((by_url[a] for a in c.aliases if a in by_url), None)
        if existing is not None:
            c.source = existing.name
            continue
        name = source_name(c.full_name)
        base, i = name, 2
        while name in names:
            name, i = f"{base}-{i}", i + 1
        extra = f", mirror of {c.mirror_of}" if c.mirror_of else (f", fork of {c.parent}" if c.fork and c.parent else "")
        src = SourceConfig(
            name=name,
            type="git",
            url=c.url,
            paths=c.sigma_paths or ["**/*"],
            licence=c.licence if c.licence and c.licence != "NOASSERTION" else None,
            priority=PRIORITY_SEED if c.seed else PRIORITY_DISCOVERED,
            # Third-party repositories are untrusted: only seeds and the top-N are enabled automatically,
            # everything else waits for a review (`sigharvest sources enable <name>`).
            enabled=(c.seed or c.key in force) and not c.archived,
            notes=f"discovered {today}: {c.valid_rule_count} valid Sigma rules{extra}"
            + ("" if (c.seed or c.key in force) and not c.archived else "; disabled: awaiting review"),
        )
        sources.append(src)
        by_url[c.key] = src
        names.add(name)
        c.source = name
        added.append(name)
    if added:
        save_sources(ws, sources)
    return added


def _names_and_urls(path: Path | None) -> set[str]:
    """Names and normalised URLs listed in a sources file or a plain YAML list (missing file: empty)."""
    if path is None or not path.exists():
        return set()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    items = data.get("sources", []) if isinstance(data, dict) else data
    out: set[str] = set()
    for item in items if isinstance(items, list) else []:
        if isinstance(item, str):
            out.update({item.lower(), normalise_url(item)} if "/" in item else {item.lower()})
        elif isinstance(item, dict):
            if item.get("name"):
                out.add(str(item["name"]).lower())
            if item.get("url"):
                out.add(normalise_url(str(item["url"])))
    return out


def write_discovered(path: Path, cands: list[Candidate], opts: DiscoveryOptions, today: str) -> list[str]:
    """Write verified repositories with enough rules to `path` as a sources file, every entry disabled.

    Repositories in --known or --denylist, mirrors and stale results are left out. The file is regenerated on each
    run, so it can be reviewed as a diff; curated lists are never edited."""
    known = opts.known if isinstance(opts.known, list) else [opts.known]
    skip = set().union(*(_names_and_urls(k) for k in known)) | _names_and_urls(opts.denylist)
    entries: list[dict[str, Any]] = []
    names: set[str] = set()
    for c in cands:
        if c.stale or not c.verified or c.valid_rule_count < opts.min_rules or c.mirror_of or c.archived:
            continue
        name = source_name(c.full_name)
        if name.lower() in skip or c.key in skip or any(a in skip for a in c.aliases):
            continue
        base, i = name, 2
        while name in names:
            name, i = f"{base}-{i}", i + 1
        names.add(name)
        licence = c.licence if c.licence and c.licence != "NOASSERTION" else None
        entries.append(
            SourceConfig(
                name=name,
                url=c.url,
                paths=c.sigma_paths or ["**/*"],
                licence=licence,
                priority=PRIORITY_DISCOVERED,
                enabled=False,
                notes=f"discovered {today}: {c.valid_rule_count} valid Sigma rules, {c.unique_logic} unique; disabled: awaiting review",
                tier="discovered",
            ).to_dict()
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    header = f"# Generated by `sigharvest discover` on {today}. Every entry is disabled until reviewed.\n"
    path.write_text(header + yaml.safe_dump({"sources": entries}, sort_keys=False, allow_unicode=True, width=200), encoding="utf-8")
    return [e["name"] for e in entries]


def write_candidates(
    path: Path,
    cands: list[Candidate],
    per_strategy: dict[str, int],
    options: DiscoveryOptions,
    today: str,
    completeness: dict[str, Any] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    status = Counter(c.status for c in cands)
    doc = {
        "generated": today,
        "completeness": completeness or {"provider_complete": False, "scope": "unknown"},
        "min_rules": options.min_rules,
        "summary": {"candidates": len(cands), "verified": sum(c.verified for c in cands), **dict(status), "found_by": per_strategy},
        "candidates": [c.to_record() for c in cands],
    }
    header = "# Generated by `sigharvest discover`. Confidence formula: see sigharvest.discover.confidence_score.\n"
    path.write_text(header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=200), encoding="utf-8")


def write_top(path: Path, top: list[Candidate], today: str) -> None:
    total = sum(c.valid_rule_count for c in top)
    lines = [
        f"# Top {len(top)} Sigma repositories by valid rule count",
        "",
        f"Generated {today} by `sigharvest discover`. A rule counts when a YAML document is a Sigma rule, correlation or filter",
        "and its logic hash computes. `unique` is the number of distinct logic hashes; `SigmaHQ` is the share of those",
        "already present in SigmaHQ/sigma, `known` the share present in SigmaHQ/sigma or Yamato-Security/hayabusa-rules (whose",
        "rules are converted, so their logic differs from SigmaHQ). >= 90% known is marked as a mirror; mirrors are still synced,",
        "dedupe handles them.",
        "",
        "Discovery covers configured queries only; completeness, truncation and errors are in candidates.yaml.",
        "",
        f"Total valid rule documents across these repositories: **{total}**.",
        "",
        "| # | repository | valid rules | unique | SigmaHQ | known | stars | licence | source | notes |",
        "|---|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for i, c in enumerate(top, 1):
        notes = []
        if c.mirror_of:
            notes.append(f"mirror of {c.mirror_of}")
        if c.fork:
            notes.append(f"fork of {c.parent}" if c.parent else "fork")
        if c.archived:
            notes.append("archived")
        if c.seed:
            notes.append("seed")
        if c.host == "gitlab":
            notes.append("gitlab")
        overlap = "" if c.sigmahq_overlap is None else f"{c.sigmahq_overlap:.0%}"
        known = "" if c.reference_overlap is None else f"{c.reference_overlap:.0%}"
        web = c.url.removesuffix(".git")
        lines.append(
            f"| {i} | [{c.full_name}]({web}) | {c.valid_rule_count} | {c.unique_logic} | {overlap} | {known} | {c.stars or 0} | {c.licence or ''} | "
            f"{c.source or ''} | {', '.join(notes)} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_discovery(ws: Workspace, options: DiscoveryOptions | None = None, progress: Callable[[str], None] | None = None) -> DiscoveryReport:
    opts = options or DiscoveryOptions()
    say = progress or (lambda msg: log.info("%s", msg))
    now = datetime.now(UTC)
    today = now.date().isoformat()
    cache_root = opts.cache_dir or ws.cache
    if opts.candidates is not None:
        return _verify_collected(ws, opts, say, now)
    client = CachedClient(cache_root / "github", token=github_token(), max_age=opts.cache_max_age, max_requests=opts.max_http_requests)
    pool: dict[str, Candidate] = {}
    try:
        add_seeds(pool)
        seeds = client.coverage.start("seed", "configured seeds")
        seeds.page(len(SEEDS))
        seeds.finish()
        if "awesome" in opts.strategies:
            mine_awesome(client, pool, say)
        if "repos" in opts.strategies:
            search_repos(client, pool, say)
        if "gitlab" in opts.strategies:
            search_gitlab(client, pool, say)
        if "code" in opts.strategies:
            search_code(client, pool, opts.max_code_requests, say)
        per_strategy = strategy_counts(pool.values())
        say(f"collected {len(pool)} candidates: {per_strategy}")

        ordered = sorted(pool.values(), key=_verify_order)
        to_verify = ordered if opts.max_repos <= 0 else [c for c in ordered if c.seed] + [c for c in ordered if not c.seed][: opts.max_repos]
        enrich(client, pool, to_verify)
        selected_keys = {c.key for c in to_verify}
        selected = {id(c) for key, c in pool.items() if key in selected_keys}
        verification_planned = len(selected)
        to_verify = [c for c in pool.values() if id(c) in selected and not c.reason]
        for c in pool.values():
            if id(c) not in selected and not c.reason:
                c.reason = "not verified (beyond --max-repos)"
        if opts.collect_only:
            completeness = client.coverage.summary()
            completeness["verification"] = {"selected": verification_planned, "verified": 0, "max_repos": opts.max_repos}
            cands = sorted(pool.values(), key=lambda c: c.full_name.lower())
            write_candidates(ws.root / "discovery" / "candidates.yaml", cands, per_strategy, opts, today, completeness)
            say(f"collected {len(cands)} candidates ({verification_planned} to verify): discovery/candidates.yaml")
            return DiscoveryReport(cands, per_strategy, 0, [], [], client.requests, client.cache_hits, completeness)
        return _verify_pool(ws, opts, say, now, client, pool, per_strategy, verification_planned, to_verify)
    finally:
        client.close()


def _verify_collected(ws: Workspace, opts: DiscoveryOptions, say: Callable[[str], None], now: datetime) -> DiscoveryReport:
    """Second step of a two-step run: verify the candidates a --collect-only run wrote, without any API call."""
    assert opts.candidates is not None
    doc = yaml.safe_load(opts.candidates.read_text(encoding="utf-8")) or {}
    known = {f.name for f in fields(Candidate)}
    pool: dict[str, Candidate] = {}
    for record in doc.get("candidates") or []:
        if not isinstance(record, dict):
            continue
        c = Candidate(**{k: v for k, v in record.items() if k in known})
        if not c.url.startswith(("https://github.com/", "https://gitlab.com/")):
            raise ValueError(f"candidate {c.full_name!r}: only github.com and gitlab.com repositories are verified")
        c.verified, c.status = False, STATUS_REVIEW
        pool[c.key] = c
    per_strategy = dict((doc.get("summary") or {}).get("found_by") or strategy_counts(pool.values()))
    to_verify = [c for c in pool.values() if not c.reason]
    completeness = dict(doc.get("completeness") or {})
    offline = CachedClient((opts.cache_dir or ws.cache) / "github", token=None, max_age=opts.cache_max_age, max_requests=0)
    try:
        report = _verify_pool(ws, opts, say, now, offline, pool, per_strategy, len(to_verify), to_verify)
    finally:
        offline.close()
    report.completeness = completeness | {"verification": report.completeness.get("verification", {})}
    return report


def _verify_pool(
    ws: Workspace,
    opts: DiscoveryOptions,
    say: Callable[[str], None],
    now: datetime,
    client: CachedClient,
    pool: dict[str, Candidate],
    per_strategy: dict[str, int],
    verification_planned: int,
    to_verify: list[Candidate],
) -> DiscoveryReport:
    """Clone and count the selected candidates, then classify, register or write them and the reports."""
    today = now.date().isoformat()
    cache_root = opts.cache_dir or ws.cache
    clone_root = cache_root / "discovery"
    clone_root.mkdir(parents=True, exist_ok=True)
    cache_path = clone_root / "_verify.json"
    vcache = _load_verify_cache(cache_path)
    by_provider = {(key.split("/", 1)[0], hit["provider_id"]): key for key, hit in vcache.items() if hit.get("provider_id")}
    for candidate in pool.values():
        previous_key = by_provider.get((candidate.key.split("/", 1)[0], candidate.provider_id))
        if previous_key and previous_key != candidate.key:
            candidate.aliases = sorted(set([*candidate.aliases, previous_key]))

    def cached_result(c: Candidate) -> bool:
        if opts.reverify:
            return False
        hit = vcache.get(c.key) or next((vcache[a] for a in c.aliases if a in vcache), None)
        if not hit or hit.get("pushed_at") != c.pushed_at or c.pushed_at is None:
            return False
        if not hit.get("valid_rule_count") and time.time() - hit.get("verified_at", 0) >= 3600:
            return False
        if c.provider_id and hit.get("provider_id") != c.provider_id:
            return False
        if hit.get("valid_rule_count") and hit.get("refs") != REFERENCE_VERSION:
            return False  # overlap fields were computed against other references
        for name in _VERIFY_FIELDS:
            setattr(c, name, hit.get(name))
        c.verified = True
        c.sigma_paths = c.sigma_paths or []
        return True

    def remember(c: Candidate) -> None:
        if c.verified:
            vcache[c.key] = {
                "pushed_at": c.pushed_at,
                "refs": REFERENCE_VERSION,
                "provider_id": c.provider_id,
                "verified_at": time.time(),
                **{n: getattr(c, n) for n in _VERIFY_FIELDS},
            }

    references: dict[str, set[str]] = {}
    ref_cands = [pool[k] for k in REFERENCE_REPOS if k in pool and not pool[k].reason]
    for ref in ref_cands:
        _, references[REFERENCE_REPOS[ref.key]] = verify(ref, clone_root, None)
        remember(ref)
        say(f"{ref.full_name}: {ref.valid_rule_count} valid rules (reference)")
    for ref in ref_cands:  # overlap of each reference with the others
        others = {n: v for n, v in references.items() if n != REFERENCE_REPOS[ref.key]}
        own = references[REFERENCE_REPOS[ref.key]]
        if own and "SigmaHQ/sigma" in others:
            ref.sigmahq_overlap = round(len(own & others["SigmaHQ/sigma"]) / len(own), 3)
        remember(ref)
    pending = []
    for c in to_verify:
        if c in ref_cands:
            continue
        if not c.seed and c.size_kb is not None and c.size_kb > opts.max_repo_kb:
            c.reason = f"too large to verify ({c.size_kb} KiB)"
        elif not cached_result(c):
            if opts.verify:
                pending.append(c)
            else:
                c.reason = "not verified (--no-verify)"
    say(f"verifying {len(pending)} repositories ({len(to_verify) - len(pending)} from cache or skipped)")
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, opts.workers)) as pool_ex:
        futures = [pool_ex.submit(verify, c, clone_root, references) for c in pending]
        for fut in concurrent.futures.as_completed(futures):
            c, _ = fut.result()
            remember(c)
            done += 1
            if done % 25 == 0 or done == len(pending):
                cache_path.write_text(json.dumps(vcache), encoding="utf-8")
                say(f"verified {done}/{len(pending)} (last: {c.full_name} = {c.valid_rule_count})")
    cache_path.write_text(json.dumps(vcache), encoding="utf-8")

    cands = sorted(pool.values(), key=lambda c: (-c.valid_rule_count, c.full_name.lower()))
    for c in cands:
        hit = vcache.get(c.key) or next((vcache[a] for a in c.aliases if a in vcache), None)
        if not c.verified and hit and hit.get("valid_rule_count", 0) > 0:
            # Display last-good counts, explicitly stale; never auto-register them.
            for name in _VERIFY_FIELDS:
                if name != "reason":
                    setattr(c, name, hit.get(name))
            c.stale = True
        classify(c, opts.min_rules)
        c.confidence = confidence_score(c, now)
    top = [c for c in cands if c.verified and c.valid_rule_count > 0][: opts.top]
    force = {c.key for c in top} | {c.key for c in cands if c.seed and c.verified and c.valid_rule_count > 0}
    if opts.output is not None:
        added = write_discovered(opts.output, cands, opts, today)
    else:
        added = register_sources(ws, cands, force if opts.auto_add else set(), opts.auto_add, today)
    out_dir = ws.root / "discovery"
    completeness = client.coverage.summary()
    completeness["budget"] = {
        "http_limit": opts.max_http_requests,
        "http_attempts": client.http_attempts,
        "responses": client.requests,
        "retries": client.retries,
        "cache_hits": client.cache_hits,
        "code_query_limit": opts.max_code_requests,
        "errors": dict(client.errors),
    }
    completeness["verification"] = {
        "selected": verification_planned,
        "verified": sum(c.verified for c in cands),
        "unverified": sum(not c.verified for c in cands),
        "stale": sum(c.stale for c in cands),
        "max_repos": opts.max_repos,
    }
    write_candidates(out_dir / "candidates.yaml", cands, per_strategy, opts, today, completeness)
    write_top(out_dir / "top100.md", top, today)
    if opts.report_file is not None:
        opts.report_file.parent.mkdir(parents=True, exist_ok=True)
        write_top(opts.report_file, top, today)
    return DiscoveryReport(cands, per_strategy, sum(c.verified for c in cands), added, top, client.requests, client.cache_hits, completeness)
