"""The shell examples in README.md and docs/*.md must work as written.

Every ```bash / ```sh / ```console block in the docs carries a marker on the line above it:

    <!-- doctest -->                 run it (single commands that need the network are skipped, see SKIP below)
    <!-- doctest: skip REASON -->    never run it (network, long-running server, external tool, placeholder, ...)

A block of any language marked `<!-- doctest: write PATH -->` is written to ~/sigma/PATH when the run reaches it,
so the examples that follow use exactly the file the docs show.

`test_every_shell_block_is_marked` (plain pytest) makes sure no new block escapes, and the link, image and table
checks run in the normal test run too. `test_doc_commands_run` (marker `docs`) runs the marked blocks of each file,
in order, in one bash shell, against an offline fixture workspace: `sigharvest init ~/sigma`, every catalog source
replaced by local git repositories (the acceptance fixtures plus a few synthetic rules named like the doc examples,
including a correlation), ATT&CK and the Sigma schemas seeded in the cache, then `sigharvest update`. HOME points
at a scratch folder, so `~/sigma` is the fixture, and a dead proxy keeps every HTTP client offline.

    uv run pytest -m docs tests/test_docs.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
SHELL = {"bash", "sh", "console", "shell"}
MARK = re.compile(r"<!--\s*doctest(?::\s*(?P<verb>skip|write)\b\s*(?P<arg>[^>]*?))?\s*-->")

# Single commands that are never run, matched on the start of a command after `\` continuations are joined.
SKIP = (
    (r"(uv|pipx|git|curl|wget|sudo)\b", "network"),
    (r"sigharvest (serve|web)\b", "long-running server"),
    (r"sigharvest discover\b", "network (GitHub API)"),
    (r"sigharvest (sync|update) .*-(s|-source) (advisory|acme|myrepo)\b", "network (the source is a remote URL)"),
    (r"sigharvest init .*--from-release (latest|https?://)", "network (downloads a release)"),
    (r"sigharvest lint .*--release https?://", "network (downloads a release)"),
    (r".*\bRETAINED_SHA256\b", "placeholder"),
)
NEEDS = {"jq": "jq", "sigma": "sigma", "hayabusa": "hayabusa"}  # a command whose tool is missing is skipped


def blocks(path: Path) -> list[tuple[int, str, str | None, str, str]]:
    """(line, language, marker, argument, code) for every fenced block. marker: 'run', 'skip', 'write' or None."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out, i = [], 0
    while i < len(lines):
        if lines[i].startswith("```"):  # an opening fence (the closing one is skipped below)
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            m = MARK.search(lines[j]) if j >= 0 else None
            marker = None if m is None else (m.group("verb") or "run")
            k = i + 1
            while k < len(lines) and lines[k].strip() != "```":
                k += 1
            out.append((i + 1, lines[i][3:].strip(), marker, (m.group("arg") or "").strip() if m else "", "\n".join(lines[i + 1 : k])))
            i = k
        i += 1
    return out


def shell_blocks(path: Path) -> list[tuple[int, str | None, str]]:
    """(line, marker, code) for every shell block; marker is 'run', 'skip' or None (unmarked)."""
    return [(line, marker, code) for line, lang, marker, _, code in blocks(path) if lang in SHELL]


def commands(code: str) -> list[str]:
    """Logical commands of a block: `\\` continuations joined, blank lines and comment-only lines dropped."""
    out, cur = [], ""
    for line in code.splitlines():
        if line.rstrip().endswith("\\"):
            cur += line.rstrip()[:-1] + " "
            continue
        cur += line
        if cur.strip() and not cur.strip().startswith("#"):
            out.append(cur.strip())
        cur = ""
    return out


def skip_reason(cmd: str) -> str | None:
    for pat, why in SKIP:
        if re.match(pat, cmd):
            return why
    first = cmd.split()[0]
    if first in NEEDS and shutil.which(NEEDS[first]) is None:
        return f"{first} not installed"
    from sigharvest.conversion import ALL_BACKENDS, BACKENDS

    for target in re.findall(r"--(?:format|target)[ =](\S+)", cmd):
        if target in ALL_BACKENDS and target not in BACKENDS:
            return f"backend {target} not installed (sigharvest[convert-legacy])"
    return None


# ---------------------------------------------------------------------------------------------------------------
# static checks (normal test run)


def test_every_shell_block_is_marked():
    """A new example must say whether it runs (and then it is tested) or why not."""
    unmarked = [f"{p.relative_to(ROOT)}:{line}" for p in DOC_FILES for line, marker, _ in shell_blocks(p) if marker is None]
    assert not unmarked, "shell blocks without <!-- doctest --> or <!-- doctest: skip REASON -->: " + ", ".join(unmarked)
    no_reason = [f"{p.relative_to(ROOT)}:{line}" for p in DOC_FILES for line, lang, marker, arg, _ in blocks(p) if marker in ("skip", "write") and not arg]
    assert not no_reason, "doctest: skip/write without a reason/path: " + ", ".join(no_reason)
    runnable = {p.name for p in DOC_FILES if any(m == "run" for _, m, _ in shell_blocks(p))}
    assert {"README.md", "getting-started.md", "cli.md", "export.md", "sources.md"} <= runnable


def _prose(path: Path) -> list[tuple[int, str]]:
    """(line number, line) outside fenced code blocks."""
    out, fence = [], False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if not fence:
            out.append((n, re.sub(r"`[^`]*`", "", line)))  # inline code is not a link
    return out


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to dashes."""
    text = re.sub(r"[`*_]|<[^>]+>", "", heading.strip()).lower()
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out = set()
    for _, line in _prose(path):
        m = re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            s = _slug(m.group(1))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
    out |= set(re.findall(r'<a\s+(?:id|name)="([^"]+)"', path.read_text(encoding="utf-8")))
    return out


LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")


OWN_URLS = ("https://github.com/threat-hunter-eu/sigharvest/blob/main/", "https://raw.githubusercontent.com/threat-hunter-eu/sigharvest/main/")


README_IMAGE = re.compile(r'<(?:img|source)\b[^>]*?\b(?:src|srcset)="([^"]+)"')


def test_readme_links_are_absolute_and_images_relative():
    """docs/conventions.md: README links are absolute; its own images are relative (they render on GitHub while the
    repository is private) and scripts/maintainer/pypi_readme.py makes them absolute for PyPI at build time."""
    text = "\n".join(line for _, line in _prose(ROOT / "README.md"))
    images = README_IMAGE.findall(text) + re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", text)
    relative_links = [t for t in set(LINK.findall(text)) - set(images) if not t.startswith("#") and not re.match(r"[a-z][a-z0-9+.-]*:", t, flags=re.I)]
    assert not relative_links, relative_links
    own = [i for i in images if i.startswith(OWN_URLS)]
    assert images and not own, f"use a relative path for the repository's own images: {own}"


def test_pypi_readme_is_absolute_and_resolves():
    """What publish.yml puts on PyPI: every link and image absolute, the repository's own ones pointing at files."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("pypi_readme", ROOT / "scripts" / "maintainer" / "pypi_readme.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = mod.absolute((ROOT / "README.md").read_text(encoding="utf-8"), mod.repository(ROOT))
    targets = LINK.findall(out) + README_IMAGE.findall(out) + re.findall(r'<a\b[^>]*?\bhref="([^"]+)"', out)
    assert targets
    assert not [t for t in targets if not t.startswith("#") and not re.match(r"[a-z][a-z0-9+.-]*:", t, flags=re.I)]
    for t in README_IMAGE.findall(out):
        if t.startswith(OWN_URLS[1]):
            assert (ROOT / t.removeprefix(OWN_URLS[1])).is_file(), t
        else:
            assert t.startswith("https://") and "/blob/" not in t, t  # a blob/ URL is an HTML page, not the image
    assert mod.absolute(out, mod.repository(ROOT)) == out  # idempotent
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert 0 <= publish.index("scripts/maintainer/pypi_readme.py") < publish.index("uv build"), "publish.yml rewrites README before building"


def test_relative_links_and_images_exist():
    """Every relative link or image in the docs points at a file of the repository, and every #anchor at a heading."""
    bad = []
    for p in DOC_FILES:
        text = "\n".join(line for _, line in _prose(p))
        targets = LINK.findall(text) + re.findall(r'<(?:img|source)\s[^>]*(?:src|srcset)="([^"]+)"', text)
        targets += re.findall(r"^\s*\[[^\]]+\]:\s*(\S+)", text, flags=re.M)  # reference-style definitions
        for target in targets:
            for own in OWN_URLS:  # README links are absolute (they must work on PyPI): check them as repository paths
                if target.startswith(own):
                    target = os.path.relpath(ROOT / target.removeprefix(own), p.parent)
            if re.match(r"[a-z][a-z0-9+.-]*:", target, flags=re.I):  # https:, mailto:, ...
                continue
            path_part, _, anchor = target.partition("#")
            dest = (p.parent / unquote(path_part)).resolve() if path_part else p
            if not dest.exists():
                bad.append(f"{p.relative_to(ROOT)}: {target} (no such file)")
            elif anchor and dest.suffix == ".md" and anchor not in _anchors(dest):
                bad.append(f"{p.relative_to(ROOT)}: {target} (no such heading)")
            elif ROOT not in dest.parents and dest != ROOT:
                bad.append(f"{p.relative_to(ROOT)}: {target} (outside the repository)")
    assert not bad, "broken relative links: " + "; ".join(bad)


def test_markdown_tables_render():
    """Every run of `|` lines outside code blocks is a table GitHub renders: a header row, then a `|---|` row with
    as many columns, and no row with more cells than the header (GitHub drops the extra cells)."""

    def cols(x: str) -> int:
        return len(re.split(r"(?<!\\)\|", re.sub(r"`[^`]*`", "x", x.strip()).strip("|")))

    bad = []
    for p in DOC_FILES:
        fence, run = False, []
        for n, line in enumerate([*p.read_text(encoding="utf-8").splitlines(), ""], start=1):
            if line.lstrip().startswith("```"):
                fence = not fence
            if not fence and line.startswith("|"):
                run.append((n, line))
                continue
            if run:
                head, sep = run[0], run[1] if len(run) > 1 else (run[0][0], "")
                if not re.fullmatch(r"\|(\s*:?-+:?\s*\|)+", sep[1].strip()) or cols(sep[1]) != cols(head[1]):
                    bad.append(f"{p.relative_to(ROOT)}:{head[0]} (no |---| row under the header)")
                bad += [f"{p.relative_to(ROOT)}:{r[0]} (more cells than the header)" for r in run[2:] if cols(r[1]) > cols(head[1])]
                run = []
    assert not bad, "tables that do not render: " + ", ".join(bad)


def test_skip_rules():
    assert skip_reason("uv tool install sigharvest") == "network"
    assert skip_reason("sigharvest serve") == "long-running server"
    assert skip_reason("sigharvest search x") is None
    assert skip_reason("sigharvest update --source acme") is not None
    assert skip_reason("sigharvest update --source mine") is None
    assert skip_reason("sigharvest init ~/sigma --from-release latest") is not None
    m = MARK.search("<!-- doctest: write my-rule.yml -->")
    assert m and m.group("verb") == "write" and m.group("arg") == "my-rule.yml"
    m = MARK.search("<!-- doctest: skip needs a server -->")
    assert m and m.group("verb") == "skip"
    m = MARK.search("<!-- doctest -->")
    assert m and m.group("verb") is None
    assert commands("a \\\n  b  # c\n\n# only a comment\nd") == ["a    b  # c", "d"]


# ---------------------------------------------------------------------------------------------------------------
# the fixture: the acceptance fixture repositories plus synthetic rules (written for these tests, not copied from
# any publisher) that the doc examples search for

MIMIKATZ_ID = "0d0c5a3e-7a41-4f6e-9d2b-d0c5000000a1"
DOC_RULES_KEY_FILE = "rules/windows/proc_mimikatz_lsass.yml"


def _rule(title: str, rid: str, tags: list[str], detection: dict, level: str, status: str = "stable", description: str = "", **logsource: str) -> str:
    return yaml.safe_dump(
        {
            "title": title,
            "id": rid,
            "status": status,
            "description": description or f"{title} (documentation fixture).",
            "author": "Documentation Fixture",
            "date": "2026-01-01",
            "tags": tags,
            "logsource": logsource or {"category": "process_creation", "product": "windows"},
            "detection": {**detection, "condition": "selection"},
            "level": level,
        },
        sort_keys=False,
    )


DOC_RULES = {
    "rules/windows/proc_mimikatz_lsass.yml": _rule(
        "Mimikatz LSASS Credential Dumping",
        MIMIKATZ_ID,
        ["attack.credential-access", "attack.t1003.001"],
        {"selection": {"CommandLine|contains": ["sekurlsa::logonpasswords", "sekurlsa::pth", "lsass"]}},
        "high",
        description="Detects mimikatz credential dumping from lsass memory and pass the hash (documentation fixture).",
    ),
    "rules/windows/proc_powershell_encoded.yml": _rule(
        "PowerShell Encoded Command",
        "0d0c5a3e-7a41-4f6e-9d2b-d0c5000000a2",
        ["attack.execution", "attack.t1059.001"],
        {"selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": " -enc "}},
        "critical",
    ),
    "rules/windows/proc_procdump_lsass.yml": _rule(
        "Procdump LSASS Dump",
        "0d0c5a3e-7a41-4f6e-9d2b-d0c5000000a3",
        ["attack.credential-access", "attack.t1003.001"],
        {"selection": {"Image|endswith": "\\procdump.exe", "CommandLine|contains": "lsass"}},
        "high",
    ),
    "rules/windows/proc_bitsadmin_download.yml": _rule(
        "Bitsadmin Download",
        "0d0c5a3e-7a41-4f6e-9d2b-d0c5000000a4",
        ["attack.command-and-control", "attack.t1105"],
        {"selection": {"Image|endswith": "\\bitsadmin.exe", "CommandLine|contains": "/transfer"}},
        "high",
        description="Bitsadmin used to download a file (documentation fixture).",
    ),
    "deprecated/proc_cobalt_strike_pipe.yml": _rule(
        "Cobalt Strike Named Pipe",
        "0d0c5a3e-7a41-4f6e-9d2b-d0c5000000a5",
        ["attack.execution", "attack.t1569"],
        {"selection": {"PipeName|startswith": "\\MSSE-"}},
        "critical",
        status="deprecated",
        category="pipe_created",
        product="windows",
    ),
}

LOCAL_RULE = _rule(
    "Local Net User Enumeration",
    "0d0c5a3e-7a41-4f6e-9d2b-d0c5000000b1",
    ["attack.discovery", "attack.t1033"],
    {"selection": {"Image|endswith": "\\net.exe", "CommandLine|contains": " user"}},
    "medium",
    status="test",
)

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Documentation Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Documentation Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {**os.environ, **GIT_ENV, "HOME": str(repo.parent)}
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, capture_output=True)


def _cli() -> str:
    """The sigharvest console script of this environment (the doc commands call it by name)."""
    exe = shutil.which("sigharvest", path=str(Path(sys.executable).parent)) or shutil.which("sigharvest")
    if exe is None:
        pytest.fail("the sigharvest console script is not installed (uv sync)")
    return exe


def _env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SIGHARVEST_", "GITHUB_TOKEN", "PYTEST_"))}
    dead = "http://127.0.0.1:9"  # nothing listens there: any HTTP client that honours the proxy variables fails fast
    env.update(
        HOME=str(home),
        COLUMNS="200",
        NO_COLOR="1",
        GIT_ALLOW_PROTOCOL="file",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        http_proxy=dead,
        https_proxy=dead,
        HTTP_PROXY=dead,
        HTTPS_PROXY=dead,
        ALL_PROXY=dead,
        no_proxy="127.0.0.1,localhost",
        NO_PROXY="127.0.0.1,localhost",
        PATH=f"{Path(_cli()).parent}{os.pathsep}{os.environ.get('PATH', '')}",
    )
    return env


def _run(env: dict[str, str], cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    r = subprocess.run([_cli(), *args], check=False, env=env, cwd=cwd, capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, f"sigharvest {' '.join(args)}: exit {r.returncode}\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}"
    return r


# pySigma's tag validators read ATT&CK / D3FEND from the catalogues the validate stage prepares once in the workspace
# cache (sigharvest/pysigma_tags.py): seeded here with the suite's small ATT&CK vocabulary, as tests/offline.py does
# in process, so the CLI never downloads them.
def _seed_pysigma(cache: Path) -> None:
    import time

    from sigharvest import pysigma_tags
    from tests.helpers import ATTACK_FIXTURE

    tactics = {row[2]: row[0] for row in ATTACK_FIXTURE["tactics"]} | {"TA0005": "defense-evasion"}
    techniques = {t["id"]: t["name"] for t in ATTACK_FIXTURE["techniques"]} | {"T1110": "Brute Force", "T1140": "Deobfuscate/Decode Files or Information"}
    data = {
        "attack": {
            "mitre_attack_version": "fixture",
            "mitre_attack_tactics": tactics,
            "mitre_attack_techniques": techniques,
            "mitre_attack_techniques_tactics_mapping": {},
            "mitre_attack_intrusion_sets": {},
            "mitre_attack_software": {},
            "mitre_attack_datasources": {},
            "mitre_attack_mitigations": {},
        },
        "d3fend": {"mitre_d3fend_version": "fixture", "mitre_d3fend_tactics": {}, "mitre_d3fend_techniques": {}, "mitre_d3fend_artifacts": {}},
    }
    for c in pysigma_tags.CATALOGS:
        path = cache / "pysigma" / f"{c.name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"format": pysigma_tags.FORMAT, "url": c.url, "fetched_at": time.time(), "data": data[c.name]}
        path.write_text(json.dumps(doc), encoding="utf-8")


def build_workspace(home: Path) -> dict[str, str]:
    """Build HOME/sigma (see the module docstring); returns the placeholder substitutions for the doc commands."""
    from sigharvest.config import Workspace
    from tests.helpers import seed_attack, seed_schemas

    env = _env(home)
    ws = home / "sigma"
    fx = home / "fixture-sources"
    subprocess.run(
        [sys.executable, str(ROOT / "tests/acceptance/lib/make_fixtures.py"), "sigma", str(fx)], check=True, capture_output=True, env={**os.environ, **GIT_ENV}
    )
    docs_repo = fx / "doc-rules"
    for rel, text in DOC_RULES.items():
        (docs_repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (docs_repo / rel).write_text(text, encoding="utf-8")
    (docs_repo / "LICENSE").write_text(
        "Detection Rule License (DRL) 1.1\n\nCopyright (c) 2026 Documentation Fixture\n", encoding="utf-8"
    )  # synthetic rules: the DRL text itself is bundled by sigharvest
    _git(docs_repo, "init", "-q", "-b", "main")
    _git(docs_repo, "add", "-A")
    _git(docs_repo, "commit", "-q", "-m", "fixture: documentation rules")

    _run(env, home, "init", str(ws))
    data = yaml.safe_load((ws / "sources.yaml").read_text(encoding="utf-8"))
    by_name = {s["name"]: s for s in data["sources"]}
    core = {**by_name["sigmahq-core"], "url": f"file://{docs_repo}", "paths": ["rules/**", "deprecated/**"], "enabled": True}
    alpha = {"name": "fixture-sigma-alpha", "url": f"file://{fx / 'fixture-sigma-alpha'}", "licence": "DRL-1.1", "priority": 20, "enabled": True}
    beta = {"name": "fixture-sigma-beta", "url": f"file://{fx / 'fixture-sigma-beta'}", "licence": "MIT", "priority": 30, "enabled": True}
    noisy = {"name": "noisy-repo", "url": f"file://{fx / 'fixture-sigma-beta'}", "licence": "MIT", "priority": 90, "enabled": False}
    data["sources"] = [core, alpha, beta, noisy]
    (ws / "sources.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    w = Workspace(ws)
    seed_attack(w)
    seed_schemas(w)
    _seed_pysigma(w.cache)

    # folders and files the examples refer to
    for d in (home / "detections", home / "work" / "detections", ws / "rules"):
        d.mkdir(parents=True)
        (d / "local_net_user.yml").write_text(LOCAL_RULE, encoding="utf-8")
    _run(env, ws, "update")

    # an upstream change, so the rule has two versions (`show`, `diff KEY 1 2`), then two release folders
    (ws / "rel-old").mkdir()
    _run(env, ws, "release", "build", "rel-old")
    f = docs_repo / DOC_RULES_KEY_FILE
    f.write_text(f.read_text(encoding="utf-8").replace("documentation fixture).", "documentation fixture, revised)."), encoding="utf-8")
    _git(docs_repo, "commit", "-q", "-am", "fixture: revise the mimikatz rule", date="2026-02-01T00:00:00Z")
    _run(env, ws, "update")
    _run(env, ws, "release", "build", "rel-new")
    shutil.copytree(ws / "rel-new", ws / "last-release")

    (ws / "my-rule.yml").write_text(DOC_RULES["rules/windows/proc_powershell_encoded.yml"], encoding="utf-8")
    for name in ("ransomware", "lateral movement"):
        _run(env, ws, "collection", "add", name, "-q", "lsass")

    # the fixture looks like the real thing: the correlation and its base rule are indexed, broken.yml is quarantined
    corr = json.loads(_run(env, ws, "search", "brute force", "--json").stdout)["results"]
    assert any(h["title"] == "Fixture Brute Force Correlation" for h in corr), corr
    hits = json.loads(_run(env, ws, "search", "mimikatz", "--json").stdout)["results"]
    key = next(h for h in hits if h["rule_id"] == MIMIKATZ_ID)["logic_hash"][:10]
    quarantined = json.loads(_run(env, ws, "quarantine", "list", "--json").stdout)
    return {"key": key, "quarantine": str(quarantined["results"][0]["id"])}


def substitute(cmd: str, subst: dict[str, str]) -> str:
    """The doc's placeholders replaced by their fixture counterparts: the rule key 8c0b4bfbcc (any rule key in the
    docs; SigmaHQ's "HackTool - Mimikatz Execution" in a real workspace) is the mimikatz rule,
    quarantine record 42 is the fixture's first quarantined document."""
    cmd = cmd.replace("8c0b4bfbcc", subst["key"])
    if cmd.startswith("sigharvest quarantine "):
        cmd = re.sub(r"(?<= )42\b", subst["quarantine"], cmd)
    return cmd


@pytest.fixture(scope="session")
def doc_workspace(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, str]]:
    home = tmp_path_factory.mktemp("dochome")
    return home, build_workspace(home)


def _q(s: str | Path) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


def _script(home: Path, doc: Path, scratch: Path, subst: dict[str, str]) -> tuple[str, list[str]]:
    """The bash script for one doc file, and the commands it skips."""
    # `init ~/sigma` (or `init .` inside it): the fixture already is ~/sigma; init the same way into a scratch folder
    init = (
        'sigharvest() { if [ "$1" = init ]; then shift; local a=() x; for x in "$@"; do'
        ' if [ "$(realpath -m -- "$x")" = "$(realpath -- "$HOME/sigma")" ]; then'
        f' x=$(mktemp -d -u -p {_q(scratch)} init.XXXX); fi; a+=("$x"); done;'
        ' command sigharvest init "${a[@]}"; else command sigharvest "$@"; fi; }'
    )
    lines = ["set -eo pipefail", init, "cd ~/sigma"]
    skipped = []
    for line, lang, marker, arg, code in blocks(doc):
        if marker == "write":
            assert ".." not in arg and not arg.startswith("/"), f"{doc.name}:{line}: write needs a path inside ~/sigma"
            lines += [f'mkdir -p "$(dirname ~/sigma/{_q(arg)})"', f"cat > ~/sigma/{_q(arg)} <<'DOCTEST_EOF'", code, "DOCTEST_EOF"]
            continue
        if marker != "run" or lang not in SHELL:
            continue
        lines.append(f"cd ~/sigma  # {doc.name}:{line}")
        for cmd in commands(code):
            why = skip_reason(cmd)
            if why:
                skipped.append(f"{cmd}  ({why})")
                continue
            cmd = substitute(cmd, subst)
            # `a && b` hides a failing `a` from `set -e`: the group's status is checked explicitly
            lines += [f"echo {_q('$ ' + cmd)}", "{", cmd, '} || { rc=$?; echo "exit status $rc"; exit "$rc"; }']
    return "\n".join(lines) + "\n", skipped


RUNNABLE = [p for p in DOC_FILES if any(m == "run" for _, m, _ in shell_blocks(p))]


@pytest.mark.docs
@pytest.mark.parametrize("doc", RUNNABLE, ids=[p.name for p in RUNNABLE])
def test_doc_commands_run(doc: Path, doc_workspace: tuple[Path, dict[str, str]], tmp_path: Path):
    fixture_home, subst = doc_workspace
    home = tmp_path / "home"
    shutil.copytree(fixture_home, home, symlinks=True)  # sources.yaml still points at the session's fixture repos
    script, skipped = _script(home, doc, tmp_path, subst)
    r = subprocess.run(["bash", "-c", script], check=False, cwd=home, env=_env(home), capture_output=True, text=True, timeout=900)
    out = r.stdout + r.stderr
    for bad in ("Traceback (most recent call last)", "Internal Server Error"):
        assert bad not in out, f"{doc.name}: {bad} in the output:\n{out[-6000:]}"
    assert r.returncode == 0, f"{doc.name}: a documented command failed (the last '$ ' line is the command):\n{out[-6000:]}"
    print(f"{doc.name}: skipped {len(skipped)}:", *skipped, sep="\n  ")


if __name__ == "__main__":  # build a fixture workspace to explore: python -m tests.test_docs HOME
    print(build_workspace(Path(sys.argv[1]).resolve()))
