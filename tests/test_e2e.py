r"""End-to-end: the whole user journey on a small but realistic rule community, through the CLI.

The community is three local git repositories that the workspace reaches through their real https URLs (git's
`url.<local>.insteadOf` rewrites them; GIT_ALLOW_PROTOCOL=file from conftest refuses anything else), so
well-known source detection, GitHub links and release sources behave as they do in production:

- sigma (SigmaHQ/sigma): reference rules, regression_data/ with an info.yml and a JSON sample, a deprecated/ rule;
- hayabusa (Yamato-Security/hayabusa-rules): a `related: derived` copy, an exact copy, a changed copy of the
  deprecated rule, config/proven_rules.txt and config/noisy_rules.txt;
- junk (example/junk-rules, no licence): two unrelated rules sharing a placeholder UUID, a synthetic "Scale
  Variant 0001 Marker" rule, a test fixture under tests/, a splunk_spl wrapper, a rule whose metadata is broken
  but whose detection is valid, and a broken fork of a SigmaHQ rule (an OR list turned into an AND map).

Steps: init, sources remove/add, update (sync + test + index + report), search with inline filters, show,
collections, coverage, an upstream change and re-sync (collections follow), release build, lint against the
release and site build.
"""

from __future__ import annotations

import gzip
import json
import re
import textwrap
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sigharvest import conversion
from sigharvest.cli import app
from sigharvest.config import Workspace, load_sources
from sigharvest.index import GroupFilters, search_groups
from sigharvest.models import LogicGroup
from sigharvest.service import open_db
from tests.helpers import seed_attack, seed_schemas
from tests.test_pipeline import commit, git

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

SIGMA_URL = "https://github.com/SigmaHQ/sigma"
HAYABUSA_URL = "https://github.com/Yamato-Security/hayabusa-rules"
JUNK_URL = "https://github.com/example/junk-rules"

RID_WHOAMI = "6e2b9d4f-a817-4c3e-b05d-93f1c7a2e648"
RID_CERTUTIL = "9a6e3b14-f8c2-4d07-b1a5-3e9d70c2f846"
RID_MIMIKATZ = "d2f7a058-1b6e-4c93-8e0a-f564c9b31d27"
RID_PSEXEC = "7b13e9c6-04da-4f81-9c2e-a8d5f61037be"
RID_HAYABUSA_WHOAMI = "c590fa2d-e7b4-4318-a6c1-2d9e08f75b43"
PLACEHOLDER = "00000000-0000-0000-0000-000000000000"
NEW_ID = "3c8d1e5a-97b2-4f06-a1d4-6e0b29f7c385"


def _y(text: str) -> str:
    return textwrap.dedent(text).lstrip()


WHOAMI = _y(rf"""
    title: Whoami Recon
    id: {RID_WHOAMI}
    status: test
    description: Detects whoami.exe used to discover the current user.
    author: Fixture Author
    date: 2024-01-10
    modified: 2026-01-10
    tags:
        - attack.discovery
        - attack.t1033
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            - Image|endswith: '\whoami.exe'
            - OriginalFileName: 'whoami.exe'
        condition: selection
    level: medium
""")
CERTUTIL = _y(rf"""
    title: Certutil Download
    id: {RID_CERTUTIL}
    status: stable
    description: certutil.exe downloads a file with -urlcache.
    author: Fixture Author
    date: 2025-05-01
    tags:
        - attack.command-and-control
        - attack.t1105
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image|endswith: '\certutil.exe'
            CommandLine|contains: 'urlcache'
        condition: selection
    level: high
""")
MIMIKATZ = _y(rf"""
    title: Mimikatz Command Line
    id: {RID_MIMIKATZ}
    status: stable
    description: Mimikatz modules on the command line.
    author: Fixture Author
    date: 2025-02-01
    tags:
        - attack.credential-access
        - attack.t1003.001
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|contains:
                - 'sekurlsa::logonpasswords'
                - 'lsadump::sam'
        condition: selection
    level: critical
""")
PSEXEC = _y(rf"""
    title: PsExec Service Start
    id: {RID_PSEXEC}
    status: deprecated
    description: PsExec service binary started.
    author: Fixture Author
    date: 2019-01-01
    tags:
        - attack.execution
        - attack.t1569
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image|endswith: '\PSEXESVC.exe'
        condition: selection
    level: low
""")
# Hayabusa: the original detection with its channel and event id made explicit, linked by `related: derived`.
HAYABUSA_WHOAMI = WHOAMI.replace(f"id: {RID_WHOAMI}", f"id: {RID_HAYABUSA_WHOAMI}\nrelated:\n    - id: {RID_WHOAMI}\n      type: derived").replace(
    "    condition: selection",
    "    sysmon:\n        Channel: Microsoft-Windows-Sysmon/Operational\n        EventID: 1\n    condition: selection and sysmon",
)
# A copy that still uses the id SigmaHQ deprecated, with a changed detection and without saying it is deprecated.
HAYABUSA_PSEXEC = PSEXEC.replace("status: deprecated", "status: test").replace(
    "        Image|endswith: '\\PSEXESVC.exe'", "        Image|endswith:\n            - '\\PSEXESVC.exe'\n            - '\\PSEXEC.exe'"
)
# A broken fork: the OR list became an AND map, so it no longer fires on the recorded attack.
BROKEN_FORK = WHOAMI.replace(
    "        - Image|endswith: '\\whoami.exe'\n        - OriginalFileName: 'whoami.exe'",
    "        Image|endswith: '\\whoami.exe'\n        OriginalFileName: 'whoami.exe'",
).replace("author: Fixture Author", "author: Someone Else")
for _variant in (HAYABUSA_WHOAMI, HAYABUSA_PSEXEC, BROKEN_FORK):
    assert _variant.count("Fixture Author") + _variant.count("Someone Else") == 1
NET_USE = _y(rf"""
    title: Net Use Share Mapping
    id: {PLACEHOLDER}
    status: experimental
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|contains: 'net use \\'
        condition: selection
    level: low
""")
RUNDLL = _y(rf"""
    title: Rundll32 Without Arguments
    id: {PLACEHOLDER}
    status: experimental
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|endswith: 'rundll32.exe'
        condition: selection
    level: medium
""")
SYNTHETIC = _y("""
    title: Attack Scale Variant 0001 Marker
    id: 5c08d7f2-a3e9-41b6-8d4c-e9271f0b63a5
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|contains: 'marker-0001'
        condition: selection
""")
FIXTURE_RULE = _y("""
    title: Fixture Rule For Unit Tests
    id: 18e6c3fb-9a52-4d0e-87b9-c4f1a03e6d25
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image|endswith: '\\fixture.exe'
        condition: selection
""")
SPLUNK_WRAPPER = _y("""
    title: Splunk Wrapped Search
    id: f0a49d71-3c8e-4b25-9e6d-57b2c18af039
    splunk_spl: 'index=wineventlog EventCode=4688 New_Process_Name="*\\\\evil.exe"'
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4688
        condition: selection
""")
# Metadata pySigma refuses (id, date, level), detection fine: a warning, and still converted.
BROKEN_META = _y(r"""
    title: Encoded PowerShell
    id: not-a-uuid
    date: 2023/31/12
    level: urgent
    author: Junk Author
    tags:
        - attack.execution
        - attack.t1059.001
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            Image|endswith: '\powershell.exe'
            CommandLine|contains: ' -enc '
        condition: selection
""")


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _repo(path: Path, files: dict[str, str]) -> Path:
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    _write(path, files)
    commit(path, "init")
    return path


def _sysmon(image: str, cmd: str) -> dict[str, Any]:
    return {
        "Event": {
            "System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Computer": "ws1"},
            "EventData": {"Image": image, "CommandLine": cmd},
        }
    }


WHOAMI_EVENT = _sysmon("C:\\Windows\\System32\\whoami.exe", "whoami /all")
CERTUTIL_EVENT = _sysmon("C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f http://x/a.exe a.exe")
BENIGN_EVENT = _sysmon("C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt")


def build_community(tmp: Path) -> dict[str, Path]:
    regression = "regression_data/rules/windows/process_creation/proc_creation_win_whoami_recon"
    info = (
        f"id: 0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e\nrule_metadata:\n  - id: {RID_WHOAMI}\n    title: Whoami Recon\n"
        f"regression_tests_info:\n  - name: Sysmon whoami\n    type: json\n    provider: Microsoft-Windows-Sysmon\n"
        f"    match_count: 1\n    path: {regression}/{RID_WHOAMI}.json\n"
    )
    sigma = _repo(
        tmp / "remote" / "sigma",
        {
            "rules/windows/process_creation/proc_creation_win_whoami_recon.yml": WHOAMI,
            "rules/windows/process_creation/proc_creation_win_certutil_download.yml": CERTUTIL,
            "rules/windows/process_creation/proc_creation_win_mimikatz_cli.yml": MIMIKATZ,
            "deprecated/windows/proc_creation_win_psexec_service.yml": PSEXEC,
            f"{regression}/info.yml": info,
            f"{regression}/{RID_WHOAMI}.json": json.dumps(WHOAMI_EVENT),
            "README.md": "# Sigma\n",
        },
    )
    hayabusa = _repo(
        tmp / "remote" / "hayabusa",
        {
            "sigma/builtin/process_creation/proc_creation_win_whoami_recon.yml": HAYABUSA_WHOAMI,
            "sigma/builtin/process_creation/proc_creation_win_certutil_download.yml": CERTUTIL,
            "sigma/builtin/process_creation/proc_creation_win_psexec_service.yml": HAYABUSA_PSEXEC,
            "config/proven_rules.txt": f"# rules that fired on the sample EVTX\n{RID_HAYABUSA_WHOAMI}\n",
            "config/noisy_rules.txt": f"{RID_CERTUTIL} # Certutil Download\n",
        },
    )
    junk = _repo(
        tmp / "remote" / "junk",
        {
            "rules/net_use.yml": NET_USE,
            "rules/rundll32.yml": RUNDLL,
            "rules/generated/scale_variant_0001.yml": SYNTHETIC,
            "tests/fixtures/fixture_rule.yml": FIXTURE_RULE,
            "rules/splunk/wrapped.yml": SPLUNK_WRAPPER,
            "rules/encoded_powershell.yml": BROKEN_META,
            "rules/whoami_fork.yml": BROKEN_FORK,
        },
    )
    return {"sigma": sigma, "hayabusa": hayabusa, "junk": junk}


def _redirect_git(monkeypatch: pytest.MonkeyPatch, repos: dict[str, Path]) -> None:
    """Make git fetch each https URL from its local fixture repository (no network)."""
    pairs = [(repos["sigma"], SIGMA_URL), (repos["hayabusa"], HAYABUSA_URL), (repos["junk"], JUNK_URL)]
    monkeypatch.setenv("GIT_CONFIG_COUNT", str(len(pairs)))
    for i, (path, url) in enumerate(pairs):
        monkeypatch.setenv(f"GIT_CONFIG_KEY_{i}", f"url.{path.resolve().as_uri()}.insteadOf")
        monkeypatch.setenv(f"GIT_CONFIG_VALUE_{i}", url)


class Cli:
    """CliRunner on one workspace; every call asserts its exit code."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        self.monkeypatch = monkeypatch
        self.home = home
        self.runner = CliRunner(env={"COLUMNS": "220"})

    def __call__(self, *args: str, code: int = 0) -> str:
        self.monkeypatch.setenv("SIGHARVEST_HOME", str(self.home))
        r = self.runner.invoke(app, list(args))
        assert r.exit_code == code, f"sigharvest {' '.join(args)} -> {r.exit_code}\n{r.output}\n{r.exception!r}"
        return r.output


def _groups(ws: Workspace) -> dict[str, LogicGroup]:
    """Every logic group by "source:title" of its canonical copy (unique in this community)."""
    with open_db(ws, migrate=True)() as s:
        out = {f"{g.canonical_source}:{g.title}": g for g in s.scalars(select(LogicGroup))}
        for g in out.values():
            s.expunge(g)
    return out


def _search(ws: Workspace, query: str | None, **filters: Any) -> list[str]:
    with open_db(ws, migrate=True)() as s:
        groups, _n = search_groups(s, query, GroupFilters(**filters), limit=200, per_family=False)
        return sorted(f"{g.canonical_source}:{g.title}" for g in groups)


def test_user_journey(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repos = build_community(tmp_path)
    _redirect_git(monkeypatch, repos)
    home = tmp_path / "ws"
    ws = Workspace(home)
    sigharvest = Cli(monkeypatch, home)

    # ------------------------------------------------------------------ init, sources
    out = sigharvest("init", str(home), "--preset", "sigmahq")
    assert "sources (preset sigmahq)" in out
    sigharvest("init", str(home), code=1)  # refuses to replace sources.yaml without --force
    for cfg in load_sources(ws):
        sigharvest("sources", "remove", cfg.name)
    assert load_sources(ws) == []
    sigharvest("sources", "add", "sigma", SIGMA_URL, "--licence", "DRL-1.1", "--priority", "10")
    sigharvest("sources", "add", "hayabusa", HAYABUSA_URL, "--licence", "DRL-1.1", "--priority", "20")
    sigharvest("sources", "add", "junk", JUNK_URL, "--priority", "50")
    sigharvest("sources", "add", "junk", JUNK_URL, code=2)  # duplicate name
    sigharvest("sources", "disable", "junk")
    assert re.search(r"junk\s+│ git\s+│ 50\s+│ no ", sigharvest("sources", "list"))
    sigharvest("sources", "enable", "junk")
    assert [c.name for c in load_sources(ws) if c.enabled] == ["sigma", "hayabusa", "junk"]
    seed_schemas(ws)  # the validate stage reads its pinned JSON schemas from the cache
    seed_attack(ws)  # coverage and lint read the ATT&CK matrix from the cache

    # ------------------------------------------------------------------ update: sync + test + index + report
    out = sigharvest("update", "--convert", "-j", "2")  # stores conversions for the backend checks below
    assert "sources failed" not in out
    summary = (home / "reports" / "summary.md").read_text()
    assert "| Unique logic (logic_hash) |" in summary and "| sigma | 10 | DRL-1.1 |" in summary
    g = _groups(ws)
    assert len(g) == 13, " | ".join(sorted(g))
    whoami, h_whoami, fork = g["sigma:Whoami Recon"], g["hayabusa:Whoami Recon"], g["junk:Whoami Recon"]
    # related: derived and the shared id put the original, the Hayabusa copy and the fork in one family
    assert whoami.family_id == h_whoami.family_id == fork.family_id and whoami.family_size == 3
    # the exact copy is one logic group with two copies from two sources; SigmaHQ holds the canonical copy
    cert = g["sigma:Certutil Download"]
    assert cert.copies == 2 and cert.sources == ["hayabusa", "sigma"] and cert.n_independent == 2
    # a placeholder UUID does not merge unrelated rules
    net, rundll = g["junk:Net Use Share Mapping"], g["junk:Rundll32 Without Arguments"]
    assert net.rule_id == rundll.rule_id == PLACEHOLDER and net.family_id != rundll.family_id
    # junk is flagged by content and hidden by default
    flags = {k: set(v.quality_flags or []) for k, v in g.items()}
    assert "synthetic" in flags["junk:Attack Scale Variant 0001 Marker"]
    assert "test_fixture" in flags["junk:Fixture Rule For Unit Tests"]
    assert "foreign_query" in flags["junk:Splunk Wrapped Search"]
    assert "upstream_deprecated" in flags["hayabusa:PsExec Service Start"]  # SigmaHQ deprecated this id
    assert g["sigma:PsExec Service Start"].status == "deprecated"
    visible = _search(ws, None)
    assert visible == sorted(
        [
            "hayabusa:Whoami Recon",
            "junk:Encoded PowerShell",
            "junk:Net Use Share Mapping",
            "junk:Rundll32 Without Arguments",
            "junk:Whoami Recon",
            "sigma:Certutil Download",
            "sigma:Mimikatz Command Line",
            "sigma:Whoami Recon",
        ]
    )
    assert len(_search(ws, None, include_junk=True, include_deprecated=True)) == 13
    # broken metadata, valid detection: validation warning, converted for the backends that map it
    meta = g["junk:Encoded PowerShell"]
    assert meta.validation == "warning" and "splunk" in (meta.converts or [])
    assert whoami.validation == cert.validation == "ok" and set(whoami.converts or []) >= {"splunk", "lucene"} & set(conversion.BACKENDS)
    assert g["junk:Splunk Wrapped Search"].validation == "warning"  # pySigma: specific instead of generic log source
    if "microsoft365defender" in conversion.BACKENDS:  # [convert-legacy] only while kusto lacks pySigma 2
        assert (meta.conversion or {}).get("microsoft365defender", {}).get("status") == "ok"

    # ------------------------------------------------------------------ search and show
    out = sigharvest("search", "whoami level:medium product:windows", "--per-logic")
    assert out.count("Whoami Recon") == 3 and "3 rules in 1 family match; showing 3 rules" in out
    out = sigharvest("search", "whoami")
    assert "3 rules in 1 family match; showing 1 family" in out  # one row per family
    out = sigharvest("search", "title:certutil tag:t1105 source:hayabusa", "--per-logic")
    assert "Certutil Download" in out and "1 rule in 1 family match" in out
    out = sigharvest("search", "--per-logic", "--limit", "50", "--", "-whoami")
    assert "Whoami" not in out and "Mimikatz" in out
    assert "Scale Variant" in sigharvest("search", "marker", "--include-junk")
    assert "no rules match" in sigharvest("search", "marker")
    assert "Ambiguous rule key" in sigharvest("show", RID_WHOAMI[:8], code=2)
    out = sigharvest("show", RID_WHOAMI)
    assert "canonical copy: sigma" in out and "family of 3" in out and "validation ok" in out
    assert "licence: DRL-1.1 (permissive), from source sigma; redistributable:" in " ".join(out.split())
    sigharvest("show", "ffffffffff", code=1)

    # ------------------------------------------------------------------ collections
    sigharvest("collection", "create", "recon", "-d", "discovery rules")
    out = sigharvest("collection", "add", "recon", g["sigma:Whoami Recon"].logic_hash[:12], "--note", "keep an eye")
    assert "added 1" in out
    out = sigharvest("collection", "add", "recon", "-q", "certutil")
    assert "added 1" in out
    assert "Certutil Download" in sigharvest("collection", "show", "recon")
    exported = tmp_path / "export-recon"
    sigharvest("export", "-c", "recon", "--out", str(exported))
    manifest = [json.loads(x) for x in (exported / "manifest.jsonl").read_text().splitlines()]
    assert sorted(m["title"] for m in manifest) == ["Certutil Download", "Whoami Recon"]
    assert all(m["licence"] == "DRL-1.1" for m in manifest)
    sigharvest("collection", "show", "nope", code=2)

    # ------------------------------------------------------------------ coverage (ATT&CK fixture)
    layer = tmp_path / "layer.json"
    out = sigharvest("coverage", "--gaps", "--navigator", str(layer))
    assert "ATT&CK 20.0" in out  # covered techniques are checked in the Navigator layer below
    techniques = {t["techniqueID"] for t in json.loads(layer.read_text())["techniques"] if t.get("score")}
    assert {"T1033", "T1105"} <= techniques

    # ------------------------------------------------------------------ upstream change, re-sync
    old_whoami = g["sigma:Whoami Recon"].logic_hash
    changed = WHOAMI.replace("        - OriginalFileName: 'whoami.exe'", "        - OriginalFileName: 'whoami.exe'\n        - CommandLine|contains: 'whoami /'")
    assert changed != WHOAMI
    (repos["sigma"] / "rules/windows/process_creation/proc_creation_win_whoami_recon.yml").write_text(changed)
    commit(repos["sigma"], "whoami: also match the command line")
    sigharvest("update", "-j", "2", "--no-report")
    g = _groups(ws)
    new_whoami = g["sigma:Whoami Recon"]
    assert new_whoami.logic_hash != old_whoami and new_whoami.rule_id == RID_WHOAMI
    out = sigharvest("collection", "show", "recon")
    assert "updated upstream" in out
    sigharvest("collection", "update", "recon")
    with open_db(ws, migrate=True)() as s:
        from sigharvest import collections as col

        states = {r.group.title: (r.state, r.group.logic_hash) for r in col.resolve(s, col.require(s, "recon")) if r.group}
    # The saved rule follows its rule id upstream to the best-scored current logic with that id.
    assert states["Whoami Recon"][0] == "current"
    with open_db(ws)() as s:
        followed = s.scalar(select(LogicGroup).where(LogicGroup.logic_hash == states["Whoami Recon"][1]))
    assert followed is not None and followed.rule_id == RID_WHOAMI

    # ------------------------------------------------------------------ release build
    release = tmp_path / "release"
    sigharvest("release", "build", str(release))
    assert {"ATTRIBUTION.md", "SHA256SUMS", "manifest.json", "rules.jsonl.gz", "NOTICE.md", "index.json.gz"} <= {p.name for p in release.iterdir()}
    with gzip.open(release / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        rows = {f"{r['canonical']['source']}:{r['title']}": r for r in map(json.loads, fh)}
    assert "junk:Attack Scale Variant 0001 Marker" not in rows  # junk stays out of releases by default
    assert rows["sigma:Whoami Recon"]["yaml"] and rows["sigma:Whoami Recon"]["licence_class"] == "permissive"
    assert rows["sigma:Whoami Recon"]["canonical"]["url"].startswith(f"{SIGMA_URL}/blob/")
    assert rows["junk:Encoded PowerShell"]["yaml"] is None and rows["junk:Encoded PowerShell"]["licence_class"] == "none"
    manifest = json.loads((release / "manifest.json").read_text())
    assert {x["name"] for x in manifest["sources"]} == {"sigma", "hayabusa", "junk"}

    # ------------------------------------------------------------------ lint a new rule file against the release
    mine = tmp_path / "mine"
    _write(
        mine,
        {
            # same detection as SigmaHQ's certutil rule, new id
            "certutil_copy.yml": CERTUTIL.replace(RID_CERTUTIL, NEW_ID).replace("Certutil Download", "My Certutil Rule"),
            # reuses the mimikatz id for a different detection
            "id_clash.yml": MIMIKATZ.replace("lsadump::sam", "kerberos::golden").replace("Mimikatz Command Line", "My Kerberos Rule"),
        },
    )
    findings_file = tmp_path / "lint.json"
    out = sigharvest("lint", str(mine), "--release", str(release), "--json", str(findings_file), code=1)
    findings = json.loads(findings_file.read_text())
    by_check = {(Path(f["path"]).name, f["rule"]) for f in findings}
    assert ("certutil_copy.yml", "duplicate-logic") in by_check
    assert ("id_clash.yml", "id-collision") in by_check
    sigharvest("lint", str(mine), "--release", str(release), "--fail-on", "never")

    # ------------------------------------------------------------------ static site from the release
    site = tmp_path / "site"
    sigharvest("site", "build", str(site), "--release", str(release), "--min-score", "0", "--no-collections")
    root = site / "rules"
    assert (root / "index.html").is_file() and (root / "data" / "meta.json").is_file()
    pages = {p.read_text(encoding="utf-8").split("<title>", 1)[1].split("<", 1)[0]: p for p in (root / "r").glob("*.html")}
    whoami_page = next(p for t, p in pages.items() if t.startswith("Whoami Recon")).read_text(encoding="utf-8")
    assert "detection:" in whoami_page and "DRL-1.1" in whoami_page
    meta_page = next(p for t, p in pages.items() if t.startswith("Encoded PowerShell")).read_text(encoding="utf-8")
    assert "Text not redistributed" in meta_page and "-enc" not in meta_page
    blobs = [p.read_text(encoding="utf-8") for p in root.rglob("*") if p.is_file() and p.suffix in (".html", ".json")]
    assert not any("' -enc '" in b for b in blobs)  # the unlicensed rule's text is nowhere on the site
