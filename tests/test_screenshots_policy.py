"""Published screenshots only show rules the project redistributes (scripts/maintainer/screenshots.py).

A demo workspace where the canonical copy of a rule comes from a source without a licence (as on the real corpus)
must never yield that rule for the rule or search shot; a rule without a licence, restricted or with a copyleft
licence whose text is not shipped is refused outright."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.service import open_db, sync_all

ROOT = Path(__file__).resolve().parents[1]
RULE = """title: {title}
id: {uid}
status: stable
description: {title} described in prose
author: Someone
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: '{needle}'
  condition: selection
level: high
"""
LSASS = {"title": "LSASS Dump Via Procdump", "uid": "5afee48e-67dd-4e03-a783-f74259dcf998", "needle": "procdump -ma lsass"}
OTHER = {"title": "LSASS Access From Comsvcs", "uid": "0f3e2a1b-1111-4c2d-9e8f-123456789abc", "needle": "comsvcs MiniDump lsass"}
# The current shots search for mimikatz: a rule with a copy in the unlicensed source too would be refused by the guard,
# this one only lives in the licensed source.
MIMI = {"title": "Mimikatz Use", "uid": "06d71506-7beb-4f22-8888-e2e5e2ca7fd8", "needle": "sekurlsa::logonpasswords mimikatz"}


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("screenshots", ROOT / "scripts" / "maintainer" / "screenshots.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["screenshots"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def shots() -> Any:
    return _script()


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    root: Path = tmp_path_factory.mktemp("shots")
    (root / "nolicence").mkdir()
    (root / "nolicence" / "lsass.yml").write_text(RULE.format(**LSASS))
    (root / "drl").mkdir()
    (root / "drl" / "lsass.yml").write_text(RULE.format(**LSASS))
    (root / "drl" / "other.yml").write_text(RULE.format(**OTHER))
    (root / "drl" / "mimikatz.yml").write_text(RULE.format(**MIMI))
    ws = Workspace(root / "ws")
    ws.root.mkdir()
    save_sources(
        ws,
        [  # the unlicensed copy wins the canonical slot (lower priority number), as in the demo corpus
            SourceConfig(name="someone__nolicence", type="local", url=str(root / "nolicence"), licence=None, priority=10),
            SourceConfig(name="drl-rules", type="local", url=str(root / "drl"), licence="DRL-1.1", redistributable=True, priority=50),
        ],
    )
    sessions = open_db(ws, migrate=True)
    sync_all(ws, workers=1)
    from sigharvest.index import rebuild
    from sigharvest.lock import mutation_lease

    with mutation_lease(ws), sessions() as s:
        assert rebuild(s, workers=1) == 3
    from sigharvest.web.app import create_app

    with TestClient(create_app(ws, sessions), base_url="http://127.0.0.1") as c:
        yield c


@pytest.fixture
def served(shots: Any, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(shots, "fetch", lambda url: client.get(url.removeprefix("http://demo")).content)
    return shots


def test_check_shareable_refuses_unlicensed_restricted_and_unshipped(shots: Any) -> None:
    for rule in ({"licence_class": "none"}, {"licence_class": "restricted", "licence": "CC-BY-NC-4.0"}, {}):
        with pytest.raises(shots.NotShareable):
            shots.check_shareable("sigharvest", rule)
    with pytest.raises(shots.NotShareable, match="not shipped"):
        shots.check_shareable("sigharvest", {"licence_class": "copyleft", "licence": "EPL-9.0"})
    for licence, cls in (("DRL-1.1", "permissive"), ("MIT", "permissive"), ("AGPL-3.0-only", "copyleft"), ("LGPL-3.0-or-later", "copyleft")):
        shots.check_shareable("sigharvest", {"licence_class": cls, "licence": licence})
    catalogue = {
        "et-open": {"name": "et-open", "licence": "BSD-3-Clause AND GPL-2.0-only", "redistribute": "yes"},
        "paw": {"name": "paw", "licence": "CC-BY-NC-SA-4.0", "redistribute": "yes"},
        "etnetera": {"name": "etnetera", "licence": "MIT", "redistribute": "unknown"},
    }
    shots.check_shareable("suriharvest", {"canonical_source": "et-open"}, catalogue)
    for source in ("paw", "etnetera", "missing"):
        with pytest.raises(shots.NotShareable):
            shots.check_shareable("suriharvest", {"canonical_source": source}, catalogue)


def test_old_query_would_show_the_unlicensed_copy(served: Any) -> None:
    """The query of the first screenshots (first hit for 'lsass status:stable') resolves to the unlicensed canonical
    copy: the guard refuses it."""
    with pytest.raises(served.NotShareable, match="no licence"):
        served.resolve("http://demo", "/rule/{first:q=lsass+status%3Astable}")
    with pytest.raises(served.NotShareable):
        served.resolve("http://demo", "/search?q=lsass+status%3Astable")


def test_rule_and_search_shots_show_only_redistributable_rules(served: Any) -> None:
    for name in ("rule", "search"):
        path = served.SHOTS["sigharvest"][name]
        resolved = served.resolve("http://demo", path, "sigharvest")  # raises NotShareable otherwise
        query = served.SIG_QUERY if name == "search" else path.split("{first:", 1)[1].rstrip("}")
        rules = served.shown_rules("http://demo", "sigharvest", query, served.VISIBLE)
        assert rules and all(r["licence_class"] in ("permissive", "copyleft") for r in rules), rules
        assert [r["title"] for r in rules] == [MIMI["title"]]
        if name == "rule":
            assert resolved == f"/rule/{rules[0]['logic_hash']}"
