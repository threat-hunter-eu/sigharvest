"""pySigma's ATT&CK / D3FEND tag catalogues: prepared once per workspace, shared with workers, never a hang offline.

No network: `fetch` is a stub; the reduction itself runs pySigma's real loader on a tiny local STIX bundle.
"""

from __future__ import annotations

import importlib
import json
import subprocess

import pytest
from sqlalchemy import select

from sigharvest import pysigma_tags, testing
from sigharvest.models import TestRun
from tests.helpers import SCHEMA_FIXTURES
from tests.test_versioned_results import InlinePool, corpus  # noqa: F401 - pytest fixture

STIX = {
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-000000000000",
    "objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "20.0"},
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--1",
            "x_mitre_shortname": "execution",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Command and Scripting Interpreter",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--2",
            "name": "Revoked",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1086"}],
        },
    ],
}
ATTACK = next(c for c in pysigma_tags.CATALOGS if c.name == "attack")
D3FEND = next(c for c in pysigma_tags.CATALOGS if c.name == "d3fend")


class Fetch:
    """Stub transport: ATT&CK answers with the tiny bundle, D3FEND is unreachable (offline)."""

    def __init__(self, attack: bytes | Exception = json.dumps(STIX).encode(), d3fend: bytes | Exception = ValueError("transport failed")) -> None:
        self.answers = {ATTACK.url: attack, D3FEND.url: d3fend}
        self.calls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        answer = self.answers[url]
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def unloaded(monkeypatch):
    """pySigma's modules as in a fresh process (tests/offline.py sets the catalogues for the rest of the suite)."""
    for c in pysigma_tags.CATALOGS:
        loaded = vars(importlib.import_module(c.module))
        for key in c.keys:
            if key in loaded:
                monkeypatch.delitem(loaded, key)


def test_downloads_once_reduces_with_pysigma_and_skips_unreachable(tmp_path, unloaded):
    fetch = Fetch()
    prepared = pysigma_tags.prepare(tmp_path, fetch=fetch)
    attack = prepared.data["attack"]
    assert attack is not None
    assert attack["mitre_attack_version"] == "20.0"
    assert attack["mitre_attack_tactics"] == {"TA0002": "execution"}
    assert attack["mitre_attack_techniques"] == {"T1059": "Command and Scripting Interpreter"}  # revoked one left out
    assert prepared.data["d3fend"] is None and prepared.skipped == ("d3fend",)
    assert len(prepared.notes) == 1 and prepared.notes[0].startswith("MITRE D3FEND tag check skipped this run")
    assert not (tmp_path / "pysigma" / "d3fend.json").exists()
    assert not list((tmp_path / "pysigma").glob("reduce-*"))  # the raw bundle is not kept

    # Second run: the stored ATT&CK copy is used; only the missing D3FEND is tried again.
    again = pysigma_tags.prepare(tmp_path, fetch=fetch)
    assert again.data["attack"] == attack
    assert fetch.calls == [ATTACK.url, D3FEND.url, D3FEND.url]


def test_ttl_refresh_and_stale_copy_when_refresh_fails(tmp_path, unloaded):
    t = [1_000_000.0]
    fetch = Fetch(d3fend=ValueError("x"))
    pysigma_tags.prepare(tmp_path, fetch=fetch, now=lambda: t[0])
    stored = json.loads((tmp_path / "pysigma" / "attack.json").read_text())
    stored["fetched_at"] = t[0]
    (tmp_path / "pysigma" / "attack.json").write_text(json.dumps(stored))

    t[0] += pysigma_tags.TTL - 1
    fetch.calls.clear()
    pysigma_tags.prepare(tmp_path, fetch=fetch, now=lambda: t[0])
    assert ATTACK.url not in fetch.calls  # still fresh

    t[0] += 2
    offline = Fetch(attack=ValueError("transport failed"), d3fend=ValueError("x"))
    stale = pysigma_tags.prepare(tmp_path, fetch=offline, now=lambda: t[0])
    assert ATTACK.url in offline.calls
    assert stale.data["attack"] == stored["data"]  # the older copy keeps the check running
    assert any(n.startswith("MITRE ATT&CK tags: could not refresh the catalogue") for n in stale.notes)
    assert stale.skipped == ("d3fend",)


def test_unreadable_download_is_a_note_not_a_failure(tmp_path, unloaded, monkeypatch):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired("python", pysigma_tags.REDUCE_SECONDS)

    with monkeypatch.context() as patch:
        patch.setattr(pysigma_tags.subprocess, "run", slow)
        prepared = pysigma_tags.prepare(tmp_path, fetch=Fetch(d3fend=b"{}"))
    assert prepared.skipped == ("attack", "d3fend")
    assert all("reading it took too long" in n for n in prepared.notes)

    garbage = pysigma_tags.prepare(tmp_path, fetch=Fetch(attack=b"not json", d3fend=ValueError("x")))
    assert "attack" in garbage.skipped and "pySigma could not read it" in garbage.notes[0]


def test_catalogues_already_set_in_process_need_nothing(tmp_path):
    # tests/offline.py set them for the session: no file, no fetch.
    prepared = pysigma_tags.prepare(tmp_path, fetch=Fetch(attack=AssertionError("fetched"), d3fend=AssertionError("fetched")))
    assert prepared.skipped == () and prepared.notes == []
    assert not (tmp_path / "pysigma").exists()


def test_workers_install_shared_data_and_leave_out_skipped_validators(tmp_path, unloaded):
    prepared = pysigma_tags.prepare(tmp_path, fetch=Fetch())
    testing._init_worker(SCHEMA_FIXTURES, "validate", prepared.data)
    from sigma.data import mitre_attack

    assert vars(mitre_attack)["mitre_attack_techniques"] == {"T1059": "Command and Scripting Interpreter"}
    names = {type(v).__name__ for v in testing._W["validator"].validators}
    assert "ATTACKTagValidator" in names and "D3FENDTagValidator" not in names
    assert testing._W["toolchain"] == testing.validation_toolchain(SCHEMA_FIXTURES, ("d3fend",))
    assert testing._W["toolchain"] != testing.validation_toolchain(SCHEMA_FIXTURES)


def test_validate_stage_prepares_once_and_reports_the_skip(corpus, monkeypatch):  # noqa: F811
    ws, factory, _ = corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    real = pysigma_tags.prepare
    calls = []

    def offline(cache, **kwargs):
        calls.append(cache)
        out = real(cache, **kwargs)
        out.data["d3fend"] = None
        out.notes.append("MITRE D3FEND tag check skipped this run: offline.")
        return out

    monkeypatch.setattr(pysigma_tags, "prepare", offline)
    with factory() as s:
        summary = testing.run_stage(ws, s, "validate", workers=3)
        assert summary.processed == 3 and calls == [ws.cache]
        assert summary.notes == ["MITRE D3FEND tag check skipped this run: offline."]
        run = s.scalars(select(TestRun).order_by(TestRun.id.desc())).first()
        assert run.params["skipped_tag_catalogues"] == ["d3fend"]
        # Results checked without the catalogue are not reused once it is available.
        monkeypatch.setattr(pysigma_tags, "prepare", real)
        assert testing.run_stage(ws, s, "validate").processed == 3
