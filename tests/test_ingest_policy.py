"""The ingest policy fingerprint covers only the code that decides stored rows."""

import pytest

from sigharvest import fingerprints, source_snapshots
from sigharvest.config import load_sources
from sigharvest.db import set_meta
from sigharvest.service import open_db, sync_all
from sigharvest.source_snapshots import (
    CONFIG_PREFIX,
    INGEST_MODULES,
    config_fingerprint,
)
from tests.test_pipeline import make_repo, workspace
from tests.test_source_snapshots import state

PLUMBING = (
    "sync.py",
    "sync_remote.py",
    "remote_documents.py",
    "source_snapshots.py",
    "source_rebaseline.py",
    "service.py",
    "lock.py",
    "fingerprints.py",
)
ROW_DECIDING = ("documents.py", *INGEST_MODULES)


@pytest.fixture
def edited(monkeypatch):
    """Pretend the named modules were edited (their source digests change)."""
    original = fingerprints.source_digest

    def edit(*modules: str) -> None:
        fake = lambda m: "0" * 64 if m in modules else original(m)  # noqa: E731
        monkeypatch.setattr(fingerprints, "source_digest", fake)
        monkeypatch.setattr(source_snapshots, "source_digest", fake)

    yield edit


def _synced(tmp_path):
    ws = workspace(tmp_path, make_repo(tmp_path))
    assert sync_all(ws)[0].status == "ok"
    return ws, load_sources(ws)[0]


def test_row_deciding_modules_are_fingerprinted_and_plumbing_is_not(tmp_path, edited):
    cfg = load_sources(workspace(tmp_path, make_repo(tmp_path)))[0]
    before = config_fingerprint(cfg)
    edited(*PLUMBING)
    assert config_fingerprint(cfg) == before
    for module in ROW_DECIDING:
        edited(module)
        assert config_fingerprint(cfg) != before, module


@pytest.mark.parametrize("module", PLUMBING)
def test_plumbing_change_keeps_rows_reusable(tmp_path, edited, module):
    ws, _ = _synced(tmp_path)
    before = state(ws)
    edited(module)
    result = sync_all(ws)[0]
    assert result.status == "ok" and result.log.files_added == 0
    after = state(ws)
    assert after["config"] == before["config"] and after["occurrences"] == before["occurrences"]


@pytest.mark.parametrize("module", ROW_DECIDING)
def test_parser_change_forces_full_reingest(tmp_path, edited, module):
    ws, _ = _synced(tmp_path)
    before = state(ws)
    edited(module)
    result = sync_all(ws)[0]
    assert result.status == "ok" and result.log.files_added == 5
    assert state(ws)["config"] != before["config"]


def _store(ws, cfg, value):
    with open_db(ws)() as s:
        set_meta(s, CONFIG_PREFIX + cfg.name, value)
        s.commit()


# config_fingerprint() of this config, computed by the f0fdd36 code itself in the
# environment below (Python and the parser packages are part of the marker).
