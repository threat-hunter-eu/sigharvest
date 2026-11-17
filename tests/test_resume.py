"""Killed stage owners preserve committed work across real and inline worker pools."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from contextlib import suppress

import pytest
from sqlalchemy import select

from sigharvest import conversion, fingerprints, testing
from sigharvest.lock import LockHeld, UpdateLock
from sigharvest.models import RuleVersion, TestResult, TestRun
from tests.test_effective_documents import CHILD, GLOBAL
from tests.test_versioned_results import InlinePool, ingest
from tests.test_versioned_results import corpus as _corpus_fixture

resume_corpus = _corpus_fixture


@pytest.mark.skipif(os.name != "posix", reason="SIGKILL and process groups are POSIX-specific")
@pytest.mark.parametrize("inline", [False, True], ids=["process-pool", "inline-pool"])
def test_kill_and_resume(resume_corpus, inline, monkeypatch):
    ws, factory, _ = resume_corpus
    if inline:
        monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    code = """
import os, signal, sys
import tests.offline  # Install the offline socket guard in this fresh interpreter.
from pathlib import Path
from sigharvest import testing
from sigharvest.config import Workspace
from sigharvest.service import open_db
from tests.test_versioned_results import InlinePool
ws = Workspace(Path(sys.argv[1]))
if sys.argv[2] == 'True':
    testing.ProcessPoolExecutor = InlinePool
chunks = testing._chunks
testing._chunks = lambda items, n: chunks(items, 1)
def killed(done, total):
    os.kill(os.getpid(), signal.SIGKILL)
with open_db(ws)() as session:
    testing.run_stage(ws, session, 'convert', workers=1, progress=killed)
"""
    proc = subprocess.Popen([sys.executable, "-c", code, str(ws.root), str(inline)], start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.wait(timeout=30)
    finally:
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
    out, err = proc.communicate(timeout=10)
    assert proc.returncode == -signal.SIGKILL, (out, err)
    with factory() as s:
        old = s.scalars(select(TestRun)).one()
        assert old.status == "running" and old.finished_at is None
        committed = list(s.scalars(select(TestResult)))
        assert len(committed) == len(testing.BACKENDS)
        assert len({r.version_id for r in committed}) == 1
        before = [(r.id, r.run_id, r.created_at, r.fingerprint) for r in committed]
        assert testing._done(s, "convert") == {committed[0].version_id}
        # Changes to scheduling parameters must not invalidate completed results.
        summary = testing.run_stage(ws, s, "convert", workers=2, limit=1)
        assert summary.processed == 1
        s.refresh(old)
        assert old.status == "interrupted" and old.finished_at is not None
        assert [(r.id, r.run_id, r.created_at, r.fingerprint) for r in s.scalars(select(TestResult).where(TestResult.run_id == old.id))] == before
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 1
        assert testing.run_stage(ws, s, "convert", workers=1).processed == 0
        assert testing.run_stage(ws, s, "convert", resume=False, workers=1).processed == 3


def test_live_lease_prevents_recovery(resume_corpus):
    ws, factory, _ = resume_corpus
    with factory() as s:
        run = TestRun(stage="convert")
        s.add(run)
        s.commit()
        with UpdateLock(ws), pytest.raises(LockHeld):
            testing.run_stage(ws, s, "convert")
        s.refresh(run)
        assert run.status == "running" and run.finished_at is None


@pytest.mark.parametrize("stage", ["convert", "validate"])
def test_resume_hashes_effective_input_and_keeps_failed_results(resume_corpus, monkeypatch, stage):
    ws, factory, root = resume_corpus
    monkeypatch.setattr(testing, "ProcessPoolExecutor", InlinePool)
    with factory() as s:
        ingest(s, root, "legacy.yml", (GLOBAL + CHILD).decode())
        legacy = s.scalars(select(RuleVersion).where(RuleVersion.context_digest.is_not(None))).one()
        assert legacy.content_hash != fingerprints.text_digest(legacy.raw)
        assert testing.run_stage(ws, s, stage).processed == 4
        assert ("skipped" if stage == "convert" else "error") in set(s.scalars(select(TestResult.status).where(TestResult.stage == stage)))
        runs = list(s.scalars(select(TestRun)))
        runs[0].status = "running"
        runs[0].finished_at = None
        s.commit()
        assert testing.run_stage(ws, s, stage).processed == 0
        s.refresh(runs[0])
        assert runs[0].status == "interrupted"
        # A failed run record is not evidence against an exact result.
        runs[0].status = "failed"
        s.commit()
        assert testing.run_stage(ws, s, stage).processed == 0


def test_conversion_key_excludes_scheduler_but_includes_worker_semantics(monkeypatch):
    original = fingerprints.source_digest
    conversion.toolchain.cache_clear()
    try:
        before = conversion.toolchain("splunk")
        monkeypatch.setattr(fingerprints, "source_digest", lambda m: "changed" if m == "testing.py" else original(m))
        conversion.toolchain.cache_clear()
        assert conversion.toolchain("splunk") == before
        monkeypatch.setattr(fingerprints, "source_digest", lambda m: "changed" if m == "testing_conversion.py" else original(m))
        conversion.toolchain.cache_clear()
        assert conversion.toolchain("splunk") != before
    finally:
        conversion.toolchain.cache_clear()
