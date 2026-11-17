"""Dead letters survive source loss, remain bounded and never hide infrastructure failures."""

import json

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from typer.testing import CliRunner

from sigharvest import documents, quarantine
from sigharvest.cli import app
from sigharvest.config import Workspace, save_sources
from sigharvest.db import session_factory
from sigharvest.ingest import Ingestor
from sigharvest.models import Occurrence, Quarantine, QuarantineAttempt, QuarantineBlob, Source

BAD = b"title: private-value\nlogsource: {product: windows}\ndetection: [broken\n"
GOOD = b"title: recovered\nlogsource: {product: windows}\ndetection: {s: {Image: cmd.exe}, condition: s}\n"


@pytest.fixture
def source_db(tmp_path):
    factory = session_factory(tmp_path / "db.sqlite", migrate=True)
    with factory() as s:
        source = Source(name="local", type="local", url=str(tmp_path))
        s.add(source)
        s.commit()
        yield s, source


def ingest(s, source, root, raw):
    (root / "rule.yml").write_bytes(raw)
    Ingestor(s, source, "revision").ingest_file(root, "rule.yml")
    s.commit()
    return s.scalar(select(Quarantine).order_by(Quarantine.id))


def test_deleted_input_replays_original_and_does_not_resurrect(tmp_path, source_db, monkeypatch):
    s, source = source_db
    raw = b"action: global\r\nlogsource: {product: windows}\r\n---\r\n" + BAD
    q = ingest(s, source, tmp_path, raw)
    assert q.retention == "retained" and q.reason_code == "yaml_error"
    blob = s.get(QuarantineBlob, q.blob_hash)
    assert blob.raw == raw and blob.raw[q.span_start : q.span_end].startswith(b"---\r\n")
    assert q.content_hash == quarantine.sha256_hex(blob.raw[q.span_start : q.span_end])
    (tmp_path / "rule.yml").unlink()
    Ingestor(s, source, None).remove("rule.yml")
    s.commit()
    assert q.resolution == "removed" and not q.present
    failure = quarantine.retry(s, q.id, parser="current")
    s.commit()
    assert failure.outcome == "rejected"
    original_loader = documents.load_documents

    def fixed_parser(raw):
        assert raw == blob.raw
        doc = original_loader(GOOD)[0]
        doc.index, doc.raw = q.doc_index, blob.raw[q.span_start : q.span_end]
        return [doc]

    monkeypatch.setattr(documents, "load_documents", fixed_parser)
    success = quarantine.retry(s, q.id, parser=quarantine.parser_version())
    s.commit()
    assert success.outcome == "recovered" and success.version_id
    assert q.resolution == "recovered" and not q.present
    assert s.scalar(select(func.count()).select_from(Occurrence)) == 0
    assert s.scalar(select(func.count()).select_from(QuarantineAttempt)) == 3


def test_poison_is_not_reparsed_by_schedule_and_repair_retires_it(tmp_path, source_db, monkeypatch):
    s, source = source_db
    q = ingest(s, source, tmp_path, BAD + b"---\n" + GOOD)
    original = documents.yaml.load
    calls = []

    def parse(raw, **kw):
        calls.append(raw)
        return original(raw, **kw)

    monkeypatch.setattr(documents.yaml, "load", parse)
    ingest(s, source, tmp_path, BAD + b"---\n" + GOOD)
    assert calls == [b"---\n" + GOOD]
    assert s.scalar(select(func.count()).select_from(QuarantineAttempt)) == 1
    assert s.scalar(select(func.count()).select_from(QuarantineBlob)) == 1
    ingest(s, source, tmp_path, GOOD)
    assert q.resolution == "superseded" and not q.present and q.resolved_at


@pytest.mark.parametrize("setting,expected", [(0, "privacy_disabled"), (1, "quota_limit")])
def test_retention_refusal_is_explicit(tmp_path, source_db, monkeypatch, setting, expected):
    s, source = source_db
    monkeypatch.setenv("SIGHARVEST_DISK_QUARANTINE_BYTES", str(setting))
    q = ingest(s, source, tmp_path, BAD)
    assert q.retention == expected and q.blob_hash is None
    assert s.scalar(select(func.count()).select_from(QuarantineBlob)) == 0
    with pytest.raises(quarantine.QuarantineError, match="unavailable"):
        quarantine.retry(s, q.id, parser="current")
    assert s.scalar(select(func.count()).select_from(QuarantineAttempt)) == 1


def test_document_resource_rejection_and_selected_snapshot(tmp_path, source_db, monkeypatch):
    s, source = source_db
    monkeypatch.setattr(documents, "MAX_YAML_DEPTH", 10)
    poison = b"logsource: {}\ndetection: " + b"[" * 20 + b"1" + b"]" * 20 + b"\n"
    q = ingest(s, source, tmp_path, poison + b"---\n" + GOOD)
    assert q.reason_code == "resource_limit"
    assert s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) == 1
    qid = q.id
    ingest(s, source, tmp_path, GOOD + b"---\n" + poison)
    other = s.scalars(select(Quarantine).where(Quarantine.id != qid)).one()
    attempt = quarantine.retry(s, qid, parser="current", snapshot=other.blob_hash)
    assert attempt.outcome == "recovered"
    with pytest.raises(quarantine.QuarantineError, match="Parser unavailable"):
        quarantine.retry(s, qid, parser="historical-v0")
    with pytest.raises(quarantine.QuarantineError, match="unavailable"):
        quarantine.retry(s, qid, parser="current", snapshot="0" * 64)


def test_database_and_read_errors_propagate(tmp_path, source_db, monkeypatch):
    s, source = source_db

    def fail(*a, **kw):
        raise OperationalError("db", {}, Exception("disk full"))

    monkeypatch.setattr(Ingestor, "_version_id", fail)
    with pytest.raises(OperationalError):
        ingest(s, source, tmp_path, GOOD)
    s.rollback()
    assert s.scalar(select(func.count()).select_from(Quarantine)) == 0
    q = ingest(s, source, tmp_path, BAD)
    monkeypatch.setattr(documents, "load_documents", lambda raw: [documents.Document(0, BAD, {"logsource": {}, "detection": {}}, "rule")])
    with pytest.raises(OperationalError):
        quarantine.retry(s, q.id, parser="current")
    s.rollback()
    assert s.scalar(select(func.count()).select_from(QuarantineAttempt)) == 1


def test_history_and_original_provenance_are_immutable(tmp_path, source_db):
    s, source = source_db
    q = ingest(s, source, tmp_path, BAD)
    for sql in (
        "UPDATE quarantine_blobs SET raw = x'00'",
        "DELETE FROM quarantine_blobs",
        "DELETE FROM quarantine_attempts",
        "UPDATE quarantine_attempts SET outcome = 'recovered'",
        "UPDATE quarantine SET snapshot_hash = 'other'",
    ):
        with pytest.raises(IntegrityError, match="immutable"):
            s.execute(text(sql))
        s.rollback()
    assert s.get(QuarantineBlob, q.blob_hash).raw == BAD


def test_cli_metadata_and_required_parser(tmp_path, monkeypatch):
    ws = Workspace(tmp_path)
    save_sources(ws, [])
    monkeypatch.setenv("SIGHARVEST_HOME", str(tmp_path))
    with session_factory(ws.db_path, migrate=True)() as s:
        source = Source(name="fixture", type="local", url=str(tmp_path))
        s.add(source)
        s.flush()
        q = ingest(s, source, tmp_path, BAD)
        qid = q.id
    runner = CliRunner()
    for args in (["quarantine", "list"], ["quarantine", "show", str(qid)]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert "private-value" not in result.output and "yaml_error" in result.output
    listed = runner.invoke(app, ["quarantine", "list"])
    assert "source" in listed.output and "reason" in listed.output and "state" in listed.output
    assert "parser_version" not in listed.output and "content_hash" not in listed.output
    machine = runner.invoke(app, ["quarantine", "list", "--json"])
    assert json.loads(machine.output)["results"][0]["id"] == qid
    assert runner.invoke(app, ["quarantine", "retry", str(qid)]).exit_code == 2
    result = runner.invoke(app, ["quarantine", "retry", str(qid), "--parser", "current"])
    assert result.exit_code == 1 and "rejected" in result.output


def test_size_and_attempt_limits_preserve_history(tmp_path, source_db, monkeypatch):
    s, source = source_db
    monkeypatch.setattr(quarantine, "MAX_BLOB_BYTES", len(BAD) - 1)
    q = ingest(s, source, tmp_path, BAD)
    assert q.retention == "size_limit" and q.blob_hash is None
    # The original retention decision is immutable, even if the limit is later raised.
    monkeypatch.setattr(quarantine, "MAX_BLOB_BYTES", documents.MAX_FILE_BYTES)
    monkeypatch.setattr(quarantine, "MAX_ATTEMPTS", 1)
    with pytest.raises(quarantine.QuarantineError, match="Attempt limit"):
        quarantine.retry(s, q.id, parser="current")
    assert s.scalar(select(func.count()).select_from(QuarantineAttempt)) == 1


def test_read_failure_does_not_quarantine_or_retire_previous_rule(tmp_path, source_db, monkeypatch):
    from pathlib import Path

    s, source = source_db
    ingest(s, source, tmp_path, GOOD)
    original = Path.open

    def denied(path, *args, **kwargs):
        if path == tmp_path / "rule.yml":
            raise PermissionError("private filesystem detail")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(PermissionError):
        Ingestor(s, source, None).ingest_file(tmp_path, "rule.yml")
    s.rollback()
    assert s.scalars(select(Occurrence)).one().present
    assert s.scalar(select(func.count()).select_from(Quarantine)) == 0


def test_ordinary_validation_failures_remain_versions(tmp_path, source_db):
    from sigharvest.models import RuleVersion

    s, source = source_db
    # Missing title/condition is for validation, not a parser/identity dead letter.
    ingest(s, source, tmp_path, b"logsource: {}\ndetection: {s: {a: b}}\n")
    assert s.scalar(select(func.count()).select_from(RuleVersion)) == 1
    assert s.scalar(select(func.count()).select_from(Quarantine)) == 0


def test_scheduled_skip_does_not_fabricate_attempt_after_upgrade(tmp_path, source_db, monkeypatch):
    s, source = source_db
    q = ingest(s, source, tmp_path, BAD)
    initial_parser = q.parser_version
    monkeypatch.setattr(quarantine, "parser_version", lambda: "next-parser")
    ingest(s, source, tmp_path, BAD)
    assert s.scalar(select(func.count()).select_from(QuarantineAttempt)) == 1
    assert q.parser_version == initial_parser
    attempt = quarantine.retry(s, q.id, parser="current")
    assert attempt.parser_version == "next-parser" and attempt.outcome == "rejected"
