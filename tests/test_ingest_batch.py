"""Batch ingest (a source's first ingest: init --from-release, a new source) stores exactly what the per-file path
stores: the same occurrences, versions and quarantine rows."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from sigharvest.config import Workspace
from sigharvest.db import session_factory
from sigharvest.ingest import Ingestor
from sigharvest.models import Occurrence, Quarantine, RuleVersion, Source
from tests.helpers import seed_schemas

RULE = """title: Rule {n}
id: 6b3e1a2c-0000-4000-8000-{n:012d}
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'tool{n}'
  condition: selection
level: high
"""


def _tree(root: Path) -> list[str]:
    files = {f"rules/r{n}.yml": RULE.format(n=n) for n in range(30)}
    files["rules/copy.yml"] = RULE.format(n=3)  # same content as r3.yml: one version, two occurrences
    files["rules/multi.yml"] = RULE.format(n=40) + "---\n" + RULE.format(n=41)  # two documents
    files["rules/broken.yml"] = "title: broken\nlogsource: {product: windows}\ndetection: [unclosed\n"
    files["rules/notes.yml"] = "just: some yaml\n"
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return sorted(files)


def _ingest(tmp: Path, root: Path, files: list[str], *, batch: bool, rows: int) -> tuple[list, list, list]:
    import sigharvest.ingest as ingest_mod

    ws = Workspace(tmp)
    seed_schemas(ws)
    factory = session_factory(ws.db_path, migrate=True)
    old = ingest_mod.BATCH_ROWS
    ingest_mod.BATCH_ROWS = rows
    try:
        with factory() as s:
            source = Source(name="fixture", type="local", url=str(root))
            s.add(source)
            s.commit()
            ing = Ingestor(s, source, "c1", batch=batch)
            for rel in files:
                ing.ingest_file(root, rel)
            ing.flush()
            ing.reconcile_paths(set(files))
            s.commit()
            occ = sorted(
                (o.path, o.doc_index, o.version.content_hash, o.file_hash, o.span_start, o.span_end, o.present, o.commit) for o in s.scalars(select(Occurrence))
            )
            versions = sorted((v.content_hash, v.logic_hash, v.rule_id) for v in s.scalars(select(RuleVersion)))
            quarantine = sorted((q.path, q.present) for q in s.scalars(select(Quarantine)))
            return occ, versions, quarantine
    finally:
        ingest_mod.BATCH_ROWS = old


def test_batch_ingest_stores_the_same_rows(tmp_path: Path) -> None:
    root = tmp_path / "src"
    files = _tree(root)
    plain = _ingest(tmp_path / "plain", root, files, batch=False, rows=1000)
    assert len(plain[0]) == 33 and len(plain[1]) == 32 and plain[2]
    assert _ingest(tmp_path / "batch", root, files, batch=True, rows=1000) == plain
    assert _ingest(tmp_path / "small", root, files, batch=True, rows=4) == plain  # several executemany batches


def test_batch_mode_handles_a_path_seen_twice(tmp_path: Path) -> None:
    root = tmp_path / "src"
    files = _tree(root)
    twice = [*files, "rules/r1.yml"]
    plain = _ingest(tmp_path / "plain", root, twice, batch=False, rows=1000)
    assert _ingest(tmp_path / "batch", root, twice, batch=True, rows=1000) == plain
