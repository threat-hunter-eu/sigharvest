"""Published prose stays neutral: no internal review, audit or walkthrough references, no finding ids (`M1`,
`S4`...) and no names or temp paths of the tools used to write the code (use `/tmp/agent-1234/` in examples) in docs,
the changelog, source comments or tests. Rule data and fixtures are not prose and are skipped."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORDS = re.compile(r"review[- ]?\d|walkthrough|\bcarve|audit[- ]?\d|checkpoint[- ]?\d|novice|" + "clau" + r"de|anth" + r"ropic|/tmp/[a-z]+-\d+/-home", re.I)
FINDING_ID = re.compile(r"\b[CHMLSN]\d\b")
# Real names that look like finding ids: C0/C1 control characters, ATT&CK C2, Amazon S3.
NOT_A_FINDING = re.compile(r"\bC[01]\b.*control|control.*\bC[01]\b|\bC2\b|Amazon S3|\bs3\b", re.I)
SUFFIXES = {".py", ".md", ".sh", ".yml", ".yaml", ".toml", ".txt", ".html", ".cfg"}
SKIP = ("sources/", "tests/fixtures/", "tests/acceptance/fixtures/", "src/sigharvest/licences/", "src/sigharvest/mappings/", "src/sigharvest/presets/")


def _prose_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
    return [ROOT / f for f in out if Path(f).suffix in SUFFIXES and not f.startswith(SKIP) and f != "tests/test_neutral_wording.py" and (ROOT / f).is_file()]


def test_no_internal_review_references_or_finding_ids() -> None:
    hits = []
    for path in _prose_files():
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if WORDS.search(line) or (FINDING_ID.search(line) and not NOT_A_FINDING.search(line)):
                hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not hits, "\n".join(hits)
