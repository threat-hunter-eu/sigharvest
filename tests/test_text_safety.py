"""Lone surrogates from YAML escapes and FTS exclusion precedence (bugs fixed in the public edition)."""

from __future__ import annotations

import sqlite3

import yaml

from sigharvest.documents import load_documents
from sigharvest.fingerprints import digest, text_digest
from sigharvest.identity import canonical_logic_bytes, logic_hash, utf8
from sigharvest.index import fts_query

SURROGATE_RULE = b"""title: "lone \\ud800 surrogate"
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: "\\ud800abc"
    condition: selection
"""


def test_yaml_escape_produces_a_lone_surrogate() -> None:
    assert yaml.safe_load('title: "\\ud800"')["title"] == "\ud800"


def test_utf8_keeps_lone_surrogates_and_ordinary_text_unchanged() -> None:
    assert utf8("abc é") == "abc é".encode()
    assert utf8("\ud800") == b"\xed\xa0\x80"


def test_hashes_accept_lone_surrogates() -> None:
    data = yaml.safe_load(SURROGATE_RULE)
    assert canonical_logic_bytes(data)
    assert len(logic_hash(data)) == 64
    assert len(text_digest("\ud800")) == 64
    assert len(digest({"x": "\ud800"})) == 64


def test_document_with_lone_surrogate_never_raises() -> None:
    # libyaml may reject the escape (the document is then quarantined with an error); it must never crash ingestion.
    docs = load_documents(SURROGATE_RULE)
    assert len(docs) == 1
    assert docs[0].error is not None or docs[0].kind == "rule"


def test_logic_hash_of_plain_rule_is_stable() -> None:
    # Hash values must not change for ordinary text (no surrogates): the namespace stays "sigharvest-logic-v1".
    data = {"logsource": {"product": "windows"}, "detection": {"sel": {"Image|endswith": "\\\\x.exe"}, "condition": "sel"}}
    assert canonical_logic_bytes(data).startswith(b"sigharvest-logic-v1\n")


def _fts(rows: list[str], match: str) -> set[int]:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE VIRTUAL TABLE t USING fts5(body)")
    db.executemany("INSERT INTO t(rowid, body) VALUES (?, ?)", list(enumerate(rows, 1)))
    return {r[0] for r in db.execute("SELECT rowid FROM t WHERE t MATCH ?", (match,))}


def test_exclusion_applies_to_every_alternative() -> None:
    match, exclude_only = fts_query("alpha OR beta -gamma")
    assert exclude_only == ""
    assert match.startswith("(") and "NOT" in match
    # "beta gamma" and "alpha gamma" both contain the excluded word.
    assert _fts(["alpha gamma", "beta gamma", "alpha", "beta"], match) == {3, 4}


def test_exclusion_only_and_plain_queries() -> None:
    assert fts_query("-gamma") == ("", '"gamma"*')
    match, _ = fts_query("alpha beta")
    assert "NOT" not in match and not match.startswith("(")
