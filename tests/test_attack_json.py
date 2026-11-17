"""Structural budgets precede full decoding without changing JSON semantics."""

import json
import math

import pytest

from sigharvest import attack_io, attack_json


@pytest.mark.parametrize(
    ("raw", "limit", "exact", "message"),
    [
        (b'{"a":[{"b":0}]}', "MAX_DEPTH", 3, "depth"),
        (b'{"a":[0,1,true,null,"x",{}]}', "MAX_NODES", 9, "node/member"),
        (b'{"a":0,"b":1,"c":2}', "MAX_NODES", 7, "node/member"),
        (b'{"a":"\\u00e9\\ud83d\\ude00\\ud800"}', "MAX_TEXT_BYTES", 10, "decoded text"),
        (b'{"a":"12345678"}', "MAX_TOKEN_BYTES", 10, "token byte"),
        (b'{"a":1234567890}', "MAX_TOKEN_BYTES", 10, "token byte"),
        (b'{"12345678":0}', "MAX_TOKEN_BYTES", 10, "token byte"),
    ],
)
def test_inclusive_budgets_before_full_decode(monkeypatch, raw, limit, exact, message):
    expected = json.loads(raw)
    monkeypatch.setattr(attack_json, limit, exact)
    assert attack_io.json_object(raw) == expected
    monkeypatch.setattr(attack_json, limit, exact - 1)
    monkeypatch.setattr(json, "loads", lambda *a, **kw: pytest.fail("full graph constructed"))
    with pytest.raises(attack_json.ExpansionLimit, match=message):
        attack_io.json_object(raw)


def test_structure_counts_and_escaped_delimiters():
    raw = b'{"a":["\\"{}[]\\\\", {}, [], 0, false, null]}'
    assert attack_json.preflight(raw) == attack_json.Structure(9, 3, 7, 10)
    assert attack_io.json_object(raw) == json.loads(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"n":123456789012345678901234567890,"f":-0.0,"e":1.23456789012345678}',
        b'{"n":1e999999999999999999999,"f":-1e9999,"tiny":1e-999999999999999999999}',
        b'{"s":"\\ud800x\\udfff","pair":"\\ud83d\\ude00"}',
        '{"é":"☃😀","escaped":"\\u00e9"}'.encode(),
        b'{"a":[0,true,false,null,-0,-0.0,1e-300,1e300]}',
    ],
)
def test_stdlib_value_type_and_number_fidelity(raw):
    before = json.loads(raw)
    after = attack_io.json_object(raw)
    assert before == after
    assert repr(before) == repr(after)
    if "f" in after and after["f"] == 0:
        assert math.copysign(1, after["f"]) == -1


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":0,"\\u0061":0}',
        b'{"x":{"\\ud83d\\ude00":0,"\xf0\x9f\x98\x80":1}}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":"\xff"}',
        b'{"a":0}\xff',
        b'{"a":"\xed\xa0\x80"}',
        b'{"a":01}',
        b'{"a":1,}',
        b'{"a" 1}',
        b'{"a":}',
        b'{"a":"\\uZZZZ"}',
        b'{"a":"\\',
        b'{"a":"\n"}',
        b"{}{}",
        b"[]",
        b"null",
        b'"text"',
        b'{"a":[0}}',
    ],
)
def test_final_strict_decoder_remains_authoritative(raw):
    with pytest.raises(ValueError):
        attack_io.json_object(raw)


def test_token_refusal_precedes_string_allocation(monkeypatch):
    monkeypatch.setattr(attack_json, "MAX_TOKEN_BYTES", 32)
    monkeypatch.setattr(attack_json, "scanstring", lambda *a: pytest.fail("oversize token decoded"))
    for raw in (b'{"' + b"x" * 100_000 + b'":0}', b'{"' + b"\\u0061" * 20_000 + b'":0}'):
        with pytest.raises(attack_json.ExpansionLimit, match="token byte"):
            attack_io.json_object(raw)


def test_all_ignored_content_counts(monkeypatch):
    monkeypatch.setattr(attack_json, "MAX_NODES", 100)
    for raw in (b'{"ignored":[' + b"0," * 100 + b"0]}", b'{"ignored":[' + b"{}," * 100 + b"{}]}"):
        with pytest.raises(attack_json.ExpansionLimit, match="node/member"):
            attack_io.json_object(raw)


def test_plain_strings_count_bytes_without_token_materialization(monkeypatch):
    raw = '{"é":"☃😀","empty":"","ascii":"short"}'.encode()
    monkeypatch.setattr(attack_json, "scanstring", lambda *a: pytest.fail("plain token materialized"))
    stats = attack_json.preflight(raw)
    assert stats == attack_json.Structure(7, 1, 24, 9)
    assert attack_io.json_object(raw) == json.loads(raw)


@pytest.mark.parametrize("value", ['\\"', "\\", '"', "\ud800", "\udfff", "\ud83d\ude00", "\\u0061", "\n\t\b\f\r"])
def test_escape_fallback_counts_stdlib_utf8(monkeypatch, value):
    raw = json.dumps({"s": value}).encode()
    expected = json.loads(raw)
    text_bytes = 1 + len(expected["s"].encode("utf-8", "surrogatepass"))
    monkeypatch.setattr(attack_json, "MAX_TEXT_BYTES", text_bytes)
    assert attack_json.preflight(raw).text_bytes == text_bytes
    assert attack_io.json_object(raw) == expected
    monkeypatch.setattr(attack_json, "MAX_TEXT_BYTES", text_bytes - 1)
    monkeypatch.setattr(json, "loads", lambda *a, **kw: pytest.fail("graph constructed"))
    with pytest.raises(attack_json.ExpansionLimit, match="decoded text byte"):
        attack_io.json_object(raw)


@pytest.mark.parametrize("raw", [b'{"x":"\x00"}', b'{"x":"\xc0\xaf"}', b'{"x":"\xf4\x90\x80\x80"}', b'{"x":"\x80"}'])
def test_fast_string_span_still_requires_final_strict_decode(raw):
    # Preflight is a budget scanner, not an independent UTF-8/grammar admission.
    assert attack_json.preflight(raw).nodes == 3
    with pytest.raises(ValueError, match="invalid UTF-8 JSON"):
        attack_io.json_object(raw)


@pytest.mark.parametrize("raw", ['{"é":"😀"}'.encode(), b'{"x":"abc"}', b'{"abc":0}'])
def test_fast_string_exact_text_and_token_limits(monkeypatch, raw):
    stats = attack_json.preflight(raw)
    expected = json.loads(raw)
    for limit, exact in (("MAX_TEXT_BYTES", stats.text_bytes), ("MAX_TOKEN_BYTES", stats.token_bytes)):
        with monkeypatch.context() as m:
            m.setattr(attack_json, limit, exact)
            assert attack_io.json_object(raw) == expected
            m.setattr(attack_json, limit, exact - 1)
            m.setattr(json, "loads", lambda *a, **kw: pytest.fail("graph constructed"))
            with pytest.raises(attack_json.ExpansionLimit):
                attack_io.json_object(raw)
