"""Bound ATT&CK JSON expansion before the authoritative stdlib decoder runs.

This lexical pass retains at most one bounded string, never a second object graph
or a set of keys. It deliberately leaves grammar, duplicate keys and numeric values
to the final decoder. ijson's numeric and surrogate policies differ from that
decoder, even with use_float=False. Count all content, including ignored STIX.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from json.decoder import scanstring  # type: ignore[attr-defined]

# Inclusive, independent limits. See the expansion report for the reduced-cache
# pilot, container costs and original-bundle qualification gap.
MAX_DEPTH = 64
MAX_NODES = 8_000_000
MAX_TEXT_BYTES = 256 * 1024 * 1024
MAX_TOKEN_BYTES = 1024 * 1024

_SKIP = re.compile(rb"[\x20\t\r\n,:]+")
_BARE = re.compile(rb'[^\x20\t\r\n{}\[\],:"]+')
_SPECIAL = re.compile(rb'["\\]')


class ExpansionLimit(ValueError):
    """A fixed, value-free diagnostic safe to present through existing readers."""

    def __init__(self, budget: str) -> None:
        super().__init__(f"ATT&CK JSON exceeds the {budget} budget; supply a complete bundle within the documented structural limits")


@dataclass(frozen=True)
class Structure:
    nodes: int
    depth: int
    text_bytes: int
    token_bytes: int


def preflight(raw: bytes) -> Structure:
    """Scan bounded source bytes lazily; do not certify JSON or STIX validity.

    A node is a container, scalar value or object key (members therefore cost
    both a key and a value). Root container depth is one. Text includes keys and
    string values, measured as UTF-8 after escapes; lone surrogates cost three
    bytes via surrogatepass, preserving the stdlib's existing acceptance. Token
    bytes include quotes and escapes and are checked *before* slicing/decoding.
    Numeric tokens are counted, never converted. Invalid input may fail either
    here or in the final strict decoder; only that decoder admits an object.
    """
    pos = nodes = depth = peak = text = token_peak = 0
    length = len(raw)
    while pos < length:
        first = raw[pos]
        if first in b" \t\r\n,:":
            skip = _SKIP.match(raw, pos)
            assert skip is not None
            pos = skip.end()
            continue
        if first in (125, 93):  # } ]
            depth -= 1
            if depth < 0:
                raise ValueError("invalid JSON nesting")
            pos += 1
            continue
        nodes += 1
        if nodes > MAX_NODES:
            raise ExpansionLimit("node/member")
        if first in (123, 91):  # { [
            depth += 1
            if depth > MAX_DEPTH:
                raise ExpansionLimit("depth")
            if depth > peak:
                peak = depth
            pos += 1
            continue
        start = pos
        # Search no further than the admitted token span. Regex searches do not
        # copy their match, and no unbounded token reaches a string parser.
        end = start + MAX_TOKEN_BYTES
        if end > length:
            end = length
        if first == 34:
            pos += 1
            escaped = False
            while True:
                special = _SPECIAL.search(raw, pos, end)
                if special is None:
                    if end < length:
                        raise ExpansionLimit("token byte")
                    raise ValueError("unterminated JSON string")
                pos = special.end()
                if raw[pos - 1] == 34:
                    break
                escaped = True
                pos += 1  # Skip the escaped byte, including an escaped quote.
            size = pos - start
            if size > token_peak:
                token_peak = size
            if escaped:
                decoded, _ = scanstring(raw[start:pos].decode("utf-8"), 1)
                text += len(decoded.encode("utf-8", "surrogatepass"))
                del decoded
            else:
                # For valid UTF-8 without escapes, decoded UTF-8 has exactly
                # the source byte length. No slice, decode or encode is needed.
                # The final reader still rejects invalid UTF-8/control bytes.
                text += size - 2
            if text > MAX_TEXT_BYTES:
                raise ExpansionLimit("decoded text byte")
        else:
            bare = _BARE.match(raw, pos, min(length, end + 1))
            assert bare is not None
            pos = bare.end()
            if pos - start > MAX_TOKEN_BYTES:
                raise ExpansionLimit("token byte")
            if pos - start > token_peak:
                token_peak = pos - start
    return Structure(nodes, peak, text, token_peak)
