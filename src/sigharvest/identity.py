"""Rule identity: content hash, logic hash, title slug and fallback UUIDs.

The canonicalisation implemented here is specified in docs/identity.md. Any change to the
output of `canonical_logic` must bump LOGIC_VERSION, because stored logic hashes would no
longer be comparable.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import uuid
from typing import Any

# Hashed prefixes: part of the hashed bytes, so changing them changes every logic hash and effective content hash.
LOGIC_VERSION = "sigharvest-logic-v1"
EFFECTIVE_VERSION = "sigharvest-effective-v1"

# Namespace for UUIDv5 ids generated for rules without an `id`. A fixed constant (the public project URL): it must
# never change, or every generated id would change with it.
SIGHARVEST_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/threat-hunter-eu/sigharvest")

# Modifiers after which string values are compared case-sensitively (so we must not case-fold them).
CASE_SENSITIVE_MODIFIERS = {"cased", "re", "base64", "base64offset", "utf16le", "utf16be", "wide", "utf16", "fieldref"}

CONDITION_KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "by", "count", "near"}
_CONDITION_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def utf8(text: str) -> bytes:
    """UTF-8 bytes of `text`, keeping lone surrogates.

    YAML allows escapes such as "\\ud800", so parsed rule text can hold lone surrogates that a strict `.encode()`
    rejects. Strings without surrogates encode exactly as before, so no stored hash changes.
    """
    return text.encode("utf-8", "surrogatepass")


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of some bytes."""
    return hashlib.sha256(data).hexdigest()


def content_hash(raw: bytes) -> str:
    """SHA-256 of the raw bytes of one YAML document (for single-document files: the whole file)."""
    return sha256_hex(raw)


def effective_content_hash(raw: bytes, context_digest: str | None = None) -> str:
    """Keep ordinary content keys; include exact inherited context for legacy children."""
    if context_digest is None:
        return content_hash(raw)
    return sha256_hex(EFFECTIVE_VERSION.encode("ascii") + b"\n" + context_digest.encode("ascii") + b"\n" + raw)


def rule_kind(doc: dict[str, Any]) -> str | None:
    """Classify a parsed YAML document. Returns 'rule', 'correlation', 'filter' or None if it is not Sigma."""
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("correlation"), dict):
        return "correlation"
    if isinstance(doc.get("filter"), dict) and isinstance(doc.get("logsource"), dict):
        return "filter"
    if isinstance(doc.get("detection"), dict) and isinstance(doc.get("logsource"), dict):
        return "rule"
    return None


# --------------------------------------------------------------------------- canonical form


def _split_key(key: str) -> tuple[str, list[str]]:
    parts = str(key).split("|")
    return parts[0].strip(), [m.strip().lower() for m in parts[1:] if m.strip()]


def _canon_scalar(value: Any, modifiers: list[str]) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        # Sigma treats 4688 and '4688' the same way; numbers are serialised as strings.
        return str(value)
    text = unicodedata.normalize("NFC", str(value))
    if not CASE_SENSITIVE_MODIFIERS.intersection(modifiers):
        text = text.casefold()
    return text


def _sort_key(item: Any) -> str:
    return json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _canon_values(value: Any, modifiers: list[str]) -> Any:
    if isinstance(value, list):
        # A value list is OR (or AND with |all); in both cases order is irrelevant.
        items = {_sort_key(_canon_scalar(v, modifiers)): _canon_scalar(v, modifiers) for v in value}
        return [items[k] for k in sorted(items)]
    return _canon_scalar(value, modifiers)


def _canon_map(mapping: dict[str, Any]) -> list[list[Any]]:
    pairs = []
    for key, value in mapping.items():
        field, modifiers = _split_key(key)
        canon_key = "|".join([field, *modifiers])
        pairs.append([canon_key, _canon_values(value, modifiers)])
    return sorted(pairs, key=_sort_key)


def _canon_search(value: Any) -> Any:
    if isinstance(value, dict):
        return {"map": _canon_map(value)}
    if isinstance(value, list):
        items = {}
        for v in value:
            c = {"map": _canon_map(v)} if isinstance(v, dict) else _canon_scalar(v, [])
            items[_sort_key(c)] = c
        return {"or": [items[k] for k in sorted(items)]}
    return {"keyword": _canon_scalar(value, [])}


def canonical_condition(condition: Any) -> Any:
    """Whitespace-normalised condition with lower-case keywords; identifier names and order are kept."""
    if isinstance(condition, list):
        return [canonical_condition(c) for c in condition]
    if condition is None:
        return None
    tokens = _CONDITION_TOKEN.findall(str(condition))
    return " ".join(t.lower() if t.lower() in CONDITION_KEYWORDS else t for t in tokens)


def _canon_logsource(logsource: Any) -> dict[str, str]:
    if not isinstance(logsource, dict):
        return {}
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in logsource.items() if v is not None and str(k).strip().lower() != "definition"}


def _canon_detection(detection: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in detection.items():
        if name == "condition":
            out["condition"] = canonical_condition(value)
        elif name == "timeframe":
            out["timeframe"] = str(value).strip().lower()
        else:
            out[str(name)] = _canon_search(value)
    return out


def _canon_generic(value: Any) -> Any:
    """Canonical form for correlation blocks: sorted keys, case-folded strings, list order kept."""
    if isinstance(value, dict):
        return {str(k).strip().lower(): _canon_generic(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canon_generic(v) for v in value]
    return _canon_scalar(value, [])


def canonical_logic(doc: dict[str, Any]) -> dict[str, Any]:
    """The parts of a document that define its logic, in canonical form (docs/identity.md)."""
    kind = rule_kind(doc)
    if kind == "rule":
        return {"kind": "rule", "logsource": _canon_logsource(doc["logsource"]), "detection": _canon_detection(doc["detection"])}
    if kind == "filter":
        flt = dict(doc["filter"])
        rules = flt.pop("rules", None)
        return {
            "kind": "filter",
            "logsource": _canon_logsource(doc["logsource"]),
            "filter": _canon_detection(flt),
            "rules": sorted(map(str, rules)) if isinstance(rules, list) else _canon_generic(rules),
        }
    if kind == "correlation":
        return {"kind": "correlation", "correlation": _canon_generic(doc["correlation"])}
    raise ValueError("not a Sigma rule document")


def canonical_logic_bytes(doc: dict[str, Any]) -> bytes:
    """The bytes the logic hash is computed on: LOGIC_VERSION, a newline and the canonical JSON."""
    body = json.dumps(canonical_logic(doc), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return utf8(LOGIC_VERSION + "\n" + body)


def logic_hash(doc: dict[str, Any]) -> str:
    """SHA-256 of the canonical logic: equal for documents with the same detection and log source."""
    return sha256_hex(canonical_logic_bytes(doc))


# --------------------------------------------------------------------------- ids and titles


def title_slug(title: Any) -> str:
    """Lower-case ASCII title with words joined by '-', for comparing titles."""
    text = unicodedata.normalize("NFKD", str(title or "")).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return text


def normalise_rule_id(value: Any) -> str | None:
    """Return the id as a canonical lower-case UUID string, or None if it is missing or not a UUID."""
    if value is None:
        return None
    try:
        return str(uuid.UUID(str(value).strip()))
    except ValueError:
        return None


_HEX = "0123456789abcdef"


def placeholder_uuid(rule_id: str, threshold: float = 0.66) -> bool:
    """Whether a UUID looks hand-made rather than random: 00000000-..., 11111111-..., a1b2c3d4-e5f6-7890-...,
    12345678-1234-... Such ids are copied between unrelated rules, so they must not link rules into one family.

    Score: share of positions where the next or next-but-one character is the same or a neighbour in the hex
    alphabet. Measured on 20,000 uuid4 values the maximum was 0.60; placeholders in the corpus score 0.67-1.0.
    """
    h = rule_id.replace("-", "").lower()
    if len(h) != 32 or any(c not in _HEX for c in h):
        return False

    def near(a: str, b: str) -> bool:
        d = (_HEX.index(a) - _HEX.index(b)) % 16
        return d in (0, 1, 15)

    hits = sum(1 for i in range(len(h) - 2) if near(h[i], h[i + 1]) or (near(h[i], h[i + 2]) and h[i] != h[i + 2]))
    return hits / (len(h) - 2) >= threshold


def fallback_rule_id(logic: str) -> str:
    """A stable UUIDv5 from the logic hash, for rules without a valid id."""
    return str(uuid.uuid5(SIGHARVEST_NAMESPACE, logic))


def resolve_rule_id(doc: dict[str, Any], logic: str) -> tuple[str, str | None]:
    """Return (rule_id, flag). flag is None, 'id_missing' or 'id_invalid'."""
    raw = doc.get("id")
    rid = normalise_rule_id(raw)
    if rid:
        return rid, None
    return fallback_rule_id(logic), ("id_missing" if raw in (None, "") else "id_invalid")
