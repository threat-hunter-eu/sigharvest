"""Conversion worker semantics, fingerprinted independently of scheduling and run bookkeeping."""

from __future__ import annotations

from typing import Any

from sigharvest import conversion
from sigharvest.conversion import BACKENDS
from sigharvest.fingerprints import result_key, text_digest

# Some pySigma backends are very slow on huge rules (Loki partitions large OR lists: minutes for one 700 KB IOC
# rule), which used to stall a whole worker chunk. Each backend gets this much time per rule in a worker.
CONVERT_TIMEOUT = 30.0


def _convert_with_timeout(raw: str, name: str, kind: str, siblings: list[str]) -> tuple[str, dict[str, Any]]:
    conv = conversion.convert(raw, name, kind=kind, siblings=siblings, timeout=CONVERT_TIMEOUT)
    return conv.status, conv.detail()


def _convert_one(item: tuple[int, str, str, list[str]], targets: list[str] | None = None) -> list[tuple[int, str, str, dict[str, Any]]]:
    vid, kind, raw, siblings = item
    out = []
    for name in BACKENDS if targets is None else targets:
        status, detail = _convert_with_timeout(raw, name, kind, siblings)
        detail["fingerprint"] = result_key(conversion.toolchain(name), text_digest(raw), kind, [text_digest(raw) for raw in siblings])
        out.append((vid, name, status, detail))
    return out
