"""Private byte-bounded conversion handoff, independent of semantic fingerprints.

Workers spill complete JSON rows into parent-owned slots and return only a small
receipt. Reservations cover each slot's maximum plus the parent's decoded batch.
Backend objects and JSON encoder temporaries are not a heap/RSS limit.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sigharvest.conversion_spills import Ticket

from sigharvest.errors import SigharvestError

TARGET_REPLY_BYTES = 32 * 1024 * 1024
RULE_REPLY_BYTES = 64 * 1024 * 1024
PENDING_OUTPUT_BYTES = 512 * 1024 * 1024
# Spill reservations grow to one rule per admitted worker, up to this ceiling.
MAX_PENDING_OUTPUT_BYTES = 4 * 1024 * 1024 * 1024
BUFFER_OUTPUT_BYTES = 64 * 1024 * 1024
IPC_RECEIPT_BYTES = 512
PROTOCOL = 1

Row = tuple[int, str, str, dict[str, Any]]
Item = tuple[int, str, str, list[str]]


class OutputFailure(SigharvestError):
    """No result is published for an incomplete or refused rule."""


class CleanupFailure(OutputFailure):
    """Unverifiable ownership or failed cleanup must not prune retained history."""


def pending_output_bytes(workers: int) -> int:
    """PENDING_OUTPUT_BYTES, grown so every admitted worker can hold one rule in flight.

    The fixed 512 MiB holds six spill slots, so a seventh worker would sit idle.
    """
    base = (PENDING_OUTPUT_BYTES - BUFFER_OUTPUT_BYTES - RULE_REPLY_BYTES) // RULE_REPLY_BYTES
    if base < 1 or workers <= base:
        return PENDING_OUTPUT_BYTES
    return min(PENDING_OUTPUT_BYTES + (workers - base) * RULE_REPLY_BYTES, MAX_PENDING_OUTPUT_BYTES)


@dataclass(frozen=True)
class Receipt:
    version_id: int
    size: int = 0
    sha256: str = ""
    error: str = ""
    protocol: int = PROTOCOL


def spill(item: Item, targets: list[str], path: str, worker: Callable[..., list[Row]]) -> Receipt:
    """Never put query objects or arbitrary exception text on the result pipe."""
    vid = item[0]
    size = 0
    sha = hashlib.sha256()
    try:
        rows = worker(item, targets)
        with open(path, "xb", buffering=64 * 1024) as output:
            os.chmod(path, 0o600)
            for row in rows:
                target_bytes = 0
                for chunk in json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False).iterencode(row):
                    # Character length is a cheap lower bound before UTF-8 allocation.
                    if len(chunk) > TARGET_REPLY_BYTES - target_bytes or len(chunk) > RULE_REPLY_BYTES - size:
                        raise OutputFailure("reply cap")
                    data = chunk.encode("utf-8")
                    target_bytes += len(data)
                    size += len(data)
                    if target_bytes + 1 > TARGET_REPLY_BYTES or size + 1 > RULE_REPLY_BYTES:
                        raise OutputFailure("reply cap")
                    output.write(data)
                    sha.update(data)
                output.write(b"\n")
                sha.update(b"\n")
                size += 1
        return Receipt(vid, size, sha.hexdigest())
    except OutputFailure:
        return Receipt(vid, error="reply-cap")
    except MemoryError:
        return Receipt(vid, error="worker-memory")
    except OSError:
        return Receipt(vid, error="spill-io")
    except BaseException:  # noqa: BLE001 - never pickle arbitrary backend exceptions, including SystemExit
        return Receipt(vid, error="worker-failure")


def receive(receipt: Receipt, path: Path, version_id: int, expected: dict[str, tuple[str, str]]) -> list[Row]:
    """Validate exact bytes, target membership and implementation/input keys.

    The parent supplies the path; a worker never chooses a path to read. The slot
    remains reserved until this function and its consumer have finished.
    """
    original = None
    try:
        with suppress(FileNotFoundError):
            original = path.lstat()
        if original is not None and (not stat.S_ISREG(original.st_mode) or original.st_nlink != 1):
            original = None
            raise OutputFailure("unsafe-spill")
        if (
            type(receipt) is not Receipt
            or type(receipt.protocol) is not int
            or receipt.protocol != PROTOCOL
            or type(receipt.version_id) is not int
            or receipt.version_id != version_id
        ):
            raise OutputFailure("invalid-envelope")
        if receipt.error:
            if receipt.error == "spill-ownership":
                raise CleanupFailure("spill-ownership")
            raise OutputFailure(
                receipt.error if receipt.error in {"reply-cap", "spill-io", "worker-failure", "worker-memory", "spill-ownership"} else "invalid-envelope"
            )
        if type(receipt.size) is not int or not 0 < receipt.size <= RULE_REPLY_BYTES:
            raise OutputFailure("invalid-size")
        rows: list[Row] = []
        sha = hashlib.sha256()
        size = 0
        seen: set[str] = set()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as source:
            opened = os.fstat(source.fileno())
            if original is None or (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino):
                raise OutputFailure("replaced-spill")
            if opened.st_size != receipt.size:
                raise OutputFailure("invalid-size")
            for _ in expected:
                line = source.readline(TARGET_REPLY_BYTES + 1)
                size += len(line)
                if not line.endswith(b"\n") or len(line) > TARGET_REPLY_BYTES or size > RULE_REPLY_BYTES:
                    raise OutputFailure("invalid-target-size")
                sha.update(line)
                row = json.loads(line)
                if not isinstance(row, list) or len(row) != 4:
                    raise OutputFailure("invalid-target")
                vid, target, status, detail = row
                if type(vid) is not int or vid != version_id or not isinstance(target, str) or target not in expected or target in seen:
                    raise OutputFailure("invalid-target")
                if not isinstance(status, str) or not isinstance(detail, dict):
                    raise OutputFailure("invalid-target")
                toolchain, fingerprint = expected[target]
                if detail.get("toolchain") != toolchain or detail.get("fingerprint") != fingerprint:
                    raise OutputFailure("invalid-implementation")
                seen.add(target)
                rows.append((vid, target, status, detail))
            if source.read(1) or seen != set(expected) or size != receipt.size or sha.hexdigest() != receipt.sha256:
                raise OutputFailure("invalid-envelope")
        return rows
    except (OutputFailure, OSError, ValueError, TypeError, RecursionError) as exc:
        reason = str(exc) if isinstance(exc, OutputFailure) else "invalid-spill"
        failure = CleanupFailure if isinstance(exc, CleanupFailure) else OutputFailure
        raise failure(
            f"conversion version {version_id}: output resource failure ({reason}); "
            f"limits target={TARGET_REPLY_BYTES}, rule={RULE_REPLY_BYTES} bytes. "
            "No incomplete target set was saved; check output size and temporary disk space, then resume."
        ) from None
    finally:
        if original is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino) or not stat.S_ISREG(current.st_mode):
                    raise CleanupFailure("conversion output cleanup refused: spill replaced")
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                raise CleanupFailure("conversion output cleanup failed; committed results remain, inspect ownership and resume") from None


def owned_spill(item: Item, targets: list[str], ticket: Ticket, worker: Callable[..., list[Row]]) -> Receipt:
    """Hold independent ownership before backend execution through the final write."""
    from sigharvest.conversion_spills import attach

    try:
        with attach(ticket) as attempt:
            attempt.require_live_parent()
            return spill(item, targets, str(attempt.slot(item[0])), worker)
    except OutputFailure:
        return Receipt(item[0], error="spill-ownership")
