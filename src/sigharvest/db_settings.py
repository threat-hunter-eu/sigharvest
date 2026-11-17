"""Explicit durability policy for the workspace's short-lived SQLite writers."""

from __future__ import annotations

import os

from sigharvest.errors import SigharvestError


def sqlite_synchronous() -> str:
    """Keep NORMAL compatibility; allow FULL for acknowledged-commit durability.

    FULL synchronizes each WAL commit, assuming the filesystem/device honors
    fsync. OFF is intentionally unavailable for authoritative workspace data.
    """
    value = os.environ.get("SIGHARVEST_SQLITE_SYNCHRONOUS", "NORMAL").strip().upper()
    if value not in {"NORMAL", "FULL"}:
        raise SigharvestError("SIGHARVEST_SQLITE_SYNCHRONOUS must be NORMAL or FULL")
    return value
