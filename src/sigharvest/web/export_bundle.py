"""Size limits and zip packing for web downloads."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import LargeBinary, cast, func, select
from sqlalchemy.orm import Session

from sigharvest.models import LogicGroup, RuleVersion


def check_selection_size(s: Session, members: list[LogicGroup], limit: int = 64 * 1024**2) -> None:
    """Bound raw input before constructing a collection download in memory."""
    version_ids = sorted({group.canonical_version_id for group in members})
    size = 0
    for offset in range(0, len(version_ids), 500):
        size += s.scalar(select(func.sum(func.length(cast(RuleVersion.raw, LargeBinary)))).where(RuleVersion.id.in_(version_ids[offset : offset + 500]))) or 0
        if size > limit:
            raise HTTPException(413, "Export exceeds 64 MiB; select fewer rules")


def check_output_size(root: Path, limit: int = 64 * 1024**2) -> None:
    paths = root.rglob("*") if root.is_dir() else [root]
    if sum(path.stat().st_size for path in paths if path.is_file()) > limit:
        raise HTTPException(413, "Export exceeds 64 MiB; select fewer rules")


def zip_folder(root: Path, limit: int = 64 * 1024**2, *, prefix: str = "") -> bytes:
    """Zip every file under root; `prefix` gives the same top folder as the public ZIP download."""
    check_output_size(root, limit)
    paths = sorted(path for path in root.rglob("*") if path.is_file())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            relative = path.relative_to(root)
            archive.write(path, str(Path(prefix) / relative if prefix else relative))
    return buffer.getvalue()
