"""Fixed option values as Literal types: Typer turns them into choices through its public annotation support.

Each Literal mirrors a tuple that the rest of the code uses; the assertions keep them in step.
"""

from __future__ import annotations

from typing import Literal, get_args

from sigharvest.config import PRESETS, SOURCE_TYPES
from sigharvest.normalize import LEVELS
from sigharvest.search_options import SORTS

Level = Literal["informational", "low", "medium", "high", "critical"]
Validation = Literal["ok", "warning", "error"]
Sort = Literal["relevance", "score", "sources", "title", "modified", "level"]
Preset = Literal["curated", "all", "sigmahq"]
SourceType = Literal["git", "http", "local", "http-files", "html", "huggingface"]
ConvertScope = Literal["all", "canonical"]
STAGES = ("validate", "convert")  # repeatable --stage: typer has no list-of-Literal type

assert get_args(Level) == tuple(LEVELS)
assert get_args(Sort) == tuple(SORTS)
assert get_args(Preset) == tuple(PRESETS)
assert get_args(SourceType) == tuple(SOURCE_TYPES)
