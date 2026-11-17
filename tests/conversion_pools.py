"""Conversion worker pools for tests that start real memory-capped workers.

A forked copy of a long-lived xdist worker can already map more than the 512 MiB
worker cap, so conversion_memory.install() refuses by design and such tests fail
only in full-suite runs. Production starts workers from a small forkserver; these
pools start each worker in a fresh interpreter (spawn) instead, which gives it a
small, predictable mapping whatever the parent has loaded.

A fresh interpreter does not see the parent's monkeypatches. Every module
attribute the worker needs is passed explicitly as an override and set in the
child before the real initializer runs. Values must pickle (functions by
reference, so they must be module-level).
"""

from __future__ import annotations

import importlib
import multiprocessing
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from typing import Any

Override = tuple[str, str, Any]


def _initialize(overrides: tuple[Override, ...], initializer: Callable[..., None] | None, initargs: tuple[Any, ...]) -> None:
    for module, name, value in overrides:
        setattr(importlib.import_module(module), name, value)
    if initializer is not None:
        initializer(*initargs)


def spawn_pool(*overrides: Override) -> type[ProcessPoolExecutor]:
    """A ProcessPoolExecutor class whose workers are fresh interpreters with `overrides` applied."""

    class SpawnPool(ProcessPoolExecutor):
        def __init__(
            self, max_workers: int | None = None, initializer: Callable[..., None] | None = None, initargs: tuple[Any, ...] = (), **kwargs: Any
        ) -> None:
            super().__init__(
                max_workers=max_workers,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=_initialize,
                initargs=(overrides, initializer, initargs),
                **kwargs,
            )

    return SpawnPool
