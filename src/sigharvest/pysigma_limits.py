"""Bounds on pySigma work that grows exponentially with rule text.

pySigma's `|windash` modifier expands every dash or slash at a word start into five variants (`-`, `/`, en dash,
em dash, horizontal bar), so a value with N such tokens becomes 5**N values: 6 tokens take seconds, 10 take minutes
and gigabytes. One upstream rule must never stall `update`, a query export or the web server, so `install()`
replaces the modifier with a guarded one that refuses, before expanding:

- a value with more than WINDASH_MAX_TOKENS tokens;
- a field whose modifier chain has `windash` more than once (`|windash|windash` multiplies the expansions);
- inside `budget()` (every sigharvest parse wrapper opens one per document), a document whose expansions add up to
  more than WINDASH_MAX_VARIANTS values across all its fields and values.

pySigma 2 refuses a value with more than three windash tokens by itself (`SigmaWindowsDashModifier.max_expanded_dashes`,
a `SigmaModifiedError`), so with pySigma 2 the per-value limit here is a backstop; the chain and per-document limits
are still sigharvest's own.

pySigma collects the refusal like any other rule error: validation reports it, conversion records `skipped`. The
per-document wall-clock limits of the validate and convert stages stay as the backstop.

Every place that parses rules with pySigma calls `install()` first (it is idempotent and cheap).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

# 5**5 = 3125 variants per value: well above what real rules use (one or two parameters), still fast.
WINDASH_MAX_TOKENS = 5
# Expanded values per document, over all windash fields and values (a few seconds of pySigma work at most).
WINDASH_MAX_VARIANTS = 10_000
_WINDASH_TOKEN = re.compile(r"\B[-/]\b")  # the pattern pySigma's SigmaWindowsDashModifier expands
_installed = False
_budget: ContextVar[list[int] | None] = ContextVar("sigharvest_windash_budget", default=None)


def windash_tokens(value: str) -> int:
    """How many dash/slash tokens `|windash` would expand in `value`."""
    return len(_WINDASH_TOKEN.findall(value))


@contextmanager
def budget() -> Iterator[None]:
    """Count windash expansions of one document (one parse) against WINDASH_MAX_VARIANTS."""
    token = _budget.set([0])
    try:
        yield
    finally:
        _budget.reset(token)


_re2_quiet = False
log = logging.getLogger("sigharvest.pysigma")


def quiet_re2() -> None:
    """Stop RE2 from printing parse errors to stderr (once per process).

    pySigma 2 checks every `|re` value with RE2, which has no lookarounds or backreferences. RE2's C++ library logs
    each refused pattern to stderr ("E0000 ... re2.cc:242] Error parsing '...': invalid perl operator: (?!", after
    "WARNING: All log messages before absl::InitializeLog() ..."), lines that look like a crash. The refusal itself
    is unchanged: pySigma raises, the rule is a validation error (`regex refused by RE2` in the validate summary) and
    the pattern is logged here at debug level only. Patterns compiled with explicit options are left alone."""
    global _re2_quiet
    if _re2_quiet:
        return
    _re2_quiet = True
    try:
        import re2
    except ImportError:  # pySigma 1.x: Python's re, nothing to silence
        return
    original = re2.compile
    if getattr(original, "_sigharvest_quiet", False):
        return
    silent = re2.Options()
    silent.log_errors = False

    def compile(pattern: Any, options: Any = None) -> Any:
        if options is None and not isinstance(pattern, re2._Regexp):
            options = silent
        try:
            return original(pattern, options)
        except re2.error as exc:
            log.debug("RE2 refused a regular expression (%s): %.200r", exc, pattern)
            raise

    compile._sigharvest_quiet = True  # type: ignore[attr-defined]
    re2.compile = compile


def install() -> None:
    """Guard pySigma's `|windash` modifier and quiet RE2's stderr logging (once per process)."""
    global _installed
    quiet_re2()
    if _installed:
        return
    from sigma.exceptions import SigmaValueError
    from sigma.modifiers import SigmaWindowsDashModifier

    original = SigmaWindowsDashModifier.modify
    if getattr(original, "_sigharvest_guard", False):
        _installed = True
        return

    def refuse(self: Any, message: str) -> None:
        raise SigmaValueError(f"windash modifier: {message}", source=getattr(self, "source", None))

    def modify(self: Any, val: Any) -> Any:
        chain = [*getattr(self, "applied_modifiers", []), *getattr(getattr(self, "detection_item", None), "modifiers", [])]
        if sum(1 for m in getattr(self, "applied_modifiers", []) if m is SigmaWindowsDashModifier) or (
            sum(1 for m in getattr(getattr(self, "detection_item", None), "modifiers", []) if m is SigmaWindowsDashModifier) > 1
        ):
            refuse(self, f"applied more than once in one modifier chain ({len(chain)} modifiers)")
        text = getattr(val, "original", None)
        n = windash_tokens(text if isinstance(text, str) else str(val))
        if n > WINDASH_MAX_TOKENS:
            refuse(self, f"{n} dash/slash tokens would expand to 5^{n} values (limit {WINDASH_MAX_TOKENS})")
        counter = _budget.get()
        if counter is not None:
            counter[0] += 5**n
            if counter[0] > WINDASH_MAX_VARIANTS:
                refuse(self, f"the document's windash values expand to more than {WINDASH_MAX_VARIANTS} values")
        return original(self, val)

    modify._sigharvest_guard = True  # type: ignore[attr-defined]
    SigmaWindowsDashModifier.modify = modify  # type: ignore[method-assign]
    _installed = True
