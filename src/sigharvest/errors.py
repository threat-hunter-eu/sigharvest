"""User-facing errors.

A SigharvestError means the request cannot be done as asked: an unknown collection or rule, a source
that is not synced, a folder that is not a workspace. Its message says what is wrong in plain words, so callers
show it as is: the CLI prints it and exits with code 2, the web UI shows it on the page. Bugs are not SigharvestErrors.
"""

from __future__ import annotations


class SigharvestError(Exception):
    """Base class of the errors whose message is meant for the user."""


class SchemaUnavailable(SigharvestError):
    """The connected database schema cannot be read by this process."""
