"""Facts about rule sources that several modules need: which source is SigmaHQ or Hayabusa, where its synced git
repository is, and how to link to one of its files.

Well-known sources are found by URL, not by name, because every workspace names its sources as it likes.
"""

from __future__ import annotations

from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.models import Source

# Repository URLs, lower case, without ".git" or a trailing slash.
WELL_KNOWN = {
    "sigmahq": "https://github.com/sigmahq/sigma",
    "hayabusa": "https://github.com/yamato-security/hayabusa-rules",
}


def _plain_url(url: str) -> str:
    return url.lower().rstrip("/").removesuffix(".git")


def is_well_known(url: str, which: str) -> bool:
    """True when `url` is the repository of WELL_KNOWN[which] ("sigmahq" or "hayabusa")."""
    return _plain_url(url) == WELL_KNOWN[which]


def well_known_sources(s: Session, which: str) -> list[str]:
    """Names of the sources in the database whose URL is WELL_KNOWN[which] (usually zero or one)."""
    return [name for name, url in s.execute(select(Source.name, Source.url)) if is_well_known(url, which)]


def file_link(url: str, commit: str | None, path: str) -> str | None:
    """https link to a file of a GitHub or GitLab source at a commit (HEAD when unknown); None for other hosts.

    The commit and the path come from the source repository, so they are percent-encoded: a file name with a newline,
    a space, `>` or `)` must not end the link, or add Markdown, where the link is written (SKIPPED.md, attributions)."""
    if not url.startswith(("https://github.com/", "https://gitlab.com/")):
        return None
    base = url.removesuffix(".git")
    sep = "/-/blob/" if "gitlab.com" in base else "/blob/"
    return f"{base}{sep}{quote(commit or 'HEAD', safe='', errors='replace')}/{quote(path, safe='/', errors='replace')}"
