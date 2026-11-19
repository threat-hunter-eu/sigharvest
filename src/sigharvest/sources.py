"""Facts about rule sources that several modules need: which source is SigmaHQ or Hayabusa, where its synced git
repository is, and how to link to one of its files.

Well-known sources are found by URL, not by name, because every workspace names its sources as it likes.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from sigharvest.models import Source

# Repository URLs, lower case, without ".git" or a trailing slash.
WELL_KNOWN = {
    "sigmahq": "https://github.com/sigmahq/sigma",
    "hayabusa": "https://github.com/yamato-security/hayabusa-rules",
}


_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#]*@")


def _plain_url(url: str) -> str:
    return url.lower().rstrip("/").removesuffix(".git")


def is_well_known(url: str, which: str) -> bool:
    """True when `url` is the repository of WELL_KNOWN[which] ("sigmahq" or "hayabusa")."""
    return _plain_url(url) == WELL_KNOWN[which]


def well_known_sources(s: Session, which: str) -> list[str]:
    """Names of the sources in the database whose URL is WELL_KNOWN[which] (usually zero or one)."""
    return [name for name, url in s.execute(select(Source.name, Source.url)) if is_well_known(url, which)]


def public_url(url: str) -> str:
    """`url` as it may be shown or published: without the credentials of an http(s) URL (user, password or a token
    given as the user) and without the password of any other URL. SSH user names such as `git@` are kept; anything
    that is not a `scheme://` URL (an scp-like `git@host:path`, a local path) is returned unchanged."""
    try:
        parts = urlsplit(url)
        if not parts.scheme or "@" not in parts.netloc:
            return url
        userinfo, _, host = parts.netloc.rpartition("@")
        if parts.scheme.lower() in ("http", "https"):
            netloc = host
        elif ":" in userinfo:
            netloc = f"{userinfo.partition(':')[0]}@{host}"
        else:
            return url
        return urlunsplit(parts._replace(netloc=netloc))
    except ValueError:  # malformed (an unclosed IPv6 bracket): drop the whole userinfo rather than show it
        return _USERINFO.sub(r"\1", url)


def file_link(url: str, commit: str | None, path: str) -> str | None:
    """https link to a file of a GitHub or GitLab source at a commit (HEAD when unknown); None for other hosts."""
    if not url.startswith(("https://github.com/", "https://gitlab.com/")):
        return None
    base = url.removesuffix(".git")
    # Decide by the host, not by a substring: a GitHub repository path can contain "gitlab.com".
    sep = "/-/blob/" if url.startswith("https://gitlab.com/") else "/blob/"
    return f"{base}{sep}{commit or 'HEAD'}/{path}"
