"""Title-first lexical ranking and searchable CamelCase title aliases.

FTS5 supplies prefix/token matching without a Python callback per candidate.
Title coverage takes priority over body-only BM25. Bounded quality breaks ties
within a title-coverage tier without changing the order of different tiers.
"""

from __future__ import annotations

import re

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
MAX_TITLE_TERMS = 32


def indexed_title(title: str) -> str:
    """Retain original tokens/phrases and append split compound-word aliases."""
    aliases = [_CAMEL.sub(" ", word) for word in re.findall(r"\w+", title) if _CAMEL.search(word)]
    return " ".join([title, *aliases])


def rank_sql(query: str, weights: tuple[float, ...]) -> tuple[str, dict[str, str]]:
    """Rank title term coverage, then body BM25, without rewarding repetition.

    Each uncorrelated title lookup uses FTS posting lists once per SQL statement.
    Bound parameters retain column/phrase/exclusion semantics. At most 32 distinct
    positive terms affect title ranking; retrieval still evaluates the full query.
    """
    from sigharvest.index import _TERM, _phrase

    terms: list[str] = []
    negative = False
    for raw in _TERM.findall(query):
        if raw == "NOT":
            negative = True
            continue
        if raw in {"OR", "AND", "(", ")"}:
            continue
        if negative or raw.startswith("-"):
            negative = False
            continue
        phrase = _phrase(raw)
        if phrase and not phrase.startswith('"'):
            column, _, phrase = phrase.partition(":")
            if column != "title":
                continue
        if phrase and phrase not in terms:
            terms.append(phrase)
            if len(terms) == MAX_TITLE_TERMS:
                break
    params = {f"title_term_{i}": f"title:{term}" for i, term in enumerate(terms)}
    hits = (
        " + ".join(
            f"(g.id IN (SELECT rowid FROM rules_fts WHERE rules_fts MATCH :{key}))"  # noqa: S608 - generated parameter names, bound terms
            for key in params
        )
        or "0"
    )
    body = "bm25(rules_fts, {})".format(", ".join(map(str, weights)))
    # Title tiers are whole negative integers. Quality contributes at most 0.1,
    # so even extreme local adjustments cannot cross a tier. Body-only scores
    # remain in (-1, 0). A scalar key preserves the fast min(key) family collapse.
    quality = "min(100.0, max(0.0, g.score)) / 1000.0"
    return f"coalesce(nullif(-({hits}), 0) - {quality}, {body} / (1 - {body}))", params


def default_sort(query: str | None) -> str:
    """Text searches default to best match; filter-only browsing to quality score."""
    from sigharvest.index import parse_query

    return "relevance" if parse_query(query or "")[0].strip() else "score"
