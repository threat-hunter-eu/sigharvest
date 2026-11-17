"""Index generation fingerprint: tells whether the published index was built by the current code and inputs.

The index is always rebuilt in full (index.rebuild); these keys only let `doctor` and `update` notice a stale index.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from sigharvest.attack_score import Context as AttackScoreContext
from sigharvest.fingerprints import digest, implementation

FORMAT_KEY = "index_format"
USER_REVISION_KEY = "indexed_user_revision"


def user_revision(s: Session) -> str:
    """Transactional user edits, independent of wall-clock order and row deletion."""
    from sigharvest.read_cache import revision

    return digest(revision(s, ("collections", "collection_items")))


def fingerprint() -> str:
    from sigharvest.page_summaries import code_version

    return implementation(
        "index",
        modules=(
            "index.py",
            "title_relevance.py",
            "attack.py",
            "attack_score.py",
            "index_delta.py",
            "index_families.py",
            "index_near.py",
            "index_workers.py",
            "text_metadata.py",
            "ruleview.py",
            "neardup.py",
            "quality.py",
            "quality_templates.py",
            "family_links.py",
            "logsource_inference.py",
            "logsource_catalog.py",
            "quality_precision.py",
            "quality_unused.py",
            "quality_quotes.py",
            "normalize.py",
            "datasources.py",
            "source_overlap.py",
            "search_summary.py",
            "corpus_stats.py",
            "page_summaries.py",
        ),
        options={"year": datetime.now(UTC).year, "pages": code_version()},
    )


def publication_fingerprint(s: Session, attack_context: AttackScoreContext | None = None) -> str:
    """Implementation plus the offline catalog used for structural metadata credit."""
    if attack_context is None:
        from sigharvest.attack import session_matrix

        attack_context = AttackScoreContext(session_matrix(s))
    return digest([fingerprint(), attack_context.fingerprint])
