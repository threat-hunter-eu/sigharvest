"""Re-ingesting unchanged files rewrites no row state and queues no index work."""

from sqlalchemy import select

from sigharvest.models import Occurrence, RuleVersion
from sigharvest.service import open_db, sync_all
from tests.test_pipeline import RULE, UIDS, commit, make_repo, workspace


def _rows(ws):
    with open_db(ws)() as s:
        occurrences = list(
            s.execute(
                select(
                    Occurrence.id,
                    Occurrence.version_id,
                    Occurrence.path,
                    Occurrence.doc_index,
                    Occurrence.file_hash,
                    Occurrence.commit,
                    Occurrence.present,
                    Occurrence.span_start,
                    Occurrence.span_end,
                    Occurrence.first_seen,
                ).order_by(Occurrence.id)
            )
        )
        versions = list(s.execute(select(RuleVersion.id, RuleVersion.content_hash, RuleVersion.flags, RuleVersion.product).order_by(RuleVersion.id)))
        last_seen = dict(s.execute(select(Occurrence.id, Occurrence.last_seen)).all())
        return occurrences, versions, last_seen


def _logic(ws, title):
    with open_db(ws)() as s:
        return s.scalar(select(RuleVersion.logic_hash).where(RuleVersion.title == title))


def test_rescan_of_unchanged_files_keeps_rows(tmp_path):
    ws = workspace(tmp_path, make_repo(tmp_path))
    assert sync_all(ws)[0].status == "ok"
    occurrences, versions, seen = _rows(ws)
    result = sync_all(ws, rescan=True)[0]
    assert result.status == "ok" and result.log.files_added == 5
    after, after_versions, after_seen = _rows(ws)
    assert (after, after_versions) == (occurrences, versions)
    assert all(after_seen[i] >= seen[i] for i in seen) and after_seen != seen


def test_changed_document_retires_only_its_own_occurrence(tmp_path):
    repo = make_repo(tmp_path)
    ws = workspace(tmp_path, repo)
    assert sync_all(ws)[0].status == "ok"
    before, _, _ = _rows(ws)
    old_d, kept_c = _logic(ws, "Test d"), _logic(ws, "Test c")
    (repo / "rules" / "multi.yaml").write_text(RULE.format(n="c", uid=UIDS[3]) + "---\n" + RULE.format(n="z", uid=UIDS[6]))
    commit(repo, "replace the second document")
    assert sync_all(ws)[0].status == "ok"
    after, _, _ = _rows(ws)
    multi_before = {r.id: r for r in before if r.path == "rules/multi.yaml"}
    multi_after = {r.id: r for r in after if r.path == "rules/multi.yaml"}
    first = next(i for i, r in multi_before.items() if r.doc_index == 0)
    second = next(i for i, r in multi_before.items() if r.doc_index == 1)
    assert multi_after[first].present and multi_after[first].version_id == multi_before[first].version_id
    assert multi_after[first].first_seen == multi_before[first].first_seen
    assert not multi_after[second].present
    (new,) = set(multi_after) - set(multi_before)
    assert multi_after[new].present and multi_after[new].doc_index == 1
    assert old_d != _logic(ws, "Test z") and kept_c == _logic(ws, "Test c")
    # Restoring the old document reactivates its original occurrence row.
    (repo / "rules" / "multi.yaml").write_text(RULE.format(n="c", uid=UIDS[3]) + "---\n" + RULE.format(n="d", uid=UIDS[4]))
    commit(repo, "restore")
    assert sync_all(ws)[0].status == "ok"
    restored = {r.id: r for r in _rows(ws)[0] if r.path == "rules/multi.yaml"}
    assert restored[second].present and not restored[new].present and restored[first].present
