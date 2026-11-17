"""Data release: licence classes decide whether the YAML text is included."""

import gzip
import json
from pathlib import Path

from sigharvest.licensing import licence_class
from sigharvest.release import build
from sigharvest.service import open_db
from tests.helpers import set_licence
from tests.test_collections import _setup


def _rows(folder: Path) -> list[dict[str, object]]:
    with gzip.open(folder / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


def test_licence_classes() -> None:
    assert licence_class("MIT") == licence_class("DRL-1.1") == licence_class("Detection Rule License 1.1") == "permissive"
    assert licence_class("GPL-3.0") == licence_class("AGPL-3.0") == "copyleft"
    assert licence_class("Elastic-2.0") == licence_class("CC-BY-NC-4.0") == "restricted"
    assert licence_class(None) == licence_class("NOASSERTION") == "none"


def test_release_keeps_unlicensed_text_out(tmp_path: Path) -> None:
    _repo, ws, _S = _setup(tmp_path)
    S = open_db(ws, migrate=True)
    with S() as s:
        m = build(s, tmp_path / "rel")
    rows = _rows(tmp_path / "rel")
    assert len(rows) == m["counts"]["rules"] == 5
    # the fixture source has no licence: metadata only
    assert all(r["yaml"] is None and r["licence_class"] == "none" for r in rows)
    assert (tmp_path / "rel" / "ATTRIBUTION.md").read_text().count("| local |") == 1
    assert "rules.jsonl.gz" in (tmp_path / "rel" / "SHA256SUMS").read_text()
    set_licence(ws, "MIT")
    with S() as s:
        m = build(s, tmp_path / "rel2")
    rows = _rows(tmp_path / "rel2")
    assert all(r["yaml"] and r["licence"] == "MIT" for r in rows) and m["counts"]["with_yaml"] == 5


def test_release_artifacts_content_id_and_changes(tmp_path: Path) -> None:
    import zipfile

    from sigharvest.release_reader import open_release

    _repo, ws, _S = _setup(tmp_path)
    S = open_db(ws, migrate=True)
    set_licence(ws, "MIT")
    with S() as s:
        first = build(s, tmp_path / "rel", build_epoch=1_700_000_000)
        again = build(s, tmp_path / "again", build_epoch=1_800_000_000)
    rel = tmp_path / "rel"
    expected = {
        "sigharvest-rules-permissive.zip",
        "sigharvest-rules-copyleft.zip",
        "index.json.gz",
        "provenance.json.gz",
        "attack-navigator-layer.json",
        "changes.json",
        "NOTICE.md",
        "stats.json",
        "RELEASE_NOTES.md",
        "manifest.json",
        "rules.jsonl.gz",
        "ATTRIBUTION.md",
        "SHA256SUMS",
        "LICENSES.zip",
    }
    assert expected <= {p.name for p in rel.iterdir()}
    sums = (rel / "SHA256SUMS").read_text()
    assert all(name in sums for name in expected - {"SHA256SUMS"})
    # content_id depends on rule content and counts, not on build time
    assert first["content_id"] == again["content_id"] and first["created"] != again["created"]
    with zipfile.ZipFile(rel / "sigharvest-rules-permissive.zip") as zf:
        assert sum(n.endswith(".yml") for n in zf.namelist()) == 5 and {"NOTICE.md", "ATTRIBUTION.md", "manifest.jsonl"} <= set(zf.namelist())
        credits = [json.loads(x) for x in zf.read("manifest.jsonl").decode().splitlines()]
        assert len(credits) == 5 and all(c["licence"] == "MIT" and c["source"] == "local" and c["path"] in zf.namelist() for c in credits)
        assert zf.read("ATTRIBUTION.md").decode().count("| local | [MIT](https://spdx.org/licenses/MIT.html) |") == 5
    with zipfile.ZipFile(rel / "sigharvest-rules-copyleft.zip") as zf:
        assert sorted(zf.namelist()) == ["ATTRIBUTION.md", "LICENSES/INDEX.md", "NOTICE.md", "manifest.jsonl"]
    index = json.loads(gzip.decompress((rel / "index.json.gz").read_bytes()))
    provenance = json.loads(gzip.decompress((rel / "provenance.json.gz").read_bytes()))
    assert len(index["rules"]) == 5 and set(provenance["rules"]) == {r["logic_hash"] for r in index["rules"]}
    stats = json.loads((rel / "stats.json").read_text())
    assert stats["rules"] == 5 and stats["zip"] == {"permissive": 5}
    assert json.loads((rel / "changes.json").read_text()) == {"previous": None, "new": [], "changed": [], "removed": []}
    with open_release(rel) as reader:
        assert len(list(reader.rows())) == 5
    # a previous release: nothing changed, then one rule removed
    with S() as s:
        build(s, tmp_path / "rel2", previous=rel)
    changes = json.loads((tmp_path / "rel2" / "changes.json").read_text())
    assert changes["previous"] == first["content_id"] and changes["new"] == changes["removed"] == []
    with S() as s:
        from sigharvest.index import rebuild
        from sigharvest.models import Occurrence

        s.query(Occurrence).filter(Occurrence.path.like("%a.yml")).update({Occurrence.present: False}, synchronize_session=False)
        s.commit()
        rebuild(s)
        build(s, tmp_path / "rel3", previous=rel)
    changes = json.loads((tmp_path / "rel3" / "changes.json").read_text())
    assert len(changes["removed"]) + len(changes["changed"]) >= 1
    assert "since the previous release" in (tmp_path / "rel3" / "RELEASE_NOTES.md").read_text()


def test_redistributable_false_ships_metadata_only(tmp_path: Path) -> None:
    from sigharvest.config import SourceConfig
    from sigharvest.models import Source

    _repo, ws, _S = _setup(tmp_path)
    with open_db(ws, migrate=True)() as s:
        s.query(Source).update({Source.licence: "MIT"})
        s.commit()
        configs = {"local": SourceConfig(name="local", url="x", type="local", licence="MIT", redistributable=False)}
        m = build(s, tmp_path / "rel", configs=configs)
    assert m["counts"].get("with_yaml", 0) == 0 and all(r["yaml"] is None for r in _rows(tmp_path / "rel"))


def test_release_build_refuses_unknown_licence_classes(tmp_path) -> None:
    from typer.testing import CliRunner

    from sigharvest.cli import app

    result = CliRunner().invoke(app, ["release", "build", str(tmp_path / "out"), "--licence-class", "private"])
    assert result.exit_code == 2 and not (tmp_path / "out").exists()
