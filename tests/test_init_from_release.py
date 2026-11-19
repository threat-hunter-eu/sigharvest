"""`sigharvest init --from-release`: a searchable workspace from a release pack, offline, without git sources."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigharvest.cli import app
from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.service import open_db, sync_all
from tests.test_pipeline import commit, make_repo

LICENCE = "MIT License\n\nCopyright (c) 2023 Pack Labs\n\nPermission is hereby granted...\n"


@pytest.fixture(scope="module")
def pack(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A release built locally from a workspace with one MIT git source and one unlicensed local source."""
    root = tmp_path_factory.mktemp("pack")
    repo = make_repo(root)
    (repo / "LICENSE").write_text(LICENCE)
    commit(repo, "licence")
    other = root / "nolic"
    other.mkdir()
    (other / "x.yml").write_text(
        "title: Unlicensed\nid: 9b1c9f8e-0000-4000-8000-000000000099\nstatus: test\nlogsource:\n  product: linux\n"
        "detection:\n  sel:\n    Image|endswith: /nolic\n  condition: sel\nlevel: low\n"
    )
    ws = Workspace(root / "ws")
    ws.root.mkdir()
    save_sources(
        ws,
        [
            SourceConfig(name="upstream", url=str(repo.resolve()), paths=["rules/*"], licence="MIT", redistributable=True, priority=10),
            SourceConfig(name="nolic", type="local", url=str(other)),
        ],
    )
    sessions = open_db(ws, migrate=True)
    assert all(o.status == "ok" for o in sync_all(ws, workers=1))
    from sigharvest.index import rebuild
    from sigharvest.release import build

    with sessions() as s:
        rebuild(s, workers=1)
        s.commit()
        build(s, root / "release")
    return root / "release"


def run(*args: str, home: Path | None = None):  # type: ignore[no-untyped-def]
    env = {"COLUMNS": "200"} | ({"SIGHARVEST_HOME": str(home)} if home else {})
    return CliRunner().invoke(app, list(args), env=env)


def test_init_from_a_local_release_folder(pack: Path, tmp_path: Path) -> None:
    target = tmp_path / "new ws"
    started = time.monotonic()
    result = run("init", str(target), "--from-release", str(pack))
    assert result.exit_code == 0, result.output
    assert time.monotonic() - started < 60
    assert "5 rules from 1 sources" in result.output and "1 rules of the pack are metadata only" in result.output
    # output to a pipe or log gets a line per step, the index steps included
    for step in ("ingesting 5 rules", "indexing", "index: identity families", "index: near-duplicate rules"):
        assert step in result.output, step
    (src,) = load_sources(Workspace(target))
    assert src.name == "release-upstream" and src.type == "local" and src.licence == "MIT" and src.redistributable is True
    assert "upstream" in (src.notes or "")
    # the original paths are kept (SigmaHQ-style folders still decide rule types for --profile)
    files = sorted(p.relative_to(Path(src.url)).as_posix() for p in Path(src.url).rglob("*.yml"))
    assert files and all(f.startswith("rules/") for f in files)
    found = json.loads(run("search", "--json", "--limit", "50", "--per-logic", home=target).output)
    assert found["total"] == 5 and not found["incomplete"]
    assert all(r["sources"] == ["release-upstream"] for r in found["results"])
    # the publisher's licence file travelled through LICENSES.zip and ships again with exports
    out = tmp_path / "x.zip"
    assert run("export", "--format", "zip", "--out", str(out), home=target).exit_code == 0
    import zipfile

    with zipfile.ZipFile(out) as zf:
        assert any(n.endswith("LICENSES/release-upstream/LICENSE") for n in zf.namelist())


def test_refuses_a_tampered_release(pack: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    shutil.copytree(pack, bad)
    with (bad / "rules.jsonl.gz").open("ab") as fh:
        fh.write(b"x")
    result = run("init", str(tmp_path / "ws"), "--from-release", str(bad))
    assert result.exit_code != 0 and "SHA-256" in result.output
    assert not (tmp_path / "ws" / "sources.yaml").exists()
    assert not (tmp_path / "ws").exists()  # the folder init created is removed again


def test_failed_start_keeps_a_folder_that_existed(tmp_path: Path) -> None:
    ws = tmp_path / "mine"
    ws.mkdir()
    (ws / "notes.txt").write_text("keep me")
    result = run("init", str(ws), "--from-release", str(tmp_path / "missing"))
    assert result.exit_code == 2 and "not a release folder" in result.output
    assert (ws / "notes.txt").read_text() == "keep me"


def test_latest_resolves_the_newest_rules_release(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from sigharvest import release_bootstrap

    def fake_get(url: str, **_: object) -> httpx.Response:
        assert url.startswith("https://api.github.com/repos/owner/repo/releases")
        return httpx.Response(200, json=[{"tag_name": "v1.0.0", "draft": False}, {"tag_name": "rules-2026-11-14", "draft": False}])

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setenv("SIGHARVEST_RELEASE_REPO", "owner/repo")
    assert release_bootstrap.resolve("latest") == "https://github.com/owner/repo/releases/download/rules-2026-11-14/"


@pytest.mark.parametrize("missing", ["404", "no rules release"])
def test_latest_falls_back_to_the_tool_repository_until_the_rules_repository_has_a_release(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    import httpx

    from sigharvest import release_bootstrap

    asked = []

    def fake_get(url: str, **_: object) -> httpx.Response:
        asked.append(url)
        if f"/repos/{release_bootstrap.DEFAULT_REPO}/" in url:
            return httpx.Response(404, json={}) if missing == "404" else httpx.Response(200, json=[{"tag_name": "v1.0.0", "draft": False}])
        assert f"/repos/{release_bootstrap.FALLBACK_REPO}/" in url
        return httpx.Response(200, json=[{"tag_name": "rules-2026-11-15", "draft": False}])

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.delenv("SIGHARVEST_RELEASE_REPO", raising=False)
    notes: list[str] = []
    url = release_bootstrap.resolve("latest", notes.append)
    assert url == f"https://github.com/{release_bootstrap.FALLBACK_REPO}/releases/download/rules-2026-11-15/"
    assert len(asked) == 2 and len(notes) == 1 and "\n" not in notes[0] and release_bootstrap.FALLBACK_REPO in notes[0]


def test_an_explicit_release_repo_never_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from sigharvest import release_bootstrap

    monkeypatch.setattr(httpx, "get", lambda url, **_: httpx.Response(404, json={}))
    monkeypatch.setenv("SIGHARVEST_RELEASE_REPO", "owner/fork")
    with pytest.raises(release_bootstrap.NoRelease, match="owner/fork"):
        release_bootstrap.resolve("latest", pytest.fail)


def _resign(folder: Path) -> None:
    from sigharvest.release_reader import file_digest

    names = sorted(p.name for p in folder.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (folder / "SHA256SUMS").write_text("".join(f"{file_digest(folder / n)}  {n}\n" for n in names))


@pytest.mark.parametrize("content_id", ["../../../../victim", "0123456789abcdef/../..", "ABCDEF0123456789", ""])
def test_a_crafted_content_id_never_becomes_a_path(pack: Path, tmp_path: Path, content_id: str) -> None:
    """content_id comes from an untrusted manifest and named a folder that is deleted."""
    bad = tmp_path / "bad"
    shutil.copytree(pack, bad)
    manifest = json.loads((bad / "manifest.json").read_text())
    manifest["content_id"] = content_id
    (bad / "manifest.json").write_text(json.dumps(manifest))
    _resign(bad)  # checksums match: only the content is hostile
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("x")
    result = run("init", str(tmp_path / "ws" / "a" / "b"), "--from-release", str(bad))
    assert result.exit_code != 0 and "content_id" in result.output
    assert (victim / "keep.txt").exists()


def test_licence_zip_reading_is_bounded(tmp_path: Path) -> None:
    import re
    import zipfile

    from sigharvest import release_bootstrap

    path = tmp_path / "LICENSES.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("LICENSES/used/LICENSE", "Copyright 2020 Used\n")
        zf.writestr("LICENSES/used/NOTICE", b"\0" * (20 * 1024**2))  # a zip bomb member: 20 MiB of zeros, tiny compressed
        zf.writestr("LICENSES/other/LICENSE", "not used by this workspace\n")
        zf.writestr("LICENSES/used/../../x/LICENSE", "traversal\n")
        for i in range(release_bootstrap.MAX_FILES_PER_SOURCE + 5):
            zf.writestr(f"LICENSES/many/LICENSE-{i}", "x\n")
    rx = re.compile(r"^(?:LICEN[CS]E|NOTICE)(?:[._-][\w.-]{0,40})?$", re.I)
    out = release_bootstrap._upstream_licences(path, {"used": "used", "many": "many"}, rx, 1024)
    assert out["used"] == {"LICENSE": b"Copyright 2020 Used\n"}
    assert "other" not in out and len(out["many"]) == release_bootstrap.MAX_FILES_PER_SOURCE


def test_release_downloads_are_https_only(tmp_path: Path) -> None:
    from sigharvest.release_reader import ReleaseError, fetch_release

    with pytest.raises(ReleaseError, match="https"):
        fetch_release("http://example.invalid/release/", tmp_path)


def _rewrite(pack: Path, dest: Path, rows=None, manifest=None) -> Path:  # type: ignore[no-untyped-def]
    """A copy of the pack with rewritten rows and/or manifest, checksums re-made: only the content is unusual."""
    import gzip

    shutil.copytree(pack, dest)
    if rows is not None:
        with gzip.open(pack / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
            original = [json.loads(line) for line in fh if line.strip()]
        with gzip.open(dest / "rules.jsonl.gz", "wt", encoding="utf-8") as fh:
            for row in rows(original):
                fh.write(json.dumps(row) + "\n")
    if manifest is not None:
        data = json.loads((pack / "manifest.json").read_text())
        (dest / "manifest.json").write_text(json.dumps(manifest(data)))
    _resign(dest)
    return dest


def _with_text(rows: list[dict]) -> list[dict]:  # type: ignore[type-arg]
    return [r for r in rows if r.get("yaml")]


def test_source_names_that_sanitise_alike_stay_distinct(pack: Path, tmp_path: Path) -> None:
    def rows(original):  # type: ignore[no-untyped-def]
        for i, r in enumerate(_with_text(original)):
            r["canonical"] = dict(r["canonical"], source="up stream" if i % 2 else "up-stream")
        return original

    bad = _rewrite(pack, tmp_path / "bad", rows=rows, manifest=lambda m: m | {"sources": []})
    target = tmp_path / "ws"
    result = run("init", str(target), "--from-release", str(bad))
    assert result.exit_code == 0, result.output
    names = sorted(s.name for s in load_sources(Workspace(target)))
    assert len(names) == 2 and names[0] == "release-up-stream" and names[1].startswith("release-up-stream-")
    found = json.loads(run("search", "--json", "--limit", "50", "--per-logic", home=target).output)
    assert found["total"] == 5


def test_rule_paths_the_file_system_cannot_hold_fall_back_to_hash_names(pack: Path, tmp_path: Path) -> None:
    def rows(original):  # type: ignore[no-untyped-def]
        paths = ["rules/a.yml", "rules/a.yml/b.yml", "rules/" + "x" * 140 + ".yml", "rules/" + "y" * 300 + ".yml", "rules/a.yml"]
        for r, p in zip(_with_text(original), paths, strict=False):
            r["canonical"] = dict(r["canonical"], path=p)
        return original

    bad = _rewrite(pack, tmp_path / "bad", rows=rows)
    target = tmp_path / "ws"
    result = run("init", str(target), "--from-release", str(bad))
    assert result.exit_code == 0, result.output
    (src,) = load_sources(Workspace(target))
    assert len(list(Path(src.url).rglob("*.yml"))) == 5
    assert json.loads(run("search", "--json", "--limit", "50", "--per-logic", home=target).output)["total"] == 5


def test_network_errors_are_clean_messages_and_leave_no_workspace(tmp_path: Path) -> None:
    target = tmp_path / "ws"
    result = run("init", str(target), "--from-release", "https://127.0.0.1:9/")
    assert result.exit_code != 0 and "cannot download the release" in result.output
    assert isinstance(result.exception, SystemExit) and "Traceback" not in result.output
    assert not (target / "sources.yaml").exists()


def test_sums_digest_pins_the_pack(pack: Path, tmp_path: Path) -> None:
    import hashlib

    wrong = run("init", str(tmp_path / "a"), "--from-release", str(pack), "--sums-sha256", "0" * 64)
    assert wrong.exit_code != 0 and "--sums-sha256" in wrong.output
    assert not (tmp_path / "a" / "sources.yaml").exists()
    digest = hashlib.sha256((pack / "SHA256SUMS").read_bytes()).hexdigest()
    assert run("init", str(tmp_path / "b"), "--from-release", str(pack), "--sums-sha256", digest).exit_code == 0


def test_an_incomplete_pack_is_flagged_and_not_republished(pack: Path, tmp_path: Path) -> None:
    bad = _rewrite(pack, tmp_path / "partial", manifest=lambda m: m | {"incomplete": True})
    result = run("init", str(tmp_path / "ws"), "--from-release", str(bad))
    assert result.exit_code == 0 and "marked incomplete" in result.output
    site = run("site", "build", str(tmp_path / "site"), "--release", str(bad), home=tmp_path / "ws")
    assert site.exit_code == 1 and "not publishing an incomplete corpus" in site.output


def test_an_oversized_licence_zip_is_refused_before_it_is_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import re

    from sigharvest import release_bootstrap

    path = tmp_path / "LICENSES.zip"
    path.write_bytes(b"PK" + b"\0" * 4096)
    monkeypatch.setattr(release_bootstrap, "MAX_ZIP_FILE", 1024)
    with pytest.raises(release_bootstrap.BootstrapError, match=r"LICENSES\.zip is larger"):
        release_bootstrap._upstream_licences(path, {"used": "used"}, re.compile("LICENSE"), 1024)


def test_a_source_named_like_a_licence_file_gets_its_own_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    from sigharvest import licence_texts

    monkeypatch.setattr(licence_texts, "upstream", lambda ws, name: [("LICENSE", b"Copyright 2024 Someone\n")])
    files = [name for name, _ in licence_texts.bundle(None, {"MIT.txt": "MIT", "INDEX.md": "MIT", "plain": "MIT"})]
    assert "LICENSES/MIT.txt.source/LICENSE" in files and "LICENSES/INDEX.md.source/LICENSE" in files
    assert "LICENSES/plain/LICENSE" in files and files.count("LICENSES/MIT.txt") == 1 and files.count("LICENSES/INDEX.md") == 1
    assert not any(f.startswith(("LICENSES/MIT.txt/", "LICENSES/INDEX.md/")) for f in files)


@pytest.mark.parametrize("path", ["/etc/cron.d/x", "//etc/cron.d/x", "///etc/cron.d/x"])
def test_a_rooted_rule_path_becomes_relative(path: str) -> None:
    """PurePosixPath keeps exactly two leading slashes as a "//" root, which used to survive as "///etc/...":
    every rooted path must come back relative, the resolve guard in _write_rule is only the second layer."""
    from sigharvest.release_bootstrap import _safe_rel

    assert _safe_rel(path, "fallback.yml") == "etc/cron.d/x.yml"
