"""http sources: archives and files served by a mock transport (no network), with the extraction safety limits."""

from __future__ import annotations

import contextlib
import io
import stat
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

import sigharvest.sync as sync_mod
from sigharvest.config import SourceConfig, Workspace, save_sources
from sigharvest.models import RuleVersion, SyncLog
from sigharvest.service import open_db, sync_all
from sigharvest.sync import (
    SyncError,
    SyncResult,
    _auth_header,
    _check_git_inputs,
    path_selected,
    selected_files,
    sync_http,
)
from tests.test_pipeline import RULE, UIDS

_RealClient = httpx.Client


def serve(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> list[httpx.Request]:
    """Route every httpx.Client created by sync.py through `handler`; returns the requests seen."""
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def factory(*args: object, **kwargs: object) -> httpx.Client:
        return _RealClient(*args, transport=httpx.MockTransport(wrapped), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(sync_mod.httpx, "Client", factory)
    return seen


def ok(body: bytes) -> Callable[[httpx.Request], httpx.Response]:
    """A handler that answers every request with `body`."""
    return lambda request: httpx.Response(200, content=body)


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def tar_bytes(members: dict[str, bytes], mode: str = "w:gz", links: dict[str, tuple[bytes, str]] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:  # type: ignore[call-overload]
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, (kind, target) in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


def ws_for(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "ws")
    ws.root.mkdir(parents=True)
    return ws


def rule(n: str, uid: int = 1) -> bytes:
    return RULE.format(n=n, uid=UIDS[uid]).encode()


def files_under(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink()}


def test_zip_extraction_and_diff_between_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    src = SourceConfig(name="z", type="http", url="https://example.org/rules.zip?ref=main")
    payload = {"body": zip_bytes({"rules/a.yml": rule("a"), "rules/b.yml": rule("b", 2), "rules/dir/": b""})}
    serve(monkeypatch, lambda r: httpx.Response(200, content=payload["body"]))
    first = sync_http(src, ws)
    assert first.added == {"rules/a.yml", "rules/b.yml"} and not first.changed and not first.removed
    assert first.new_commit and first.root == ws.source_dir("z")
    payload["body"] = zip_bytes({"rules/a.yml": rule("a") + b"# changed\n", "rules/c.yml": rule("c", 3)})
    second = sync_http(src, ws)
    assert (second.added, second.changed, second.removed) == ({"rules/c.yml"}, {"rules/a.yml"}, {"rules/b.yml"})
    assert second.new_commit != first.new_commit
    assert not (ws.corpus / "z.tmp").exists()


@pytest.mark.parametrize(("suffix", "mode"), [(".tar.gz", "w:gz"), (".tgz", "w:gz"), (".tar", "w")])
def test_tar_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str, mode: str) -> None:
    ws = ws_for(tmp_path)
    body = tar_bytes({"pkg/rules/a.yml": rule("a"), "pkg/README.md": b"# hi\n"}, mode=mode)
    serve(monkeypatch, lambda r: httpx.Response(200, content=body))
    res = sync_http(SourceConfig(name="t", type="http", url=f"https://example.org/archive{suffix}"), ws)
    assert res.added == {"pkg/rules/a.yml", "pkg/README.md"}
    assert (ws.source_dir("t") / "pkg/rules/a.yml").read_bytes() == rule("a")


def test_path_traversal_never_leaves_the_corpus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    evil = {"../escape.yml": b"x", "/etc/abs.yml": b"x", "a/../../up.yml": b"x", "ok/fine.yml": rule("a")}
    for src, name, body in (("ez", "rules.zip", zip_bytes(evil)), ("et", "rules.tar.gz", tar_bytes(evil))):
        serve(monkeypatch, ok(body))
        res = sync_http(SourceConfig(name=src, type="http", url=f"https://example.org/{name}"), ws)
        assert res.added == {"ok/fine.yml"}, name
    assert files_under(tmp_path) == {"ws/corpus/ez/ok/fine.yml", "ws/corpus/et/ok/fine.yml"}


def test_tar_links_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    target = tmp_path / "secret.txt"
    target.write_text("secret")
    links = {"sym.yml": (tarfile.SYMTYPE, str(target)), "hard.yml": (tarfile.LNKTYPE, "a.yml"), "dev": (tarfile.CHRTYPE, "")}
    body = tar_bytes({"a.yml": rule("a")}, links=links)
    serve(monkeypatch, lambda r: httpx.Response(200, content=body))
    res = sync_http(SourceConfig(name="l", type="http", url="https://example.org/x.tar.gz"), ws)
    assert res.added == {"a.yml"}
    assert not any(p.is_symlink() for p in ws.source_dir("l").rglob("*"))


def test_zip_symlink_entry_is_written_as_plain_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link.yml")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    serve(monkeypatch, lambda r: httpx.Response(200, content=buf.getvalue()))
    sync_http(SourceConfig(name="zl", type="http", url="https://example.org/x.zip"), ws)
    link = ws.source_dir("zl") / "link.yml"
    assert link.is_file() and not link.is_symlink() and link.read_text() == "/etc/passwd"


def test_oversized_members_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_mod, "MAX_FILE_BYTES", 1000)
    ws = ws_for(tmp_path)
    members = {"small.yml": rule("a"), "big.yml": b"x" * 5000}
    for name, body in (("a.zip", zip_bytes(members)), ("a.tar", tar_bytes(members, mode="w"))):
        serve(monkeypatch, ok(body))
        res = sync_http(SourceConfig(name="o", type="http", url=f"https://example.org/{name}"), ws)
        assert (ws.source_dir("o") / "small.yml").read_bytes() == rule("a") and "big.yml" not in res.added
        assert not (ws.source_dir("o") / "big.yml").exists(), name


def test_zip_header_lying_about_size_cannot_write_more(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A member that declares a small size but holds more data: never more than the declared bytes are written."""
    monkeypatch.setattr(sync_mod, "MAX_FILE_BYTES", 1000)
    ws = ws_for(tmp_path)
    big = b"A" * 50_000
    raw = bytearray(zip_bytes({"lie.yml": big}))
    size = len(big).to_bytes(4, "little")
    small = (100).to_bytes(4, "little")
    assert raw.count(size) == 2  # local header and central directory record
    raw = bytearray(bytes(raw).replace(size, small))
    serve(monkeypatch, lambda r: httpx.Response(200, content=bytes(raw)))
    with contextlib.suppress(zipfile.BadZipFile, SyncError):  # failing cleanly is fine
        sync_http(SourceConfig(name="lie", type="http", url="https://example.org/x.zip"), ws)
    written = [p.stat().st_size for p in ws.corpus.rglob("*") if p.is_file()]
    assert all(n <= 1000 for n in written)


def test_decompression_bomb_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_mod, "MAX_EXTRACTED_BYTES", 100_000)
    ws = ws_for(tmp_path)
    members = {f"f{i}.yml": b"0" * 40_000 for i in range(5)}  # 200 kB that compresses to almost nothing
    body = zip_bytes(members)
    assert len(body) < 5_000
    serve(monkeypatch, lambda r: httpx.Response(200, content=body))
    with pytest.raises(SyncError, match="size limit"):
        sync_http(SourceConfig(name="bomb", type="http", url="https://example.org/bomb.zip"), ws)
    assert not ws.source_dir("bomb").exists()


def test_download_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_mod, "MAX_DOWNLOAD_BYTES", 1000)
    serve(monkeypatch, lambda r: httpx.Response(200, content=b"x" * 5000))
    with pytest.raises(SyncError, match="download larger"):
        sync_http(SourceConfig(name="d", type="http", url="https://example.org/a.yml"), ws_for(tmp_path))


def test_single_file_token_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    monkeypatch.setenv("RULES_TOKEN", "s3cret")
    seen = serve(monkeypatch, lambda r: httpx.Response(200, content=rule("a")))
    res = sync_http(SourceConfig(name="f", type="http", url="https://example.org/path/Rule.YML", auth="RULES_TOKEN"), ws)
    assert res.added == {"rule.yml"}  # the URL is lower-cased for type detection, the file keeps that name
    assert seen[0].headers["authorization"] == "Bearer s3cret"
    with pytest.raises(SyncError, match="http"):
        sync_http(SourceConfig(name="f2", type="http", url="ftp://example.org/a.zip"), ws)
    seen.clear()
    with pytest.raises(SyncError, match="plain http"):
        sync_http(SourceConfig(name="f4", type="http", url="http://example.org/a.yml", auth="RULES_TOKEN"), ws)
    assert seen == []  # the token never left the process
    serve(monkeypatch, lambda r: httpx.Response(404))
    with pytest.raises(httpx.HTTPStatusError):
        sync_http(SourceConfig(name="f3", type="http", url="https://example.org/missing.zip"), ws)


def test_sync_all_with_http_source_and_a_failing_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws = ws_for(tmp_path)
    local = tmp_path / "local"
    local.mkdir()
    (local / "l.yml").write_bytes(rule("l", 4))
    save_sources(
        ws,
        [
            SourceConfig(name="web", type="http", url="https://example.org/r.zip", licence="MIT"),
            SourceConfig(name="down", type="http", url="https://down.example.org/r.zip"),
            SourceConfig(name="disk", type="local", url=str(local)),
        ],
    )
    body = zip_bytes({"rules/a.yml": rule("a"), "rules/b.yml": rule("b", 2), "notes.txt": b"hello"})
    serve(monkeypatch, lambda r: httpx.Response(503) if r.url.host.startswith("down") else httpx.Response(200, content=body))
    open_db(ws, migrate=True)
    out = {o.name: o for o in sync_all(ws, workers=2)}
    assert out["web"].status == "ok" and out["disk"].status == "ok"
    assert out["down"].status == "error" and "503" in out["down"].message
    with open_db(ws, migrate=True)() as s:
        assert sorted(str(v.title) for v in s.scalars(select(RuleVersion))) == ["Test a", "Test b", "Test l"]
        failed = s.scalars(select(SyncLog).where(SyncLog.status == "error")).all()
        assert len(failed) == 1 and failed[0].error and "HTTPStatusError" in failed[0].error


def test_git_input_checks_auth_headers_and_path_selection() -> None:
    for url in ("--upload-pack=x", "ext::sh -c x", "relative/path", "http://plain.example/repo"):
        with pytest.raises(SyncError, match="refusing git url"):
            _check_git_inputs(url, None)
    for ref in ("-x", "a..b", "bad ref", "x" * 201):
        with pytest.raises(SyncError, match="refusing git ref"):
            _check_git_inputs("https://github.com/a/b", ref)
    _check_git_inputs("/abs/path", "v1.2/main")
    assert _auth_header("t", "https://gitlab.com/g/p.git").startswith("Authorization: Basic ")
    assert _auth_header("t", "https://gitlab.example.com/g/p.git").startswith("Authorization: Basic ")
    assert _auth_header("t", "https://github.com/a/b.git") == "Authorization: Bearer t"

    src = SourceConfig(name="p", type="local", url="/x", paths=["rules/*"], exclude=["rules/deprecated/*"])
    assert path_selected("rules/a.yml", src) and path_selected("rules/sub/a.yml", src)
    assert not path_selected("rules/deprecated/a.yml", src) and not path_selected("other/a.yml", src)
    res = SyncResult(None, "x", Path("/nonexistent"), added={"rules/a.yml", "other/b.yml"}, changed={"rules/deprecated/c.yml"})
    assert selected_files(res, src) == ["rules/a.yml"]
