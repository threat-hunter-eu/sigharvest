"""scripts/privacy_gate.py: commit-scoped allowlist entries match exactly the commits they name."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _gate():
    spec = importlib.util.spec_from_file_location("privacy_gate", ROOT / "scripts" / "privacy_gate.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["privacy_gate"] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


gate = _gate()
SHA = "0e6ca78def0123456789abcdef0123456789abcd"


def _author(sha: str = SHA) -> object:
    return gate.Finding("email-commit-author", "email", gate.BLOCK, f"commit:{sha[:10]}:<author>", 0, "author x", "commits", raw_line="x@corp.example",
                        commit=sha)  # fmt: skip


def _entries(tmp_path: Path, *lines: str) -> list:
    path = tmp_path / "allow.txt"
    path.write_text("".join(f"{line} -- reason\n" for line in lines), encoding="utf-8")
    return gate.load_allowlist(path)


@pytest.mark.parametrize(
    "glob", ["commit:0e6ca78*", "commit:0e6ca78def*", "commit:0e6ca78def:*", "commit:0e6ca78def", f"commit:{SHA}", f"commit:{SHA}:<author>"]
)
def test_commit_entries_match_their_commit_in_every_spelling(tmp_path: Path, glob: str) -> None:
    (entry,) = _entries(tmp_path, f"{glob} email-commit-author")
    assert entry.matches(_author())
    assert not entry.matches(_author("1" * 40))


def test_commit_entries_never_match_tree_or_blob_findings(tmp_path: Path) -> None:
    (entry,) = _entries(tmp_path, "commit:0e6ca78def* *")
    tree = gate.Finding("email-real", "email", gate.BLOCK, "docs/a.md", 1, "x", "tree")
    blob = gate.Finding("file-binary", "file", gate.WARN, "blob:0e6ca78def:docs/a.bin", 0, "x", "history")
    assert not entry.matches(tree)
    assert not entry.matches(blob)


def test_commit_entry_with_a_path_glob_is_limited_to_that_path(tmp_path: Path) -> None:
    (entry,) = _entries(tmp_path, "commit:0e6ca78def:docs/* email-real")
    inside = gate.Finding("email-real", "email", gate.BLOCK, "commit:0e6ca78def:docs/a.md", 1, "x", "history", commit=SHA)
    outside = gate.Finding("email-real", "email", gate.BLOCK, "commit:0e6ca78def:src/a.py", 1, "x", "history", commit=SHA)
    assert entry.matches(inside)
    assert not entry.matches(outside)


@pytest.mark.parametrize("glob", ["commit:0e6c*", "commit:xyz*", f"commit:{SHA}0"])
def test_too_short_or_invalid_commit_entries_are_refused(tmp_path: Path, glob: str) -> None:
    with pytest.raises(SystemExit):
        _entries(tmp_path, f"{glob} email-commit-author")


def test_history_scan_honours_a_commit_entry_for_the_author_identity(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout

    git("init", "-q")
    git("config", "user.name", "Someone")
    git("config", "user.email", "someone" + "@" + "acme-widgets" + ".com")  # built at run time: the tree scan must not see it
    git("config", "commit.gpgsign", "false")
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    git("add", "a.txt")
    git("commit", "-qm", "first")
    git("config", "user.email", "someone@users.noreply.github.com")
    (repo / "a.txt").write_text("y\n", encoding="utf-8")
    git("commit", "-qam", "second")
    first = git("rev-list", "--max-parents=0", "HEAD").strip()
    findings = [f for f in gate.scan_commit_identities(repo) if f.rule == "email-commit-author"]
    assert {f.commit for f in findings} == {first}
    entries = _entries(tmp_path, f"commit:{first[:12]}* email-commit-author")
    assert all(any(e.matches(f) for e in entries) for f in findings)


def test_terms_rules_are_reported_without_their_id_or_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    for name in gate.TERMS_ENVS:
        monkeypatch.delenv(name, raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "notes.txt").write_text("mentions the zorbex platform\n", encoding="utf-8")
    assert gate.run([str(repo), "--gitleaks", "off"]) == 0
    assert "sensitive terms: NOT loaded" in capsys.readouterr().out
    terms = tmp_path / "terms.txt"
    terms.write_text("# comment\nplatform-name block url=warn re:\\bzorbex\\b\n", encoding="utf-8")
    monkeypatch.setenv("SIGHARVEST_PRIVACY_TERMS", str(terms))
    assert gate.run([str(repo), "--gitleaks", "off"]) == 1
    out = capsys.readouterr().out
    assert "sensitive-term" in out
    assert "platform-name" not in out and "zorbex" not in out
    assert gate.run([str(repo), "--gitleaks", "off", "--show-sensitive"]) == 1
    out = capsys.readouterr().out
    assert "platform-name" in out and "zorbex" in out


# SHA-256 of scripts/privacy_gate.py. The script is a shared file: it must stay byte-identical in sigharvest and
# suriharvest (each repo keeps its own .github/privacy-allowlist.txt; the sensitive terms live outside both).
GATE_SHA256 = "18a5915dc0c6318f2a1eafe515829d73e5cc94c05c52ea52e2f4b90e91438c5f"


def test_gate_is_the_shared_copy() -> None:
    """scripts/privacy_gate.py is byte-identical in sigharvest and suriharvest.

    To change it: edit the script in one repo, copy the same bytes to scripts/privacy_gate.py of the other repo,
    run `sha256sum scripts/privacy_gate.py` and put the new hash in GATE_SHA256 of tests/test_privacy_gate.py in
    BOTH repos (same commit message in each). CRLF is normalised to LF so a Windows checkout gives the same hash.
    """
    path = Path(__file__).resolve().parents[1] / "scripts" / "privacy_gate.py"
    data = path.read_bytes().replace(b"\r\n", b"\n")
    assert data.splitlines()[1].startswith(b"# shared file; keep identical in sigharvest and suriharvest")
    assert hashlib.sha256(data).hexdigest() == GATE_SHA256, "privacy_gate.py changed: update it in both repos (see this docstring)"
