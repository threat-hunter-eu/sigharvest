from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import sigharvest.discover as discover_mod
from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources
from sigharvest.discover import (
    STATUS_AUTO,
    STATUS_REJECTED,
    STATUS_REVIEW,
    Candidate,
    classify,
    confidence_score,
    count_rules,
    extract_repo_links,
    github_candidate,
    iter_blobs,
    merge_candidate,
    mirror_of,
    normalise_url,
    register_sources,
    sigma_paths,
    source_name,
    verify,
)

NOW = datetime(2026, 10, 26, tzinfo=UTC)

RULE = """title: Test {n}
id: 5f2b6c3e-0000-4000-8000-00000000000{n}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\evil{n}.exe'
  condition: selection
level: high
"""


@pytest.fixture(autouse=True)
def _no_disk_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI runners have little free disk; the low-disk clean-up must not delete test clones."""
    monkeypatch.setattr(discover_mod, "MIN_FREE_BYTES", 0)


# ------------------------------------------------------------------ URL normalisation and names


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/SigmaHQ/sigma",
        "https://github.com/SigmaHQ/sigma.git",
        "https://www.github.com/sigmahq/sigma/",
        "http://github.com/SigmaHQ/sigma/tree/master/rules",
        "git@github.com:SigmaHQ/sigma.git",
        "ssh://git@github.com/SigmaHQ/sigma.git",
        "github.com/SigmaHQ/sigma",
    ],
)
def test_normalise_url_github_variants(url: str) -> None:
    assert normalise_url(url) == "github.com/sigmahq/sigma"


def test_normalise_url_gitlab_keeps_subgroups() -> None:
    assert normalise_url("https://gitlab.com/Group/Sub/Proj.git") == "gitlab.com/group/sub/proj"
    assert normalise_url("https://gitlab.com/group/proj/-/tree/main") == "gitlab.com/group/proj"


def test_source_name_sanitising() -> None:
    assert source_name("SigmaHQ/sigma") == "sigmahq__sigma"
    assert source_name("tsale/Sigma_rules") == "tsale__sigma_rules"
    assert source_name("mthcht/ThreatHunting-Keywords-sigma-rules") == "mthcht__threathunting-keywords-sigma-rules"
    assert source_name("owner/repo.with.dots") == "owner__repo-with-dots"
    assert source_name("group/sub/proj") == "group__sub__proj"
    assert source_name("Ünï/çødé!") == "n__d"


# ------------------------------------------------------------------ awesome-list links


def test_extract_repo_links() -> None:
    text = """
    - [SigmaHQ](https://github.com/SigmaHQ/sigma) - main
    - https://github.com/SigmaHQ/sigma/tree/master/rules (dupe)
    - [x](https://github.com/joesecurity/sigma-rules.git).
    - <a href="https://github.com/topics/sigma">topic</a>
    - https://github.com/sponsors/someone
    - https://gitlab.com/group/sub/sigma-rules/-/tree/main
    - https://gitlab.com/explore/projects
    - https://github.com/orgs/foo/repositories
    """
    gh, gl = extract_repo_links(text)
    assert gh == ["SigmaHQ/sigma", "joesecurity/sigma-rules"]
    assert gl == ["group/sub/sigma-rules"]


# ------------------------------------------------------------------ merging


def test_merge_candidate_unions_strategies_and_fills_metadata() -> None:
    pool: dict[str, Candidate] = {}
    a = github_candidate("Foo/Bar", "code_search")
    a.code_hits = 2
    merge_candidate(pool, a)
    b = github_candidate("foo/bar", "topic")
    b.code_hits = 1
    b.stars = 42
    b.licence = "MIT"
    merged = merge_candidate(pool, b)
    c = github_candidate("foo/bar", "code_search")
    c.code_hits = 1
    merge_candidate(pool, c)
    assert len(pool) == 1 and merged is a
    assert a.strategies == ["code_search", "topic"]
    assert a.code_hits == 4
    assert a.stars == 42 and a.licence == "MIT"


# ------------------------------------------------------------------ scoring and classification


def _cand(**kw: object) -> Candidate:
    c = github_candidate("o/r", "code_search")
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_confidence_zero_without_rules() -> None:
    assert confidence_score(_cand(valid_rule_count=0, licence="MIT"), NOW) == 0.0


def test_confidence_full_marks() -> None:
    c = _cand(
        valid_rule_count=500,
        rule_files=100,
        yaml_files=100,
        strategies=["code_search", "topic", "awesome_list"],
        licence="MIT",
        pushed_at=(NOW - timedelta(days=10)).isoformat(),
    )
    assert confidence_score(c, NOW) == 1.0


def test_confidence_components() -> None:
    # 9 rules -> volume 0.5; purity 0.5; one strategy; no licence; pushed 2 years ago -> activity 0.5
    c = _cand(valid_rule_count=9, rule_files=5, yaml_files=10, pushed_at=(NOW - timedelta(days=730)).isoformat())
    assert confidence_score(c, NOW) == pytest.approx(0.45 * 0.5 + 0.2 * 0.5 + 0.15 * 0.5, abs=1e-3)
    c.host = "gitlab"
    assert confidence_score(c, NOW) == pytest.approx((0.45 * 0.5 + 0.2 * 0.5 + 0.15 * 0.5) * 0.85, abs=1e-3)


def test_confidence_monotonic_in_rules() -> None:
    lo = _cand(valid_rule_count=3, rule_files=3, yaml_files=3)
    hi = _cand(valid_rule_count=60, rule_files=60, yaml_files=60)
    assert confidence_score(hi, NOW) > confidence_score(lo, NOW)


def test_classify() -> None:
    c = _cand(verified=True, valid_rule_count=5)
    classify(c, 5)
    assert c.status == STATUS_AUTO
    c = _cand(verified=True, valid_rule_count=2)
    classify(c, 5)
    assert c.status == STATUS_REVIEW and "threshold" in (c.reason or "")
    c = _cand(verified=True, valid_rule_count=0)
    classify(c, 5)
    assert c.status == STATUS_REJECTED
    c = _cand(verified=False, reason="not found (deleted)")
    classify(c, 5)
    assert c.status == STATUS_REJECTED
    c = _cand(verified=False)
    classify(c, 5)
    assert c.status == STATUS_REVIEW


def test_sigma_paths() -> None:
    assert sigma_paths(["rules/windows/a.yml", "rules/linux/b.yml"]) == ["rules/*"]
    assert sigma_paths(["detections/sigma/a.yml", "detections/sigma/x/b.yml", "other/c.yml"]) == ["detections/sigma/*", "other/*"]
    assert sigma_paths(["a.yml", "rules/b.yml"]) == ["**/*"]
    assert sigma_paths([]) == ["**/*"]


# ------------------------------------------------------------------ counting on a real local git repo


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def sigma_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "src"
    (repo / "rules" / "windows").mkdir(parents=True)
    (repo / "rules" / "windows" / "r1.yml").write_text(RULE.format(n=1))
    (repo / "rules" / "windows" / "r2.yaml").write_text(RULE.format(n=2))
    # Sigma content with a non-YAML extension and two documents in one file.
    (repo / "rules" / "multi.txt").write_text(RULE.format(n=3) + "---\n" + RULE.format(n=4))
    # Not Sigma: YAML config, broken YAML, detection without logsource, a binary file.
    (repo / "config.yml").write_text("name: x\nvalues: [1, 2]\n")
    (repo / "rules" / "broken.yml").write_text("title: broken\ndetection: [\n")
    (repo / "rules" / "nolog.yml").write_text("title: x\ndetection:\n  sel: {a: 1}\n  condition: sel\n")
    (repo / "blob.bin").write_bytes(bytes(range(256)) * 4)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")
    return repo


def test_count_rules_on_local_repo(sigma_repo: Path, tmp_path: Path) -> None:
    cand = Candidate(url=f"file://{sigma_repo}", full_name="local/sigma")
    out, logic = verify(cand, tmp_path / "clones", references=None)
    assert out.verified, out.reason
    assert out.valid_rule_count == 4
    assert out.rule_files == 3
    assert out.unique_logic == 4 and len(logic) == 4
    assert out.yaml_files == 6  # five .yml/.yaml files plus multi.txt detected by content
    assert out.sigma_paths == ["rules/*"]
    assert (tmp_path / "clones" / "local__sigma").exists()  # kept: it has rules


def test_verify_marks_mirror_and_deletes_empty(sigma_repo: Path, tmp_path: Path) -> None:
    clones = tmp_path / "clones"
    _, logic = verify(Candidate(url=f"file://{sigma_repo}", full_name="a/a"), clones, None)
    mirror, _ = verify(Candidate(url=f"file://{sigma_repo}", full_name="b/b"), clones, {"SigmaHQ/sigma": logic})
    assert mirror.sigmahq_overlap == 1.0 and mirror.reference_overlap == 1.0 and mirror.mirror_of == "SigmaHQ/sigma"
    # Second verification of the same repo reuses the up-to-date clone.
    again, _ = verify(Candidate(url=f"file://{sigma_repo}", full_name="b/b"), clones, None)
    assert again.valid_rule_count == 4 and again.mirror_of is None

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.md").write_text("nothing here\n")
    _git(empty, "init", "-q", "-b", "main")
    _git(empty, "add", ".")
    _git(empty, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")
    res, _ = verify(Candidate(url=f"file://{empty}", full_name="e/e"), clones, None)
    assert res.verified and res.valid_rule_count == 0
    assert not (clones / "e__e").exists()


def test_verify_refuses_unsafe_url(tmp_path: Path) -> None:
    res, _ = verify(Candidate(url="-uhttps://evil", full_name="x/y"), tmp_path, None)
    assert not res.verified and "refusing" in (res.reason or "")


def test_count_rules_skips_garbage() -> None:
    blobs = [(["a.yml"], b"\xff\xfe detection: \x00"), (["b.yml"], RULE.format(n=5).encode())]
    out = count_rules(blobs)
    assert out.valid_rule_count == 1 and out.yaml_files == 2


def test_iter_blobs_reads_all_paths(sigma_repo: Path, tmp_path: Path) -> None:
    clones = tmp_path / "c"
    verify(Candidate(url=f"file://{sigma_repo}", full_name="x/x"), clones, None)
    paths = sorted(p for ps, _ in iter_blobs(clones / "x__x") for p in ps)
    assert "rules/windows/r1.yml" in paths and "blob.bin" in paths


# ------------------------------------------------------------------ sources.yaml registration


def test_register_sources_no_duplicates_and_priorities(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    save_sources(ws, [SourceConfig(name="sigmahq", type="git", url="https://github.com/SigmaHQ/sigma.git", priority=10)])

    def verified(fn: str, n: int, *, seed: bool = False) -> Candidate:
        c = github_candidate(fn, "seed" if seed else "code_search")
        c.verified, c.valid_rule_count, c.seed, c.sigma_paths, c.licence = True, n, seed, ["rules/*"], "MIT"
        classify(c, 5)
        return c

    cands = [
        verified("sigmahq/sigma", 3000, seed=True),
        verified("Some-Org/Sigma.Rules", 12),
        verified("seed/rules", 3, seed=True),  # below threshold but forced (seed)
        verified("tiny/repo", 2),  # below threshold, not forced
    ]
    added = register_sources(ws, cands, force={cands[2].key}, auto_add=True, today="2026-10-26")
    assert added == ["some-org__sigma-rules", "seed__rules"]
    srcs = {s.name: s for s in load_sources(ws)}
    assert set(srcs) == {"sigmahq", "some-org__sigma-rules", "seed__rules"}
    assert srcs["sigmahq"].priority == 10
    assert srcs["some-org__sigma-rules"].priority == 50 and srcs["some-org__sigma-rules"].paths == ["rules/*"]
    assert srcs["seed__rules"].priority == 20 and srcs["seed__rules"].licence == "MIT"
    assert cands[0].source == "sigmahq"
    # Second run is idempotent.
    assert register_sources(ws, cands, force={cands[2].key}, auto_add=True, today="2026-10-26") == []
    assert len(load_sources(ws)) == 3


def test_verify_empty_repository(tmp_path: Path) -> None:
    empty = tmp_path / "bare.git"
    _git(tmp_path, "init", "-q", "--bare", str(empty))
    res, _ = verify(Candidate(url=f"file://{empty}", full_name="z/z"), tmp_path / "clones", None)
    assert res.verified and res.valid_rule_count == 0 and res.reason == "empty repository"
    classify(res, 5)
    assert res.status == STATUS_REJECTED and res.reason == "empty repository"


def test_mirror_of_union_of_references() -> None:
    sig = {f"s{i}" for i in range(10)}
    hay = {f"h{i}" for i in range(10)}
    assert mirror_of(set(), {"SigmaHQ/sigma": sig}) == (None, None)
    # Half SigmaHQ, half hayabusa: a mirror of the union, labelled with both, largest first.
    logic = {"s1", "s2", "s3", "h1", "h2", "h3", "h4"}
    assert mirror_of(logic, {"SigmaHQ/sigma": sig, "Yamato-Security/hayabusa-rules": hay}) == (1.0, "Yamato-Security/hayabusa-rules + SigmaHQ/sigma")
    overlap, label = mirror_of({"s1", "x1", "x2"}, {"SigmaHQ/sigma": sig})
    assert overlap == pytest.approx(0.333) and label is None
