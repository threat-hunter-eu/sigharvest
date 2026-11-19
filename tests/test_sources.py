import pytest

from sigharvest.sources import file_link, is_well_known


def test_well_known_sources_are_found_by_url() -> None:
    for url in ("https://github.com/SigmaHQ/sigma", "https://github.com/sigmahq/sigma.git", "https://github.com/SigmaHQ/sigma/"):
        assert is_well_known(url, "sigmahq")
    assert not is_well_known("https://github.com/someone/sigma", "sigmahq")
    assert is_well_known("https://github.com/Yamato-Security/hayabusa-rules.git", "hayabusa")


def test_file_links_only_for_github_and_gitlab() -> None:
    assert file_link("https://github.com/a/b.git", "abc", "rules/x.yml") == "https://github.com/a/b/blob/abc/rules/x.yml"
    assert file_link("https://gitlab.com/a/b", None, "x.yml") == "https://gitlab.com/a/b/-/blob/HEAD/x.yml"
    assert file_link("file:///tmp/repo", "abc", "x.yml") is None
    # The host decides the link style, not a "gitlab.com" substring elsewhere in the URL.
    assert file_link("https://github.com/gitlab.com/b", "abc", "x.yml") == "https://github.com/gitlab.com/b/blob/abc/x.yml"
    assert file_link("https://gitlab.com/a/b.git", "abc", "x.yml") == "https://gitlab.com/a/b/-/blob/abc/x.yml"


def test_source_config_defaults_and_unknown_keys(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import pytest
    import yaml

    from sigharvest.config import SourceConfig, Workspace, load_sources, read_sources_file, save_sources

    cfg = SourceConfig.from_dict({"name": "r", "url": "https://github.com/a/b.git", "redistributable": True, "tier": "curated", "stars": 3})
    assert cfg.type == "git" and cfg.redistributable is True and cfg.tier == "curated"
    assert "type" not in cfg.to_dict() and "stars" not in cfg.to_dict()
    ws = Workspace(tmp_path / "ws")
    save_sources(ws, [cfg])
    assert load_sources(ws) == [cfg]
    with pytest.raises(ValueError, match="environment variable"):
        SourceConfig(name="x", url="u", auth="not a name")
    dupes = tmp_path / "dupes.yaml"
    dupes.write_text(yaml.safe_dump({"sources": [{"name": "a", "url": "u"}, {"name": "a", "url": "v"}]}))
    with pytest.raises(ValueError, match="duplicate"):
        read_sources_file(dupes)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("no", False),
        ("False", False),
        ("NO", False),
        ("0", False),
        ("yes", True),
        ("True", True),
        ("unknown", "unknown"),
        ("maybe", "unknown"),
        (None, None),
        (False, False),
    ],
)
def test_redistributable_strings_are_normalised_fail_closed(value, expected) -> None:
    from sigharvest.config import SourceConfig

    assert SourceConfig(name="x", url="https://example.org/x.git", redistributable=value).redistributable == expected


def test_priority_zero_survives_a_save_and_load(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from sigharvest.config import SourceConfig, Workspace, load_sources, save_sources

    ws = Workspace(tmp_path / "ws")
    cfg = SourceConfig(name="first", url="https://github.com/a/b.git", priority=0)
    assert cfg.to_dict()["priority"] == 0
    save_sources(ws, [cfg])
    assert load_sources(ws)[0].priority == 0


def test_file_link_percent_encodes_untrusted_paths_and_commits() -> None:
    # A file name from a source repository must not end the link or add Markdown where the link is written.
    hostile = "rules/x>\n\n[Updated rule pack](https://attacker.example)\n<.yml"
    link = file_link("https://github.com/a/b.git", "abc", hostile)
    assert link is not None and link.startswith("https://github.com/a/b/blob/abc/rules/")
    assert not any(c in link for c in "\n <>[]()")
    assert file_link("https://github.com/a/b", "a/b c", "my rule.yml") == "https://github.com/a/b/blob/a%2Fb%20c/my%20rule.yml"
    assert file_link("https://github.com/a/b", None, "bad\udcffname.yml") == "https://github.com/a/b/blob/HEAD/bad%3Fname.yml"
