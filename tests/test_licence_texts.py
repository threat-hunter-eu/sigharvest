"""Licence obligations: licence texts, upstream copyright and NOTICE files, ATT&CK terms, modification and DRL
origin marks travel with redistributed rules."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from sigharvest import licence_texts, release
from sigharvest.export_policy import DRL_NOTE, MODIFIED_NOTE, attribution_markdown, licence_notes
from sigharvest.index import rebuild
from sigharvest.licensing import current_spdx
from sigharvest.service import open_db, sync_all
from tests.helpers import set_licence
from tests.test_pipeline import commit, make_repo, workspace

MIT = "MIT License\n\nCopyright (c) 2022 Example Labs\n\nPermission is hereby granted, free of charge...\n"
NOTICE = "Example rules\nCopyright 2022 Example Labs\nThis product includes rules by the Example team.\n"


@pytest.fixture
def ws(tmp_path: Path):  # type: ignore[no-untyped-def]
    repo = make_repo(tmp_path)
    (repo / "LICENSE").write_text(MIT)
    (repo / "NOTICE").write_text(NOTICE)
    (repo / "secrets.txt").write_text("not a licence file\n")
    (repo / "rules" / "LICENSE").write_text("nested: not copied\n")
    commit(repo, "licence files")
    workspace_ = workspace(tmp_path, repo)
    set_licence(workspace_, "MIT")
    assert sync_all(workspace_)[0].status == "ok"
    with open_db(workspace_)() as s:
        rebuild(s)
        s.commit()
    return workspace_


def test_sync_keeps_only_root_licence_files(ws) -> None:  # type: ignore[no-untyped-def]
    stored = licence_texts.licence_dir(ws, "local")
    assert sorted(p.name for p in stored.iterdir()) == ["LICENSE", "NOTICE"]
    assert (stored / "LICENSE").read_text() == MIT


def test_release_ships_licence_texts_copyright_and_notice(ws, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    with open_db(ws)() as s:
        release.build(s, tmp_path / "rel")
    rel = tmp_path / "rel"
    with zipfile.ZipFile(rel / "sigharvest-rules-permissive.zip") as zf:
        names = set(zf.namelist())
        assert {"LICENSES/MIT.txt", "LICENSES/local/LICENSE", "LICENSES/local/NOTICE", "LICENSES/INDEX.md"} <= names
        notice = zf.read("NOTICE.md").decode()
        assert "Copyright (c) 2022 Example Labs" in notice and "This product includes rules by the Example team." in notice
        index = zf.read("LICENSES/INDEX.md").decode()
        assert "[MIT](https://spdx.org/licenses/MIT.html)" in index and "Copyright (c) 2022 Example Labs" in index
    with zipfile.ZipFile(rel / "LICENSES.zip") as zf:
        assert {"LICENSES/MIT.txt", "LICENSES/local/LICENSE"} <= set(zf.namelist())
    top = (rel / "NOTICE.md").read_text()
    assert "LICENSES.zip" in top and "Copyright (c) 2022 Example Labs" in top
    assert "LICENSES.zip" in (rel / "SHA256SUMS").read_text()


def test_release_notice_carries_mitre_terms_when_attack_metadata_is_present(ws, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    with open_db(ws)() as s:
        release.build(s, tmp_path / "plain")
    assert "reproduced and distributed with the permission of The MITRE Corporation" not in (tmp_path / "plain" / "NOTICE.md").read_text()
    monkeypatch.setattr(release, "tag_metadata", lambda *a, **k: [{"id": "T1003", "name": "OS Credential Dumping"}])
    with open_db(ws)() as s:
        release.build(s, tmp_path / "attack")
    notice = (tmp_path / "attack" / "NOTICE.md").read_text()
    # The exact designation the ATT&CK terms of use ask for, the trademark notice and the terms.
    assert "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." in notice
    assert "MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation." in notice
    assert notice.count("attack.mitre.org/resources/legal-and-branding/terms-of-use") == 1


def test_export_zip_carries_licences(ws) -> None:  # type: ignore[no-untyped-def]
    from sigharvest.export_zip import write_zip
    from sigharvest.models import LogicGroup

    with open_db(ws)() as s:
        buf = io.BytesIO()
        write_zip(s, list(s.query(LogicGroup)), buf, "x")
    with zipfile.ZipFile(buf) as zf:
        names = set(zf.namelist())
        assert {"x/LICENSES/MIT.txt", "x/LICENSES/local/LICENSE", "x/LICENSES/INDEX.md"} <= names
        assert "Copyright (c) 2022 Example Labs" in zf.read("x/NOTICE.md").decode()


def test_modified_and_drl_origin_marks() -> None:
    entry = {"title": "T", "licence": "MIT", "rule_id": "u1", "yaml_representation": "effective", "source": "s", "author": "A"}
    notes = licence_notes(entry, {"u1"})
    assert notes == {"modified": MODIFIED_NOTE, "drl_origin": DRL_NOTE}
    assert licence_notes(entry | {"licence": "DRL-1.1", "yaml_representation": "source"}, {"u1"}) == {}
    table = attribution_markdown([entry | notes])
    assert "flattened from a multi-document collection" in table and "derived from a DRL-1.1 rule" in table
    assert "[MIT](https://spdx.org/licenses/MIT.html) + [DRL-1.1]" in table


def test_drl_text_is_bundled_and_deprecated_ids_are_current() -> None:
    assert licence_texts.text("DRL-1.1") and b"Detection Rule License" in (licence_texts.text("DRL-1.1") or b"")
    assert licence_texts.text("GPL-3.0") == licence_texts.text("GPL-3.0-only")
    assert licence_texts.link("LicenseRef-custom") is None
    assert licence_texts.spdx_ids("(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0") == ["MIT", "Apache-2.0", "GPL-2.0-only"]
    assert current_spdx("GPL-3.0") == "GPL-3.0-only" and current_spdx("MIT") == "MIT"
    assert licence_texts.copyright_lines([("LICENSE", b"Copyright (c) <year> <copyright holders>\nCopyright 2020 Real Co\n")]) == ["Copyright 2020 Real Co"]


def test_catalogs_use_current_spdx_ids() -> None:
    import re

    root = Path(__file__).resolve().parents[1]
    for path in [*root.glob("sources/*.yaml"), *root.glob("src/sigharvest/presets/*.yaml")]:
        deprecated = re.findall(r"^\s*licence: ((?:A|L)?GPL-[0-9.]+)\s*$", path.read_text(), re.M)
        assert not deprecated, (path.name, deprecated)


LICENCE_FILES = Path(__file__).parent / "fixtures" / "licence_files"


def test_licence_boilerplate_is_never_a_copyright_line() -> None:
    """The GPL and Apache LICENSE files as projects ship them (wrapped at 70-80 columns) and every bundled licence
    text: words such as "copyright on the Program" or "(c) You must retain" start lines, none is a statement."""
    files = [(f.name, f.read_bytes()) for f in sorted(LICENCE_FILES.iterdir())]
    assert {name for name, _ in files} == {"Apache-2.0-LICENSE", "GPL-2.0-COPYING", "GPL-3.0-LICENSE"}
    assert licence_texts.copyright_lines(files) == []
    for spdx in ("Apache-2.0", "GPL-2.0-only", "GPL-3.0-only", "LGPL-2.1-only", "MPL-2.0", "CC-BY-4.0", "CC-BY-SA-4.0", "MIT", "BSD-3-Clause"):
        assert licence_texts.copyright_lines([(spdx, licence_texts.text(spdx) or b"")]) == [], spdx
    # the project's own line above a standard licence text is kept, the licence text adds nothing
    apache = dict(files)["Apache-2.0-LICENSE"]
    project = b"Copyright 2023 Example Labs\n\n" + apache.replace(b"Copyright [yyyy] [name of copyright owner]", b"Copyright [2023] [Example Labs]")
    assert licence_texts.copyright_lines([("LICENSE", project)]) == ["Copyright 2023 Example Labs", "Copyright [2023] [Example Labs]"]


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        ("Copyright (c) 2022 Huntress Labs", True),
        ("Copyright © 2025, Okta, Inc.", True),
        ("Copyright (c) 2014-2018 ESET spol. s r.o.", True),
        ("© 2023 Example Ltd", True),
        ("(c) 2021 Example GmbH", True),
        ("COPYRIGHT 2019 Example Corp", True),
        ("Copyright 2021, by Jane Analyst", True),
        ("Copyright The Example Authors", True),
        ("copyright on the Program, and are irrevocable provided the stated", False),
        ("copyright notice that is included in or attached to the work", False),
        ("(c) You must retain, in the Source form of any Derivative Works", False),
        ("copyright and certain other rights. Our licenses are", False),
        ("Copyright (C) 1989, 1991 Free Software Foundation, Inc.", False),
        ("Copyright (C) year name of author", False),
        ("Copyright notice", False),
        ("Copyright (c) <year> <copyright holders>", False),
    ],
)
def test_copyright_statement(line: str, kept: bool) -> None:
    assert licence_texts.copyright_statement(line) is kept


@pytest.fixture
def bare_ws(tmp_path: Path):  # type: ignore[no-untyped-def]
    """A synced source with no licence file of its own: only bundled texts can travel with its rules."""
    repo = make_repo(tmp_path)
    workspace_ = workspace(tmp_path, repo)
    assert sync_all(workspace_)[0].status == "ok"
    with open_db(workspace_)() as s:
        rebuild(s)
        s.commit()
    return workspace_


@pytest.mark.parametrize(
    ("licence", "texts"),
    [
        ("AGPL-3.0-only", {"AGPL-3.0-only"}),
        ("AGPL-3.0-or-later", {"AGPL-3.0-only"}),
        ("LGPL-3.0-only", {"LGPL-3.0-only", "GPL-3.0-only"}),
        ("EUPL-1.2", {"EUPL-1.2"}),
    ],
)
def test_copyleft_pack_ships_the_licence_text_without_an_upstream_file(bare_ws, tmp_path: Path, licence: str, texts: set[str]) -> None:  # type: ignore[no-untyped-def]
    set_licence(bare_ws, licence)
    with open_db(bare_ws)() as s:
        release.build(s, tmp_path / "rel")
    with zipfile.ZipFile(tmp_path / "rel" / "sigharvest-rules-copyleft.zip") as zf:
        names = set(zf.namelist())
    assert {f"LICENSES/{t}.txt" for t in texts} <= names
    assert not any(n.startswith("LICENSES/local/") for n in names)


@pytest.mark.parametrize("order", [1, -1])
def test_every_licence_of_a_source_ships_with_its_text_and_notice(ws, order: int) -> None:  # type: ignore[no-untyped-def]
    """Credits are per rule and a rule may be narrower than its source (export.effective_licence): one source, two licences."""
    from sigharvest.licence_texts import for_credits

    credits = [{"source": "local", "licence": "MIT"}, {"source": "local", "licence": "GPL-3.0-only"}][::order]
    with open_db(ws)() as s:
        notice, files = for_credits(s, credits)
    names = {name for name, _ in files}
    assert {"LICENSES/MIT.txt", "LICENSES/GPL-3.0-only.txt"} <= names
    assert "MIT" in notice and "GPL-3.0-only" in notice
    index = dict(files)["LICENSES/INDEX.md"].decode()
    assert "MIT" in index and "GPL-3.0-only" in index
    assert (notice, files) == for_credits_once(ws, credits[::-1])  # the order of the credits does not matter


def for_credits_once(ws, credits):  # type: ignore[no-untyped-def]
    from sigharvest.licence_texts import for_credits

    with open_db(ws)() as s:
        return for_credits(s, credits)


def test_a_free_text_licence_next_to_an_spdx_id_is_reduced_to_its_id() -> None:
    """A rule's own `license:` text ("CC BY-SA 4.0") is only recognised as a whole, so it must not be joined raw."""
    from sigharvest.licence_texts import licence_ids, missing_texts, shipped_licences

    credits = [{"source": "acme", "licence": "MIT"}, {"source": "acme", "licence": "CC BY-SA 4.0"}]
    shipped = shipped_licences(credits)
    assert shipped == shipped_licences(credits[::-1])
    assert licence_ids(shipped["acme"]) == ["CC-BY-SA-4.0", "MIT"]
    assert missing_texts(None, shipped) == []


def test_a_licence_expression_is_parenthesised_when_joined_with_another() -> None:
    from sigharvest.licence_texts import licence_ids, shipped_licences

    shipped = shipped_licences([{"source": "acme", "licence": "MIT OR Apache-2.0"}, {"source": "acme", "licence": "GPL-3.0-only"}])
    assert shipped["acme"] == "(MIT OR Apache-2.0) AND GPL-3.0-only"
    assert licence_ids(shipped["acme"]) == ["MIT", "Apache-2.0", "GPL-3.0-only"]


def test_a_source_with_one_licence_keeps_it_as_stated() -> None:
    from sigharvest.licence_texts import shipped_licences

    for stated in ("MIT", "CC BY-SA 4.0", "MIT OR Apache-2.0"):
        assert shipped_licences([{"source": "acme", "licence": stated}, {"source": "acme", "licence": stated}]) == {"acme": stated}


def test_free_text_licence_ships_its_text_with_an_spdx_one(ws) -> None:  # type: ignore[no-untyped-def]
    credits = [{"source": "local", "licence": "MIT"}, {"source": "local", "licence": "CC BY-SA 4.0"}]
    notice, files = for_credits_once(ws, credits)
    names = {name for name, _ in files}
    assert {"LICENSES/MIT.txt", "LICENSES/CC-BY-SA-4.0.txt"} <= names
    assert "CC-BY-SA-4.0" in notice


def test_licences_zip_keeps_the_licences_of_both_zips(tmp_path: Path) -> None:
    """The top-level LICENSES.zip covers both packs: the copyleft pack must not replace the permissive licence of a source."""
    builder = release._Extras.__new__(release._Extras)
    builder.ws, builder.configs, builder.out = None, {}, tmp_path
    builder.credits = {"permissive": [{"source": "acme", "licence": "MIT"}], "copyleft": [{"source": "acme", "licence": "GPL-3.0-only"}]}
    builder.licences_zip()
    with zipfile.ZipFile(tmp_path / "LICENSES.zip") as zf:
        names = set(zf.namelist())
    assert {"LICENSES/MIT.txt", "LICENSES/GPL-3.0-only.txt", "LICENSES/INDEX.md"} <= names


def test_release_refuses_a_pack_whose_licence_text_is_not_shipped(bare_ws, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    set_licence(bare_ws, "BSD-3-Clause-Clear")  # permissive (bsd-*), no bundled text, no upstream LICENSE
    with open_db(bare_ws)() as s, pytest.raises(release.PublicationError, match="local: BSD-3-Clause-Clear"):
        release.build(s, tmp_path / "rel")


def test_upstream_licence_file_satisfies_the_guard(ws) -> None:  # type: ignore[no-untyped-def]
    assert licence_texts.missing_texts(ws, {"local": "BSD-3-Clause-Clear"}) == []
    assert licence_texts.missing_texts(None, {"x": "BSD-3-Clause-Clear"}) == ["x: BSD-3-Clause-Clear"]
    assert licence_texts.missing_texts(None, {"x": "Detection Rule License 1.1", "y": "GPLv3", "z": None}) == []


def test_every_redistributable_catalogue_licence_has_a_bundled_text() -> None:
    """Build-time check on the catalogues: any permissive or copyleft licence a source states has its text bundled."""
    import re

    from sigharvest.licensing import licence_class

    root = Path(__file__).resolve().parents[1]
    missing = set()
    for path in [*root.glob("sources/*.yaml"), *root.glob("src/sigharvest/presets/*.yaml")]:
        for lic in re.findall(r"^\s*licence: (\S.*?)\s*$", path.read_text(), re.M):
            lic = lic.strip("'\"")
            if lic != "null" and licence_class(lic) in ("permissive", "copyleft"):
                missing |= {i for i in licence_texts.licence_ids(lic) if licence_texts.text(i) is None}
    assert not missing, sorted(missing)


@pytest.mark.parametrize("expression", ["x\\1", "MIT OR a\\q", "a\\n"])
def test_linked_inserts_rule_licence_ids_literally(expression):
    # A rule's `license:` is third-party text: a backslash in it must not be read as a re.sub template.
    out = licence_texts.linked(expression)
    for i in licence_texts.spdx_ids(expression):
        assert f"[{i}](" in out
