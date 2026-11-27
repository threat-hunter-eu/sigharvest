"""Static site: layout, licence policy, escaping of hostile rule text (static HTML and browser-rendered JSON), embed."""

from __future__ import annotations

import gzip
import json
import re
import shutil
import subprocess
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from sigharvest import collections as col
from sigharvest.models import LogicGroup
from sigharvest.release import build as build_release
from sigharvest.site import SiteError, build_site, collections_snapshot, site_command, tokens
from sigharvest.site.build import HERE, licence_links, safe_url, shard_key, source_quality
from tests.helpers import reseal, set_licence
from tests.test_collections import _setup

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'&"
NODE = shutil.which("node")


def _rows(folder: Path) -> list[dict[str, object]]:
    with gzip.open(folder / "rules.jsonl.gz", "rt", encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


def _write_rows(folder: Path, rows: list[dict[str, object]]) -> None:
    with gzip.open(folder / "rules.jsonl.gz", "wt", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    reseal(folder)


def _release(tmp_path: Path, licence: str | None = None, name: str = "rel") -> tuple[Path, object]:
    _repo, ws, S = _setup(tmp_path)
    if licence:
        set_licence(ws, licence)
    with S() as s:
        c = col.create(s, "ransom note", "<b>bold</b> articles")
        col.add(s, c, [s.query(LogicGroup).filter(LogicGroup.title == "Test a").one()], note="<i>why</i>")
        s.commit()
        build_release(s, tmp_path / name)
        (tmp_path / name / "collections.json").write_text(json.dumps(collections_snapshot(s)))
    return tmp_path / name, ws


class _Tags(HTMLParser):
    """Real tags and attributes of a page: no event handlers, inline styles, inline scripts or unexpected elements."""

    def __init__(self) -> None:
        super().__init__()
        self.bad: list[str] = []
        self.in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = {k for k, _v in attrs}
        if tag in ("img", "iframe", "object", "embed", "form") and not (tag == "form" and dict(attrs).get("role") == "search"):
            self.bad.append(tag)
        if any(k.startswith("on") or k == "style" for k in names):
            self.bad.append(f"{tag} {sorted(names)}")
        if tag == "script":
            self.in_script = True
            if "src" not in names:
                self.bad.append("inline script")
        for k, v in attrs:
            if k in ("href", "src") and v and not v.startswith(("https://", "/")) and not v.startswith("#"):
                self.bad.append(f"{k}={v}")

    def handle_endtag(self, tag: str) -> None:
        self.in_script = False if tag == "script" else self.in_script

    def handle_data(self, data: str) -> None:
        if self.in_script and data.strip():
            self.bad.append("inline script body")


def _html_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.html"))


def test_tokens_and_keys() -> None:
    assert tokens("HackTool - Mimikatz Execution via cmd.exe") == {"hacktool", "mimikatz", "execution", "cmd.exe", "cmd", "exe"}
    assert tokens("t1059.001") == {"t1059.001", "t1059", "001"}
    assert shard_key("t1059.001") == "t10" and shard_key("powershell") == "po" and shard_key("t1") == "t1"
    assert safe_url("https://github.com/a/b") and safe_url("javascript:alert(1)") is None and safe_url('https://x/"><b>') is None


def test_site_from_workspace(tmp_path: Path) -> None:
    _rel, ws = _release(tmp_path)
    out = tmp_path / "site"
    st = build_site(ws.root, out, min_score=0)  # type: ignore[attr-defined]
    root = out / "rules"
    assert (out / ".sigharvest-site").exists()
    for rel in (
        "index.html",
        "rule.html",
        "404.html",
        "attribution.html",
        "ATTRIBUTION.md",
        "sitemap.xml",
        "data/meta.json",
        "data/attack.json",
        "static/embed.js",
        "static/site.css",
    ):
        assert (root / rel).is_file(), rel
    assert st.rules == 5 and st.pages == 5 and st.collections == 1
    meta = json.loads((root / "data/meta.json").read_text())
    assert meta["rules"] == 5 and meta["collections"] == [["ransom note", "ransom-note", 1]]
    assert len(list((root / "r").glob("*.html"))) == 5
    # unknown paths get the site's own 404 page (absolute links, not indexed); scrollable rule text is keyboard-reachable
    missing = (root / "404.html").read_text()
    assert 'name="robots" content="noindex"' in missing and 'href="/rules/"' in missing
    shown = [p.read_text() for p in (root / "r").glob("*.html")]
    assert all(p.count('tabindex="0"') == p.count("<pre ") for p in shown)
    assert not any("<aside" in p for p in shown)
    page = (root / "c/ransom-note.html").read_text()
    assert "&lt;b&gt;bold&lt;/b&gt;" in page and "&lt;i&gt;why&lt;/i&gt;" in page and "<b>bold" not in page
    sitemap = (root / "sitemap.xml").read_text()
    assert "https://example.org/rules/c/ransom-note.html" in sitemap and sitemap.count("<loc>") == 2 + 1 + 5
    # rebuilding replaces the folder; a foreign non-empty folder is refused
    build_site(ws.root, out, min_score=0, collections=[])  # type: ignore[attr-defined]
    assert not (root / "c").exists()
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "keep.txt").write_text("mine")
    with pytest.raises(SiteError):
        build_site(ws.root, tmp_path / "other")  # type: ignore[attr-defined]
    assert (tmp_path / "other" / "keep.txt").read_text() == "mine"


def test_licence_policy(tmp_path: Path) -> None:
    rel, _ws = _release(tmp_path)  # the fixture source states no licence
    out = build_site(rel, tmp_path / "s1", min_score=0).root / "rules"
    blobs = [p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file() and p.suffix in (".html", ".json")]
    assert not any("Image|endswith" in b or "detection:" in b for b in blobs)  # no rule text anywhere
    page = next((out / "r").glob("*.html")).read_text()
    assert "Text not redistributed" in page and "copy YAML" not in page
    details = [d for p in (out / "data/d").glob("*.json") for d in json.loads(p.read_text()).values()]
    assert details and all(d["yaml"] is None and d["yaml_note"] == "licence" and d["licence_class"] == "none" for d in details)

    rel2, _ = _release(tmp_path / "mit", licence="MIT")
    out2 = build_site(rel2, tmp_path / "s2", min_score=0).root / "rules"
    page = next((out2 / "r").glob("*.html")).read_text()
    assert "detection:" in page and "MIT" in page and "Text not redistributed" not in page
    assert json.loads((out2 / "data/meta.json").read_text())["facets"]["text"] == 5


def _hostile_release(tmp_path: Path) -> Path:
    rel, _ = _release(tmp_path, licence="MIT")
    rows = _rows(rel)
    for r in rows:
        r["title"] = HOSTILE + str(r["title"])
        r["description"] = HOSTILE
        r["author"] = HOSTILE
        r["licence"] = "MIT" + HOSTILE
        r["tags"] = [HOSTILE, "attack.t1059.001", "attack.execution"]
        r["sources"] = [HOSTILE, "local"]
        r["quality_flags"] = []
        r["canonical"] = {"source": HOSTILE, "path": HOSTILE, "commit": HOSTILE, "url": "javascript:alert(4)"}
        r["yaml"] = "title: x\n# </code></pre><script>alert(5)</script>\n"
        r["logsource"] = {"product": HOSTILE, "category": "process_creation", "service": None}
    _write_rows(rel, rows)
    m = json.loads((rel / "manifest.json").read_text())
    m["sources"].append({"name": HOSTILE, "url": "javascript:alert(6)", "licence": HOSTILE, "rules": 1, "commit": HOSTILE})
    (rel / "manifest.json").write_text(json.dumps(m))
    (rel / "collections.json").write_text(
        json.dumps({"collections": [{"name": "c1", "description": HOSTILE, "items": [{"logic_hash": rows[0]["logic_hash"], "note": HOSTILE}]}]})
    )
    reseal(rel)
    return rel


def test_hostile_text_is_neutralised_in_static_html_and_json(tmp_path: Path) -> None:
    rel = _hostile_release(tmp_path)
    root = build_site(rel, tmp_path / "site", min_score=0).root / "rules"
    for p in _html_files(root):
        text = p.read_text(encoding="utf-8")
        assert "<script>alert" not in text and "<img src=x" not in text, p
        assert "javascript:" not in text, p
        tags = _Tags()
        tags.feed(text)
        assert not tags.bad, (p, tags.bad)
    page = next((root / "r").glob("*.html")).read_text()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;alert(5)" in page
    # the embed snippet shown for copying never carries rule text
    snippet = re.search(r'id="embed-[0-9a-f]+"[^>]*><code>(.*?)</code>', page, re.S)
    assert snippet and "alert" not in snippet.group(1)
    for p in (root / "data").rglob("*.json"):
        raw = p.read_text(encoding="utf-8")
        assert "<" not in raw and ">" not in raw, p  # escaped as < / >
    details = [d for p in (root / "data/d").glob("*.json") for d in json.loads(p.read_text()).values()]
    assert all(d["title"].startswith(HOSTILE) and d["canonical"]["url"] is None for d in details)  # round-trips, bad link dropped
    for js in (HERE / "static").glob("*.js"):
        code = js.read_text()
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert bad not in code, (js.name, bad)


def _node(tmp_path: Path, root: Path, mode: str, arg: str) -> object:
    script = Path(__file__).parent / "site_dom.js"
    out = subprocess.run([NODE or "node", str(script), str(root), mode, arg], capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


def _walk(n: dict[str, object]) -> list[dict[str, object]]:
    out = [n]
    for c in n.get("children", []):  # type: ignore[attr-defined]
        out += _walk(c)
    return out


def _assert_safe_tree(tree: dict[str, object]) -> str:
    texts = []
    for n in _walk(tree):
        if "text" in n:
            texts.append(str(n["text"]))
            continue
        assert n["tag"] in {
            "div",
            "article",
            "h1",
            "h2",
            "h3",
            "p",
            "span",
            "a",
            "ul",
            "li",
            "dl",
            "dt",
            "dd",
            "code",
            "pre",
            "details",
            "summary",
            "strong",
            "button",
            "aside",
        }
        for k, v in n["attrs"].items():  # type: ignore[attr-defined]
            assert not k.startswith("on") and k != "style"
            if k == "href":
                assert v.startswith(("https://", "/rules/")), v
    return "".join(texts)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_browser_rendering_uses_text_nodes_only(tmp_path: Path) -> None:
    rel = _hostile_release(tmp_path)
    root = build_site(rel, tmp_path / "site", min_score=0).root / "rules"
    lid = next(iter(json.loads(next((root / "data/d").glob("*.json")).read_text())))
    text = _assert_safe_tree(_node(tmp_path, root, "render", lid))  # type: ignore[arg-type]
    assert HOSTILE in text and "alert(5)" in text  # shown as text, not as markup
    card = _node(tmp_path, root, "embed", lid)
    text = _assert_safe_tree(card)  # type: ignore[arg-type]
    assert "fallback" not in text and HOSTILE in text
    assert _node(tmp_path, root, "embed", "zz<script>") == {
        "tag": "div",
        "attrs": {"data-rule": "zz<script>"},
        "cls": "",
        "children": [{"text": "fallback"}],
    }


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_embed_card_and_search(tmp_path: Path) -> None:
    rel, _ = _release(tmp_path, licence="MIT")
    root = build_site(rel, tmp_path / "site", min_score=0).root / "rules"
    meta = json.loads((root / "data/meta.json").read_text())
    shard = {k: v for p in (root / "data/d").glob("*.json") for k, v in json.loads(p.read_text()).items()}
    lid = next(lid for lid, d in shard.items() if d["title"] == "Test a")
    card = _node(tmp_path, root, "embed", lid)
    nodes = _walk(card)  # type: ignore[arg-type]
    links = [n["attrs"].get("href") for n in nodes if n.get("tag") == "a"]  # type: ignore[union-attr]
    assert f"https://blog.example/rules/r/{lid}.html" in links  # card links to the full page, on the site's origin
    assert any(n.get("tag") == "details" for n in nodes) and "detection:" in _assert_safe_tree(card)  # type: ignore[arg-type]
    assert "Licence: MIT" in _assert_safe_tree(card)  # type: ignore[arg-type]
    assert meta["lid"] == 12 and len(lid) == 12
    assert len(_node(tmp_path, root, "search", "test")) == 5  # type: ignore[arg-type]
    assert sorted(_node(tmp_path, root, "search", "windows")) == ["Test a", "Test b", "Test c", "Test d", "Test e"]  # type: ignore[arg-type]
    assert _node(tmp_path, root, "search", "nosuchword") == []


def test_file_budget(tmp_path: Path) -> None:
    rel, _ = _release(tmp_path)
    full = build_site(rel, tmp_path / "a", min_score=0, collections=[])
    assert full.pages == 5
    st = build_site(rel, tmp_path / "a", min_score=0, collections=[], max_files=full.files - 2)
    assert st.files == full.files - 2 and st.pages == 3
    with pytest.raises(SiteError):
        build_site(rel, tmp_path / "b", min_score=0, max_files=10)
    with pytest.raises(SiteError):
        build_site(rel, tmp_path / "c", base_url="rules")
    with pytest.raises(SiteError):
        build_site(rel, tmp_path / "d", collections=["nope"])


def test_site_command_wiring(tmp_path: Path) -> None:
    rel, _ = _release(tmp_path)
    app = typer.Typer()
    site_app = typer.Typer()
    app.add_typer(site_app, name="site")
    site_app.command("build")(site_command)
    res = CliRunner().invoke(app, ["site", "build", str(tmp_path / "out"), "--release", str(rel), "--collection", "ransom note", "--min-score", "0"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "out/rules/c/ransom-note.html").exists() and "static rule pages" in res.output


def test_hostile_release_identifiers_cannot_escape_the_site(tmp_path: Path) -> None:
    from sigharvest.site.build import SiteError, _read_release, _Writer

    rel = tmp_path / "rel"
    rel.mkdir()
    (rel / "manifest.json").write_text('{"format": 1}')
    import gzip
    import json

    with gzip.open(rel / "rules.jsonl.gz", "wt") as fh:
        fh.write(json.dumps({"logic_hash": "../../etc/passwd" + "0" * 48}) + "\n")
        fh.write(json.dumps({"logic_hash": "ab" * 32}) + "\n")
    (rel / "ATTRIBUTION.md").write_text("fixture")
    reseal(rel)
    with pytest.raises(SiteError, match="logic_hash"):
        _read_release(rel, None)
    w = _Writer(tmp_path / "out")
    with pytest.raises(SiteError):
        w.text("../escape.html", "x")


@pytest.mark.parametrize("case", ["root-list", "scalar", "duplicate", "casing", "parent-missing", "phases-unknown", "version", "missing-tactics"])
def test_attack_sidecar_uses_common_structural_admission(tmp_path, case):
    from sigharvest.site import SiteError
    from sigharvest.site.build import _load_attack
    from tests.test_attack import _invalid_catalog

    path = tmp_path / "attack.json"
    path.write_text(json.dumps(_invalid_catalog(case)))
    with pytest.raises(SiteError, match="verified reduced Enterprise"):
        _load_attack(path)


def test_attack_sidecar_valid_projection_and_duplicate_key_rejection(tmp_path):
    from sigharvest.attack import ATTACK_VERSION
    from sigharvest.site import SiteError
    from sigharvest.site.build import _load_attack
    from tests.helpers import ATTACK_FIXTURE

    path = tmp_path / "attack.json"
    payload = json.dumps({"version": ATTACK_VERSION, **ATTACK_FIXTURE})
    path.write_text(payload)
    result = _load_attack(path)
    assert result == {
        "version": ATTACK_VERSION,
        "tactics": {short: [tid, name] for short, name, tid in ATTACK_FIXTURE["tactics"]},
        "techniques": {t["id"]: t["name"] for t in ATTACK_FIXTURE["techniques"]},
        "replaced": ATTACK_FIXTURE["replaced"],
        "deprecated": ATTACK_FIXTURE["deprecated"],
    }
    path.write_text(payload.replace('"id": "T1003"', '"id": "T1003", "id": "T1003"'))
    with pytest.raises(SiteError):
        _load_attack(path)


def test_source_quality_counts_each_rule_once_under_its_canonical_source() -> None:
    def row(src: str, score: float, validation: str, **conv: str) -> dict[str, object]:
        return {"canonical": {"source": src}, "score": score, "validation": validation, "conversion": {k: {"status": v} for k, v in conv.items()}}

    rows = [
        row("a", 80, "ok", splunk="ok", sqlite="raw"),
        row("a", 40, "warning", splunk="error", sqlite="ok"),
        row("a", 60, "ok", splunk="ok"),
        row("b", 10, "error"),
        {"score": 99, "validation": "ok"},  # no canonical copy: not attributed to any source
    ]
    backends, q = source_quality(rows)
    assert backends == ["splunk", "sqlite"]
    assert q["a"] == {"n": 3, "score": 60, "valid": 66, "mapped": {"splunk": 66, "sqlite": 50}}
    assert q["b"] == {"n": 1, "score": 10, "valid": 0, "mapped": {"splunk": None, "sqlite": None}}
    assert source_quality([row("c", 1, "ok"), row("c", 4, "ok")])[1]["c"]["score"] == 2  # even count: mean of the middle two, rounded


def test_attribution_page_shows_source_quality(tmp_path: Path) -> None:
    rel, _ws = _release(tmp_path, "MIT")
    rows = _rows(rel)
    for r in rows:
        r["conversion"] = {"splunk": {"status": "ok"}}
    _write_rows(rel, rows)
    out = tmp_path / "site"
    build_site(rel, out, min_score=0)
    page = (out / "rules" / "attribution.html").read_text()
    assert '<th scope="col" class="opt">canonical</th>' in page and '<th scope="col" class="opt">splunk</th>' in page
    assert '<td class="opt mono">100%</td>' in page
    parser = _Tags()
    parser.feed(page)
    assert parser.bad == []


def test_licences_link_to_their_text_and_footer_names_corrections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """DRL item 3 / CC-BY §3(a)(1)(C): the licence text or its URI next to the rule; ATT&CK designation, the
    non-affiliation line and the correction/removal channel (configurable repository) on every page."""
    monkeypatch.setenv("SIGHARVEST_REPO", "example-org/sigharvest")
    rel, _ws = _release(tmp_path, "DRL-1.1")
    out = tmp_path / "site"
    build_site(rel, out, min_score=0)
    root = out / "rules"
    drl = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
    pages = [p.read_text() for p in (root / "r").glob("*.html")]
    assert pages and all(f'<a href="{drl}" rel="noopener">DRL-1.1</a>' in p for p in pages)
    attribution = (root / "attribution.html").read_text()
    assert f'<a href="{drl}" rel="noopener">DRL-1.1</a>' in attribution
    assert "https://github.com/example-org/sigharvest/issues" in attribution and 'href="NOTICE.md"' not in attribution
    assert (root / "NOTICE.md").is_file() and '<a href="/rules/NOTICE.md">NOTICE.md</a>' in attribution
    index = (root / "index.html").read_text()
    assert "Not affiliated with or endorsed by SigmaHQ, OISF, Proofpoint/Emerging Threats or MITRE." in index
    assert "https://github.com/example-org/sigharvest/issues" in index
    # RFC 9116: the role address, the advisory form, an expiry and the canonical URL under the base path
    sec = (root / ".well-known" / "security.txt").read_text().splitlines()
    assert "Contact: mailto:security@threat-hunting.eu" in sec and "Preferred-Languages: en" in sec
    assert "Contact: https://github.com/example-org/sigharvest/security/advisories/new" in sec
    assert any(x.startswith("Expires: ") and x.endswith("Z") for x in sec)
    assert "Canonical: https://example.org/rules/.well-known/security.txt" in sec
    details = "".join(p.read_text() for p in (root / "data" / "d").glob("*.json"))
    assert '"licence_links":[{"id":"DRL-1.1","url":"https://github.com/SigmaHQ/Detection-Rule-License' in details


def test_project_pages_base_path_links_resolve(tmp_path: Path) -> None:
    """GitHub project Pages: base_path /<repo> -> `--base-url /<repo>/`; pages.yml uploads OUT/<repo> as the site root."""
    rel, _ = _release(tmp_path)
    out = tmp_path / "_site"
    build_site(rel, out, min_score=0, base_url="/sigharvest/")
    root = out / "sigharvest"
    assert [p.name for p in out.iterdir() if not p.name.startswith(".")] == ["sigharvest"] and (root / "index.html").is_file()
    links: set[str] = set()

    class _Links(HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            links.update(v for k, v in attrs if k in ("href", "src") and v and v.startswith("/"))

    for page in root.rglob("*.html"):
        _Links().feed(page.read_text(encoding="utf-8"))
    assert links
    for link in links:
        path = re.split(r"[?#]", link, maxsplit=1)[0]
        assert path.startswith("/sigharvest/") and not path.startswith("/sigharvest/sigharvest/"), link
        target = root / path.removeprefix("/sigharvest/")
        assert (target / "index.html" if path.endswith("/") else target).is_file(), link


def test_hostile_release_error_is_printed_without_markup_or_controls(tmp_path: Path) -> None:
    rel = tmp_path / "rel"
    rel.mkdir()
    (rel / "manifest.json").write_text(json.dumps({"format": "\x1b[2J[link=https://evil.example]fix[/link] [/x]"}))
    with gzip.open(rel / "rules.jsonl.gz", "wt") as fh:
        fh.write("")
    (rel / "ATTRIBUTION.md").write_text("fixture")
    reseal(rel)
    app = typer.Typer()
    site_app = typer.Typer()
    app.add_typer(site_app, name="site")
    site_app.command("build")(site_command)
    res = CliRunner().invoke(app, ["site", "build", str(tmp_path / "out"), "--release", str(rel)])
    assert res.exit_code == 2, res.output
    assert "\x1b" not in res.output and "�[2J[link=https://evil.example]fix[/link] [/x]" in res.output


def test_licence_links_is_linear_on_a_long_unknown_id() -> None:
    # A letter, a long digit run and one out-of-class character backtracked quadratically (about 10 s at 20k digits).
    start = time.perf_counter()
    assert licence_links("a" + "1" * 20_000 + "!") == [{"id": "a" + "1" * 20_000 + "!", "url": None}]
    assert time.perf_counter() - start < 1.0
    # The id shape that gets an SPDX link is unchanged: a letter first, a digit somewhere after it.
    for i in ("Foo-2.0", "x2", "a.1+b"):
        assert licence_links(i) == [{"id": i, "url": f"https://spdx.org/licenses/{i}.html"}]
    for i in ("1BSD", "a1!", "Foo-only", "LicenseRef-x"):
        assert licence_links(i) == [{"id": i, "url": None}]
