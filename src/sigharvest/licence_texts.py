"""Licence texts and upstream notices that travel with redistributed rules.

Releases and export zips ship, next to the rules:
- `LICENSES/<SPDX id>.txt`: the full text of every licence present (unmodified SPDX copies in `licences/`, plus the
  Detection Rule License 1.1 from SigmaHQ/Detection-Rule-License), or a link when no text is bundled;
- `LICENSES/<source>/<file>` (`<source>.source/` for a source named like a licence file, licence_folder): the
  LICENSE / COPYING / NOTICE files at the root of each contributing source's synced commit (copied at sync time
  into data/licences/<source>/, never arbitrary files), so the publishers' own copyright lines (MIT, BSD, Apache
  §4(c)) and Apache NOTICE files (§4(d)) are kept;
- `LICENSES/INDEX.md`: source, licence (linked), copyright lines and files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

TEXTS = Path(__file__).parent / "licences"
# Deprecated or version-ambiguous SPDX ids -> the text to ship (GPL-3 §14: no stated version means any version).
ALIASES = {
    "GPL-2.0": "GPL-2.0-only",
    "GPL-2.0+": "GPL-2.0-only",
    "GPL-2.0-or-later": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "GPL-3.0+": "GPL-3.0-only",
    "GPL-3.0-or-later": "GPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-2.1-or-later": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "LGPL-3.0+": "LGPL-3.0-only",
    "LGPL-3.0-or-later": "LGPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
    "AGPL-3.0+": "AGPL-3.0-only",
    "AGPL-3.0-or-later": "AGPL-3.0-only",
    "EUPL-1.2+": "EUPL-1.2",
    "EUPL-1.2-or-later": "EUPL-1.2",
    "DRL": "DRL-1.1",
    "Detection Rule License 1.1": "DRL-1.1",
}
# Licences that are additional permissions on top of another text: both texts travel together (LGPL-3.0 is GPL-3.0
# plus the LGPL permissions).
COMPANIONS = {"LGPL-3.0-only": ("GPL-3.0-only",)}
LINKS = {
    "DRL-1.1": "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md",
    "DRL-1.0": "https://github.com/SigmaHQ/Detection-Rule-License",
}
# Upstream files kept per source: LICENSE, LICENCE, COPYING, NOTICE, optionally with a suffix (.txt, .md, -MIT...).
LICENCE_FILE = re.compile(r"^(?:LICEN[CS]E|COPYING|NOTICE|COPYRIGHT)(?:[._-][\w.-]{0,40})?$", re.IGNORECASE)
MAX_LICENCE_BYTES = 256 * 1024
MAX_LICENCE_FILES = 8
# A copyright statement starts a line with "Copyright" (optionally "(c)" or "©"), or with "(c)"/"©" and a year, and
# names a holder. Licence texts use the word inside sentences ("copyright on the Program", "copyright notice that
# is included...", "(c) You must retain..."): those wrapped fragments are not statements.
_COPYRIGHT = re.compile(r"^(?:Copyright|COPYRIGHT)\b\s*(?:\([cC]\)|©)?\s*(?P<rest>.{3,200})$|^(?:\([cC]\)|©)\s*(?P<dated>\d{4}.{2,200})$")
_YEARS = re.compile(r"^[\s\d,\-–/]*")
# First words after "Copyright" (and the years) that are licence prose or template placeholders, not a holder.
_NOT_HOLDER = frozenset(
    [
        "notice",
        "notices",
        "holder",
        "holders",
        "owner",
        "owners",
        "license",
        "licence",
        "licenses",
        "licences",
        "law",
        "laws",
        "statement",
        "statements",
        "and",
        "or",
        "on",
        "of",
        "to",
        "in",
        "that",
        "is",
        "for",
        "year",
        "yyyy",
        "name",
        "you",
        "this",
        "all",
        "and/or",
        "protection",
    ]
)


def copyright_statement(line: str) -> bool:
    """Whether one line (whitespace collapsed) is a real copyright statement with a holder, not licence boilerplate:
    template lines ("Copyright (c) <year> <copyright holders>", "[yyyy] [name of copyright owner]"), the copyright of
    the licence text itself (Free Software Foundation) and sentence fragments of GPL, Apache or CC texts are not."""
    m = _COPYRIGHT.match(line)
    if not m or "<" in line or "{" in line or "[yyyy]" in line.lower() or "free software foundation" in line.lower():
        return False
    rest = m.group("rest") if m.group("rest") is not None else m.group("dated")
    dated = bool(re.match(r"[\[(]?\d{4}", rest))
    holder = _YEARS.sub("", rest.replace("[", "").replace("]", ""))
    holder = re.sub(r"^by\s+", "", holder, flags=re.IGNORECASE).strip()
    word = re.match(r"[\w.&'\"-]+", holder)
    if not word or len(re.findall(r"[^\W\d_]", holder)) < 2 or word.group(0).strip("\"'.").lower() in _NOT_HOLDER:
        return False
    return dated or not holder[0].islower()


def spdx_ids(expression: str | None) -> list[str]:
    """The licence ids of an SPDX expression ("MIT", "Apache-2.0 OR MIT", "GPL-2.0-only WITH x")."""
    if not expression:
        return []
    words = re.split(r"[\s()]+", expression)
    out: list[str] = []
    skip = False
    for w in words:
        if not w or w.upper() in ("AND", "OR"):
            continue
        if w.upper() == "WITH":
            skip = True
            continue
        if skip:
            skip = False
            continue
        if w not in out:
            out.append(w)
    return out


def text(spdx_id: str) -> bytes | None:
    """The bundled full text of a licence, or None."""
    name = ALIASES.get(spdx_id, spdx_id)
    if not re.fullmatch(r"[A-Za-z0-9.+-]+", name):
        return None
    f = TEXTS / f"{name}.txt"
    return f.read_bytes() if f.is_file() else None


def bundled_id(licence: str) -> str | None:
    """The id of the bundled text for a licence id or a common spelling of one ("GPLv3", "DRL 1.1", "agpl-3.0")."""
    name = ALIASES.get(licence, licence)
    if text(name) is not None:
        return name
    from sigharvest.licensing import normalise

    key = normalise(licence)
    if not key:
        return None
    stems = {f.stem.lower(): f.stem for f in TEXTS.glob("*.txt")}
    stems |= {k.lower(): v for k, v in ALIASES.items()}
    return stems.get(key)


def licence_ids(expression: str | None) -> list[str]:
    """The licence ids of a stated licence: the whole text when it names one licence ("Apache License 2.0"),
    otherwise the ids of the SPDX expression, each mapped to its bundled text id when there is one."""
    if not expression:
        return []
    whole = bundled_id(expression.strip())
    if whole:
        return [whole]
    return [bundled_id(i) or i for i in spdx_ids(expression)]


def texts_for(spdx_id: str) -> list[tuple[str, bytes]]:
    """(id, text) of a licence and of the texts it builds on (COMPANIONS); empty when no text is bundled."""
    name = bundled_id(spdx_id) or spdx_id
    own = text(name)
    if own is None:
        return []
    return [(name, own), *((c, t) for c in COMPANIONS.get(name, ()) if (t := text(c)) is not None)]


def missing_texts(ws: Any, sources: dict[str, str | None]) -> list[str]:
    """`source: id` for every licence id of shipped rules whose text would not travel with them: no bundled
    `<id>.txt` and no licence file of the source's own (LICENSE / COPYING). An empty list means every rule in a
    pack carries its licence text; release builds refuse to publish otherwise."""
    out = []
    for name in sorted(sources):
        ids = licence_ids(sources[name])
        if not ids:
            continue
        own_files = any(not f.upper().startswith("NOTICE") for f, _ in upstream(ws, name))
        out += [f"{name}: {i}" for i in ids if text(i) is None and not own_files]
    return out


def link(spdx_id: str) -> str | None:
    """Where the licence text is published (None for LicenseRef-* ids, which have no public text)."""
    name = ALIASES.get(spdx_id, spdx_id)
    if name in LINKS:
        return LINKS[name]
    if name.startswith("LicenseRef-"):
        return None
    return f"https://spdx.org/licenses/{name}.html"


def linked(expression: str | None) -> str:
    """A licence expression with each id linked to its text (markdown); 'not stated' when empty."""
    if not expression:
        return "not stated"
    out = expression
    for i in spdx_ids(expression):
        url = link(i)
        if url:
            out = re.sub(rf"(?<![\w.-]){re.escape(i)}(?![\w.-])", f"[{i}]({url})", out, count=1)
    return out


def licence_dir(ws: Any, source: str) -> Path:
    """data/licences/<source>/: the upstream licence files of a source, as of its last sync."""
    return Path(ws.root) / "data" / "licences" / source


def store_upstream(ws: Any, source: str, files: dict[str, bytes]) -> None:
    """Replace the stored licence files of a source (called by sync with the files at the synced commit's root)."""
    folder = licence_dir(ws, source)
    folder.mkdir(parents=True, exist_ok=True)
    keep = set()
    for name, data in sorted(files.items())[:MAX_LICENCE_FILES]:
        if not LICENCE_FILE.fullmatch(name) or "/" in name or len(data) > MAX_LICENCE_BYTES:
            continue
        keep.add(name)
        target = folder / name
        if not target.is_file() or target.read_bytes() != data:
            target.write_bytes(data)
    for old in folder.iterdir():
        if old.name not in keep and old.is_file() and not old.is_symlink():
            old.unlink()


def upstream(ws: Any, source: str) -> list[tuple[str, bytes]]:
    """(file name, bytes) of the stored upstream licence files of a source."""
    folder = licence_dir(ws, source) if ws is not None else None
    if folder is None or not folder.is_dir() or folder.is_symlink():
        return []
    out = []
    for f in sorted(folder.iterdir()):
        if f.is_file() and not f.is_symlink() and LICENCE_FILE.fullmatch(f.name) and f.stat().st_size <= MAX_LICENCE_BYTES:
            out.append((f.name, f.read_bytes()))
    return out[:MAX_LICENCE_FILES]


def copyright_lines(files: list[tuple[str, bytes]], declared: str | None = None) -> list[str]:
    """The copyright lines of a source: `copyright:` from sources.yaml first, then those found in its licence files
    (only real statements with a holder: templates and licence prose are skipped, see copyright_statement)."""
    lines = [declared.strip()] if declared and declared.strip() else []
    for _name, data in files:
        for raw in data.decode("utf-8", "replace").splitlines()[:400]:
            line = " ".join(raw.split())
            if copyright_statement(line) and line not in lines:
                lines.append(line)
    return lines[:10]


def licence_folder(source: str) -> str:
    """The folder of a source's own licence files under LICENSES/. The folder sits beside `<SPDX id>.txt` and
    INDEX.md, so a source named like one of those files (`MIT.txt`, `INDEX.md`) gets a `.source` suffix."""
    return f"{source}.source" if source.casefold().endswith((".txt", ".md", ".source")) else source


def bundle(ws: Any, sources: dict[str, str | None], configs: dict[str, Any] | None = None, prefix: str = "LICENSES/") -> list[tuple[str, bytes]]:
    """Files for `LICENSES/` covering `sources` (name -> licence expression of the rules shipped from it)."""
    configs = configs or {}
    files: list[tuple[str, bytes]] = []
    texts: dict[str, bytes] = {}
    rows = [
        "# Licences\n\n",
        "Each rule keeps the licence of its source. Full texts are in this folder (`<id>.txt`); the publishers' own\n",
        "licence and notice files, with their copyright lines, are in `<source>/`.\n\n",
        "| source | licence | copyright | files |\n|---|---|---|---|\n",
    ]
    for name in sorted(sources):
        expression = sources[name]
        cfg = configs.get(name)
        found = upstream(ws, name)
        shown: list[str] = []
        for fname, data in found:
            files.append((f"{prefix}{licence_folder(name)}/{fname}", data))
            shown.append(f"`{licence_folder(name)}/{fname}`")
        for i in licence_ids(expression):
            for key, t in texts_for(i):
                texts[key] = t
                shown.append(f"`{key}.txt`")
        notice = "; ".join(copyright_lines(found, getattr(cfg, "copyright", None))) or "see the source"
        rows.append(f"| {_cell(name)} | {linked(expression)} | {_cell(notice)} | {', '.join(shown) or '-'} |\n")
    files += [(f"{prefix}{i}.txt", t) for i, t in sorted(texts.items())]
    files.append((f"{prefix}INDEX.md", "".join(rows).encode("utf-8")))
    return files


def notice_section(ws: Any, sources: dict[str, str | None], configs: dict[str, Any] | None = None, where: str = "`LICENSES/`") -> str:
    """NOTICE.md lines per source: licence (linked) and copyright lines, plus any Apache NOTICE file verbatim."""
    configs = configs or {}
    out = ["", "## Sources, licences and copyright notices", ""]
    for name in sorted(sources):
        found = upstream(ws, name)
        lines = copyright_lines(found, getattr(configs.get(name), "copyright", None))
        out.append(f"- **{_cell(name)}**: {linked(sources[name])}" + (f". {'; '.join(lines)}" if lines else ""))
        for fname, data in found:
            if fname.upper().startswith("NOTICE"):
                body = data.decode("utf-8", "replace").strip()[:4000]
                out += ["", f"  NOTICE of {name} (Apache-2.0 §4(d)):", "", *[f"  > {line}" if line else "  >" for line in body.splitlines()], ""]
    out.append("")
    out.append(f"Full licence texts and the publishers' licence files: {where} (see `LICENSES/INDEX.md`).")
    return "\n".join(out) + "\n"


def for_credits(s: Any, credits: list[dict[str, Any]]) -> tuple[str, list[tuple[str, bytes]]]:
    """(NOTICE.md section, LICENSES/ files) for the rules described by `credits` (attribution entries with
    `source`, `licence` and optional `drl_origin`), from the session's workspace."""
    from sigharvest.source_metadata import source_configs, workspace_of

    ws, configs = workspace_of(s), source_configs(s)
    shipped: dict[str, str | None] = {str(c.get("source")): c.get("licence") for c in credits}
    if any(c.get("drl_origin") for c in credits):
        shipped["rules derived from DRL rules"] = "DRL-1.1"
    return notice_section(ws, shipped, configs), bundle(ws, shipped, configs)


def _cell(value: object) -> str:
    return " ".join(str(value or "").split()).replace("|", "\\|")[:300]
