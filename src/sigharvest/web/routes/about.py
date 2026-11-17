"""About & licences: what sigharvest does, licence classes, search syntax, the CLI cheat sheet, data and privacy,
versions. Old addresses (/guide, /cli, /help) redirect here."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from sigharvest.web import present
from sigharvest.web.deps import WebDep

router = APIRouter()
PACKAGES = (
    "sigharvest",
    "pysigma",
    "pysigma-backend-splunk",
    "pysigma-backend-elasticsearch",
    "pysigma-backend-kusto",
    "pysigma-backend-opensearch",
    "pysigma-backend-loki",
    "pysigma-backend-sqlite",
    "pysigma-pipeline-sysmon",
    "pysigma-pipeline-windows",
)
SYNTAX = (
    ("mimikatz", "every word must appear (title, description, detection values, tags, author)"),
    ('"net user"', "an exact phrase"),
    ("certutil OR bitsadmin", "either word"),
    ("powershell -test", "exclude rules with a word"),
    ("T1003.001", "an ATT&CK technique id (its sub-techniques too)"),
    ("level:high", "a field filter: level, status, product, category, service, tag, author, id"),
    ("category:ps_script mimikatz", "filters and words together"),
    ('author:"Florian Roth"', "a field filter with a phrase"),
)
CLI = (
    ("sigharvest init --preset curated", "create a workspace with the curated list of public sources"),
    ("sigharvest update", "download rule changes, validate and index them (queries are converted on demand)"),
    ("sigharvest search mimikatz --level high", "search from the terminal"),
    ("sigharvest show 4f1c9a7b", "one rule: YAML, copies, versions, test results"),
    ("sigharvest convert 4f1c9a7b --to splunk", "one rule as a query for a backend"),
    ("sigharvest export --product windows --format zip --out windows.zip", "save rules (YAML, zip, JSONL, CSV or queries)"),
    ("sigharvest coverage --navigator layer.json", "ATT&CK coverage and a Navigator layer"),
    ("sigharvest sources list", "the sources of this workspace"),
    ("sigharvest serve", "this web interface, on 127.0.0.1"),
)


def _version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


@router.get("/about", response_class=HTMLResponse)
def about_page(request: Request, web: WebDep) -> HTMLResponse:
    from sigharvest.conversion import ALL_BACKENDS, BACKENDS

    versions = [(name, _version(name)) for name in PACKAGES]
    classes = [
        {"cls": c, "examples": present.LIC_EXAMPLES[c], "meaning": present.LIC_SENTENCE[c].split(". ")[0] + ".", "export": exp}
        for c, exp in (
            ("permissive", "copied, in permissive/<licence>/"),
            ("copyleft", "copied, in copyleft/<licence>/ with the licence text"),
            ("restricted", "left out unless you choose “everything with a licence”"),
            ("none", "never copied: listed in SKIPPED.md with a link"),
        )
    ]
    return web.render(
        request,
        "about.html",
        {
            "versions": versions,
            "classes": classes,
            "syntax": SYNTAX,
            "cli": CLI,
            "workspace": present.display_path(web.ws.root),
            "backends_missing": missing_by_extra([b for b in ALL_BACKENDS if b not in BACKENDS]),
        },
    )


def _to_about(anchor: str = "") -> Response:
    return RedirectResponse("/about" + (f"#{anchor}" if anchor else ""), status_code=301)


@router.get("/guide")
def old_guide() -> Response:
    return _to_about()


@router.get("/help")
def old_help() -> Response:
    return _to_about()


@router.get("/cli")
def old_cli() -> Response:
    return _to_about("cli")


def missing_by_extra(missing: list[str]) -> list[tuple[str, list[str]]]:
    """Missing backends grouped by the extra that installs them ([convert] first, then [convert-legacy])."""
    from sigharvest.conversion import install_extra

    out: dict[str, list[str]] = {}
    for name in missing:
        out.setdefault(install_extra(name), []).append(name)
    return sorted(out.items(), key=lambda kv: kv[0] != "convert")
