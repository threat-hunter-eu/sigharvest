# Static rules site

`sigharvest site build` builds a static website of the rules: a search page, rule pages, collection pages, an attribution page and embeddable rule cards for articles. The output is plain
HTML, CSS, JS and JSON files: no server code, no external CDN, no inline scripts or styles.

## Build

From a published data release (no database needed, good for CI):

<!-- doctest -->
```sh
sigharvest release build release/                          # rules.jsonl.gz, manifest.json, ATTRIBUTION.md
sigharvest site build site/ --save-collections release/collections.json   # optional: publish collections
sigharvest site build site/ --release release/
```

From the workspace directly (the database is only read; a temporary release is built first):

<!-- doctest -->
```sh
sigharvest site build site/ --collection ransomware --collection "lateral movement"
```

Options:

| option | default | meaning |
|---|---|---|
| `--release DIR` | workspace | build from a release folder (`rules.jsonl.gz`, `manifest.json`, optional `collections.json`, `attack.json`) |
| `--collection NAME` | all | collections to publish (repeatable); `--no-collections` for none; `--collections-file` to use a JSON snapshot |
| `--base-url` | `/rules/` | where the site is served; files go to `OUT/<base-url>` so that `OUT` is the web root |
| `--site-url` | `https://example.org` | origin for canonical links and `sitemap.xml` |
| `--all` | off | search every non-junk rule instead of the best rule of each family |
| `--min-score` / `--max-pages` | 70 / 10000 | static HTML pages for the best family rules with at least this score (collection rules always get one) |
| `--max-files` | 20000 | file budget (Cloudflare Workers static assets and Pages allow 20,000 files) |
| `--limit N` | all | only the first N rules (quick previews) |

From Python: `sigharvest.site.build_site(source, out, collections=None, theme="default", base_url="/rules/", limit=None, ...)`.
ATT&CK technique names come from the workspace's ATT&CK cache (or `attack.json` in the release folder, the same
reduced format); without it techniques are shown by id.

The output folder is replaced on every build. A non-empty folder that sigharvest did not write is refused.

## Layout

```
OUT/rules/index.html            search page (the 30 best rules are listed in the HTML for crawlers and no-JS)
OUT/rules/rule.html?l=<lid>     any rule, rendered in the browser from its detail shard
OUT/rules/r/<lid>.html          static rule pages (collections + best family rules), with SEO meta
OUT/rules/c/<slug>.html         collection pages
OUT/rules/attribution.html      sources and licences (+ ATTRIBUTION.md), linked from every footer
OUT/rules/sitemap.xml           every generated HTML page
OUT/rules/changes.json          every new, changed and removed rule (the release's changes.json, or the last update's report)
OUT/rules/feed.xml              the same as an Atom feed (linked from every page head; the first 200 entries, full counts in its subtitle)
OUT/rules/data/meta.json        counts, dictionaries, shard layout
OUT/rules/data/t/<xx>.json      inverted index: token -> rule ranks (delta-encoded)
OUT/rules/data/f/<facet>.json   level, product, text available, validates
OUT/rules/data/m/<n>.json       result rows, 200 per file, in rank (score) order
OUT/rules/data/d/<hex>.json     everything about a rule, by the first hex digits of its logic hash
OUT/rules/static/               site.css, common.js, search.js, rule.js, embed.js, embed.css, favicon.svg
OUT/rules/.well-known/security.txt  RFC 9116 contact (security@threat-hunting.eu), expires one year after the build
```

`<lid>` is the first 12 hex digits of the rule's logic hash (as in `sigharvest show`). A rule's logic hash changes
when its detection changes upstream, so links to `rule.html?l=` are stable for a release, not forever; collection
items follow the rule id across releases.

Measured on a large corpus (about 99,000 rules): about 15,600 files, 350 MB (265 MB of it
detail shards, 70 MB static pages), built in about 17 s. A first search downloads meta.json (12 kB gzip) and then
3-25 small files, 50-200 kB gzip, and takes under 20 ms of CPU.

## Preview locally

<!-- doctest: skip long-running server -->
```sh
python -m http.server -d site 8000
# open http://127.0.0.1:8000/rules/
```

## Publishing

The output is a plain static folder: publish it with GitHub Pages, any static host or a CDN. Nothing is deployed
by sigharvest itself.

## Embedding a rule card in an article

Every rule page has an "Embed" box with the snippet; it is always:

```html
<div class="sigharvest-rule" data-rule="0123456789ab"><a href="/rules/rule.html?l=0123456789ab">Sigma rule 0123456789ab</a></div>
<script src="/rules/static/embed.js" defer></script>
```

The script (once per article, however many cards) replaces each `div.sigharvest-rule` with a card: title linked to the
full page, level, score, log source, ATT&CK techniques, the YAML in a collapsible block when the
licence allows it (otherwise "Text not redistributed (licence). View at source"), and the licence and author. It
loads `embed.css` itself. Without JavaScript, or if the rule is not in the release, the link stays.
The article page's CSP must allow `script-src 'self'`, `style-src 'self'` and `connect-src 'self'`. Cards are served
from the site's own origin; serving them to another origin would need CORS headers on `/rules/data/`.

## Licence policy

The site never publishes more than the release: the YAML text is included only for rules whose licence class the
release redistributes (permissive and copyleft by default). Rules without a stated licence, and
restricted ones unless the release opted in, are shown with their metadata and a link to the canonical copy.
Every rule shows its licence, where the licence comes from, the author and the canonical copy; every page links
to the attribution page, which lists every source with its licence and rule count, and the MITRE ATT&CK notice.

Corrections and removal requests: every footer and the attribution page link to the repository's issues and name
the address `security@threat-hunting.eu` (the project's role address, read by the maintainers).
`SIGHARVEST_CONTACT` overrides the address (a fork) and an empty value hides it; `SIGHARVEST_REPO` sets the
repository. The same address is the `Contact:` of `.well-known/security.txt` (GitHub Pages: the workflow uploads
hidden files for it).

## Security

Rule titles, descriptions, authors, tags, paths and source names come from untrusted repositories. Static pages are
rendered by Jinja2 with autoescaping; the browser renders JSON with `textContent` and `setAttribute` only (no
`innerHTML`); links are only written for `https://` URLs (canonical links only for GitHub and GitLab), and ids
from the URL are checked against `^[0-9a-f]{6,64}$`. JSON files escape `<`, `>` and `&`. The copyable embed
snippet contains only the hex id, never rule text. `tests/test_site.py` builds a release with hostile titles and
checks the static HTML (parsed: no event handlers, inline styles or inline scripts) and the browser rendering
(run in node with a minimal DOM).
