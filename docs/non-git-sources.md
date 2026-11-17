# Non-git rule sources

Besides `git`, `http` and `local`, `sigharvest sources add` supports three source types for rules published outside
Git: `http-files`, `html` and `huggingface`. ZIP and tar archives use `--type http` (with bounded extraction).

<!-- doctest -->
```bash
sigharvest sources add advisory https://example.org/advisory --type http-files \
  --url https://example.org/first.txt --url https://example.org/second.yml --disabled
sigharvest sources add detections https://example.org/detections/ --type html --disabled
sigharvest sources add dataset https://huggingface.co/datasets/OWNER/DATASET \
  --type huggingface --file rules.jsonl --ref main --disabled
sigharvest sources enable advisory
sigharvest sync -s advisory
```

The positional URL identifies the publisher. Repeated `--url` options supply the exact HTTPS resources to
fetch instead; without them, `http-files` and `html` fetch the positional URL. They never crawl links.
Repeated `--file` options select exact JSON/JSONL paths in a Hugging Face dataset. Without them all JSON/JSONL
siblings listed by the API are considered, so explicit files are recommended for mixed datasets. No dataset
scripts, Python code, Parquet files or streaming viewer APIs are executed or consumed.

Hugging Face `--ref` accepts a branch, tag or SHA and defaults to `main`. The API resolves it to a 40-character
SHA before any data file is fetched. Use a SHA for a reproducible snapshot; a branch follows future updates,
with each resolved SHA recorded. Datasets are read through the [Hugging Face Hub API](https://huggingface.co/docs/hub/api).

## Extraction

- `http-files`: UTF-8 YAML (including multiple documents), or complete YAML in closed Markdown fences with
  no language or `yaml`, `yml`, `sigma`, or four-space/tab-indented blocks separated from prose by a blank line.
- `html`: complete YAML in closed `<pre>` or `<code>` elements. Nested pre/code pairs produce one block;
  syntax-highlighting spans and HTML entities are handled. Scripts and styles are ignored.
- `huggingface`: JSON arrays, single row objects or JSONL rows. A row can contain structured `logsource` and
  `detection`, or a `raw_yaml`/`sigma_rule` string holding complete YAML. Structured fields take precedence.

No title/detection fragments are guessed or stitched together. Every nonempty YAML document in a block must
have Sigma structure. Parsing rejects aliases, duplicate keys and excessive nesting. This is conservative
extraction, not semantic validation; run `sigharvest test` after sync. Metadata and detection values are preserved.
The adapter does not promote wrapper IDs such as `DET-001` or `seed-001` into Sigma UUIDs.

Some datasets double-encode newlines inside `raw_yaml`. Structured fields avoid interpreting those strings.
If only double-encoded YAML exists, the adapter reports an error instead of replacing every literal `\n`,
which could change a path such as `C:\new\tool.exe` or a regex. Supply structured fields or normal JSON string
encoding upstream. Invalid rule-bearing rows fail the source; unrelated dataset rows are ignored.

## Incremental sync and provenance

The generated paths are `<URL-SHA256>/document.yml`, `<URL-SHA256>/fence-LINE.yml`,
`<URL-SHA256>/indent-LINE.yml`, `<URL-SHA256>/block-NUMBER.yml`, or
`<dataset-file>/row-NUMBER.yml`. JSONL row numbers are physical lines. JSON row numbers are one-based indices.
`paths` and `exclude` remain globs on these generated paths; `files` selects remote dataset files.
Different URLs with the same filename cannot overwrite one another.

`data/cache/non-git/<source>/manifest.json` records:

- `revision`: the dataset SHA, or SHA-256 of the sorted URL-to-raw-hash mapping for HTTP sources;
- `resources`: exact configured/pinned URLs, raw SHA-256 and available ETag/Last-Modified validators;
- `outputs`: generated file path, resource URL, block/row identifier and extracted SHA-256.

Original response bodies are stored as `<SHA256>.bin` beside the manifest. Validators are sent only after
checking a cached body's hash. A 304 reuses that verified body; immutable dataset file URLs reuse it directly.
Changed or missing cache blobs are downloaded again. Re-extraction compares generated file hashes, so prose
changes update the source revision without creating new rule versions. The source and its sync log record the
revision. Earlier raw blobs remain available, while the manifest describes
the latest successful fetch. The cache is derived data and can be removed when no sync is running.

A failed download, invalid dataset, or resource with no complete rules keeps the previous corpus and manifest.
The next successful sync can recover an interrupted ingest by scanning all generated files and reconciling
removed occurrences. Rule history remains in the database. Empty sources require an explicit configuration
change rather than trusting a page that might actually be a login/error page.

## Limits

Downloads require HTTPS, including redirects. Authorization headers follow only the original origin.
Each text/HTML resource or extracted document is limited to 2 MiB, each dataset file to 32 MiB, and a source
run to 128 MiB of input and 128 MiB of extracted output. There are at most 1,000 remote resources including
API metadata, 10,000 text/HTML blocks, 100,000 JSONL rows and 100,000 parsed nodes per YAML stream/JSON value,
with nesting limited to 64. Redirects are limited to five and request timeout is 120 seconds.

Only UTF-8 is supported. Unclosed blocks, legacy global YAML collections, ambiguous text and escaped-only
YAML need to be fixed upstream or converted separately. Cached bodies accumulate across revisions; nothing
removes old ones automatically. The corpus and manifest are published separately, so a process
crash during publication can require another sync; ordinary fetch/parse failures leave the old snapshot intact.
