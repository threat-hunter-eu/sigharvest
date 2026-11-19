# Quarantine

A document goes to quarantine when its YAML does not parse, hits a parser resource limit or has no usable identity.
Sigma validation and conversion failures are test results, not quarantine entries. Database, storage and file-read
failures are reported as errors of the run; they never turn a document into a quarantine entry.

<!-- doctest -->
```bash
sigharvest quarantine list --unresolved --limit 100
sigharvest quarantine list --after 100
sigharvest quarantine show 42
```

<!-- doctest: skip needs a quarantined document that the current parser now accepts -->
```bash
sigharvest quarantine retry 42 --parser current
sigharvest quarantine retry 42 --parser current --snapshot RETAINED_SHA256
```

`list` prints a table (id, source, path, document, reason, state). `list --json` and `show` print JSON metadata
without source text, paths, URLs or exception bodies: the source id, document position, reason code and version,
parser fingerprint, snapshot and document hashes, byte span, retention decision, presence and resolution. `show`
also lists the retry attempts.

`retry` needs an explicit `--parser`: `current`, or the exact installed fingerprint that `show` reports; a parser
that is no longer installed is refused. Exit codes: 0 when the document is recovered (or turns out not to be Sigma),
1 when it is rejected again, 2 for an unavailable parser, a missing snapshot, an invalid id or too many attempts.

The whole original file is kept, with its exact bytes (BOM and CRLF included) and any legacy `action: global`
context. The byte span is half-open and relative to that file. A retry checks the stored file's SHA-256, parses the
complete file with the installed, bounded loader, then evaluates the original document position. `--snapshot`
picks another file version that quarantine already keeps for the same source and path; the same position is then
read in that version, which does not mean the document order or identity stayed the same.

A successful retry records the rule version and the resolution in one transaction. It does not reactivate an old
occurrence, mark the source as synced or rebuild the index, so it is safe even after the source was removed or its
files disappeared. To publish recovered content, sync the source again and rebuild the index (`sigharvest update`).

During a normal sync, unchanged rejected bytes in the same file context are skipped, even after a parser upgrade;
the healthy documents of the same file are still processed. A changed file context is evaluated once, and every
explicit retry creates a new attempt. When the source fixes the document the entry is marked `superseded`; when the
file goes away it is marked `removed`. The original provenance and every attempt are immutable (SQLite triggers),
and a resolved entry and its stored inputs stay inspectable.

## Storage and privacy

- A kept file is at most 2 MiB. Files are stored once per SHA-256, within a total budget of 256 MiB by default.
- `SIGHARVEST_DISK_QUARANTINE_BYTES` changes the total budget. Set it to `0` before a sync to stop keeping new
  files; files already kept stay (this setting deletes nothing).
- When a file is not kept (size, budget or privacy), the entry keeps its metadata and says why in `retention`; it
  cannot be retried.
- At most 100 attempts are kept per entry. After that `retry` refuses, and normal syncs still skip the last
  rejected version without parsing it again. Fix the source instead of rescanning it.
- Before writing, the free space of the file system that holds the database is checked, including the growth of the
  stored files and the WAL. This is a check, not a reservation: a write that fails later still rolls back its
  transaction.
- Stored files and attempts live in the workspace database (and its WAL), protected by foreign keys and immutable
  triggers; `sigharvest db compact` does not delete them. Include the database in your backups.
- Stored files can contain sensitive upstream content and are not encrypted: protect the workspace folder and its
  backups. No command or web page shows or exports their raw text.

Quarantine entries created by older versions have no stored file or attempts: their reason is `legacy` and their
retention `legacy_unavailable`; they can be inspected but not retried. A parser fingerprint records the installed
YAML library version and the depth, node and expanded scalar size limits; it never installs parser code.
