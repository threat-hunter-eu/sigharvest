# FAQ

**Is this a replacement for sigma-cli or pySigma?**
No. sigharvest collects, deduplicates and filters rules; conversion is done by pySigma backends, the same ones
`sigma-cli` uses. If you only need to convert rules you already have, use `sigma-cli`.

**Why not just clone SigmaHQ?**
SigmaHQ is the best single source and it is in every preset, with top priority. But many good rules live
elsewhere (The DFIR Report, Yamato Security, independent researchers, cloud and SaaS rule sets), and many
repositories copy SigmaHQ with small changes. sigharvest gives you all of them, once.

**How do you decide two rules are duplicates?**
By the normalised `logsource` + `detection`: same logic, same rule, whatever the title, id or author say. Rules
that differ but are clearly related (same trusted id, `related:` links, same parsed condition) are grouped as a
family. Similar-but-different rules are shown as "similar", never merged. See
[sources.md](sources.md#priority-and-the-canonical-copy) and [identity.md](identity.md).

**Which copy do I get?**
The canonical copy: from the source with the lowest `priority` number (SigmaHQ in the presets), else the earliest
seen. `sigharvest show KEY --copies` lists all others.

**Does it need internet access?**
Only for `update`/`sync` (Git clones and downloads), `discover`, and the first download of the Sigma JSON schema
and ATT&CK data. Search, show, export, convert, coverage and the web UI work offline.

**How much disk does it use?**
Curated preset: a few hundred MB (clones + database). `--preset all`: several GB.

**How often should I update?**
Daily is plenty. Updates are incremental and usually take a minute or two. See the cron example in
[getting-started.md](getting-started.md#5-keep-it-up-to-date).

**A source failed during update. Did I lose its rules?**
No. A failing source keeps its last good copy; the run report lists it. If many sources fail at once, or the
number of unique rules drops sharply, the update gate fails and the previous index stays published, so a broken
upstream cannot empty your index.

**Can I use rules from repositories without a licence?**
In your own workspace you fetch them yourself, for your own use. sigharvest never redistributes them: release
packs only list them with a link. If you want to publish or ship them, ask the author for a licence.

**Can I use the converted queries commercially?**
Depends on the rule's licence. DRL-1.1 (SigmaHQ) allows it with author credit; GPL rules stay GPL; check the
licences in your export's `manifest.jsonl`. Not legal advice.

**Why are some rules missing from search?**
By default search hides deprecated and unsupported rules and "junk" (test fixtures, synthetic series, templates,
SIEM queries wrapped in YAML). Add `--include-deprecated` or `--include-junk`. Files whose YAML could not be parsed
at all are quarantined: `sigharvest quarantine list` ([quarantine.md](quarantine.md)).

**Why does a rule not convert to my SIEM?**
Usually a modifier the backend does not support, or no field mapping for that logsource. `sigharvest convert KEY
--target X` prints the status and the reason. `--allow-raw` on export writes the query with Sigma field names.

**Can I expose the web UI to my team?**
It is meant for local use: bound to 127.0.0.1, where it has no login. On any other address it requires a token and
the host names clients use: `SIGHARVEST_UI_TOKEN=... sigharvest serve --host 0.0.0.0 --token-env SIGHARVEST_UI_TOKEN
--allow-host rules.example.org` (repeatable; or `SIGHARVEST_ALLOWED_HOSTS=a,b`). Browsers ask for a user name (any)
and the token as password; scripts send `Authorization: Bearer <token>`. Put TLS (a reverse proxy) in front of it
on a network you do not trust. The UI refuses any other `Host` header. Better: publish a static site with `sigharvest site build` ([site.md](site.md)) or
share exports.

**Does it phone home or collect telemetry?**
No. It talks only to the sources you configured, the GitHub/GitLab APIs for `discover`, and the hosts of the Sigma
schema and ATT&CK data.

**Can I add Sigma rules from my company?**
Yes, as a local folder or private Git source ([sources.md](sources.md#add-your-own-repository-or-local-folder)).
They stay in your workspace. Never commit them to a public repository.

**Is there a Docker image?**
No. `uv tool install` gives you an isolated install in seconds.

**Does it work on Windows?**
Through WSL ([getting-started.md](getting-started.md#windows-use-wsl)). Native Windows is refused at the first
workspace write: the workspace lock needs POSIX `flock` and the conversion workers rely on Linux process and memory
limits.

**I found a rule that's wrong / a duplicate that wasn't caught.**
Rule content issues belong upstream (the source repository, linked on every rule page). Dedup or tool issues: open
an issue here with both rule keys from `sigharvest search`.


**How does sigharvest compare with other Sigma tools?**
It builds on the Sigma ecosystem; it does not replace it. If you only use SigmaHQ rules and only need conversion,
`sigma-cli` with the SigmaHQ release packages is simpler. sigharvest is for when you want every public rule,
without duplicates, with filters and provenance.

| | sigharvest | [sigma-cli](https://github.com/SigmaHQ/sigma-cli) / pySigma | [SigmaHQ release packages](https://github.com/SigmaHQ/sigma/releases) | [detection.fyi](https://detection.fyi/) | [sigconverter.io](https://sigconverter.io) | [RuleHound](https://github.com/infosecB/Rulehound) |
|---|---|---|---|---|---|---|
| What it is | Local aggregator + index | Converter / validator CLI and library | Zip of SigmaHQ rules | Static website | Web converter for one rule | Index of rule repositories |
| Sources | Many public repos + yours | The files you give it | SigmaHQ only | A few repos | One pasted rule | Many (repos, not rules) |
| Dedup across sources | Yes (logic hash, families) | No | n/a | No | n/a | No |
| Search / filters | Full-text + facets, CLI and web | No | No | Browse by tag | No | By repo |
| Convert to SIEM queries | Yes, via pySigma backends | **Yes (the reference)** | No | No | Yes, all pySigma backends | No |
| Bulk export | YAML, zip, JSONL, CSV, queries | Converts a folder | Zip | No | No | No |
| ATT&CK Navigator layer | Yes | `sigma analyze attack` | No | No | No | No |
| Per-rule licence + provenance | Yes | No | Single licence (DRL) | Link to source | No | Per repo |
| Offline / local | Yes | Yes | Yes | No | Self-host option | No |
