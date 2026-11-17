# Unattended updates

`sigharvest update` runs: sync every enabled source -> validate new rules -> rebuild the index -> compare counts with
the last passing run (gates) -> write `reports/runs/<stamp>.md` and `.json`. Exit code 0 = everything passed; 1 = a
source or a gate failed; 2 = bad options, not a workspace, or the workspace is busy (see
[exit codes](cli.md#scripting-and-exit-codes)).

## Gates

| gate | fails when | usual cause |
|---|---|---|
| unique logic | unique logic drops more than 5% | a source emptied or rewritten; a parser or identity regression |
| quarantine | quarantined documents grow more than 20% **and** by 50+ | parser regression; a new source with broken files |
| failed sources | more than 10% of enabled sources fail to fetch (1 always allowed) | network, rate limit, a source moved or died |
| index complete | a rule is missing from the index | interrupted index: run `sigharvest index` |

A failed run never becomes the baseline and keeps the previously published index. When a change is intended (a
source removed on purpose), make that run the baseline with `sigharvest runs accept latest`. `sigharvest runs list`
and `sigharvest runs show latest` show history and reports. A failed source keeps its previous rules, so a network
outage cannot shrink the index by itself.

## cron

```cron
17 6 * * *  SIGHARVEST_HOME=$HOME/sigma  $HOME/.local/bin/sigharvest update --allow-failures --wait 600 >> $HOME/sigma/update.log 2>&1
```

`--wait 600` waits up to ten minutes when another command (a manual `index`, a collection edit) holds the
workspace, instead of exiting 2 at once.

## systemd

Files in [`deploy/systemd/`](../deploy/systemd/): `sigharvest-update.service` (oneshot, waits up to 10 minutes for
a busy workspace), `sigharvest-update.timer` (daily 06:17, `Persistent=true`), `sigharvest-update-failed@.service`
(OnFailure hook: replace its ExecStart with your notifier). Tokens for sources that need one (`auth:`) go in
`/etc/sigharvest/env` (`EnvironmentFile=`), never in sources.yaml.

On WSL, systemd works when `/etc/wsl.conf` has `[boot] systemd=true`; the timer runs only while the WSL VM is up.
A Windows Task Scheduler entry running `wsl.exe -- sigharvest update` (with `SIGHARVEST_HOME` exported) is the
alternative.

## GitHub Actions

To build and publish rule releases from a repository on a schedule, see [automation.md](automation.md).
