# shellcheck shell=bash
# sigharvest user journey. Contract: docs/automation.md ("CLI contract"), README.md, docs/cli.md, docs/export.md.
# Uses: $BIN $WS $RUN $MODE $HOME_VAR $CAPTURE, helpers from common.sh.

# Backends promised by docs/export.md ("Formats at a glance").
SIG_BACKENDS=(splunk lucene esql opensearch microsoft365defender loki sqlite)
# Conversion targets each optional dependency set must provide (accept.sh --extra). [convert] is pySigma 2 and only
# has backends released for it; [convert-legacy] is pySigma 1 with all seven. A target outside the set may still be
# installed (a backend gains a pySigma 2 release): then it must convert; otherwise it must fail with a clear message.
declare -A SIG_EXTRA_BACKENDS=(
    [convert]="splunk loki sqlite"
    [convert-legacy]="${SIG_BACKENDS[*]}"
)

tool_version() {
    run_step "$CLI --version" -- "$BIN" --version
    check "--version names the tool" grep -q "sigharvest" "$LAST_LOG"
}

tool_contract_help() {
    local spec cmd flags f
    # command | flags (docs/automation.md "CLI contract" and docs/cli.md)
    local -a contract=(
        "init|--preset"
        "update|--sources --workers --allow-failures --max-failed-sources --report-file"
        "search|--product --category --service --level --status --technique --tactic --tag --source --validation --backend --min-sources --include-junk --json --per-logic --limit --sort"
        "show|--copies"
        "export|--format --out --unit --with-dependencies --telemetry --allow-raw --allow-warnings --rule-source --min-score"
        "convert|--target --telemetry"
        "coverage|--navigator --gaps"
        "lint|--release --sarif --fail-on"
        "sources list|"
        "sources add|--type --licence --path"
        "sources enable|"
        "sources disable|"
        "sources remove|"
        "discover|--output --known --denylist --verify --max-repos --report-file"
        "serve|--host --port"
        "doctor|"
        "release build|--licence-class --build-epoch --previous"
        "site build|--release --base-url --site-url --build-epoch"
    )
    local missing=() t0
    t0=$(_now)
    for spec in "${contract[@]}"; do
        cmd=${spec%%|*}; flags=${spec#*|}
        # shellcheck disable=SC2086
        if ! out=$("$BIN" $cmd --help 2>&1); then missing+=("'$cmd' (no such command)"); continue; fi
        for f in $flags; do grep -q -- "$f" <<<"$out" || missing+=("$cmd $f"); done
    done
    STEP_N=$((STEP_N + 1))
    if ((${#missing[@]})); then
        _record WARN "$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')" "CLI contract: commands/flags in --help" "" "missing: ${missing[*]}"
    else
        _record OK "$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')" "CLI contract: commands/flags in --help" "" "all ${#contract[@]} commands present"
    fi
}

sig_search_json() { # NAME OUTFILE ARGS... : run `search ARGS --json` in the workspace, stdout to OUTFILE
    local name=$1 out=$2; shift 2
    run_step "$name" --cwd "$WS" -- "$CAPTURE" "$out" "$BIN" search "$@" --json
}

tool_flow() {
    local fx="$RUN/fixture-repos" keep others key q
    # ---- init (README quickstart: `sigharvest init ~/sigma && cd ~/sigma && sigharvest update`)
    # README: `sigharvest init ~/sigma  # curated sources; --preset sigmahq for SigmaHQ only`
    local preset=()
    [[ $MODE == online ]] && preset=(--preset sigmahq)
    run_step "init workspace ${preset[*]:-(default preset)}" --cwd "$HOME" -- "$BIN" init "$WS" "${preset[@]}" || die "init failed"
    check "workspace has sources.yaml" test -f "$WS/sources.yaml"
    run_step "init again refuses to clobber" --expect "1 2" --cwd "$HOME" -- "$BIN" init "$WS"

    # ---- choose a small source set the way a user would: add / disable through the CLI
    if [[ $MODE == offline ]]; then
        # shellcheck source=../expected/sigharvest-offline.env
        source "$HARNESS/expected/sigharvest-offline.env"
        run_step "build fixture git repos" -- python3 -I "$HARNESS/lib/make_fixtures.py" sigma "$fx" || die "fixtures"
        run_step "sources add fixture-sigma-alpha (file://)" --cwd "$WS" -- \
            "$BIN" sources add fixture-sigma-alpha "file://$fx/fixture-sigma-alpha" --type git --licence DRL-1.1
        run_step "sources add fixture-sigma-beta (file://)" --cwd "$WS" -- \
            "$BIN" sources add fixture-sigma-beta "file://$fx/fixture-sigma-beta" --type git --licence MIT
        keep="fixture-sigma-alpha,fixture-sigma-beta"
    else
        keep="sigmahq-core"
        check "sigmahq preset contains sigmahq-core" grep -q "name: sigmahq-core" "$WS/sources.yaml"
    fi
    disable_others "$keep"
    run_step "sources list" --cwd "$WS" -- "$BIN" sources list

    # ---- update + health
    STEP_TIMEOUT=${STEP_TIMEOUT:-3600} run_step "update" --cwd "$WS" -- "$BIN" update || log "update failed; later steps will show what is missing"
    run_step "doctor" --cwd "$WS" -- "$BIN" doctor
    [[ $MODE == offline ]] && sig_changes_first
    run_step "update again (incremental, nothing changed)" --cwd "$WS" -- "$BIN" update
    if [[ $MODE == offline ]]; then
        run_step "changes after an update that changed nothing" --cwd "$WS" -- "$BIN" changes
        check "changes: 0 new, 0 changed, 0 removed" grep -q ': 0 new, 0 changed, 0 removed' "$LAST_LOG"
    fi

    # ---- search
    if [[ $MODE == offline ]]; then q=whoami; else q=mimikatz; fi
    run_step "search $q (table)" --cwd "$WS" -- "$BIN" search "$q"
    sig_search_json "search $q --json" "$RUN/search.json" "$q"
    key=$(pycheck json "$RUN/search.json" "results|rules.0.logic_hash" 2>/dev/null) || key=""
    check "search $q finds a rule" test -n "$key"
    sig_search_json "search --per-logic --json (all)" "$RUN/search-all.json" --per-logic --limit 100000
    sig_search_json "search --product windows --per-logic --json" "$RUN/search-win.json" --product windows --per-logic --limit 100000
    run_step "search via $HOME_VAR from another folder" --cwd "$HOME" -- env "$HOME_VAR=$WS" "$BIN" search "$q" --limit 3
    run_step "search with a bad query is a clear error" --expect "0 1 2" --cwd "$WS" -- "$BIN" search '(unbalanced "quote'
    if [[ $MODE == offline ]]; then
        check "unique logic count == $SIG_UNIQUE_LOGIC" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search-all.json' total); echo \"total \$n\"; [[ \$n == $SIG_UNIQUE_LOGIC ]]"
        check "whoami: one logic for 3 copies" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search.json' total); echo \"total \$n\"; [[ \$n == 1 ]]"
        check "whoami logic carried by $SIG_WHOAMI_SOURCES sources" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search.json' results.0.sources --len); echo \"sources \$n\"; [[ \$n == $SIG_WHOAMI_SOURCES ]]"
        check "--product windows logic count == $SIG_WINDOWS_LOGIC" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search-win.json' total); echo \"total \$n\"; [[ \$n == $SIG_WINDOWS_LOGIC ]]"
        sig_search_json "search certutil --per-logic --json" "$RUN/search-certutil.json" certutil --per-logic
        check "certutil: $SIG_CERTUTIL_LOGICS logics (latin-1 file name copy deduplicated)" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search-certutil.json' total); echo \"total \$n\"; [[ \$n == $SIG_CERTUTIL_LOGICS ]]"
        run_step "quarantine list" --cwd "$WS" -- "$BIN" quarantine list
        want "broken YAML is quarantined and shown" grep -q "$SIG_QUARANTINE_FILE" "$LAST_LOG"
        check "no rule from docs/not-a-rule.yaml" bash -c "! grep -q 'not-a-rule' '$RUN/search-all.json'"
        sig_filters
    else
        check "SigmaHQ core gives >= 2000 unique logics" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search-all.json' total); echo \"total \$n\"; [[ \$n -ge 2000 ]]"
    fi

    # ---- show / convert one rule
    if [[ -n $key ]]; then
        run_step "show ${key:0:10}" --cwd "$WS" -- "$BIN" show "${key:0:10}"
        check "show prints the rule YAML" grep -qE '^\s*(detection|logsource):' "$LAST_LOG"
        run_step "show --copies" --cwd "$WS" -- "$BIN" show "${key:0:10}" --copies
        [[ $MODE == offline ]] && want "copies list both fixture repos" bash -c "grep -q fixture-sigma-alpha '$LAST_LOG' && grep -q fixture-sigma-beta '$LAST_LOG'"
        run_step "convert --target splunk" --cwd "$WS" -- "$BIN" convert "${key:0:10}" --target splunk
        local conv_log=$LAST_LOG
        check "convert printed a query" grep -qiE '(=| IN \(|\| where |contains|endswith)' "$LAST_LOG"
        check "convert starts with the '# attribution:' header (author, source, licence)" bash -c "l=\$(grep -m1 -v -e '^\\$ ' -e '^# cwd: ' '$conv_log'); echo \"\$l\"; [[ \$l == '# attribution: '* && \$l == *'| author: '* && \$l == *'| licence: '* ]]"
        [[ $MODE == offline ]] && check "attribution names the canonical copy (fixture-sigma-alpha, DRL-1.1)" bash -c "grep -m1 '^# attribution:' '$conv_log' | grep -q 'source: fixture-sigma-alpha | licence: DRL-1.1'"
        sig_convert_extras "${key:0:10}"
    else
        skip "show / convert" "no rule key from search"
    fi
    run_step "show unknown key is a clear error" --expect "1 2" --cwd "$WS" -- "$BIN" show deadbeefdeadbeef

    # ---- exports (docs/export.md)
    local ex="$RUN/exports" sel=()
    mkdir -p "$ex"
    [[ $MODE == online ]] && sel=(mimikatz)
    run_step "export yaml folder (default)" --cwd "$WS" -- "$BIN" export "${sel[@]}" --out "$ex/yaml"
    if [[ $MODE == offline ]]; then
        check "yaml export re-parses as Sigma (one per family)" pycheck sigma-dir "$ex/yaml" --min "$SIG_UNIQUE_LOGIC" --max "$SIG_UNIQUE_LOGIC" --title "Fixture Brute Force Correlation"
    else
        check "yaml export re-parses as Sigma" pycheck sigma-dir "$ex/yaml" --min 1
    fi
    want "yaml export carries NOTICE.md" test -f "$ex/yaml/NOTICE.md"
    run_step "export --format zip" --cwd "$WS" -- "$BIN" export "${sel[@]}" --format zip --out "$ex/rules.zip"
    check "zip re-parses as Sigma YAML" pycheck sigma-zip "$ex/rules.zip" --min 1
    run_step "export --unit all --format zip (every copy)" --cwd "$WS" -- "$BIN" export "${sel[@]}" --unit all --format zip --out "$ex/all-copies.zip"
    if [[ $MODE == offline ]]; then
        check "all-copies zip has $SIG_ALL_COPIES_MIN-$SIG_ALL_COPIES_MAX rules, all valid UTF-8 YAML" pycheck sigma-zip "$ex/all-copies.zip" --min "$SIG_ALL_COPIES_MIN" --max "$SIG_ALL_COPIES_MAX"
        run_step "export correlation --with-dependencies" --cwd "$WS" -- "$BIN" export "Brute Force" --unit logic --with-dependencies --out "$ex/correlation"
        check "correlation export includes its base rule" pycheck sigma-dir "$ex/correlation" --min 2 --correlation-complete --title "Fixture Failed Logon"
    else
        check "all-copies zip re-parses" pycheck sigma-zip "$ex/all-copies.zip" --min 1
    fi
    run_step "export --format jsonl" --cwd "$WS" -- "$BIN" export "${sel[@]}" --format jsonl --out "$ex/rules.jsonl"
    check "jsonl rows parse, have logic_hash + title" pycheck jsonl "$ex/rules.jsonl" --min 1 --keys "logic_hash,title"
    want "jsonl has the documented fields" pycheck jsonl "$ex/rules.jsonl" --keys "rule_id,level,status,licence,licence_class,source,source_url,yaml"
    run_step "export --format csv" --cwd "$WS" -- "$BIN" export "${sel[@]}" --format csv --out "$ex/rules.csv"
    check "csv parses, has title column, no formula injection" pycheck csv "$ex/rules.csv" --min 1 --cols "title,logic_hash"
    local b
    local promised=" ${SIG_EXTRA_BACKENDS[${EXTRA:-convert}]-${SIG_BACKENDS[*]}} " installed
    installed=" $("$TOOL_PY" -I -c 'from sigharvest.conversion import BACKENDS; print(" ".join(BACKENDS))' 2>/dev/null) "
    log "[${EXTRA:-convert}] promises:${promised% } | installed:${installed% }"
    for b in "${SIG_BACKENDS[@]}"; do
        if [[ $promised == *" $b "* || $installed == *" $b "* ]]; then
            run_step "export --format $b (pySigma)" --cwd "$WS" -- "$BIN" export "${sel[@]}" --product windows --format "$b" --out "$ex/q-$b"
            check "$b output is not empty" pycheck nonempty "$ex/q-$b" --min-bytes 20
        else
            run_step "export --format $b without its backend is a clear error" --expect "1 2" --cwd "$WS" -- "$BIN" export "${sel[@]}" --product windows --format "$b" --out "$ex/q-$b"
            check "$b error says the backend is not installed" grep -q "not installed" "$LAST_LOG"
        fi
    done
    if [[ -f $ex/q-splunk ]]; then
        check "splunk export: '# attribution:' per query + .ATTRIBUTION.md + .NOTICE.md" bash -c "n=\$(grep -c '^# attribution: ' '$ex/q-splunk'); echo \"\$n attribution lines\"; [[ \$n -ge 1 ]] && test -s '$ex/q-splunk.ATTRIBUTION.md' && test -s '$ex/q-splunk.NOTICE.md'"
    fi
    run_step "export --format splunk --telemetry sysmon" --cwd "$WS" -- "$BIN" export "${sel[@]}" --product windows --format splunk --telemetry sysmon --out "$ex/q-splunk-sysmon"
    check "splunk+sysmon output is not empty" pycheck nonempty "$ex/q-splunk-sysmon" --min-bytes 20
    run_step "export unknown format is a clear error" --expect "1 2" --cwd "$WS" -- "$BIN" export --format nosuchbackend --out "$ex/bad"
    run_step "export over an existing file is refused or replaced cleanly" --expect "0 1 2" --cwd "$WS" -- "$BIN" export "${sel[@]}" --format zip --out "$ex/rules.zip"
    check "rules.zip still valid after the second export" pycheck sigma-zip "$ex/rules.zip" --min 1
    run_step "coverage --navigator" --soft --cwd "$WS" -- "$BIN" coverage --navigator "$ex/layer.json"
    [[ -f $ex/layer.json ]] && check "navigator layer is JSON with techniques" pycheck json "$ex/layer.json" techniques --len
    run_step "lint own rules (fixture folder)" --soft --expect "0 1" --cwd "$WS" -- "$BIN" lint "$HARNESS/fixtures/sigma/beta/rules"
    run_step "release build (licence packs)" --cwd "$WS" -- "$BIN" release build "$ex/release" --build-epoch 1767225600
    if [[ -d $ex/release ]]; then
        check "release has manifest.json + SHA256SUMS + permissive zip, checksums verify" bash -c "cd '$ex/release' && test -f manifest.json && test -f SHA256SUMS && test -f sigharvest-rules-permissive.zip && sha256sum --check --quiet SHA256SUMS"
        [[ -f $ex/release/sigharvest-rules-permissive.zip ]] && check "permissive pack re-parses as Sigma" pycheck sigma-zip "$ex/release/sigharvest-rules-permissive.zip" --min 1
        [[ $MODE == offline ]] && sig_release_offline
    fi
    [[ $MODE == offline ]] && sig_bump_and_changes
    [[ $MODE == offline ]] && sig_incomplete
    KEY=$key
}

# ------------------------------------------------------------------------------------------------ v3 additions
# Features added after the first harness (CHANGELOG 0.1.0): changes, multi-value filters, --profile, convert
# attribution, [convert] vs [convert-legacy], LICENSES/ + copyright in releases, init --from-release
# (+ --sums-sha256), changes between releases, incomplete-corpus gating. Offline mode only (exact numbers).

sig_count() { # JSONFILE -> total
    pycheck json "$1" total 2>/dev/null
}

sig_changes_first() {
    run_step "changes --json (after the first update)" --cwd "$WS" -- "$CAPTURE" "$RUN/changes-first.json" "$BIN" changes --json
    check "changes: $SIG_FIRST_NEW new, 0 changed, 0 removed" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/changes-first.json' new --len); c=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/changes-first.json' changed --len); echo \"new \$n changed \$c\"; [[ \$n == $SIG_FIRST_NEW && \$c == 0 ]]"
    run_step "changes --limit $SIG_CHANGES_LIMIT (text, capped)" --cwd "$WS" -- "$BIN" changes --limit "$SIG_CHANGES_LIMIT"
    local more=$((SIG_FIRST_NEW - SIG_CHANGES_LIMIT))
    check "cap message: '$more more: --limit $SIG_FIRST_NEW or --json'" grep -q "$more more: --limit $SIG_FIRST_NEW or --json" "$LAST_LOG"
    run_step "changes --run and --since together is a usage error" --expect 2 --cwd "$WS" -- "$BIN" changes --run latest --since 2026-01-01
    run_step "changes --from-release without --to-release is a usage error" --expect 2 --cwd "$WS" -- "$BIN" changes --from-release "$RUN"
}

sig_filters() {
    local f
    sig_search_json "search --level high,critical --per-logic" "$RUN/f-comma.json" --level high,critical --per-logic --limit 1000
    sig_search_json "search --level high --level critical --per-logic" "$RUN/f-repeat.json" --level high --level critical --per-logic --limit 1000
    sig_search_json "search 'level:high OR level:critical' --per-logic" "$RUN/f-inline.json" 'level:high OR level:critical' --per-logic --limit 1000
    sig_search_json "search level:high,critical --per-logic" "$RUN/f-inline-comma.json" 'level:high,critical' --per-logic --limit 1000
    for f in comma repeat inline inline-comma; do
        check "multi-value level filter ($f) == $SIG_HIGH_CRIT logics" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/f-$f.json' total); echo \"total \$n\"; [[ \$n == $SIG_HIGH_CRIT ]]"
    done
    run_step "OR between two different filters is refused with a message" --expect "1 2" --cwd "$WS" -- "$BIN" search 'level:high OR product:linux'
    check "refusal explains: run separate searches" grep -qi 'separate searches' "$LAST_LOG"
    run_step "a typo in an inline filter is refused with a suggestion" --expect "1 2" --cwd "$WS" -- "$BIN" search 'mimikatz prodct:windows'
    check "refusal suggests product:" grep -q 'did you mean product:' "$LAST_LOG"
    run_step "an unknown inline level is refused with a suggestion" --expect "1 2" --cwd "$WS" -- "$BIN" search 'level:hgh'
    check "refusal suggests level:high" grep -q 'did you mean level:high' "$LAST_LOG"
    sig_search_json "search --profile core --per-logic" "$RUN/p-core.json" --profile core --per-logic --limit 1000
    check "--profile core == $SIG_PROFILE_CORE logics (threat-hunting rule left out)" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/p-core.json' total); echo \"total \$n\"; [[ \$n == $SIG_PROFILE_CORE ]] && ! grep -q 'Decode Or Urlcache' '$RUN/p-core.json'"
    sig_search_json "search --profile core++ --per-logic" "$RUN/p-corepp.json" --profile core++ --per-logic --limit 1000
    check "--profile core++ == $SIG_PROFILE_COREPP logics" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/p-corepp.json' total); echo \"total \$n\"; [[ \$n == $SIG_PROFILE_COREPP ]]"
    run_step "export --profile core --unit logic --include-junk (SigmaHQ package selection)" --cwd "$WS" -- "$BIN" export --profile core --unit logic --include-junk --out "$RUN/exports/profile-core"
    check "profile core export has $SIG_PROFILE_CORE rules" pycheck sigma-dir "$RUN/exports/profile-core" --min "$SIG_PROFILE_CORE" --max "$SIG_PROFILE_CORE"
    run_step "search --profile bogus is a clear error" --expect 2 --cwd "$WS" -- "$BIN" search --profile bogus
    check "error lists the profiles" grep -q 'core, core+, core++' "$LAST_LOG"
}

sig_convert_extras() { # KEY
    local key=$1 promised installed t
    promised=" ${SIG_EXTRA_BACKENDS[${EXTRA:-convert}]-${SIG_BACKENDS[*]}} "
    installed=" $("$TOOL_PY" -I -c 'from sigharvest.conversion import BACKENDS; print(" ".join(BACKENDS))' 2>/dev/null) "
    # [convert] (pySigma 2) vs [convert-legacy] (pySigma 1): lucene is legacy-only today.
    t=lucene
    if [[ $promised == *" $t "* || $installed == *" $t "* ]]; then
        run_step "convert --target $t ([$EXTRA] has it)" --cwd "$WS" -- "$BIN" convert "$key" --target "$t"
        check "$t query printed with the attribution header" bash -c "grep -q '^# attribution: ' '$LAST_LOG' && grep -qiE 'whoami|certutil|:' '$LAST_LOG'"
    else
        run_step "convert --target $t without its backend is a clear error" --expect "1 2" --cwd "$WS" -- "$BIN" convert "$key" --target "$t"
        check "error names the extra that provides $t (convert-legacy)" bash -c "tr -d '\n│' < '$LAST_LOG' | tr -s ' ' | grep -q 'sigharvest\[convert-legacy\]'"
    fi
    run_step "convert a YAML file (no workspace rule)" --cwd "$WS" -- "$BIN" convert "$HARNESS/fixtures/sigma/beta/rules/linux_shadow_read.yml" --target loki
    check "file conversion has no attribution header (not a corpus rule)" bash -c "! grep -q '^# attribution:' '$LAST_LOG'"
}

sig_release_offline() {
    local rel="$RUN/exports/release" d
    check "release counts: $SIG_RELEASE_RULES rules, all with YAML" bash -c "r=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$rel/manifest.json' counts.rules); y=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$rel/manifest.json' counts.with_yaml); echo \"rules \$r with_yaml \$y\"; [[ \$r == $SIG_RELEASE_RULES && \$y == $SIG_RELEASE_RULES ]]"
    check "NOTICE.md carries both publishers' copyright lines" bash -c "grep -qF '$SIG_RELEASE_COPYRIGHT_ALPHA' '$rel/NOTICE.md' && grep -qF '$SIG_RELEASE_COPYRIGHT_BETA' '$rel/NOTICE.md'"
    check "permissive zip ships LICENSES/ (DRL + MIT texts, each source's LICENSE)" pycheck archive "$rel/sigharvest-rules-permissive.zip" --has LICENSES/DRL-1.1.txt --has LICENSES/MIT.txt --has LICENSES/fixture-sigma-alpha/LICENSE --has LICENSES/fixture-sigma-beta/LICENSE --has NOTICE.md --grep "NOTICE.md=$SIG_RELEASE_COPYRIGHT_ALPHA"
    check "manifest.json is not marked incomplete" bash -c "! grep -q '\"incomplete\": *true' '$rel/manifest.json'"

    # init --from-release DIR: a workspace from the locally built pack
    run_step "init --from-release DIR (local pack)" --cwd "$HOME" -- "$BIN" init "$RUN/ws-from-release" --from-release "$rel"
    sig_search_json_in() { run_step "$1" --cwd "$2" -- "$CAPTURE" "$3" "$BIN" search --per-logic --limit 1000 --json; }
    sig_search_json_in "search in the from-release workspace" "$RUN/ws-from-release" "$RUN/from-release.json"
    check "from-release workspace has the $SIG_RELEASE_RULES pack rules" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/from-release.json' total); echo \"total \$n\"; [[ \$n == $SIG_RELEASE_RULES ]]"
    run_step "sources list (from-release workspace)" --cwd "$RUN/ws-from-release" -- "$BIN" sources list
    check "one release-<name> local source per original source" bash -c "grep -q 'release-fixture-sigma-alpha' '$LAST_LOG' && grep -q 'release-fixture-sigma-beta' '$LAST_LOG'"
    d=$(sha256sum "$rel/SHA256SUMS" | cut -d' ' -f1)
    run_step "init --from-release DIR --sums-sha256 <right digest>" --cwd "$HOME" -- "$BIN" init "$RUN/ws-from-release-pinned" --from-release "$rel" --sums-sha256 "$d"
    run_step "init --from-release --sums-sha256 <wrong digest> is refused" --expect "1 2" --cwd "$HOME" -- "$BIN" init "$RUN/ws-from-release-bad" --from-release "$rel" --sums-sha256 "$(printf '0%.0s' {1..64})"
    check "refusal names the digest mismatch" grep -qi 'sums-sha256' "$LAST_LOG"
    check "refused init leaves no sources.yaml (no half workspace)" bash -c "! test -e '$RUN/ws-from-release-bad/sources.yaml'"
    rm -rf "$RUN/release-tampered"; cp -a "$rel" "$RUN/release-tampered"; printf 'x' >>"$RUN/release-tampered/rules.jsonl.gz"
    run_step "init --from-release of a tampered pack is refused" --expect "1 2" --cwd "$HOME" -- "$BIN" init "$RUN/ws-from-tampered" --from-release "$RUN/release-tampered"
    check "refusal is a checksum error" grep -qiE 'sha256|checksum' "$LAST_LOG"
}

sig_bump_and_changes() {
    local fx="$RUN/fixture-repos" rel1="$RUN/exports/release" rel2="$RUN/exports/release-2"
    run_step "fixture: upstream changes the DNS rule's detection (same id)" -- python3 -I "$HARNESS/lib/make_fixtures.py" sigma-bump "$fx"
    run_step "update (picks up the changed rule)" --cwd "$WS" -- "$BIN" update
    run_step "changes --json (after the upstream change)" --cwd "$WS" -- "$CAPTURE" "$RUN/changes-bump.json" "$BIN" changes --json
    check "changes: $SIG_BUMP_CHANGED changed (same id, new logic), 0 new, 0 removed" bash -c "c=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/changes-bump.json' changed --len); n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/changes-bump.json' new --len); r=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/changes-bump.json' removed --len); echo \"changed \$c new \$n removed \$r\"; [[ \$c == $SIG_BUMP_CHANGED && \$n == 0 && \$r == 0 ]] && grep -q 'Fixture DNS Query' '$RUN/changes-bump.json'"
    run_step "release build #2 --previous #1" --cwd "$WS" -- "$BIN" release build "$rel2" --previous "$rel1" --build-epoch 1767312000
    [[ -f $rel2/changes.json ]] && check "release #2 changes.json: $SIG_BUMP_CHANGED changed" bash -c "c=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$rel2/changes.json' changed --len); echo \"changed \$c\"; [[ \$c == $SIG_BUMP_CHANGED ]]"
    run_step "changes --from-release #1 --to-release #2 --json" --cwd "$WS" -- "$CAPTURE" "$RUN/changes-releases.json" "$BIN" changes --from-release "$rel1" --to-release "$rel2" --json
    check "changes between releases: $SIG_BUMP_CHANGED changed" bash -c "c=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/changes-releases.json' changed --len); echo \"changed \$c\"; [[ \$c == $SIG_BUMP_CHANGED ]]"
    run_step "changes between a release and a tampered copy is refused" --expect "1 2" --cwd "$WS" -- "$BIN" changes --from-release "$rel1" --to-release "$RUN/release-tampered"
}

# A first update killed mid-run (SIGKILL: no chance to record anything) leaves a partial corpus. search and doctor
# must say so, release build must refuse it (unless --allow-incomplete, then marked), and the next update must
# record the killed run as interrupted and clear the state.
sig_incomplete() {
    local ws="$RUN/ws-incomplete" fx="$RUN/fixture-repos-incomplete" killed=0
    run_step "incomplete: build a second set of fixture repos" -- python3 -I "$HARNESS/lib/make_fixtures.py" sigma "$fx"
    run_step "incomplete: init a second workspace" --cwd "$HOME" -- "$BIN" init "$ws"
    run_step "incomplete: sources add alpha" --cwd "$ws" -- "$BIN" sources add fixture-sigma-alpha "file://$fx/fixture-sigma-alpha" --type git --licence DRL-1.1
    run_step "incomplete: sources add beta" --cwd "$ws" -- "$BIN" sources add fixture-sigma-beta "file://$fx/fixture-sigma-beta" --type git --licence MIT
    local others
    others=$(pycheck sources "$ws/sources.yaml" --enabled --keep "fixture-sigma-alpha,fixture-sigma-beta")
    # shellcheck disable=SC2086
    [[ -n $others ]] && run_step "incomplete: disable the other sources" --cwd "$ws" -- "$BIN" sources disable $others
    check "incomplete: only the fixtures enabled" bash -c "[[ -z \$('$TOOL_PY' -I '$HARNESS/lib/checks.py' sources '$ws/sources.yaml' --enabled --keep fixture-sigma-alpha,fixture-sigma-beta) ]]" ||
        { skip "incomplete-corpus gating" "other sources still enabled (would hit the network)"; return; }
    # kill -9 once the run row exists and at least one rule version is stored (a partial corpus)
    run_step "first update killed with SIGKILL mid-run" --cwd "$ws" -- "$TOOL_PY" -I "$HARNESS/lib/checks.py" interrupt "$ws/data/sigharvest.db" \
        "select count(*) from update_runs where finished_at is null and exists (select 1 from rule_versions)" -- "$BIN" update && killed=1
    if [[ $killed != 1 ]]; then
        skip "incomplete-corpus checks" "could not interrupt the first update (see the previous step)"
        return
    fi
    run_step "incomplete: search warns" --cwd "$ws" -- "$BIN" search whoami
    check "search says 'corpus incomplete'" grep -q 'corpus incomplete' "$LAST_LOG"
    run_step "incomplete: doctor reports it" --expect "0 1" --cwd "$ws" -- "$BIN" doctor
    check "doctor says 'corpus incomplete'" grep -q 'corpus incomplete' "$LAST_LOG"
    run_step "incomplete: stats reports it" --expect "0 1" --cwd "$ws" -- "$BIN" stats
    want "stats says 'incomplete'" grep -qi 'incomplete' "$LAST_LOG"
    run_step "incomplete: release build refuses (exit 1)" --expect 1 --cwd "$ws" -- "$BIN" release build "$RUN/exports/release-incomplete" --build-epoch 1767225600
    check "release refusal names the incomplete corpus and --allow-incomplete" bash -c "grep -q 'corpus incomplete' '$LAST_LOG' && grep -q -- '--allow-incomplete' '$LAST_LOG'"
    check "refused release wrote no pack" bash -c "! test -e '$RUN/exports/release-incomplete/manifest.json'"
    run_step "incomplete: site build refuses" --expect "1 2" --cwd "$ws" -- "$BIN" site build "$RUN/exports/site-incomplete"
    check "site build refusal names the incomplete corpus" grep -q 'corpus incomplete' "$LAST_LOG"
    run_step "incomplete: update again (completes)" --cwd "$ws" -- "$BIN" update
    run_step "incomplete: runs list" --cwd "$ws" -- "$BIN" runs list
    check "the killed run is recorded as interrupted" grep -qE '(status: interrupted|^[│| ]*1 .*interrupted)' "$LAST_LOG"
    run_step "incomplete: search after the full update" --cwd "$ws" -- "$BIN" search whoami
    check "no 'corpus incomplete' line any more" bash -c "! grep -q 'corpus incomplete' '$LAST_LOG'"
    run_step "incomplete: release build works after the full update" --cwd "$ws" -- "$BIN" release build "$RUN/exports/release-after-incomplete" --build-epoch 1767225600
    check "that release is not marked incomplete" bash -c "test -f '$RUN/exports/release-after-incomplete/manifest.json' && ! grep -q '\"incomplete\": *true' '$RUN/exports/release-after-incomplete/manifest.json'"
}

tool_web() {
    local port url k
    port=$(free_port)
    url="http://127.0.0.1:$port"
    STEP_N=$((STEP_N + 1))
    local t0; t0=$(_now)
    (cd "$WS" && exec "$BIN" serve --host 127.0.0.1 --port "$port") >"$RUN/logs/server.log" 2>&1 </dev/null &
    SERVER_PID=$!
    local up=0
    for _ in $(seq 1 120); do
        if curl -fsS -o /dev/null "$url/" 2>/dev/null; then up=1; break; fi
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.5
    done
    local secs; secs=$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')
    if [[ $up != 1 ]]; then
        _record FAIL "$secs" "serve: start on $url" "$RUN/logs/server.log" "not answering; $(tail -n 3 "$RUN/logs/server.log" | tr '\n' ' ')"
        return
    fi
    _record OK "$secs" "serve: start on $url" "$RUN/logs/server.log" "up"
    k=${KEY:-0000000000}
    local q=whoami; [[ $MODE == online ]] && q=mimikatz
    http_get "GET /" "$url/"
    http_get "GET /overview" "$url/overview"
    http_get "GET /search?q=$q" "$url/search?q=$q"
    http_get "GET /search (empty)" "$url/search"
    if [[ -n ${KEY:-} ]]; then
        http_get "GET /rule/<key>" "$url/rule/$k"
        http_get "GET /rule/<key>/yaml" "$url/rule/$k/yaml" any
        http_get "GET /family/<key>" "$url/family/$k"
        http_get "GET /api/rule/<key>" "$url/api/rule/$k" json
        http_get "GET /api/convert/<key>?target=splunk" "$url/api/convert/$k?target=splunk" json
    else
        skip "rule, family and /api/rule pages" "no rule key (search found nothing)"
    fi
    http_get "GET /sources" "$url/sources"
    http_get "GET /coverage" "$url/coverage"
    http_get "GET /coverage/navigator.json" "$url/coverage/navigator.json" json
    http_get "GET /search/export?q=$q (download)" "$url/search/export?q=$q" any
    http_get "GET /api/search?q=$q" "$url/api/search?q=$q" json
    http_get "GET /api/facets" "$url/api/facets" json
    http_get "GET /static/app.js" "$url/static/app.js" any
    check "GET /rule/<unknown> is 404, not 500" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url/rule/deadbeefdeadbeef" --kind any --status 404
    check "GET /search?q=<script> does not reflect raw HTML" bash -c "! curl -fsS '$url/search?q=%3Cscript%3Ealert(1)%3C/script%3E' | grep -q '<script>alert(1)'"
    check "POST without same-origin is refused" bash -c "code=\$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Origin: http://evil.invalid' '$url/collections'); echo \"HTTP \$code\"; [[ \$code == 403 || \$code == 405 || \$code == 404 ]]"
    check "Host header check (DNS rebinding)" bash -c "code=\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.invalid' '$url/'); echo \"HTTP \$code\"; [[ \$code == 400 || \$code == 403 || \$code == 421 ]]"
    if [[ $KEEP_SERVER == 1 ]]; then log "server left running: $url (pid $SERVER_PID)"; SERVER_PID=""; return; fi
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
    check "server log has no traceback" bash -c "! grep -E '$BAD_OUTPUT_RE' '$RUN/logs/server.log'"
    check "port released after stop" bash -c "! curl -s -o /dev/null '$url/'"
}
