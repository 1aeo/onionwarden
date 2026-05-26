# onionwarden — 5-round refactor critique

Sequential DRY / helper-extraction / loop-simplification / variable-consolidation
audit of the `1aeo/onionwarden` codebase (57 shell+python source files, ~7.9k
LoC). All file paths are relative to the repo root.

## Executive summary

1. **Diff-pattern explosion** — 35 callsites of `comm -13/-23 <(filter "$base")
   <(filter "$cur")` repeat the same 4-line incantation. A 6-line helper pair
   collapses every callsite to one line.
2. **Three near-identical flat-JSON field readers** (`manifest_get`,
   `_supp_field`, `sev_of`, plus inline `sed -n 's/.*"X":"...".*/\1/p'` chains)
   can share one `json_field` helper in `common.sh`.
3. **`awk -F= '$1=="K"{print $2}' | head -n1`** appears 3× in `lib/fatal.sh`
   reading per-state-file scalars; one `kv_read` helper saves the boilerplate.

Combined: ~80-100 net LoC reduced with zero behavioural risk (every change is
a pure extraction; output bytes identical).

---

## Round 1 — DRY scan (findings)

| # | Pattern | Instances | Locations |
|---|---------|-----------|-----------|
| 1 | `comm -13 <(filter "$base_file") <(filter "$cur_file")` | 29 | `lib/checks/*.sh` (28) + `bin/onionwarden-baseline:98` |
| 2 | `comm -23 …` (removed-set companion) | 6 | `lib/checks/*.sh` (4) + `bin/onionwarden-baseline:99` + `lib/checks/modules.sh:47` |
| 3 | flat-JSON string extraction | 3 families | `lib/baseline.sh:32` (`manifest_get`), `lib/suppress.sh:28` (`_supp_field`), `bin/onionwarden-run:320` (`sev_of`) + ad-hoc seds at 386 & 408 |
| 4 | `awk -F= '$1=="K"{print $2}' F \| head -n1` | 3 | `lib/fatal.sh:44, 74, 77` |
| 5 | sourced-once-guard header | 10 | every file under `lib/*.sh` |
| 6 | `command -v X >/dev/null 2>&1` | 52 | everywhere; bypasses the existing `require_cmd` |
| 7 | `mkdir -p P 2>/dev/null \|\| true` | 5 | run-time state dir creation across bin/* and lib/suppress.sh |
| 8 | `cat F 2>/dev/null \|\| printf 0` | 7 | counters/state files in alert.sh, baseline.sh, suppress.sh, profile.sh, onionwarden-run |
| 9 | per-check `_collect` "OS not Linux → printf na" early-exit | 4 | `boot_integrity`, `kernel_state`, `modules`, `nested_vm` (different shape — left alone) |
| 10 | per-check CLI shim (`if [ BASH_SOURCE = $0 ]; then check_run_cli "$@"; fi`) | 24 | every `lib/checks/*.sh` |

## Round 2 — Helper extraction (proposals)

Building on Round 1; the four worth extracting are:

1. **`state_added_field BASE CUR FIELD [COL]`** + **`state_removed_field`** — the
   awk-`$1==X` flavour (12 callsites). `COL` defaults to 2.
2. **`state_added_prefix BASE CUR PREFIX`** + **`state_removed_prefix`** — the
   grep-`^X ` flavour (16 callsites).
3. **`json_field FILE KEY`** in `lib/common.sh` — replaces `manifest_get`
   (`lib/baseline.sh:32`), `_supp_field` (`lib/suppress.sh:28`), and the inline
   `sev_of` shape.
4. **`kv_read FILE KEY`** in `lib/common.sh` — replaces 3 `awk -F='$1=="K"…'`
   calls in `lib/fatal.sh`.

Not extracted (deliberately):
- `command -v X >/dev/null 2>&1` → `require_cmd` already exists; 52 mechanical
  rewrites across nearly every file is too churny for net 1-line wins.
- The sourced-once guard cannot be wrapped in a function (the function does not
  exist yet when the file is first sourced).
- The per-check CLI shim is already 3 lines and can't shrink without per-file
  invariants.

## Round 3 — Loop / iteration simplification

- `bin/onionwarden-snapshot:376-398` runs a manual counted loop to invoke N
  parallel SSH preflights and then a second manual loop to count successes —
  could be a single loop or a `seq 1 N` / `find` count, but the imperative
  variant is already clear and bash-3.2 safe. **Skip.**
- `lib/checks/hardware.sh:111-129` walks `mount` lines and re-runs sets of
  `case ",$opts," in *,noexec,*) ... esac` — fine; bash has no comprehension.
- `bin/onionwarden-run:380-389` while-reads findings; could be one `grep -E |
  while`. Marginal. **Skip.**
- `bin/onionwarden-baseline:91-118` uses `comm`. Caught above in Round 1.
- Net: **no Round-3-specific changes** beyond what Round 2 already covers.

## Round 4 — Variable consolidation

- `lib/fatal.sh:30-31` defines `fatal_armed_file`/`fatal_cooldown_file` as
  one-line `printf` functions; each is called twice. **Could** be inlined as
  `"$(onionwarden_state_dir)/fatal_armed"`. Saves 4 lines but loses one
  intention-revealing name; left alone.
- `bin/onionwarden-run:113` packs `NA_COUNT DISABLED_COUNT CLEAN_COUNT
  DEVIATION_COUNT FINDING_COUNT` on one line — already consolidated.
- `bin/onionwarden-run:373-375` could collapse `case "$RUN_MAX_SEV" in
  WARN|CRIT) deadman_ping fail ;; *) deadman_ping ok ;; esac` to a one-liner;
  current shape is clearest. **Skip.**

## Round 5 — Synthesis

Net LoC saved per proposal (count from `git diff --stat`-style estimate):

| Proposal | Saved | Risk | Verdict |
|---|---|---|---|
| `state_added/removed_{field,prefix}` helpers | **~70-85 LoC** | Low (pure stdout transformation) | **HIGH** |
| `json_field` shared helper, replace 3 inline JSON readers | **~12 LoC** | Low | **HIGH** |
| `kv_read` helper for `awk -F= '$1=="K"{print $2}'` | **~3 LoC** | Trivial | **HIGH** (folded into same commit as json_field) |
| Inline `fatal_armed_file`/`fatal_cooldown_file` | 4 | Low | LOW (readability tradeoff) |
| `command -v` → `require_cmd` blanket pass | 52 | Medium (52 files) | REJECTED — diff size dominates the actual saving |
| Per-check CLI shim removal | 72 | High (changes invocation model) | REJECTED |
| Test fixture consolidation | 80-100 | High (would touch every test) | REJECTED |

---

## HIGH PRIORITY (will apply)

### H1. Diff helpers in `lib/common.sh`

Add four helpers, refactor 35 callsites.

Before (typical, in `lib/checks/auth_log.sh:84-86`):
```bash
  done <<< "$(comm -13 \
      <(awk '$1=="sudouser"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="sudouser"{print $2}' "$cur_file" | sort -u))"
```

After:
```bash
  done <<< "$(state_added_field "$base_file" "$cur_file" sudouser 2)"
```

Helpers (in `lib/common.sh`):
```bash
state_added_field()   { comm -13 <(awk -v f="$3" -v c="${4:-2}" '$1==f{print $c}' "$1" 2>/dev/null | sort -u) <(awk -v f="$3" -v c="${4:-2}" '$1==f{print $c}' "$2" 2>/dev/null | sort -u); }
state_removed_field() { comm -23 <(awk -v f="$3" -v c="${4:-2}" '$1==f{print $c}' "$1" 2>/dev/null | sort -u) <(awk -v f="$3" -v c="${4:-2}" '$1==f{print $c}' "$2" 2>/dev/null | sort -u); }
state_added_prefix()  { comm -13 <(grep "^$3 " "$1" 2>/dev/null | sort -u) <(grep "^$3 " "$2" 2>/dev/null | sort -u); }
state_removed_prefix() { comm -23 <(grep "^$3 " "$1" 2>/dev/null | sort -u) <(grep "^$3 " "$2" 2>/dev/null | sort -u); }
```

Callsites refactored (file:line, sample):
- `lib/checks/accounts.sh:86,95`
- `lib/checks/auth_log.sh:84,93`
- `lib/checks/console_login.sh:68,80`
- `lib/checks/filesystem.sh:80`
- `lib/checks/hardware.sh:95,105,127,138`
- `lib/checks/input_devices.sh:111,120,129,139`
- `lib/checks/kernel_state.sh:222`
- `lib/checks/ld_preload.sh:74`
- `lib/checks/modules.sh:98,105`
- `lib/checks/nested_vm.sh:75,84,93`
- `lib/checks/network_deep.sh:160,183,192`
- `lib/checks/ports.sh:159,168`
- `lib/checks/process_ancestry.sh:100`
- `lib/checks/scheduled.sh:101,109,123`
- `lib/checks/snap.sh:85`
- `bin/onionwarden-baseline:98,99` (whole-file variant — not refactored;
  `comm -13/-23 <(sort -u "$b") <(sort -u "$c")` is already a one-liner.)

Two callsites have shapes that don't fit cleanly and are left as-is:
- `lib/checks/modules.sh:47` — runs `tr -d '\t'` post-pipe; idiosyncratic.
- `lib/checks/kernel_state.sh:222` (awk multi-condition `$2!="na"&&$2!="none"`)
  — keep the inline filter.

### H2. `json_field FILE KEY` helper in `lib/common.sh`

Unify `manifest_get` (`lib/baseline.sh:32-48`) and `_supp_field`
(`lib/suppress.sh:28-33`).

Helper (in `lib/common.sh`):
```bash
# json_field FILE KEY — extract a string field from one-line flat JSON.
# (We only ever parse our own emitted JSON — never untrusted input.)
json_field() {
  awk -v k="$2" '
    { if (match($0, "\"" k "\"[ ]*:[ ]*\"")) {
        r = substr($0, RSTART + RLENGTH); q = index(r, "\"")
        print substr(r, 1, q - 1); exit } }' "$1"
}
```

Then:
- `lib/baseline.sh` — keep `manifest_get` as a thin wrapper (some callers
  expect the bare-number-or-string variant), but reuse `json_field` for the
  string path.
- `lib/suppress.sh` — drop `_supp_field`, call `json_field` directly.

### H3. `kv_read FILE KEY` helper in `lib/common.sh`

Replace `awk -F= '$1=="K"{print $2}' F | head -n1` (3 callsites in
`lib/fatal.sh`, plus 1 in `bin/onionwarden-onboard:430`).

```bash
# kv_read FILE KEY — read first `KEY=VALUE` from a flat key=value file.
# VALUE may contain `=`; everything after the first `=` is preserved
# (the old `-F=` split would truncate `KEY=a=b` to `a`).
kv_read() {
  awk -v k="$2" '
    { p = k "="
      if (substr($0, 1, length(p)) == p) { print substr($0, length(p) + 1); exit } }
  ' "$1" 2>/dev/null
}
```

Callsites refactored:
- `lib/fatal.sh:44` `_fatal_armed_scope`
- `lib/fatal.sh:74,77` `_fatal_in_cooldown`

---

## MEDIUM PRIORITY (not applied this pass)

- **M1** `cat F 2>/dev/null || printf 0` → `read_or_default F 0` — 7 instances.
  Saves ~7 LoC; trivial gain, not worth the per-file churn.
- **M2** `mkdir -p P 2>/dev/null || true` → `ensure_dir P` — 5 instances.
  Saves ~3 LoC; same trade.
- **M3** Inline `fatal_armed_file`/`fatal_cooldown_file` — 4 LoC saved, but
  the named functions are the only callers' interface.
- **M4** `sev_of` in `bin/onionwarden-run:320` (sed-based severity extract) +
  inline regex at `bin/onionwarden-run:386,408` (summary). The inline shapes
  use different regexes (one captures `[A-Z]*`, the other `[^"]*`); folding
  into one helper changes the contract. Left alone.

## LOW PRIORITY (just listed)

- `lib/common.sh:36-47` `json_escape` reads `$1` into a local and does five
  bash parameter expansions back-to-back — readable, leave alone.
- `bin/onionwarden-snapshot:165-172` `_strip` uses awk's `index($0, …)` then a
  skip counter — clear; leave alone.
- `lib/profile.sh:38` `_b()` is a one-line bool — fine as-is.
- `lib/checks/hardware.sh:111-129` mount-options check duplicates the
  `findmnt`/`mount` parser; could be a helper, but the two parsers really do
  shape-different lines.
- `bin/onionwarden-fatal` and `bin/onionwarden-suppress` share argparse-style
  while-`shift` loops; identical *pattern*, different *args*. Not worth a
  generic option parser.

## REJECTED / out-of-scope

- **`command -v` → `require_cmd` mechanical sweep** (52 callsites). Mechanical
  change with one-line-per-callsite net saving; the diff dominates the
  benefit and increases review friction for no behavioural gain.
- **Per-check CLI shim removal.** Cannot collapse below 3 lines without
  inventing an autoload mechanism that would change how checks are invoked
  (tests, snapshot bundle).
- **Test fixture consolidation.** `conftest.py:31-60` (`run_analyze`) is
  already the consolidated helper; further pull-up into the bats suite or the
  receiver tests would touch every test file for marginal gain.
- **Snapshot single-bundle / per-check bundle de-duplication** in
  `bin/onionwarden-snapshot:185-280`. The two bundle generators share a
  `_emit_lib_prologue` + watchdog `__snap`/`__snap_one` shape, but the
  full-bundle variant carries delimiter markers (`###ONIONWARDEN-SNAPSHOT…`)
  that the per-check variant does not. Re-deduplication risks breaking the
  `awk` stream-splitter at `:346-362`.
- **Sourced-once guard normalisation.** Cannot be a function call (the
  function isn't yet defined when the first file is sourced). A `source-once`
  preamble macro saves at most 1 line per file.
