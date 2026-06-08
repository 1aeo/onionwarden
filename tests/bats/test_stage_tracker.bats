#!/usr/bin/env bats
# Regression tests for the hierarchical stage-output convention
# (lib/stage_tracker.sh). Shared fleet-wide with onionleak + onionarmor.
#
# Canonical shape (stderr):
#   [onionwarden] [<ancestor>] <parent>, n/N. <stage> : <status>
#
# Covered: prefix shape, status vocabulary (ok/skipped/failed), nested
# (2- and 3-level) prefixes, sibling index increment, cross-process parent
# propagation via ONIONWARDEN_STAGE_PARENT, in-stage log prefix, quiet mode,
# and an end-to-end check of bin/onionwarden-run's per-check sub-stages.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  TRACKER="$REPO/lib/stage_tracker.sh"
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/owarden-stage.XXXXXX")
}

teardown() {
  rm -rf "$TMP"
}

# --- prefix shape + status vocabulary -------------------------------------

@test "flat stage: single top-level stage prints the [onionwarden] N/M marker" {
  run bash -c ". '$TRACKER'; stage_begin 2 3 'watchdog tick'; stage_ok"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^\[onionwarden\]\ 2/3\ watchdog\ tick\ :\ ok\ \([0-9] ]]
}

@test "status: ok appends runtime in parentheses" {
  run bash -c ". '$TRACKER'; stage_begin 1 1 'x'; stage_ok"
  [[ "$output" =~ :\ ok\ \([0-9]+\.[0-9]+s\)$ ]]
}

@test "status: skipped carries the reason and no runtime" {
  run bash -c ". '$TRACKER'; stage_begin 1 2 'probe'; stage_skip 'capability absent'"
  [[ "$output" == *"[onionwarden] 1/2 probe : skipped: capability absent"* ]]
}

@test "status: failed carries the reason" {
  run bash -c ". '$TRACKER'; stage_begin 1 2 'probe'; stage_fail 'permission denied'"
  [[ "$output" == *"[onionwarden] 1/2 probe : failed: permission denied"* ]]
}

# --- nested-stage prefixes ------------------------------------------------

@test "nested 2-level: immediate parent is comma-joined to the child" {
  run bash -c ". '$TRACKER'; stage_begin 1 3 'baseline check'; stage_begin 1 4 'hash kernel image'; stage_ok"
  [[ "$output" == *"[onionwarden] 1/3 baseline check, 1/4 hash kernel image : ok ("* ]]
}

@test "nested 3-level: grandparent is bracketed, parent comma-joined" {
  run bash -c ". '$TRACKER'
    stage_begin 1 3 'baseline check'
    stage_begin 3 4 'read SUID table'
    stage_begin 1 2 'walk /usr/bin'
    stage_ok"
  [[ "$output" == *"[onionwarden] [1/3 baseline check] 3/4 read SUID table, 1/2 walk /usr/bin : ok ("* ]]
}

@test "stage indices increment across sibling stages" {
  run bash -c ". '$TRACKER'
    stage_begin 1 3 'a'; stage_ok
    stage_begin 2 3 'b'; stage_ok
    stage_begin 3 3 'c'; stage_ok"
  [[ "$output" == *"1/3 a : ok"* ]]
  [[ "$output" == *"2/3 b : ok"* ]]
  [[ "$output" == *"3/3 c : ok"* ]]
}

# --- cross-process parent propagation -------------------------------------

@test "cross-process: ONIONWARDEN_STAGE_PARENT prefixes a child process's stages" {
  run bash -c "
    . '$TRACKER'
    stage_begin 1 2 'collect baseline'
    bash -c \". '$TRACKER'; stage_begin 3 7 'classify connections'; stage_ok\"
    stage_ok"
  [[ "$output" == *"[onionwarden] 1/2 collect baseline, 3/7 classify connections : ok ("* ]]
}

# --- in-stage log line ----------------------------------------------------

@test "stage_log carries the current-stage hierarchical prefix" {
  run bash -c ". '$TRACKER'; stage_begin 1 4 'check ssh'; stage_log 'authorized_keys unchanged'; stage_ok"
  [[ "$output" == *"[onionwarden] 1/4 check ssh : authorized_keys unchanged"* ]]
}

# --- quiet mode -----------------------------------------------------------

@test "quiet mode: ONIONWARDEN_STAGES=0 suppresses every stage line" {
  # stage_summary is included so any future regression that leaks the summary
  # line through quiet mode is caught (CodeRabbit). stage_ok populates
  # _STAGE_SUMMARY, then stage_summary must produce no output.
  run bash -c "ONIONWARDEN_STAGES=0; export ONIONWARDEN_STAGES; . '$TRACKER'; stage_begin 1 1 'x'; stage_ok; stage_log 'hi'; stage_summary"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

# --- end-to-end: onionwarden-run emits nested per-check sub-stages ---------

@test "onionwarden-run --from-snapshot emits hierarchical run-checks sub-stages" {
  # Snapshot mode needs no signed baseline and never probes the host: it reads
  # pre-captured state from the snapshot dir. An empty snapshot makes every
  # check report "not in snapshot" — fast and deterministic on any CI host.
  SNAP="$TMP/snap"; mkdir -p "$SNAP"
  : > "$SNAP/profile.state"
  export ONIONWARDEN_VAR_DIR="$TMP/var"
  export ONIONWARDEN_LOG_DIR="$TMP/log"
  export ONIONWARDEN_STATE_DIR="$TMP/state"
  export ONIONWARDEN_CONF_DIR="$TMP/etc"
  mkdir -p "$ONIONWARDEN_VAR_DIR" "$ONIONWARDEN_LOG_DIR" "$ONIONWARDEN_STATE_DIR" "$ONIONWARDEN_CONF_DIR"
  run "$REPO/bin/onionwarden-run" --from-snapshot "$SNAP"
  [ "$status" -eq 0 ]
  # Top-level parent stage and at least one comma-joined per-check sub-stage.
  [[ "$output" == *"[onionwarden] 1/1 run checks (fast)"* ]]
  [[ "$output" == *"run checks (fast), "*" check "* ]]
}
