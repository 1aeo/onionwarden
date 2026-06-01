# shellcheck shell=bash
# lib/stage_tracker.sh — hierarchical stage-output convention for onionwarden.
#
# Fleet-wide convention shared with onionleak and onionarmor. Every
# stage-emitting script sources this file and brackets its work in
# stage_begin / stage_ok|stage_skip|stage_fail pairs so an operator sees a
# stable, greppable progress stream on stderr.
#
# Output shape (one line per stage, on stderr):
#
#   [onionwarden] [<ancestor>] <parent>, n/N. <stage> : <status>
#
# Concretely:
#   * Every line carries the `[onionwarden] ` prefix so the whole run is
#     greppable as `grep '^\[onionwarden\] '`.
#   * `<index>/<total> <name>` is the stage marker (1-based index out of the
#     total stages at that level).
#   * A stage's IMMEDIATE parent is comma-joined to it: `parent, child`.
#   * Any GRANDPARENT (and higher ancestor) is bracketed: `[grandparent] `.
#   * `: <status>` is the terminal status — `ok (0.4s)`, `skipped: <reason>`,
#     or `failed: <reason>`.
#
#   [onionwarden] 1/3 baseline check, 1/4 hash kernel image : ok (0.2s)
#   [onionwarden] [1/3 baseline check] 3/4 read SUID table, 1/2 walk /usr/bin : ok (0.4s)
#   [onionwarden] 2/3 watchdog tick : ok (1.1s)
#
# Nesting works two ways, transparently:
#   * In-process: nested stage_begin calls push onto an internal stack.
#   * Across processes: stage_begin exports ONIONWARDEN_STAGE_PARENT (a
#     unit-separator-joined marker list). A child process that also sources
#     this file reads it and renders its own stages underneath the parent's
#     hierarchy. This is how `onionwarden-baseline` brackets the per-check
#     collectors it spawns. Mirrors onionleak's _StageTracker / common.sh.
#
# Quiet mode: ONIONWARDEN_STAGES=0 suppresses every stage line (status lines
# still influence nothing else — they are pure operator UX). Default is on.
#
# Portability: bash 3.2 (macOS test host) and bash 5 (Ubuntu/Debian). No
# associative arrays, no mapfile. Safe under `set -u`.

# Guard against double-sourcing.
if [ -n "${_ONIONWARDEN_STAGE_TRACKER_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_STAGE_TRACKER_SH=1

# Tool label rendered in the leading bracket.
_STAGE_TOOL="onionwarden"
# Unit Separator (0x1f) — joins markers in the cross-process env var. Markers
# carry spaces and slashes but never a US byte, so it is an unambiguous split.
_STAGE_US=$(printf '\037')

# Snapshot the inherited parent chain ONCE at source time. We render our own
# lines from this immutable copy and are then free to overwrite the exported
# ONIONWARDEN_STAGE_PARENT with the deeper chain handed to child processes.
_STAGE_INHERITED="${ONIONWARDEN_STAGE_PARENT:-}"

# In-process stack of active stages (parallel arrays). Each entry is a marker
# "n/N name" plus the monotonic-ish start time captured at stage_begin.
_STAGE_NAMES=()
_STAGE_STARTS=()

# Per-run summary accumulator ("stage 0.2s, stage 1.1s, ...").
_STAGE_SUMMARY=""

# --- time helpers (portable; mirror onionleak's common.sh) ----------------
_stage_now() {
  # Prefer GNU `date +%s.%N`; BSD date lacks %N and prints a literal N, so
  # fall back to whole seconds there. Either form feeds awk fine.
  local out
  out="$(date +%s.%N 2>/dev/null)"
  case "$out" in
    *N*) date +%s ;;
    *)   printf '%s\n' "$out" ;;
  esac
}

_stage_fmt_elapsed() {
  # Render a (possibly decimal) seconds value as "0.4s".
  awk -v t="$1" 'BEGIN { if (t < 0) t = 0; printf "%.1fs\n", t }'
}

# --- chain rendering ------------------------------------------------------
_stage_chain() {
  # Populate the global array _STAGE_CHAIN with the full ancestor+current
  # marker list: inherited (cross-process) markers first, then in-process
  # frames outermost-first.
  _STAGE_CHAIN=()
  if [ -n "$_STAGE_INHERITED" ]; then
    local IFS="$_STAGE_US" m
    for m in $_STAGE_INHERITED; do
      _STAGE_CHAIN+=("$m")
    done
  fi
  if [ "${#_STAGE_NAMES[@]}" -gt 0 ]; then
    _STAGE_CHAIN+=(${_STAGE_NAMES[@]+"${_STAGE_NAMES[@]}"})
  fi
}

_stage_render() {
  # Render _STAGE_CHAIN into the prefix string. The last element (the current
  # stage) is bare; the second-to-last (immediate parent) is comma-joined; any
  # earlier ancestor is bracketed.
  local n=${#_STAGE_CHAIN[@]}
  [ "$n" -eq 0 ] && { printf ''; return; }
  local out="" i
  i=0
  while [ "$i" -lt "$n" ]; do
    if [ "$i" -eq $((n - 1)) ]; then
      out="${out}${_STAGE_CHAIN[$i]}"
    elif [ "$i" -eq $((n - 2)) ]; then
      out="${out}${_STAGE_CHAIN[$i]}, "
    else
      out="${out}[${_STAGE_CHAIN[$i]}] "
    fi
    i=$((i + 1))
  done
  printf '%s' "$out"
}

_stage_emit() {
  # Print one stage/log line to stderr: "[onionwarden] <chain> : <text>".
  # With an empty chain (a bare log outside any stage) the " : " is dropped.
  [ "${ONIONWARDEN_STAGES:-1}" = "0" ] && return 0
  local text="$*" chain
  _stage_chain
  chain="$(_stage_render)"
  if [ -n "$chain" ]; then
    printf '[%s] %s : %s\n' "$_STAGE_TOOL" "$chain" "$text" >&2
  else
    printf '[%s] %s\n' "$_STAGE_TOOL" "$text" >&2
  fi
}

_stage_publish_parent() {
  # Re-export ONIONWARDEN_STAGE_PARENT = inherited markers + every in-process
  # frame, so a child process descends underneath the deepest active stage.
  local parts=() IFS m
  if [ -n "$_STAGE_INHERITED" ]; then
    IFS="$_STAGE_US"
    for m in $_STAGE_INHERITED; do parts+=("$m"); done
    unset IFS
  fi
  if [ "${#_STAGE_NAMES[@]}" -gt 0 ]; then
    parts+=(${_STAGE_NAMES[@]+"${_STAGE_NAMES[@]}"})
  fi
  if [ "${#parts[@]}" -gt 0 ]; then
    IFS="$_STAGE_US"
    ONIONWARDEN_STAGE_PARENT="${parts[*]}"
    unset IFS
  else
    ONIONWARDEN_STAGE_PARENT=""
  fi
  export ONIONWARDEN_STAGE_PARENT
}

# --- public API -----------------------------------------------------------
stage_begin() {
  # stage_begin <index> <total> <name...>  — open a stage. No line is printed
  # on entry; the terminal status line (stage_ok/skip/fail) carries the marker.
  local n="$1" total="$2"; shift 2
  _STAGE_NAMES+=("$n/$total $*")
  _STAGE_STARTS+=("$(_stage_now)")
  _stage_publish_parent
}

_stage_close() {
  # _stage_close <kind> [extra...]  — pop the current frame and emit its status.
  # kind: ok | skipped | failed | raw.
  local kind="$1"; shift
  local depth=${#_STAGE_NAMES[@]}
  [ "$depth" -eq 0 ] && return 0
  local idx=$((depth - 1))
  local start="${_STAGE_STARTS[$idx]}" name="${_STAGE_NAMES[$idx]}"
  local elapsed_fmt
  elapsed_fmt="$(_stage_fmt_elapsed "$(awk -v a="$(_stage_now)" -v b="$start" \
    'BEGIN { printf "%.2f", a - b }')")"
  local text
  case "$kind" in
    ok)      text="ok ($elapsed_fmt)" ;;
    skipped) text="skipped: $*" ;;
    failed)  text="failed: $*" ;;
    *)       text="${*:-ok}" ;;
  esac
  _stage_emit "$text"
  # Record for the optional end-of-run summary (name + elapsed).
  local short="${name#*/* }"   # strip the "n/N " marker prefix
  if [ -n "$_STAGE_SUMMARY" ]; then
    _STAGE_SUMMARY="$_STAGE_SUMMARY, $short $elapsed_fmt"
  else
    _STAGE_SUMMARY="$short $elapsed_fmt"
  fi
  # Pop the frame (and re-pack so set -u stays happy on the now-shorter array).
  unset "_STAGE_NAMES[$idx]"
  unset "_STAGE_STARTS[$idx]"
  if [ "$idx" -gt 0 ]; then
    _STAGE_NAMES=(${_STAGE_NAMES[@]+"${_STAGE_NAMES[@]}"})
    _STAGE_STARTS=(${_STAGE_STARTS[@]+"${_STAGE_STARTS[@]}"})
  else
    _STAGE_NAMES=()
    _STAGE_STARTS=()
  fi
  _stage_publish_parent
}

stage_ok()   { _stage_close ok; }
stage_skip() { _stage_close skipped "$*"; }
stage_fail() { _stage_close failed "$*"; }
stage_end()  { _stage_close raw "${*:-ok}"; }

stage_log() {
  # stage_log <message...>  — an in-stage diagnostic line carrying the same
  # hierarchical prefix as the surrounding stage markers (current stage becomes
  # the immediate parent of the message). Outside any stage it renders bare.
  _stage_emit "$*"
}

stage_summary() {
  # Print the accumulated one-line run summary (always, even when ONIONWARDEN_
  # STAGES=0 would suppress per-stage lines — it is the "what happened" line).
  [ -n "$_STAGE_SUMMARY" ] || return 0
  _stage_chain
  local chain; chain="$(_stage_render)"
  if [ -n "$chain" ]; then
    printf '[%s] %s : stage summary: %s\n' "$_STAGE_TOOL" "$chain" "$_STAGE_SUMMARY" >&2
  else
    printf '[%s] stage summary: %s\n' "$_STAGE_TOOL" "$_STAGE_SUMMARY" >&2
  fi
}
