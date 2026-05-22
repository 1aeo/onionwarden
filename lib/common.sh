# shellcheck shell=bash
# lib/common.sh — shared primitives for onionwarden.
#
# Sourced by every bin/ entrypoint and every lib/checks/*.sh module.
# POSIX-leaning bash, must run on bash 3.2+ (the test host) and bash 5 (Ubuntu/Debian).
# No associative arrays, no ${var,,}, no mapfile.

# Guard against double-sourcing.
if [ -n "${_ONIONWARDEN_COMMON_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_COMMON_SH=1

# --- severity model -------------------------------------------------------
# NA  = detect-and-skip (capability absent); not a deviation.
# OK  = check ran, no deviation.
# INFO/WARN/CRIT = deviations of rising severity.
sev_rank() {
  case "$1" in
    CRIT) printf '3' ;;
    WARN) printf '2' ;;
    INFO) printf '1' ;;
    OK|NA|DISABLED) printf '0' ;;
    *) printf '0' ;;
  esac
}

# sev_max A B -> the higher-ranked of two severities
sev_max() {
  if [ "$(sev_rank "$1")" -ge "$(sev_rank "$2")" ]; then printf '%s' "$1"; else printf '%s' "$2"; fi
}

# --- JSON emission --------------------------------------------------------
# We only ever *emit* JSON (with printf) and read our own flat manifests.
# We never parse untrusted arbitrary JSON in the watchdog runtime — that
# keeps jq off the Phase-1 dependency list (PLAN §7).

json_escape() {
  # Escape a string for use as a JSON string value.
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  # Strip any remaining raw control characters (defensive; our inputs are tame).
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
  printf '%s' "$s"
}

# emit_finding CHECK SIGNAL SEVERITY SUMMARY BASELINE OBSERVED [FATAL_CANDIDATE]
#
# Prints ONE newline-delimited JSON "finding-core" object to stdout. analyze()
# functions emit only this core (deterministic, no timestamps) — the dispatcher
# enriches with ts/run_id/host_id when it logs. Keeping analyze output free of
# wall-clock data is what makes the checks unit-testable as pure functions.
emit_finding() {
  local check=$1 signal=$2 severity=$3 summary=$4 baseline=$5 observed=$6
  local fatal=${7:-false}
  case "$fatal" in true|false) ;; *) fatal=false ;; esac
  printf '{"check":"%s","signal":"%s","severity":"%s","summary":"%s","baseline":"%s","observed":"%s","fatal_candidate":%s}\n' \
    "$(json_escape "$check")" \
    "$(json_escape "$signal")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$summary")" \
    "$(json_escape "$baseline")" \
    "$(json_escape "$observed")" \
    "$fatal"
}

# --- logging --------------------------------------------------------------
# Diagnostics go to stderr so they never contaminate finding output on stdout.
ONIONWARDEN_LOG_PREFIX="${ONIONWARDEN_LOG_PREFIX:-onionwarden}"

log_msg() { printf '%s [%s] %s\n' "$(now_iso)" "$1" "$2" >&2; }
log_info() { log_msg INFO "$*"; }
log_warn() { log_msg WARN "$*"; }
log_err()  { log_msg ERROR "$*"; }
die()      { log_msg FATAL "$*"; exit 1; }

# --- time -----------------------------------------------------------------
# ONIONWARDEN_NOW lets tests pin the clock for deterministic output.
now_iso() {
  if [ -n "${ONIONWARDEN_NOW:-}" ]; then
    printf '%s' "$ONIONWARDEN_NOW"
  else
    date -u +%Y-%m-%dT%H:%M:%SZ
  fi
}

now_epoch() {
  if [ -n "${ONIONWARDEN_NOW_EPOCH:-}" ]; then
    printf '%s' "$ONIONWARDEN_NOW_EPOCH"
  else
    date -u +%s
  fi
}

# --- hashing --------------------------------------------------------------
# Ubuntu/Debian ship sha256sum (coreutils); macOS test host has shasum.
_sha256_tool=""
_pick_sha256_tool() {
  if [ -n "$_sha256_tool" ]; then return 0; fi
  if command -v sha256sum >/dev/null 2>&1; then
    _sha256_tool="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    _sha256_tool="shasum -a 256"
  else
    die "no sha256 tool (sha256sum/shasum) found"
  fi
}

sha256_file() {
  _pick_sha256_tool
  if [ ! -e "$1" ]; then printf 'MISSING'; return 0; fi
  if [ ! -r "$1" ]; then printf 'UNREADABLE'; return 0; fi
  local h
  h=$($_sha256_tool "$1" 2>/dev/null | awk '{print $1}') || h=""
  [ -n "$h" ] || h="UNREADABLE"
  printf '%s' "$h"
}

sha256_string() {
  _pick_sha256_tool
  printf '%s' "$1" | $_sha256_tool 2>/dev/null | awk '{print $1}'
}

# --- misc -----------------------------------------------------------------
# require_cmd NAME -> 0 if present, 1 if not (never aborts; callers decide).
require_cmd() { command -v "$1" >/dev/null 2>&1; }

# onionwarden root: the directory holding bin/ lib/ roles/. Resolved relative to
# this file so the same code works at /opt/onionwarden and from the repo checkout.
onionwarden_root() {
  if [ -n "${ONIONWARDEN_ROOT:-}" ]; then printf '%s' "$ONIONWARDEN_ROOT"; return 0; fi
  local d
  d=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  printf '%s' "$d"
}

# Filesystem layout (PLAN §3.3). Every path is env-overridable so the whole
# tool runs against a scratch tree under test without touching the real system.
onionwarden_conf_dir()     { printf '%s' "${ONIONWARDEN_CONF_DIR:-/etc/onionwarden}"; }
onionwarden_var_dir()      { printf '%s' "${ONIONWARDEN_VAR_DIR:-/var/lib/onionwarden}"; }
onionwarden_log_dir()      { printf '%s' "${ONIONWARDEN_LOG_DIR:-/var/log/onionwarden}"; }
onionwarden_state_dir()    { printf '%s' "${ONIONWARDEN_STATE_DIR:-$(onionwarden_var_dir)/state}"; }
onionwarden_baseline_dir() { printf '%s' "${ONIONWARDEN_BASELINE_DIR:-$(onionwarden_var_dir)/baseline}"; }
onionwarden_host_conf()    { printf '%s' "${ONIONWARDEN_HOST_CONF:-$(onionwarden_conf_dir)/host.conf}"; }
