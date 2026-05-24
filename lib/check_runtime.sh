# shellcheck shell=bash
# lib/check_runtime.sh — the contract every lib/checks/*.sh module follows.
#
# A check module defines:
#   CHECK_NAME       short id, matches the filename
#   CHECK_CADENCE    fast | slow | daily | boot
#   <name>_collect   gather live host state -> line-oriented stdout (Linux-only)
#   <name>_analyze   BASELINE_STATE CURRENT_STATE -> findings NDJSON (PURE)
#
# analyze() is a pure function of (baseline state, current state, config): no
# clock, no host commands. That is what makes every check unit-testable from
# fixtures on any OS. collect() is the thin Linux-only half and is exercised
# only on a real host.
#
# Sourcing this file pulls in common/config/profile so checks need one source
# line. The trailing check_run_cli() lets a check be executed directly (tests,
# manual runs) while the dispatcher sources it as a library.

if [ -n "${_ONIONWARDEN_CHECK_RUNTIME_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_CHECK_RUNTIME_SH=1

# PATH normalisation. Debian 13's non-interactive shell PATH (which
# the snapshot tool's `bash -s` wire inherits) is
# `/usr/local/bin:/usr/bin:/bin:/usr/games` — no sbin dirs. That
# silently breaks `command -v` discovery for admin/daemon binaries
# (sshd, nft, dmidecode, bpftool, …) that live in /usr/sbin or
# /sbin, and a check then emits a false `na no-<tool>`. We
# unconditionally ensure the three sbin dirs are present in $PATH,
# appended (so existing /usr/bin entries still win for any binary
# that happens to live in both places). Ubuntu — where /usr/sbin
# is in PATH already — gets a no-op. The change applies once per
# bundle run / dispatcher tick (sourced-once guard above).
case ":${PATH:-}:" in *:/usr/local/sbin:*) ;; *) PATH="${PATH:-/usr/bin:/bin}:/usr/local/sbin" ;; esac
case ":$PATH:"        in *:/usr/sbin:*)       ;; *) PATH="$PATH:/usr/sbin"       ;; esac
case ":$PATH:"        in *:/sbin:*)           ;; *) PATH="$PATH:/sbin"           ;; esac
export PATH

_crt_dir="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
. "$_crt_dir/common.sh"
# shellcheck source=lib/config.sh
. "$_crt_dir/config.sh"
# shellcheck source=lib/profile.sh
. "$_crt_dir/profile.sh"

# emit_na CHECK SIGNAL REASON — record a detect-and-skip (capability absent).
# Severity NA never counts as a deviation; the rollup tallies it separately.
emit_na() {
  emit_finding "$1" "$2" "NA" "$3" "" "" false
}

# state_present FILE — 0 if FILE exists and is non-empty.
state_present() { [ -s "$1" ]; }

# physical_access_mode -> how a physical-contact fatal signal (#10 input device,
# #11 console login) should be reported:
#   allowed     host.conf:physical_access_allowed=true -> INFO, never fatal
#   suppressed  an active `onionwarden suppress` window -> WARN, not fatal
#   crit        default -> CRIT + fatal candidate
# ONIONWARDEN_SUPPRESS_PHYSICAL is set by the dispatcher from the signed window
# state; passing it via env keeps analyze() a pure function of its inputs.
physical_access_mode() {
  if cfg_bool physical_access_allowed; then printf 'allowed'; return 0; fi
  case "${ONIONWARDEN_SUPPRESS_PHYSICAL:-inactive}" in
    active) printf 'suppressed' ;;
    *)      printf 'crit' ;;
  esac
}

# check_run_cli SUBCOMMAND [--baseline F] [--current F] [--config F]
#                          [--roles DIR] [--profile F]
# Subcommands: collect | analyze | name | cadence
check_run_cli() {
  local sub="${1:-}"; shift 2>/dev/null || true
  local baseline="" current="" config="" roles="" profile=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --baseline) baseline=$2; shift 2 ;;
      --current)  current=$2;  shift 2 ;;
      --config)   config=$2;   shift 2 ;;
      --roles)    roles=$2;    shift 2 ;;
      --profile)  profile=$2;  shift 2 ;;
      *) die "check_run_cli: unknown argument: $1" ;;
    esac
  done
  [ -n "$profile" ] && prof_load "$profile"
  [ -n "$config" ]  && cfg_load "$config" "$roles"
  case "$sub" in
    collect) "${CHECK_NAME}_collect" ;;
    analyze) "${CHECK_NAME}_analyze" "$baseline" "$current" ;;
    name)    printf '%s\n' "$CHECK_NAME" ;;
    cadence) printf '%s\n' "$CHECK_CADENCE" ;;
    *) die "check_run_cli: unknown subcommand: '$sub' (collect|analyze|name|cadence)" ;;
  esac
}
