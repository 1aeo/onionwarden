#!/usr/bin/env bash
# lib/checks/console_login.sh — local-console login (PLAN §2.8, fatal #11).
#
# A login session on a physical/virtual console (tty1..N) opened after baseline
# is fatal #11. The tty[0-9] filter deliberately excludes ttyS* (serial console
# boot output, never an interactive login) and pts/* (remote SSH). Downgraded
# per physical_access_mode.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="console_login"
CHECK_CADENCE="fast"

console_login_collect() {
  if ! command -v who >/dev/null 2>&1; then
    printf 'na no-who\n'
    return 0
  fi
  # `who` lines: user tty date time ... — keep only virtual-console ttys.
  # tty[0-9]* matches tty1, tty2, ... and NOT ttyS0 (serial) or pts/N (remote).
  who 2>/dev/null | awk '$2 ~ /^tty[0-9]+$/ { print "console", $2, $1 }' | sort -u
  printf 'collected ok\n'
}

# _console_severity -> "SEV FATAL" honoring physical_access_mode.
_console_severity() {
  case "$(physical_access_mode)" in
    allowed)    printf 'INFO false' ;;
    suppressed) printf 'WARN false' ;;
    *)          printf 'CRIT true'  ;;
  esac
}

console_login_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" console_login "who not available"
    return 0
  fi
  if ! grep -q '^collected ok' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" console_login "console sessions not collected"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" console_login "no baseline console-session set"
    return 0
  fi

  local sev fatal line tty user
  read -r sev fatal <<< "$(_console_severity)"

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    tty=$(printf '%s' "$line" | awk '{print $2}')
    user=$(printf '%s' "$line" | awk '{print $3}')
    emit_finding "$CHECK_NAME" console_login "$sev" \
      "new local-console login on $tty by '$user' since baseline" \
      "absent" "$tty/$user" "$fatal"
  done <<< "$(comm -13 \
      <(grep '^console ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^console ' "$cur_file" 2>/dev/null | sort -u))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
