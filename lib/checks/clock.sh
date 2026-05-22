#!/usr/bin/env bash
# lib/checks/clock.sh — clock sanity + NTP source integrity (PLAN §2.6, M5).
#
# NTP-server config is in the integrity scope: an attacker repointing the time
# source to skew the apt_correlation_window must be caught (M5). An unsynced
# clock is WARN; a changed timesyncd/chrony/ntp config is CRIT.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="clock"
CHECK_CADENCE="fast"

clock_collect() {
  if command -v timedatectl >/dev/null 2>&1; then
    printf 'ntp_sync %s\n' \
      "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || printf unknown)"
  else
    printf 'ntp_sync na_no_timedatectl\n'
  fi
  local f
  for f in /etc/systemd/timesyncd.conf /etc/ntp.conf /etc/chrony/chrony.conf; do
    [ -f "$f" ] && printf 'ntpconf %s %s\n' "$f" "$(sha256_file "$f")"
  done
  if [ -d /etc/chrony/conf.d ]; then
    for f in /etc/chrony/conf.d/*; do
      [ -f "$f" ] && printf 'ntpconf %s %s\n' "$f" "$(sha256_file "$f")"
    done
  fi
}

clock_analyze() {
  local base_file=$1 cur_file=$2
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" clock "no baseline clock state"
    return 0
  fi

  local cs
  cs=$(awk '$1=="ntp_sync"{print $2}' "$cur_file" | head -n1)
  case "$cs" in
    no|false)
      emit_finding "$CHECK_NAME" clock_sync WARN \
        "system clock is not NTP-synchronised" "synced" "$cs" false ;;
  esac

  # NTP / time-source config integrity.
  local line path chash bhash
  while IFS= read -r line; do
    case "$line" in 'ntpconf '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    chash=$(printf '%s' "$line" | awk '{print $3}')
    bhash=$(awk -v p="$path" '$1=="ntpconf"&&$2==p{print $3}' "$base_file" | head -n1)
    if [ -z "$bhash" ]; then
      emit_finding "$CHECK_NAME" ntp_config CRIT \
        "new time-source config file: $path (clock-skew risk — M5)" "absent" "$chash" false
    elif [ "$bhash" != "$chash" ]; then
      emit_finding "$CHECK_NAME" ntp_config CRIT \
        "time-source config changed: $path (attacker may be skewing the clock — M5)" \
        "$bhash" "$chash" false
    fi
  done < "$cur_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
