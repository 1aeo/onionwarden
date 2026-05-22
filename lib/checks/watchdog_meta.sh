#!/usr/bin/env bash
# lib/checks/watchdog_meta.sh — watchdog self/meta check (PLAN §2.6, §3.5).
#
# Confirms the onionwarden timers/services are enabled+active and recomputes the
# self-hash of the installed code + config. ON ITS OWN this catches only
# non-root / accidental tampering — a root attacker can fake it (H5). The
# authoritative anchor is the receiver's off-box comparison of the reported
# self-hash + pubkey hash (PLAN §4); this check still emits so that the value
# reaches the receiver and so accidental breakage is loud.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="watchdog_meta"
CHECK_CADENCE="fast"

_WATCH_UNITS="onionwarden-fast.timer onionwarden-fast.service \
onionwarden-slow.timer onionwarden-slow.service \
onionwarden-daily.timer onionwarden-daily.service"

# onionwarden_self_hash ROOT — deterministic hash over installed code + config.
onionwarden_self_hash() {
  local root=$1 d
  {
    for d in "$root/bin" "$root/lib" "$root/roles" "$root/systemd"; do
      [ -d "$d" ] || continue
      find "$d" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do
        printf '%s  %s\n' "$(sha256_file "$f")" "${f#"$root"/}"
      done
    done
    for f in "$root/onionwarden.pub" "$root/VERSION" /etc/onionwarden/host.conf; do
      [ -f "$f" ] && printf '%s  %s\n' "$(sha256_file "$f")" "$f"
    done
  } | sha256_string "$(cat)"
}

watchdog_meta_collect() {
  local root unit en act
  root=$(onionwarden_root)
  if command -v systemctl >/dev/null 2>&1; then
    for unit in $_WATCH_UNITS; do
      en=$(systemctl is-enabled "$unit" 2>/dev/null || printf 'unknown')
      act=$(systemctl is-active "$unit" 2>/dev/null || printf 'unknown')
      printf 'unit %s %s %s\n' "$unit" "$en" "$act"
    done
  else
    printf 'unit na no-systemctl\n'
  fi
  printf 'selfhash %s\n' "$(onionwarden_self_hash "$root")"
  if [ -f "$root/onionwarden.pub" ]; then
    printf 'pubkeyhash %s\n' "$(sha256_file "$root/onionwarden.pub")"
  fi
}

watchdog_meta_analyze() {
  local base_file=$1 cur_file=$2
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" watchdog_meta "no baseline meta state"
    return 0
  fi

  # Timer/service health. A timer/service is healthy if it is a .timer that is
  # enabled+active, or a .service that is enabled (it is activated by its timer,
  # so "inactive" between ticks is normal — only failed/masked is bad).
  local line unit en act
  while IFS= read -r line; do
    case "$line" in unit\ na*) emit_na "$CHECK_NAME" watchdog_meta "systemctl unavailable"; return 0 ;; esac
    case "$line" in unit\ *) ;; *) continue ;; esac
    unit=$(printf '%s' "$line" | awk '{print $2}')
    en=$(printf '%s' "$line" | awk '{print $3}')
    act=$(printf '%s' "$line" | awk '{print $4}')
    case "$en" in
      masked)
        emit_finding "$CHECK_NAME" watchdog_meta CRIT \
          "watchdog unit '$unit' is MASKED — watchdog disabled" "enabled" "masked" true ;;
      disabled)
        emit_finding "$CHECK_NAME" watchdog_meta CRIT \
          "watchdog unit '$unit' is disabled" "enabled" "disabled" true ;;
    esac
    case "$act" in
      failed)
        emit_finding "$CHECK_NAME" watchdog_meta CRIT \
          "watchdog unit '$unit' is in failed state" "active" "failed" false ;;
    esac
    case "$unit" in
      *.timer)
        if [ "$act" != "active" ] && [ "$act" != "unknown" ] && [ "$act" != "failed" ]; then
          emit_finding "$CHECK_NAME" watchdog_meta CRIT \
            "watchdog timer '$unit' is not active ($act)" "active" "$act" true
        fi ;;
    esac
  done < "$cur_file"

  # Self-hash drift.
  local bsh csh bpk cpk
  bsh=$(awk '$1=="selfhash"{print $2}' "$base_file" | head -n1)
  csh=$(awk '$1=="selfhash"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bsh" ] && [ "$bsh" != "$csh" ]; then
    emit_finding "$CHECK_NAME" self_hash CRIT \
      "watchdog self-hash differs from baseline — installed code/config changed outside onionwarden-upgrade" \
      "$bsh" "$csh" false
  fi
  bpk=$(awk '$1=="pubkeyhash"{print $2}' "$base_file" | head -n1)
  cpk=$(awk '$1=="pubkeyhash"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bpk" ] && [ "$bpk" != "$cpk" ]; then
    emit_finding "$CHECK_NAME" pubkey_hash CRIT \
      "onionwarden.pub hash changed — verification key may have been swapped (C2)" \
      "$bpk" "$cpk" true
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
