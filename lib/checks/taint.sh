#!/usr/bin/env bash
# lib/checks/taint.sh — kernel taint flag (PLAN §2.1, §3.7 fatal #4).
#
# /proc/sys/kernel/tainted is an integer bitmask. A bit newly set relative to
# baseline is decoded per the §2.1 table. CRIT bits {P,F,R,O,E,K} map to fatal
# signal #4 — except K (live-patch), and any letter the operator lists in
# expected_taint_bits, which are documented carve-outs (PLAN §3.7).
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="taint"
CHECK_CADENCE="fast"

# taint_bit_info BITNUM -> "LETTER|SEVERITY|MEANING" ("" for unknown bits).
taint_bit_info() {
  case "$1" in
    0)  printf 'P|CRIT|proprietary module loaded' ;;
    1)  printf 'F|CRIT|module force-loaded' ;;
    2)  printf 'S|WARN|SMP kernel, CPU out of spec' ;;
    3)  printf 'R|CRIT|module force-unloaded' ;;
    4)  printf 'M|WARN|machine check' ;;
    5)  printf 'B|WARN|bad page detected' ;;
    6)  printf 'U|WARN|userspace-requested taint' ;;
    7)  printf 'D|WARN|kernel died (oops/BUG)' ;;
    9)  printf 'W|WARN|kernel warning issued' ;;
    10) printf 'C|WARN|staging driver loaded' ;;
    11) printf 'I|INFO|firmware-bug workaround' ;;
    12) printf 'O|CRIT|out-of-tree module loaded' ;;
    13) printf 'E|CRIT|unsigned module loaded' ;;
    14) printf 'L|WARN|soft lockup occurred' ;;
    15) printf 'K|CRIT|kernel live-patched' ;;
    16) printf 'X|WARN|auxiliary (distro-defined)' ;;
    18) printf 'N|INFO|in-kernel test (kunit) ran' ;;
    *)  printf '' ;;
  esac
}

taint_collect() {
  if [ -r /proc/sys/kernel/tainted ]; then
    printf 'tainted %s\n' "$(cat /proc/sys/kernel/tainted 2>/dev/null || printf 0)"
  else
    printf 'tainted NA\n'
  fi
}

# _taint_value FILE -> the integer (or "NA"/"MISSING").
_taint_value() {
  if [ ! -f "$1" ]; then printf 'MISSING'; return 0; fi
  awk '$1=="tainted"{print $2; found=1} END{if(!found)print "MISSING"}' "$1"
}

taint_analyze() {
  local base_file=$1 cur_file=$2
  local base cur
  base=$(_taint_value "$base_file")
  cur=$(_taint_value "$cur_file")

  if [ "$cur" = "NA" ] || [ "$cur" = "MISSING" ]; then
    emit_na "$CHECK_NAME" kernel_taint "/proc/sys/kernel/tainted unreadable"
    return 0
  fi
  if [ "$base" = "MISSING" ] || [ "$base" = "NA" ]; then
    emit_na "$CHECK_NAME" kernel_taint "no baseline taint value"
    return 0
  fi
  if [ "$cur" = "$base" ]; then
    return 0
  fi

  # Newly-set and newly-cleared bits.
  local newly=$(( cur & ~base ))
  local cleared=$(( base & ~cur ))

  local bit mask info letter sev meaning fatal summary
  for bit in $(seq 0 31); do
    mask=$(( 1 << bit ))
    if [ "$(( newly & mask ))" -ne 0 ]; then
      info=$(taint_bit_info "$bit")
      if [ -z "$info" ]; then
        emit_finding "$CHECK_NAME" kernel_taint WARN \
          "unknown kernel taint bit $bit newly set — kernel newer than the §2.1 decoder table" \
          "$base" "$cur" false
        continue
      fi
      letter=${info%%|*}
      sev=${info#*|}; sev=${sev%%|*}
      meaning=${info##*|}
      fatal=false
      # Documented carve-outs: K (live-patch) is never fatal, and any letter
      # the operator allowlisted (OEM out-of-tree modules etc.) is demoted.
      if cfg_list_has expected_taint_bits "$letter"; then
        sev="INFO"
        summary="taint bit $letter ($meaning) newly set — allowlisted in expected_taint_bits"
      elif [ "$letter" = "K" ]; then
        sev="WARN"
        summary="taint bit K (kernel live-patched) newly set — confirm this is an operator-applied livepatch"
      else
        summary="kernel taint bit $letter ($meaning) newly set"
        if [ "$sev" = "CRIT" ]; then fatal=true; fi
      fi
      emit_finding "$CHECK_NAME" kernel_taint "$sev" "$summary" "$base" "$cur" "$fatal"
    fi
  done

  for bit in $(seq 0 31); do
    mask=$(( 1 << bit ))
    if [ "$(( cleared & mask ))" -ne 0 ]; then
      info=$(taint_bit_info "$bit")
      letter=${info%%|*}
      [ -n "$letter" ] || letter="bit$bit"
      emit_finding "$CHECK_NAME" kernel_taint INFO \
        "kernel taint bit $letter cleared since baseline (unusual — taint bits are sticky until reboot)" \
        "$base" "$cur" false
    fi
  done
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
