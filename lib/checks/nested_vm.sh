#!/usr/bin/env bash
# lib/checks/nested_vm.sh — nested-VM layer monitor (PLAN §2.4, C4).
#
# Always on when the host is a hypervisor (the #1 asset is produced inside the
# VM layer, so it must never be invisible). The running-guest set and each
# guest's QEMU argv are stable — they do not churn like the writable overlay. A
# new guest is CRIT, a changed -netdev (a new exfil path) is CRIT.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="nested_vm"
CHECK_CADENCE="slow"

# _nv_vmname ARGV -> the guest name parsed from a QEMU argv, or "unknown".
_nv_vmname() {
  local n
  n=$(printf '%s' "$1" | sed -n 's/.*-name[ =]\([^ ,]*\).*/\1/p' | head -n1)
  [ -n "$n" ] || n="unknown"
  printf '%s' "$n"
}

nested_vm_collect() {
  if ! prof_bool is_hypervisor; then
    printf 'na not-hypervisor\n'
    return 0
  fi
  local line argv name h netdev

  # Running QEMU guests.
  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # pgrep -af line: "<pid> <full argv>"
      argv=$(printf '%s' "$line" | cut -d' ' -f2-)
      [ -n "$argv" ] || continue
      name=$(_nv_vmname "$argv")
      h=$(sha256_string "$argv")
      printf 'guest %s %s\n' "$h" "$name"
      # Extract -netdev / -device args (a new -netdev is an exfil path).
      netdev=$(printf '%s' "$argv" \
        | tr ' ' '\n' | grep -A1 -E '^-netdev$|^-device$' 2>/dev/null \
        | grep -v -E '^-netdev$|^-device$' | sort -u | tr '\n' ',' || true)
      printf 'guestarg %s netdev=%s\n' "$name" "${netdev:-none}"
    done <<< "$(pgrep -af qemu-system 2>/dev/null | sort -u)"
  fi

  # libvirt-managed guests.
  if command -v virsh >/dev/null 2>&1; then
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      printf 'virshguest %s\n' "$name"
    done <<< "$(virsh list --name 2>/dev/null | sed '/^$/d' | sort -u)"
  fi
}

nested_vm_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" nested_vm "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" nested_vm "no baseline guest set"
    return 0
  fi

  local item line name carg barg
  # New QEMU guests -> CRIT.
  while IFS= read -r item; do
    [ -n "$item" ] || continue
    emit_finding "$CHECK_NAME" guest_set CRIT \
      "new running QEMU guest since baseline: $item" "absent" "$item" false
  done <<< "$(comm -13 \
      <(grep '^guest ' "$base_file" 2>/dev/null | sed 's/^guest //' | sort -u) \
      <(grep '^guest ' "$cur_file"  2>/dev/null | sed 's/^guest //' | sort -u))"

  # Removed guests -> INFO.
  while IFS= read -r item; do
    [ -n "$item" ] || continue
    emit_finding "$CHECK_NAME" guest_set INFO \
      "QEMU guest gone since baseline: $item" "$item" "absent" false
  done <<< "$(comm -23 \
      <(grep '^guest ' "$base_file" 2>/dev/null | sed 's/^guest //' | sort -u) \
      <(grep '^guest ' "$cur_file"  2>/dev/null | sed 's/^guest //' | sort -u))"

  # New libvirt guests -> CRIT.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    emit_finding "$CHECK_NAME" guest_set CRIT \
      "new libvirt-managed guest since baseline: $name" "absent" "$name" false
  done <<< "$(state_added_field "$base_file" "$cur_file" virshguest)"

  # Changed guest argv (-netdev) -> CRIT (a new exfil path).
  while IFS= read -r line; do
    case "$line" in 'guestarg '*) ;; *) continue ;; esac
    name=$(printf '%s' "$line" | awk '{print $2}')
    carg=$(printf '%s' "$line" | cut -d' ' -f3-)
    barg=$(grep -E "^guestarg $name " "$base_file" 2>/dev/null | cut -d' ' -f3- | head -n1 || true)
    [ -n "$barg" ] || continue
    if [ "$barg" != "$carg" ]; then
      emit_finding "$CHECK_NAME" guest_argv CRIT \
        "QEMU guest '$name' network argv changed since baseline (new exfil path?)" \
        "$barg" "$carg" false
    fi
  done < "$cur_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
