#!/usr/bin/env bash
# lib/checks/hardware.sh — USB/PCI/DMI/block/CPU/mount inventory (PLAN §2.5).
#
# Hardware inventory is diffed vs baseline: a new block device or changed UUID
# is CRIT (a swapped disk), a new mount with exec+suid or a bind-mount over a
# system path is CRIT, a new USB/PCI device is WARN (hot-plug), DMI/CPU drift is
# INFO/WARN. Every collector is guarded — absent tools just shrink the inventory.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="hardware"
CHECK_CADENCE="slow"

# System paths a bind-mount on top of which is suspicious.
_HW_SYSTEM_PATHS="/usr /bin /sbin /etc /lib /boot /opt"

hardware_collect() {
  local line
  if command -v lsusb >/dev/null 2>&1; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf 'usb %s\n' "$line"
    done <<< "$(lsusb 2>/dev/null | sort -u)"
  fi
  if command -v lspci >/dev/null 2>&1; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf 'pci %s\n' "$line"
    done <<< "$(lspci -nn 2>/dev/null | sort -u)"
  fi
  # DMI needs root; guard and skip cleanly if unavailable.
  if command -v dmidecode >/dev/null 2>&1; then
    local k v
    for k in bios-version bios-vendor system-uuid baseboard-product-name; do
      v=$(dmidecode -s "$k" 2>/dev/null | grep -v '^#' | head -n1) || v=""
      [ -n "$v" ] && printf 'dmi %s %s\n' "$k" "$v"
    done
  fi
  if command -v lsblk >/dev/null 2>&1; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf 'block %s\n' "$line"
    done <<< "$(lsblk -o NAME,SIZE,TYPE,UUID,FSTYPE -nr 2>/dev/null | sort -u)"
  fi
  if command -v nproc >/dev/null 2>&1; then
    printf 'cpu nproc %s\n' "$(nproc 2>/dev/null || printf 0)"
  fi
  # Mounts: target, fstype, and whether exec+suid are both effective.
  if command -v findmnt >/dev/null 2>&1; then
    local tgt fstype opts hasexec
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      tgt=$(printf '%s' "$line" | awk '{print $1}')
      fstype=$(printf '%s' "$line" | awk '{print $2}')
      opts=$(printf '%s' "$line" | awk '{print $3}')
      hasexec="no"
      case ",$opts," in *",noexec,"*) ;; *)
        case ",$opts," in *",nosuid,"*) ;; *) hasexec="exec+suid" ;; esac ;;
      esac
      [ -n "$tgt" ] && printf 'mount %s %s %s\n' "$tgt" "${fstype:--}" "$hasexec"
    done <<< "$(findmnt -rno TARGET,FSTYPE,OPTIONS 2>/dev/null | sort -u)"
  elif command -v mount >/dev/null 2>&1; then
    local tgt fstype opts hasexec
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # mount line: "<src> on <target> type <fstype> (<opts>)"
      tgt=$(printf '%s' "$line" | sed -n 's/.* on \(.*\) type .*/\1/p')
      fstype=$(printf '%s' "$line" | sed -n 's/.* type \([^ ]*\) .*/\1/p')
      opts=$(printf '%s' "$line" | sed -n 's/.*(\(.*\)).*/\1/p')
      hasexec="no"
      case ",$opts," in *",noexec,"*) ;; *)
        case ",$opts," in *",nosuid,"*) ;; *) hasexec="exec+suid" ;; esac ;;
      esac
      [ -n "$tgt" ] && printf 'mount %s %s %s\n' "$tgt" "${fstype:--}" "$hasexec"
    done <<< "$(mount 2>/dev/null | sort -u)"
  fi
}

hardware_analyze() {
  local base_file=$1 cur_file=$2
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" hardware "no baseline hardware inventory"
    return 0
  fi

  local line item kind
  # New USB / PCI devices -> WARN.
  for kind in usb pci; do
    while IFS= read -r item; do
      [ -n "$item" ] || continue
      emit_finding "$CHECK_NAME" hardware_devices WARN \
        "new $kind device since baseline: $item" "absent" "$item" false
    done <<< "$(comm -13 \
        <(grep "^$kind " "$base_file" 2>/dev/null | sed "s/^$kind //" | sort -u) \
        <(grep "^$kind " "$cur_file"  2>/dev/null | sed "s/^$kind //" | sort -u))"
  done

  # New block devices / changed UUID -> CRIT.
  while IFS= read -r item; do
    [ -n "$item" ] || continue
    emit_finding "$CHECK_NAME" block_devices CRIT \
      "new block device or changed UUID since baseline: $item" "absent" "$item" false
  done <<< "$(comm -13 \
      <(grep '^block ' "$base_file" 2>/dev/null | sed 's/^block //' | sort -u) \
      <(grep '^block ' "$cur_file"  2>/dev/null | sed 's/^block //' | sort -u))"

  # New mounts -> CRIT if exec+suid or a bind-mount over a system path.
  local tgt fstype hasexec p sev summary
  while IFS= read -r line; do
    case "$line" in 'mount '*) ;; *) continue ;; esac
    tgt=$(printf '%s' "$line" | awk '{print $2}')
    fstype=$(printf '%s' "$line" | awk '{print $3}')
    hasexec=$(printf '%s' "$line" | awk '{print $4}')
    sev="WARN"; summary="new mount '$tgt' ($fstype) since baseline"
    if [ "$hasexec" = "exec+suid" ]; then
      sev="CRIT"; summary="new mount '$tgt' ($fstype) with exec+suid since baseline"
    fi
    for p in $_HW_SYSTEM_PATHS; do
      if [ "$tgt" = "$p" ]; then
        sev="CRIT"; summary="new mount over system path '$tgt' ($fstype) since baseline"
        break
      fi
    done
    emit_finding "$CHECK_NAME" mounts "$sev" "$summary" "absent" "$tgt $fstype $hasexec" false
  done <<< "$(comm -13 \
      <(grep '^mount ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^mount ' "$cur_file"  2>/dev/null | sort -u))"

  # DMI drift -> WARN.
  while IFS= read -r line; do
    case "$line" in 'dmi '*) ;; *) continue ;; esac
    emit_finding "$CHECK_NAME" dmi_firmware WARN \
      "DMI/firmware value changed since baseline: $(printf '%s' "$line" | sed 's/^dmi //')" \
      "$(grep "^dmi $(printf '%s' "$line" | awk '{print $2}') " "$base_file" | sed 's/^dmi //' | head -n1)" \
      "$(printf '%s' "$line" | sed 's/^dmi //')" false
  done <<< "$(comm -13 \
      <(grep '^dmi ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^dmi ' "$cur_file"  2>/dev/null | sort -u))"

  # CPU topology drift -> INFO (VM resize).
  local bcpu ccpu
  bcpu=$(awk '$1=="cpu"&&$2=="nproc"{print $3}' "$base_file" | head -n1)
  ccpu=$(awk '$1=="cpu"&&$2=="nproc"{print $3}' "$cur_file" | head -n1)
  if [ -n "$bcpu" ] && [ -n "$ccpu" ] && [ "$bcpu" != "$ccpu" ]; then
    emit_finding "$CHECK_NAME" cpu_topology INFO \
      "CPU count changed since baseline (VM resize?)" "$bcpu" "$ccpu" false
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
