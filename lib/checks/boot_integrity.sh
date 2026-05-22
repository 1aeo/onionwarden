#!/usr/bin/env bash
# lib/checks/boot_integrity.sh — kernel & boot integrity (PLAN §2.1, fatal #1).
#
# Secure Boot state, kernel cmdline, /boot file hashes (with apt-correlation),
# the legacy-BIOS GRUB core image, and running-vs-installed kernel. A /boot
# hash change that is still uncorrelated after apt-correlation is fatal #1.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"
# shellcheck source=lib/apt_correlate.sh
. "$(dirname "${BASH_SOURCE[0]}")/../apt_correlate.sh"

CHECK_NAME="boot_integrity"
CHECK_CADENCE="slow"

boot_integrity_collect() {
  # R10-3: a container has no boot of its own — out of scope for a guest.
  if prof_bool is_container; then
    printf 'na container\n'
    return 0
  fi
  # Secure Boot — only meaningful on EFI hosts with mokutil (detect-and-skip).
  if [ -d /sys/firmware/efi ] && command -v mokutil >/dev/null 2>&1; then
    printf 'secureboot %s\n' "$(mokutil --sb-state 2>/dev/null | tr -d '\n' | tr ' ' '_' || printf unknown)"
  elif [ -d /sys/firmware/efi ]; then
    printf 'secureboot na_no_mokutil\n'
  else
    printf 'secureboot na_legacy_bios\n'
  fi

  [ -r /proc/cmdline ] && printf 'cmdline %s\n' "$(tr -s ' ' < /proc/cmdline)"

  # /boot file hashes + per-file apt-correlation verdict.
  local f corr
  if [ -d /boot ]; then
    for f in /boot/vmlinuz-* /boot/initrd.img-* /boot/grub/grub.cfg \
             /boot/grub/grubenv /boot/config-* /boot/System.map-*; do
      [ -f "$f" ] || continue
      case "$f" in
        /boot/vmlinuz-*|/boot/config-*|/boot/System.map-*) corr=$(apt_correlate_file "$f") ;;
        *) corr=$(apt_correlate_kernel) ;;   # generated files: coarse signal
      esac
      printf 'bootfile %s %s %s\n' "$f" "$(sha256_file "$f")" "$corr"
    done
  fi

  # Legacy-BIOS GRUB core lives in the MBR gap — not a file (M4). R10-2: guard
  # the lsblk/findmnt tools so an unusual root device degrades to na, not abort.
  if [ ! -d /sys/firmware/efi ]; then
    local bootdev=""
    if command -v lsblk >/dev/null 2>&1 && command -v findmnt >/dev/null 2>&1; then
      bootdev=$(lsblk -ndo PKNAME "$(findmnt -no SOURCE / 2>/dev/null || true)" 2>/dev/null \
        | head -n1 || true)
    fi
    if [ -n "$bootdev" ] && [ -r "/dev/$bootdev" ]; then
      printf 'grubcore %s\n' \
        "$(dd if="/dev/$bootdev" bs=512 count=2048 2>/dev/null | sha256_string "$(cat)" || true)"
    else
      printf 'grubcore na_no_bootdev\n'
    fi
  fi

  printf 'runningkernel %s\n' "$(uname -r 2>/dev/null || printf unknown)"
  if command -v dpkg >/dev/null 2>&1; then
    printf 'installedkernel %s\n' \
      "$(dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/{print $3}' | sort -V | tail -n1)"
  fi
}

boot_integrity_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" boot_integrity "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" boot_integrity "no baseline boot state"
    return 0
  fi

  # Secure Boot.
  local bsb csb
  bsb=$(awk '$1=="secureboot"{print $2}' "$base_file" | head -n1)
  csb=$(awk '$1=="secureboot"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bsb" ] && [ "$bsb" != "$csb" ]; then
    case "$csb" in
      *disabled*) emit_finding "$CHECK_NAME" secureboot CRIT \
        "Secure Boot state changed to disabled" "$bsb" "$csb" true ;;
      *) emit_finding "$CHECK_NAME" secureboot WARN \
        "Secure Boot state changed" "$bsb" "$csb" false ;;
    esac
  fi

  # Kernel cmdline — exact-string diff.
  local bcl ccl
  bcl=$(grep '^cmdline ' "$base_file" | sed 's/^cmdline //' | head -n1 || true)
  ccl=$(grep '^cmdline ' "$cur_file"  | sed 's/^cmdline //' | head -n1 || true)
  if [ -n "$bcl" ] && [ "$bcl" != "$ccl" ]; then
    emit_finding "$CHECK_NAME" kernel_cmdline CRIT \
      "kernel cmdline changed (injected init=/removed sig_enforce?)" "$bcl" "$ccl" true
  fi

  # /boot file hashes.
  local line path chash ccorr bhash
  while IFS= read -r line; do
    case "$line" in bootfile\ *) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    chash=$(printf '%s' "$line" | awk '{print $3}')
    ccorr=$(printf '%s' "$line" | awk '{print $4}')
    bhash=$(grep -E "^bootfile $path " "$base_file" 2>/dev/null | awk '{print $3}' | head -n1 || true)
    if [ -z "$bhash" ]; then
      emit_finding "$CHECK_NAME" boot_hash CRIT "new /boot file: $path" "absent" "$chash" true
    elif [ "$bhash" != "$chash" ]; then
      if [ "$ccorr" = "correlated" ]; then
        emit_finding "$CHECK_NAME" boot_hash INFO \
          "/boot file changed but apt-correlated: $path" "$bhash" "$chash" false
      else
        emit_finding "$CHECK_NAME" boot_hash CRIT \
          "/boot file changed and NOT apt-correlated: $path" "$bhash" "$chash" true
      fi
    fi
  done < "$cur_file"

  # GRUB core image.
  local bgc cgc
  bgc=$(awk '$1=="grubcore"{print $2}' "$base_file" | head -n1)
  cgc=$(awk '$1=="grubcore"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bgc" ] && [ "$bgc" != "$cgc" ]; then
    case "$cgc" in
      na_*) ;;
      *) emit_finding "$CHECK_NAME" grub_core CRIT \
        "legacy-BIOS GRUB core image (MBR gap) changed — possible bootkit" "$bgc" "$cgc" true ;;
    esac
  fi

  # Running vs installed kernel.
  local rk ik
  rk=$(awk '$1=="runningkernel"{print $2}' "$cur_file" | head -n1)
  ik=$(awk '$1=="installedkernel"{print $2}' "$cur_file" | head -n1)
  if [ -n "$rk" ] && [ -n "$ik" ] && [ "${rk%-generic}" != "${ik}" ] \
     && ! printf '%s' "$ik" | grep -q "${rk%%-*}"; then
    emit_finding "$CHECK_NAME" kernel_version WARN \
      "running kernel ($rk) is not the newest installed ($ik) — reboot pending?" "$rk" "$ik" false
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
