#!/usr/bin/env bash
# lib/checks/filesystem.sh — world-writable paths + immutable bits (PLAN §2.4).
#
# A new world-writable file/dir in a system path is CRIT. lsattr is read on a
# fixed list of critical files: a watchdog-protected file LOSING its immutable
# `i` bit is fatal #8 (chattr -i cleared on a watchdog file); a file unexpectedly
# GAINING `i`/`a` is WARN (locks a malicious file, or blocks updates).
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="filesystem"
CHECK_CADENCE="slow"

# Critical files whose immutable/append-only attrs are tracked. The watchdog's
# own files are protected — losing their `i` bit is the fatal-#8 signal.
_FS_ATTR_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/ld.so.preload \
/opt/onionwarden/onionwarden.pub"
# Glob-expanded watchdog binaries are appended at collect time.
_FS_WATCHDOG_GLOB="/opt/onionwarden/bin"

filesystem_collect() {
  if ! command -v find >/dev/null 2>&1; then
    printf 'na no-find\n'
    return 0
  fi
  local path
  # World-writable files in system paths.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    printf 'wwfile %s\n' "$path"
  done <<< "$(find /usr /etc /bin /sbin -xdev -type f -perm -0002 2>/dev/null | sort -u)"
  # World-writable dirs without the sticky bit.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    printf 'wwdir %s\n' "$path"
  done <<< "$(find /usr /etc /bin /sbin -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | sort -u)"

  # Immutable / append-only attributes on critical + watchdog files.
  if command -v lsattr >/dev/null 2>&1; then
    local f flags files
    files="$_FS_ATTR_FILES"
    if [ -d "$_FS_WATCHDOG_GLOB" ]; then
      for f in "$_FS_WATCHDOG_GLOB"/*; do
        [ -f "$f" ] && files="$files $f"
      done
    fi
    for f in $files; do
      [ -e "$f" ] || continue
      # lsattr field 1 is the attribute string; '-' means no special attrs.
      flags=$(lsattr -d "$f" 2>/dev/null | awk '{print $1}') || flags=""
      [ -n "$flags" ] || flags="-"
      printf 'attr %s %s\n' "$f" "$flags"
    done
  fi
}

# _has_flag FLAGSTRING LETTER -> 0 if the lsattr string contains LETTER.
_has_flag() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

filesystem_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" filesystem "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" filesystem "no baseline filesystem state"
    return 0
  fi

  local kind path line bflags cflags
  # New world-writable files/dirs.
  for kind in wwfile wwdir; do
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      emit_finding "$CHECK_NAME" world_writable CRIT \
        "new world-writable ${kind#ww} in a system path: $path" "absent" "$path" false
    done <<< "$(state_added_field "$base_file" "$cur_file" "$kind")"
  done

  # Immutable / append-only attribute changes.
  while IFS= read -r line; do
    case "$line" in 'attr '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    cflags=$(printf '%s' "$line" | awk '{print $3}')
    bflags=$(awk -v p="$path" '$1=="attr"&&$2==p{print $3}' "$base_file" | head -n1)
    [ -n "$bflags" ] || continue
    [ "$bflags" = "$cflags" ] && continue
    # A watchdog-protected file losing its immutable bit is fatal #8.
    if _has_flag "$bflags" i && ! _has_flag "$cflags" i; then
      emit_finding "$CHECK_NAME" immutable_bits CRIT \
        "watchdog-protected file '$path' lost its immutable (i) attribute" \
        "$bflags" "$cflags" true
    elif { ! _has_flag "$bflags" i && _has_flag "$cflags" i; } \
      || { ! _has_flag "$bflags" a && _has_flag "$cflags" a; }; then
      emit_finding "$CHECK_NAME" immutable_bits WARN \
        "file '$path' unexpectedly gained an immutable/append-only attribute" \
        "$bflags" "$cflags" false
    else
      emit_finding "$CHECK_NAME" immutable_bits WARN \
        "attributes of '$path' changed since baseline" "$bflags" "$cflags" false
    fi
  done < "$cur_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
