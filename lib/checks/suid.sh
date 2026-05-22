#!/usr/bin/env bash
# lib/checks/suid.sh — SUID/SGID binaries + file capabilities (PLAN §2.3).
#
# Every SUID/SGID file is hashed; a new one or a hash change is CRIT and a new
# SUID-root binary maps to fatal #2. File capabilities (getcap) are diffed too —
# a new cap_* on a binary is CRIT. `find / -xdev` deliberately skips /snap; that
# squashfs is scanned separately by lib/checks/snap.sh (H3).
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="suid"
CHECK_CADENCE="slow"

suid_collect() {
  if ! command -v find >/dev/null 2>&1; then
    printf 'na no-find\n'
    return 0
  fi
  local path
  # SUID/SGID files across the root filesystem only (-xdev).
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    printf 'suid %s %s\n' "$path" "$(sha256_file "$path")"
  done <<< "$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort -u)"

  # File capabilities — optional, skip cleanly if getcap is absent.
  if command -v getcap >/dev/null 2>&1; then
    local line cpath caps
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # getcap output: "<path> <caps>" or "<path> = <caps>" depending on version.
      cpath=$(printf '%s' "$line" | awk '{print $1}')
      caps=$(printf '%s' "$line" | sed 's/^[^ ]* *=* *//')
      [ -n "$cpath" ] || continue
      printf 'cap %s %s\n' "$cpath" "${caps:--}"
    done <<< "$(getcap -r /usr /bin /sbin /opt 2>/dev/null | sort -u)"
  fi
}

suid_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" suid_binaries "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" suid_binaries "no baseline SUID/cap set"
    return 0
  fi

  local line path csha bsha sev summary
  # New / changed SUID-SGID files.
  while IFS= read -r line; do
    case "$line" in 'suid '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    csha=$(printf '%s' "$line" | awk '{print $3}')
    bsha=$(awk -v p="$path" '$1=="suid"&&$2==p{print $3}' "$base_file" | head -n1)
    if [ -z "$bsha" ]; then
      if cfg_list_has expected_suid "$path"; then
        emit_finding "$CHECK_NAME" suid_binaries INFO \
          "new SUID/SGID binary '$path' — allowlisted in expected_suid" \
          "absent" "$csha" false
      else
        emit_finding "$CHECK_NAME" suid_binaries CRIT \
          "new SUID/SGID binary '$path' since baseline" "absent" "$csha" true
      fi
    elif [ "$bsha" != "$csha" ]; then
      if cfg_list_has expected_suid "$path"; then
        sev="INFO"; summary="SUID/SGID binary '$path' content changed — allowlisted in expected_suid"
      else
        sev="CRIT"; summary="SUID/SGID binary '$path' content changed since baseline"
      fi
      emit_finding "$CHECK_NAME" suid_binaries "$sev" "$summary" "$bsha" "$csha" \
        "$( [ "$sev" = CRIT ] && printf true || printf false )"
    fi
  done < "$cur_file"

  # Removed SUID/SGID files.
  while IFS= read -r line; do
    case "$line" in 'suid '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    if ! awk -v p="$path" '$1=="suid"&&$2==p{f=1} END{exit !f}' "$cur_file"; then
      emit_finding "$CHECK_NAME" suid_binaries INFO \
        "SUID/SGID binary '$path' removed since baseline" "present" "absent" false
    fi
  done < "$base_file"

  # New file capabilities.
  while IFS= read -r line; do
    case "$line" in 'cap '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    caps=$(printf '%s' "$line" | cut -d' ' -f3-)
    if ! awk -v p="$path" '$1=="cap"&&$2==p{f=1} END{exit !f}' "$base_file"; then
      emit_finding "$CHECK_NAME" file_capabilities CRIT \
        "new file capability on '$path' since baseline" "absent" "$caps" false
    fi
  done < "$cur_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
