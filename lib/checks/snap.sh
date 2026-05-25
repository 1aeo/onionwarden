#!/usr/bin/env bash
# lib/checks/snap.sh — snap package coverage (PLAN §2.4, H3).
#
# `find / -xdev` deliberately skips other mounts and hides everything under
# /snap squashfs, so snap content is scanned separately here. A new snap or a
# revision change is WARN (apt-correlation does not cover the snap channel). A
# new SUID binary inside /snap is CRIT.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="snap"
CHECK_CADENCE="daily"

snap_collect() {
  if ! command -v snap >/dev/null 2>&1; then
    printf 'na no-snapd\n'
    return 0
  fi
  local line name rev ver
  # Installed snaps and their revisions.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name=$(printf '%s' "$line" | awk '{print $1}')
    rev=$(printf '%s' "$line" | awk '{print $3}')
    [ -n "$name" ] || continue
    printf 'snap %s %s\n' "$name" "${rev:--}"
  done <<< "$(snap list --all 2>/dev/null | awk 'NR>1' | sort -u)"

  # snapd version.
  ver=$(snap version 2>/dev/null | awk '$1=="snapd"{print $2}' | head -n1) || ver=""
  [ -n "$ver" ] && printf 'snapd %s\n' "$ver"

  # Separate SUID pass over /snap squashfs (the suid.sh -xdev scan skips it).
  if command -v find >/dev/null 2>&1 && [ -d /snap ]; then
    local path
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      printf 'snapsuid %s\n' "$path"
    done <<< "$(find /snap -xdev -perm -4000 -type f 2>/dev/null | sort -u)"
  fi
}

snap_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" snap_packages "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" snap_packages "no baseline snap set"
    return 0
  fi

  local line name crev brev bv cv path
  # New snap / revision change.
  while IFS= read -r line; do
    case "$line" in 'snap '*) ;; *) continue ;; esac
    name=$(printf '%s' "$line" | awk '{print $2}')
    crev=$(printf '%s' "$line" | awk '{print $3}')
    brev=$(awk -v n="$name" '$1=="snap"&&$2==n{print $3}' "$base_file" | head -n1)
    if [ -z "$brev" ]; then
      emit_finding "$CHECK_NAME" snap_packages WARN \
        "new snap '$name' (rev $crev) since baseline" "absent" "$name $crev" false
    elif [ "$brev" != "$crev" ]; then
      emit_finding "$CHECK_NAME" snap_packages WARN \
        "snap '$name' revision changed since baseline" "$brev" "$crev" false
    fi
  done < "$cur_file"

  # snapd version change.
  bv=$(awk '$1=="snapd"{print $2}' "$base_file" | head -n1)
  cv=$(awk '$1=="snapd"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bv" ] && [ -n "$cv" ] && [ "$bv" != "$cv" ]; then
    emit_finding "$CHECK_NAME" snap_packages WARN \
      "snapd version changed since baseline" "$bv" "$cv" false
  fi

  # New SUID binary inside /snap.
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    emit_finding "$CHECK_NAME" snap_suid CRIT \
      "new SUID binary inside /snap since baseline: $path" "absent" "$path" false
  done <<< "$(state_added_field "$base_file" "$cur_file" snapsuid)"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
