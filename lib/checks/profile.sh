#!/usr/bin/env bash
# lib/checks/profile.sh — host-profile drift (PLAN §0.2).
#
# The host profile is captured into the signed baseline, so detect-and-skip can
# never silently mask a *change*. A profile key shifting (EFI appears, virt_type
# flips, the host becomes a hypervisor, a security tool installed/removed) is
# itself a signal here.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="profile"
CHECK_CADENCE="slow"

# The current profile is produced by bin/onionwarden-detect-profile; in the
# dispatcher the freshly-detected profile file is passed as the current state.
profile_collect() {
  profile_detect
}

# Per-key severity when a profile value changes.
_profile_key_severity() {
  case "$1" in
    os_id|os_supported)                 printf 'CRIT' ;;
    virt_type|efi_present|is_hypervisor|immutable_fs_supported|openssl_ed25519)
                                        printf 'WARN' ;;
    *)                                  printf 'INFO' ;;
  esac
}

profile_analyze() {
  local base_file=$1 cur_file=$2
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" host_profile "no baseline profile"
    return 0
  fi
  if [ ! -s "$cur_file" ]; then
    emit_na "$CHECK_NAME" host_profile "no current profile detected"
    return 0
  fi

  local line key bval cval sev
  # Volatile keys carry a timestamp / nondeterministic value — not drift.
  while IFS= read -r line; do
    case "$line" in *=*) ;; *) continue ;; esac
    key=${line%%=*}
    case "$key" in detected_at) continue ;; esac
    cval=${line#*=}
    bval=$(grep -E "^${key}=" "$base_file" 2>/dev/null | tail -n1 || true)
    bval=${bval#*=}
    if [ -z "$bval" ]; then
      emit_finding "$CHECK_NAME" host_profile INFO \
        "new profile key '$key' = '$cval' (not present at baseline)" "absent" "$cval" false
    elif [ "$bval" != "$cval" ]; then
      sev=$(_profile_key_severity "$key")
      emit_finding "$CHECK_NAME" host_profile "$sev" \
        "host profile '$key' changed ($bval -> $cval)" "$bval" "$cval" false
    fi
  done < "$cur_file"
  # Keys that disappeared.
  while IFS= read -r line; do
    case "$line" in *=*) ;; *) continue ;; esac
    key=${line%%=*}
    case "$key" in detected_at) continue ;; esac
    if ! grep -qE "^${key}=" "$cur_file" 2>/dev/null; then
      emit_finding "$CHECK_NAME" host_profile WARN \
        "profile key '$key' no longer detected" "present" "absent" false
    fi
  done < "$base_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
