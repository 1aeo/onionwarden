#!/usr/bin/env bash
# lib/checks/ssh.sh — SSH keys + effective sshd config (PLAN §2.3, fatal #6).
#
# Hashes every user's authorized_keys{,2} and records key counts; captures the
# *effective* sshd config via `sshd -T` (catches drop-ins and defaults, which a
# file hash misses). A new key on a UID-0 / expected_admins account is fatal #6;
# an sshd setting weakening toward password/root login is CRIT.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="ssh"
CHECK_CADENCE="fast"

# sshd settings we track, and the value considered "hardened".
_SSH_TRACKED="permitrootlogin passwordauthentication kbdinteractiveauthentication \
pubkeyauthentication permitemptypasswords x11forwarding allowtcpforwarding usepam"

_ssh_keycount() {
  grep -cvE '^[[:space:]]*($|#)' "$1" 2>/dev/null || true
}

ssh_collect() {
  local user home f cnt
  while IFS=: read -r user _ _ _ _ home _; do
    [ -n "$home" ] || continue
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      if [ -f "$f" ]; then
        cnt=$(_ssh_keycount "$f")
        printf 'authkeys %s %s %s %s\n' "$user" "$f" "$(sha256_file "$f")" "${cnt:-0}"
      fi
    done
  done < /etc/passwd
  # Effective sshd config. `sshd -T` needs root and a valid config; tolerate
  # its failure instead of aborting the whole collector.
  if command -v sshd >/dev/null 2>&1; then
    local sshd_t key val
    sshd_t=$(sshd -T 2>/dev/null) || sshd_t=""
    if [ -n "$sshd_t" ]; then
      printf '%s\n' "$sshd_t" | while read -r key val; do
        key=$(printf '%s' "$key" | tr 'A-Z' 'a-z')
        case " $_SSH_TRACKED " in
          *" $key "*) printf 'sshd %s %s\n' "$key" "$val" ;;
        esac
      done
    else
      printf 'sshd na sshd-T-unavailable\n'
    fi
  else
    printf 'sshd na no-sshd-binary\n'
  fi
}

# 0 if a user is privileged (root or expected_admins) -> a new key is fatal.
_ssh_user_privileged() {
  [ "$1" = "root" ] && return 0
  cfg_list_has expected_admins "$1"
}

ssh_analyze() {
  local base_file=$1 cur_file=$2
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" ssh "no baseline ssh state"
    return 0
  fi

  # authorized_keys diffs, keyed by file path.
  local line user path csha ccnt bsha bcnt fatal
  while IFS= read -r line; do
    case "$line" in authkeys*) ;; *) continue ;; esac
    user=$(printf '%s' "$line" | awk '{print $2}')
    path=$(printf '%s' "$line" | awk '{print $3}')
    csha=$(printf '%s' "$line" | awk '{print $4}')
    ccnt=$(printf '%s' "$line" | awk '{print $5}')
    bsha=$(grep -E "^authkeys $user $path " "$base_file" 2>/dev/null | awk '{print $4}' | head -n1)
    bcnt=$(grep -E "^authkeys $user $path " "$base_file" 2>/dev/null | awk '{print $5}' | head -n1)
    fatal=false
    if _ssh_user_privileged "$user"; then fatal=true; fi
    if [ -z "$bsha" ]; then
      emit_finding "$CHECK_NAME" authorized_keys CRIT \
        "new authorized_keys file for '$user': $path ($ccnt keys)" "absent" "$csha" "$fatal"
    elif [ "$bsha" != "$csha" ]; then
      if [ "${ccnt:-0}" -gt "${bcnt:-0}" ]; then
        emit_finding "$CHECK_NAME" authorized_keys CRIT \
          "authorized_keys for '$user' gained keys ($bcnt -> $ccnt): $path" "$bcnt" "$ccnt" "$fatal"
      elif [ "${ccnt:-0}" -lt "${bcnt:-0}" ]; then
        emit_finding "$CHECK_NAME" authorized_keys INFO \
          "authorized_keys for '$user' lost keys ($bcnt -> $ccnt): $path" "$bcnt" "$ccnt" false
      else
        emit_finding "$CHECK_NAME" authorized_keys CRIT \
          "authorized_keys for '$user' changed (same count — key replaced): $path" "$bsha" "$csha" "$fatal"
      fi
    fi
  done < "$cur_file"
  # Removed authorized_keys files.
  while IFS= read -r line; do
    case "$line" in authkeys*) ;; *) continue ;; esac
    user=$(printf '%s' "$line" | awk '{print $2}')
    path=$(printf '%s' "$line" | awk '{print $3}')
    if ! grep -qE "^authkeys $user $path " "$cur_file" 2>/dev/null; then
      emit_finding "$CHECK_NAME" authorized_keys WARN \
        "authorized_keys file removed for '$user': $path" "present" "absent" false
    fi
  done < "$base_file"

  # sshd -T effective config drift.
  local key bval cval sev
  for key in $_SSH_TRACKED; do
    bval=$(grep -E "^sshd $key " "$base_file" 2>/dev/null | awk '{print $3}' | head -n1)
    cval=$(grep -E "^sshd $key " "$cur_file" 2>/dev/null | awk '{print $3}' | head -n1)
    [ -n "$bval$cval" ] || continue
    [ "$bval" = "$cval" ] && continue
    sev="WARN"
    case "$key" in
      permitrootlogin)
        [ "$cval" = "yes" ] && sev="CRIT" ;;
      passwordauthentication|kbdinteractiveauthentication|permitemptypasswords)
        [ "$cval" = "yes" ] && sev="CRIT" ;;
      pubkeyauthentication)
        [ "$cval" = "no" ] && sev="CRIT" ;;
    esac
    emit_finding "$CHECK_NAME" sshd_config "$sev" \
      "effective sshd setting '$key' changed ($bval -> $cval)" "$bval" "$cval" false
  done
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
