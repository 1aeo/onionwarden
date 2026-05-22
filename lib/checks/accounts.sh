#!/usr/bin/env bash
# lib/checks/accounts.sh — account & sudoers integrity (PLAN §2.3, fatal #2/#7).
#
# Hashes the account DBs and sudoers, lists UID-0 accounts, empty-password
# accounts, and sudo-group members. A new UID-0 account not in expected_uid0 is
# CRIT + fatal #7; sudoers/account-file changes and new empty passwords are CRIT.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="accounts"
CHECK_CADENCE="fast"

accounts_collect() {
  local f
  for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
    if [ -e "$f" ]; then
      printf 'filehash %s %s\n' "$f" "$(sha256_file "$f")"
    fi
  done
  if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
      [ -f "$f" ] || continue
      printf 'sudoersd %s %s\n' "$f" "$(sha256_file "$f")"
    done
  fi
  # UID-0 accounts.
  if [ -r /etc/passwd ]; then
    awk -F: '$3==0{print "uid0", $1}' /etc/passwd | sort -u
    # Empty-password accounts (shadow field 2 empty).
    if [ -r /etc/shadow ]; then
      awk -F: '($2==""){print "emptypw", $1}' /etc/shadow | sort -u
    fi
  fi
  # sudo / admin group members.
  if [ -r /etc/group ]; then
    awk -F: '$1=="sudo"||$1=="admin"{print "admingrp", $1, $4}' /etc/group | sort -u
  fi
}

accounts_analyze() {
  local base_file=$1 cur_file=$2
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" accounts "no baseline account state"
    return 0
  fi

  # Account/sudoers file hash changes.
  local line path bsha csha
  while IFS= read -r line; do
    case "$line" in filehash*|sudoersd*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    csha=$(printf '%s' "$line" | awk '{print $3}')
    bsha=$(grep -E "^(filehash|sudoersd) $path " "$base_file" 2>/dev/null | awk '{print $3}' | head -n1 || true)
    if [ -z "$bsha" ]; then
      emit_finding "$CHECK_NAME" sudoers CRIT \
        "new account/sudoers file appeared: $path" "absent" "$csha" true
    elif [ "$bsha" != "$csha" ]; then
      emit_finding "$CHECK_NAME" sudoers CRIT \
        "account/sudoers file modified: $path" "$bsha" "$csha" true
    fi
  done < "$cur_file"
  # Removed account/sudoers files.
  while IFS= read -r line; do
    case "$line" in filehash*|sudoersd*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    if ! grep -qE "^(filehash|sudoersd) $path " "$cur_file" 2>/dev/null; then
      emit_finding "$CHECK_NAME" sudoers CRIT \
        "account/sudoers file removed: $path" "present" "absent" false
    fi
  done < "$base_file"

  # New UID-0 accounts (fatal #7).
  local user
  while IFS= read -r user; do
    [ -n "$user" ] || continue
    if cfg_list_has expected_uid0 "$user"; then
      emit_finding "$CHECK_NAME" uid0 INFO \
        "UID-0 account '$user' new since baseline but allowlisted in expected_uid0" \
        "absent" "$user" false
    else
      emit_finding "$CHECK_NAME" uid0 CRIT \
        "new UID-0 account '$user' not in expected_uid0" "absent" "$user" true
    fi
  done <<< "$(comm -13 \
      <(awk '$1=="uid0"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="uid0"{print $2}' "$cur_file" | sort -u))"

  # New empty-password accounts.
  while IFS= read -r user; do
    [ -n "$user" ] || continue
    emit_finding "$CHECK_NAME" empty_password CRIT \
      "account '$user' has an empty password field" "absent" "$user" false
  done <<< "$(comm -13 \
      <(awk '$1=="emptypw"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="emptypw"{print $2}' "$cur_file" | sort -u))"

  # sudo/admin group membership change.
  local bgrp cgrp
  bgrp=$(grep '^admingrp ' "$base_file" 2>/dev/null | sort -u || true)
  cgrp=$(grep '^admingrp ' "$cur_file" 2>/dev/null | sort -u || true)
  if [ "$bgrp" != "$cgrp" ]; then
    emit_finding "$CHECK_NAME" admin_group CRIT \
      "sudo/admin group membership changed since baseline" \
      "$(printf '%s' "$bgrp" | tr '\n' ';')" "$(printf '%s' "$cgrp" | tr '\n' ';')" false
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
