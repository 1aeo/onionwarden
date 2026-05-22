#!/usr/bin/env bash
# lib/checks/auth_log.sh — SSH logins / sudo usage / journald integrity (PLAN §2.7).
#
# In production this is cursor-based; for the pure-diff model the baseline is the
# set of KNOWN-GOOD ssh source IPs and sudo users. A current-window sudo user
# not in expected_admins is CRIT; a new ssh source IP is WARN; a corrupt journal
# is WARN. journalctl absence -> N/A.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="auth_log"
CHECK_CADENCE="slow"

auth_log_collect() {
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'na no-journalctl\n'
    return 0
  fi
  local logs failn ip user

  # SSH unit logs for the last hour. Unit is ssh on Debian/Ubuntu.
  logs=$(journalctl -u ssh --since "-1h" -q --no-pager 2>/dev/null) || logs=""
  # Distinct accepted/attempted source IPs.
  while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    printf 'sshsrc %s\n' "$ip"
  done <<< "$(printf '%s\n' "$logs" \
      | grep -Eo 'from [0-9a-fA-F:.]+' 2>/dev/null \
      | awk '{print $2}' | sort -u || true)"
  # Failed-auth count, bucketed so a small churn does not flip the diff.
  failn=$(printf '%s\n' "$logs" | grep -c -i 'failed password\|authentication failure' || true)
  failn=${failn:-0}
  if [ "$failn" -eq 0 ]; then
    printf 'failauth none\n'
  elif [ "$failn" -lt 10 ]; then
    printf 'failauth low\n'
  elif [ "$failn" -lt 50 ]; then
    printf 'failauth medium\n'
  else
    printf 'failauth high\n'
  fi

  # Distinct sudo users in the last hour.
  while IFS= read -r user; do
    [ -n "$user" ] || continue
    printf 'sudouser %s\n' "$user"
  done <<< "$(journalctl _COMM=sudo --since "-1h" -q --no-pager 2>/dev/null \
      | sed -n 's/.*sudo:[[:space:]]*\([a-zA-Z0-9._-]*\)[[:space:]]*:.*/\1/p' \
      | sort -u)"

  # Journal integrity.
  if journalctl --verify -q >/dev/null 2>&1; then
    printf 'journal verify ok\n'
  else
    printf 'journal verify corrupt\n'
  fi
}

auth_log_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" auth_log "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" auth_log "no baseline known-good auth set"
    return 0
  fi

  local user ip cv
  # sudo by a non-expected_admins identity -> CRIT.
  while IFS= read -r user; do
    [ -n "$user" ] || continue
    if cfg_list_has expected_admins "$user"; then
      emit_finding "$CHECK_NAME" sudo_usage INFO \
        "sudo by '$user' new this window — allowlisted in expected_admins" \
        "absent" "$user" false
    else
      emit_finding "$CHECK_NAME" sudo_usage CRIT \
        "sudo used by '$user' — not in expected_admins" "absent" "$user" true
    fi
  done <<< "$(comm -13 \
      <(awk '$1=="sudouser"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="sudouser"{print $2}' "$cur_file" | sort -u))"

  # New SSH source IP -> WARN.
  while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    emit_finding "$CHECK_NAME" ssh_logins WARN \
      "SSH connection from a source IP not seen at baseline: $ip" "absent" "$ip" false
  done <<< "$(comm -13 \
      <(awk '$1=="sshsrc"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="sshsrc"{print $2}' "$cur_file" | sort -u))"

  # Journal corruption -> WARN.
  cv=$(awk '$1=="journal"&&$2=="verify"{print $3}' "$cur_file" | head -n1)
  if [ "$cv" = "corrupt" ]; then
    emit_finding "$CHECK_NAME" journald_integrity WARN \
      "journalctl --verify reports journal corruption" "ok" "corrupt" false
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
