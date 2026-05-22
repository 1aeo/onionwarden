#!/usr/bin/env bash
# lib/checks/scheduled.sh — cron + systemd units/timers (PLAN §2.3).
#
# Cron files are hashed; a new cron file or a hash change is CRIT. systemd
# unit-files and timers are diffed by name; a new enabled service/timer is CRIT
# (a common persistence mechanism). Allowlist: expected_extra_units demotes a
# known-good extra unit/timer to INFO (PLAN §0.3).
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="scheduled"
CHECK_CADENCE="slow"

scheduled_collect() {
  local f d
  # Cron file hashes.
  for f in /etc/crontab; do
    [ -f "$f" ] && printf 'cron %s %s\n' "$f" "$(sha256_file "$f")"
  done
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
           /etc/cron.monthly /var/spool/cron/crontabs; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      printf 'cron %s %s\n' "$f" "$(sha256_file "$f")"
    done
  done

  # systemd units and timers.
  if command -v systemctl >/dev/null 2>&1; then
    local line name state
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      name=$(printf '%s' "$line" | awk '{print $1}')
      state=$(printf '%s' "$line" | awk '{print $2}')
      [ -n "$name" ] || continue
      printf 'unitfile %s %s\n' "$name" "${state:--}"
    done <<< "$(systemctl list-unit-files --no-legend 2>/dev/null | sort -u)"
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # list-timers last column is UNIT; pick the *.timer token on the line.
      name=$(printf '%s' "$line" | tr ' ' '\n' | grep '\.timer$' | head -n1 || true)
      [ -n "$name" ] || continue
      printf 'timer %s\n' "$name"
    done <<< "$(systemctl list-timers --all --no-legend 2>/dev/null | sort -u)"
  else
    printf 'na no-systemctl\n'
  fi
}

scheduled_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    # cron records may still be present; only the systemd half is N/A.
    emit_na "$CHECK_NAME" systemd_units "systemctl not available"
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" scheduled_jobs "no baseline scheduled-job state"
    return 0
  fi

  local line path csha bsha name state
  # New / changed cron files.
  while IFS= read -r line; do
    case "$line" in 'cron '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    csha=$(printf '%s' "$line" | awk '{print $3}')
    bsha=$(awk -v p="$path" '$1=="cron"&&$2==p{print $3}' "$base_file" | head -n1)
    if [ -z "$bsha" ]; then
      emit_finding "$CHECK_NAME" cron_jobs CRIT \
        "new cron file '$path' since baseline" "absent" "$csha" false
    elif [ "$bsha" != "$csha" ]; then
      emit_finding "$CHECK_NAME" cron_jobs CRIT \
        "cron file '$path' modified since baseline" "$bsha" "$csha" false
    fi
  done < "$cur_file"
  # Removed cron files.
  while IFS= read -r line; do
    case "$line" in 'cron '*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    if ! awk -v p="$path" '$1=="cron"&&$2==p{f=1} END{exit !f}' "$cur_file"; then
      emit_finding "$CHECK_NAME" cron_jobs INFO \
        "cron file '$path' removed since baseline" "present" "absent" false
    fi
  done < "$base_file"

  # New systemd unit-files.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    state=$(awk -v n="$name" '$1=="unitfile"&&$2==n{print $3}' "$cur_file" | head -n1)
    if cfg_list_has expected_extra_units "$name"; then
      emit_finding "$CHECK_NAME" systemd_units INFO \
        "new systemd unit '$name' ($state) — allowlisted in expected_extra_units" \
        "absent" "$name" false
    else
      emit_finding "$CHECK_NAME" systemd_units CRIT \
        "new systemd unit '$name' ($state) since baseline" "absent" "$name" false
    fi
  done <<< "$(comm -13 \
      <(awk '$1=="unitfile"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="unitfile"{print $2}' "$cur_file" | sort -u))"
  # Removed systemd unit-files.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    emit_finding "$CHECK_NAME" systemd_units INFO \
      "systemd unit '$name' removed since baseline" "present" "absent" false
  done <<< "$(comm -23 \
      <(awk '$1=="unitfile"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="unitfile"{print $2}' "$cur_file" | sort -u))"

  # New timers.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if cfg_list_has expected_extra_units "$name"; then
      emit_finding "$CHECK_NAME" systemd_units INFO \
        "new timer '$name' — allowlisted in expected_extra_units" "absent" "$name" false
    else
      emit_finding "$CHECK_NAME" systemd_units CRIT \
        "new timer '$name' since baseline" "absent" "$name" false
    fi
  done <<< "$(comm -13 \
      <(awk '$1=="timer"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="timer"{print $2}' "$cur_file" | sort -u))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
