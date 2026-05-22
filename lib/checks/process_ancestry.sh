#!/usr/bin/env bash
# lib/checks/process_ancestry.sh — service-daemon shells + temp execs (PLAN §2.3).
#
# A shell/interpreter parented to a service daemon that should never spawn one
# (nginx, node, tor, vllm, ...) is a near-certain compromise — CRIT, emitted on
# *presence* (no baseline diff: any occurrence is bad). Shells parented by
# sshd/cron/systemd/login/getty are excluded (H4). Executables in world-writable
# temp dirs are diffed vs baseline (WARN).
#
# Relay-scale: one walk of /proc, parents resolved from a pid->ppid/comm map
# built in a single awk pass over /proc/<pid>/stat (one read per pid, never
# re-stat parents per child). O(pids). ONIONWARDEN_PROC overrides /proc for tests.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="process_ancestry"
CHECK_CADENCE="slow"

# Interpreters whose presence as a daemon child is suspicious.
_PA_SHELLS="sh bash dash ash zsh ksh python python2 python3 perl ruby nc ncat"
# Service daemons that must never be the parent of a shell.
_PA_DAEMONS="nginx node tor vllm apache2 apache mysqld mariadbd postgres \
postgresql redis-server memcached php-fpm haproxy"

process_ancestry_collect() {
  local proc="${ONIONWARDEN_PROC:-/proc}"

  # svcshell: a single awk pass over every /proc/<pid>/stat builds the
  # pid->comm and pid->ppid maps, then resolves each shell's parent from the
  # map. No per-child re-stat of parents.
  if [ -d "$proc" ] && ls "$proc"/[0-9]*/stat >/dev/null 2>&1; then
    awk -v shells=" $_PA_SHELLS " -v daemons=" $_PA_DAEMONS " '
      FNR==1 {
        pidf = FILENAME
        sub(/\/stat$/, "", pidf); sub(/.*\//, "", pidf)
        # /proc/<pid>/stat: "PID (comm) STATE PPID ..."; comm may hold spaces
        # and parens, so take the parenthesised span and split what follows.
        if (match($0, /\(.*\)/)) {
          c = substr($0, RSTART+1, RLENGTH-2)
          split(substr($0, RSTART+RLENGTH+1), a, " ")
          pp = a[2]
        } else { c = "?"; pp = 0 }
        comm[pidf] = c; ppid[pidf] = pp; pids[pidf] = 1
      }
      END {
        for (p in pids) {
          ch = comm[p]; base = ch; sub(/[0-9.]+$/, "", base)
          if (index(shells, " " ch " ") == 0 && index(shells, " " base " ") == 0) continue
          par = comm[ppid[p]]
          if (par == "") continue
          pbase = par; sub(/[0-9.]+$/, "", pbase)
          if (index(daemons, " " par " ") > 0 || index(daemons, " " pbase " ") > 0)
            print "svcshell", par, ch
        }
      }
    ' "$proc"/[0-9]*/stat 2>/dev/null | sort -u
  else
    printf 'na no-proc\n'
  fi

  # Executables in world-writable temp dirs.
  if command -v find >/dev/null 2>&1; then
    local path
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      printf 'tmpexec %s\n' "$path"
    done <<< "$(find /tmp /var/tmp /dev/shm -xdev -type f -perm -111 2>/dev/null | sort -u || true)"
  fi
}

process_ancestry_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" process_ancestry "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi

  # svcshell: any occurrence is bad — emit on presence, no baseline diff.
  local line parent child
  while IFS= read -r line; do
    case "$line" in 'svcshell '*) ;; *) continue ;; esac
    parent=$(printf '%s' "$line" | awk '{print $2}')
    child=$(printf '%s' "$line" | awk '{print $3}')
    emit_finding "$CHECK_NAME" service_shell CRIT \
      "service daemon '$parent' is the parent of a shell/interpreter '$child'" \
      "no-shell" "$parent->$child" true
  done < "$cur_file"

  # tmpexec: diff vs baseline (a temp dir may legitimately hold some execs).
  if [ ! -s "$base_file" ]; then
    return 0
  fi
  local path
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    emit_finding "$CHECK_NAME" temp_exec WARN \
      "new executable file in a world-writable temp dir: $path" "absent" "$path" false
  done <<< "$(comm -13 \
      <(awk '$1=="tmpexec"{print $2}' "$base_file" | sort -u) \
      <(awk '$1=="tmpexec"{print $2}' "$cur_file" | sort -u))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
