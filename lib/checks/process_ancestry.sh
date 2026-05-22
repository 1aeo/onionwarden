#!/usr/bin/env bash
# lib/checks/process_ancestry.sh — service-daemon shells + temp execs (PLAN §2.3).
#
# A shell/interpreter parented to a service daemon that should never spawn one
# (nginx, node, tor, vllm, ...) is a near-certain compromise — CRIT, emitted on
# *presence* (no baseline diff: any occurrence is bad). Shells parented by
# sshd/cron/systemd/login/getty are excluded (H4) — they legitimately spawn
# shells. Executables in world-writable temp dirs are diffed vs baseline (WARN).
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

# _pa_in_list ITEM LIST -> 0 if ITEM is a whitespace word of LIST.
_pa_in_list() {
  local needle=$1 word
  for word in $2; do
    [ "$word" = "$needle" ] && return 0
  done
  return 1
}

process_ancestry_collect() {
  if ! command -v ps >/dev/null 2>&1; then
    printf 'na no-ps\n'
    return 0
  fi
  # Build a pid->comm map line set so analyze stays pure. Try GNU ps first.
  local pslines
  pslines=$(ps -eo pid,ppid,comm 2>/dev/null) || pslines=""
  if [ -z "$pslines" ]; then
    # BSD ps fallback (macOS test host).
    pslines=$(ps -axo pid,ppid,comm 2>/dev/null) || pslines=""
  fi
  if [ -n "$pslines" ]; then
    # For each process whose comm is a shell, look up its parent's comm and
    # emit only when the parent is a service daemon (not sshd/cron/systemd).
    printf '%s\n' "$pslines" | awk -v shells=" $_PA_SHELLS " -v daemons=" $_PA_DAEMONS " '
      NR>1 {
        pid=$1; ppid=$2; comm=$3
        # strip a leading path from comm
        n=split(comm, c, "/"); comm=c[n]
        pcomm[pid]=comm; parent[pid]=ppid
        rows[NR]=pid
      }
      END {
        for (i in rows) {
          p=rows[i]; ch=pcomm[p]
          # is the child an interpreter/shell?
          base=ch; sub(/[0-9.]+$/,"",base)
          if (index(shells, " " ch " ")==0 && index(shells, " " base " ")==0) continue
          par=pcomm[parent[p]]
          if (par=="") continue
          pbase=par; sub(/[0-9.]+$/,"",pbase)
          if (index(daemons, " " par " ")>0 || index(daemons, " " pbase " ")>0)
            print "svcshell", par, ch
        }
      }' | sort -u
  fi

  # Executables in world-writable temp dirs.
  if command -v find >/dev/null 2>&1; then
    local path
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      printf 'tmpexec %s\n' "$path"
    done <<< "$(find /tmp /var/tmp /dev/shm -xdev -type f -perm -111 2>/dev/null | sort -u)"
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
    # Without a baseline, do not flag tmpexec, but svcshell above still fires.
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
