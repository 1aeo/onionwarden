#!/usr/bin/env bash
# lib/checks/ld_preload.sh — library-injection rootkit check (PLAN §2.3, fatal #3).
#
# /etc/ld.so.preload non-empty -> CRIT + fatal (writing it requires root; it is
# the classic global LD_PRELOAD rootkit hook). Per-process LD_PRELOAD/LD_AUDIT
# in the environment is also surfaced; a value not seen at baseline is WARN.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="ld_preload"
CHECK_CADENCE="fast"

ld_preload_collect() {
  if [ -e /etc/ld.so.preload ]; then
    if [ -s /etc/ld.so.preload ]; then
      printf 'ldsopreload nonempty %s %s\n' \
        "$(sha256_file /etc/ld.so.preload)" \
        "$(tr '\n' ';' < /etc/ld.so.preload 2>/dev/null | cut -c1-200)"
    else
      printf 'ldsopreload empty -\n'
    fi
  else
    printf 'ldsopreload absent -\n'
  fi

  # Per-process LD_PRELOAD / LD_AUDIT. /proc/<pid>/environ is NUL-separated and
  # root-readable. Diff by (comm, var, value) set — pids churn every run.
  local pid comm var
  for pid in /proc/[0-9]*; do
    [ -r "$pid/environ" ] || continue
    comm=$(tr -d '\0\n' < "$pid/comm" 2>/dev/null || printf '?')
    while IFS= read -r var; do
      case "$var" in
        LD_PRELOAD=*|LD_AUDIT=*)
          printf 'procenv %s %s\n' "$comm" "$var" ;;
      esac
    done <<< "$(tr '\0' '\n' < "$pid/environ" 2>/dev/null || true)"
  done | sort -u
}

ld_preload_analyze() {
  local base_file=$1 cur_file=$2
  local state sha detail

  state=$(awk '$1=="ldsopreload"{print $2}' "$cur_file" | head -n1)
  case "$state" in
    nonempty)
      sha=$(awk '$1=="ldsopreload"{print $3}' "$cur_file" | head -n1)
      detail=$(awk '$1=="ldsopreload"{$1="";$2="";$3="";print}' "$cur_file" | head -n1)
      emit_finding "$CHECK_NAME" ld_so_preload CRIT \
        "/etc/ld.so.preload is non-empty (library-injection rootkit hook):$detail" \
        "empty/absent" "$sha" true ;;
    empty|absent|"")
      : ;;  # expected state
  esac

  if [ ! -s "$base_file" ]; then
    # Without a baseline we can still report ld.so.preload (done above) but
    # cannot diff per-process env.
    return 0
  fi

  local base_env cur_env line comm
  base_env=$(grep '^procenv ' "$base_file" 2>/dev/null | sort -u || true)
  cur_env=$(grep '^procenv ' "$cur_file" 2>/dev/null | sort -u || true)
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    comm=$(printf '%s' "$line" | awk '{print $2}')
    emit_finding "$CHECK_NAME" ld_preload_env WARN \
      "process '$comm' has an LD_PRELOAD/LD_AUDIT not seen at baseline — investigate (daemon: treat as CRIT)" \
      "absent" "$(printf '%s' "$line" | sed 's/^procenv //')" false
  done <<< "$(comm -13 <(printf '%s\n' "$base_env") <(printf '%s\n' "$cur_env"))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
