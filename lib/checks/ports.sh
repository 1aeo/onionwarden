#!/usr/bin/env bash
# lib/checks/ports.sh — listening port diff (PLAN §2.2).
#
# ss -tulpnH normalised to proto/addr/port/process, diffed vs baseline. A new
# listener is CRIT; if its port is allowlisted in expected_lan_ports it is the
# operator's declared intent and demotes to INFO (PLAN §0.3 allowlist rule).
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="ports"
CHECK_CADENCE="fast"

ports_collect() {
  if ! command -v ss >/dev/null 2>&1; then
    printf 'na no-ss\n'
    return 0
  fi
  # ss -H columns: Netid State RecvQ SendQ Local:Port Peer:Port Process
  ss -tulpnH 2>/dev/null | awk '
    {
      proto=$1; local=$5; proc=$0
      # port = after the final colon; addr = everything before it
      n=split(local, a, ":")
      port=a[n]
      addr=substr(local, 1, length(local)-length(port)-1)
      if (addr=="") addr="*"
      # process name from users:(("name",pid=...))
      pname="-"
      if (match(proc, /users:\(\("[^"]+"/)) {
        pname=substr(proc, RSTART+8, RLENGTH-8-1)
      }
      print "listener", proto, addr, port, pname
    }' | sort -u
}

# _addr_is_wildcard ADDR -> 0 if the listener is reachable beyond loopback.
_addr_is_wildcard() {
  case "$1" in
    0.0.0.0|"*"|"::"|"[::]"|"") return 0 ;;
    127.*|"::1"|"[::1]") return 1 ;;
    *) return 0 ;;  # a specific non-loopback address is also externally bound
  esac
}

ports_analyze() {
  local base_file=$1 cur_file=$2

  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" listening_ports "ss not available"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" listening_ports "no baseline listener set"
    return 0
  fi

  local base cur line proto addr port pname sev summary
  base=$(grep '^listener ' "$base_file" 2>/dev/null | sort -u || true)
  cur=$(grep '^listener ' "$cur_file" 2>/dev/null | sort -u || true)

  # New listeners.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    read -r _ proto addr port pname <<< "$line"
    if cfg_list_has expected_lan_ports "$port"; then
      sev="INFO"
      summary="new listener $proto $addr:$port ($pname) — port allowlisted in expected_lan_ports"
    elif _addr_is_wildcard "$addr"; then
      sev="CRIT"
      summary="new externally-bound listener $proto $addr:$port ($pname) not in expected_lan_ports"
    else
      sev="CRIT"
      summary="new loopback listener $proto $addr:$port ($pname) since baseline"
    fi
    emit_finding "$CHECK_NAME" listening_ports "$sev" "$summary" "absent" "$proto $addr:$port $pname" false
  done <<< "$(comm -13 <(printf '%s\n' "$base") <(printf '%s\n' "$cur"))"

  # Removed listeners.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    read -r _ proto addr port pname <<< "$line"
    emit_finding "$CHECK_NAME" listening_ports INFO \
      "listener $proto $addr:$port ($pname) gone since baseline" \
      "$proto $addr:$port $pname" "absent" false
  done <<< "$(comm -23 <(printf '%s\n' "$base") <(printf '%s\n' "$cur"))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
