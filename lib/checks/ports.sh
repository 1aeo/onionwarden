#!/usr/bin/env bash
# lib/checks/ports.sh — listening port diff + bind-IP expectation check (PLAN §2.2).
#
# ss -tulpnH normalised to proto/addr/port/process, diffed vs baseline. A new
# listener is CRIT; if its port is allowlisted in expected_lan_ports it is the
# operator's declared intent and demotes to INFO (PLAN §0.3 allowlist rule).
#
# Bind-IP expectations (the `listener_binding` signal): an optional host.conf
# knob `expected_listen_binding_<port>_<proto>` declares which bind IP(s) the
# operator expects. A listener whose actual bind violates the expectation is a
# `listener_binding` finding — CRIT when it has regressed to a wildcard
# (0.0.0.0 / [::]) on a port whose declared expectation forbids wildcards
# (loopback / local / specific IP / set), WARN for non-wildcard-to-non-wildcard
# mismatches (e.g. wrong specific IP). Rationale: a wildcard regression always
# WIDENS exposure beyond the operator's declared bind — for loopback-only
# Cursor sessions it leaks beyond localhost; for a LAN-bound BGP daemon it
# offers the port to the whole world. The check is independent of the
# baseline diff: a baselined-but-regressed listener still fires.
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
# (Lenient: also returns 0 for a specific non-loopback address — used by the
# new-listener severity branch.)
_addr_is_wildcard() {
  case "$1" in
    0.0.0.0|"*"|"::"|"[::]"|"") return 0 ;;
    127.*|"::1"|"[::1]") return 1 ;;
    *) return 0 ;;
  esac
}

# _is_strict_wildcard ADDR -> 0 ONLY for an actual v4/v6 wildcard.
_is_strict_wildcard() {
  case "$1" in 0.0.0.0|"*"|"::"|"[::]"|"") return 0 ;; *) return 1 ;; esac
}

# _is_loopback_addr ADDR -> 0 for a loopback address (v4 127.x.y.z or v6 ::1).
_is_loopback_addr() {
  case "$1" in 127.*|::1|"[::1]") return 0 ;; *) return 1 ;; esac
}

# _binding_expected_items PORT PROTO -> echo the expected-items list (newline-
# separated). Defaults to the literal "any" if the operator set no expectation.
_binding_expected_items() {
  local key="expected_listen_binding_${1}_${2}" items
  items=$(cfg_list "$key")
  [ -n "$items" ] || items=$(cfg_get "$key" "")
  [ -n "$items" ] || items="any"
  printf '%s' "$items"
}

# _binding_matches ADDR ITEMS -> 0 if ADDR satisfies any item in ITEMS.
# Accepts tokens (any|loopback|local) or specific IPs (v4 dotted, v6 bracketed
# or bare — both forms compared for IPv6).
_binding_matches() {
  local addr=$1 items=$2 item naddr
  naddr="$addr"
  case "$addr" in \[*\]) naddr="${addr#\[}"; naddr="${naddr%\]}" ;; esac
  while IFS= read -r item; do
    [ -n "$item" ] || continue
    case "$item" in
      any)      return 0 ;;
      loopback) _is_loopback_addr "$addr" && return 0 ;;
      local)    _is_strict_wildcard "$addr" || return 0 ;;
      *)
        [ "$item" = "$addr" ] && return 0
        [ "$item" = "$naddr" ] && return 0
        ;;
    esac
  done <<< "$items"
  return 1
}

ports_analyze() {
  local base_file=$1 cur_file=$2

  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" listening_ports "ss not available"
    return 0
  fi

  local base cur line proto addr port pname sev summary items exp_summary
  cur=$(grep '^listener ' "$cur_file" 2>/dev/null | sort -u || true)

  # --- bind-IP expectation check (independent of baseline diff) ------------
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    read -r _ proto addr port pname <<< "$line"
    items=$(_binding_expected_items "$port" "$proto")
    [ "$items" = "any" ] && continue       # no expectation → skip
    if ! _binding_matches "$addr" "$items"; then
      sev="WARN"
      # Wildcard regression: the operator declared a non-wildcard expectation
      # (loopback / local / specific IP / set) and the listener is now bound
      # to 0.0.0.0 or [::] — exposure has WIDENED beyond declared intent.
      # Always CRIT (loopback→wildcard is an exfil-channel leak; LAN-IP→
      # wildcard is the BGP-style world-exposed regression).
      if _is_strict_wildcard "$addr"; then
        sev="CRIT"
      fi
      exp_summary=$(printf '%s' "$items" | tr '\n' ',' | sed 's/,$//')
      emit_finding "$CHECK_NAME" listener_binding "$sev" \
        "port :$port/$proto is bound to $addr but host.conf expects $exp_summary — possible bind regression" \
        "$exp_summary" "$addr" false
    fi
  done <<< "$cur"

  # --- diff against baseline (new / removed) — needs a baseline ------------
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" listening_ports "no baseline listener set"
    return 0
  fi
  base=$(grep '^listener ' "$base_file" 2>/dev/null | sort -u || true)

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
