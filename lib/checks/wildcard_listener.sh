#!/usr/bin/env bash
# lib/checks/wildcard_listener.sh — flag any process listening on a wildcard
# address (0.0.0.0 / * / [::]) as CRIT (PLAN §2.2; BGP-audit follow-up).
#
# Premise: on these relay-fleet hosts *nothing* should listen on a wildcard
# address — every daemon should bind a specific interface/IP. A wildcard bind
# offers the port to every network the host is attached to. The BGP audit found
# FRR `bgpd` listening on `0.0.0.0:179` on three hosts (relay-host-3, relay-host-5,
# relay-host-6) that onionwarden did not catch, because `ports.sh`'s bind-IP
# expectation check is opt-in (it only fires when the operator has *declared* an
# `expected_listen_binding_<port>_<proto>` for that port). This check inverts
# that default: a wildcard bind is CRIT *unless* the operator has explicitly
# allowlisted it.
#
# Allowlist: `/etc/onionwarden/wildcard-listener.allow` (override the path for
# tests/alternate roots via $ONIONWARDEN_WILDCARD_ALLOW). One exception per
# line, exact `<comm>:<port>:<proto>` — e.g. `sshd:22:tcp`. All three fields
# must match (proto specificity matters: an entry for tcp does NOT permit the
# udp bind). `#`-comments and blank lines are ignored; malformed lines (not
# exactly three non-empty fields) are skipped but never abort the parse. The
# shipped default is **empty** — the operator permits, with a SECURITY
# justification comment, exactly what they intend to expose. See
# docs/WILDCARD_LISTENER.md.
#
# Each offending listener is its own CRIT finding (one alert per process+port),
# carrying comm/port/proto/pid/user/exe + a remediation hint. Under the Phase-4
# canary Option-D model a CRIT must be remediated or signed-acked to WARN; it
# never silently passes.
#
# analyze() stays a pure function of (current state, allowlist file): collect()
# captures pid/user/exe into the state line so analyze() runs no host commands.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="wildcard_listener"
CHECK_CADENCE="fast"

WILDCARD_ALLOW_DEFAULT="/etc/onionwarden/wildcard-listener.allow"

# _wl_is_wildcard ADDR -> 0 if ADDR is an any-address wildcard bind.
_wl_is_wildcard() {
  case "$1" in 0.0.0.0|"*"|"::"|"[::]"|"") return 0 ;; *) return 1 ;; esac
}

wildcard_listener_collect() {
  if ! command -v ss >/dev/null 2>&1; then
    printf 'na no-ss\n'
    return 0
  fi
  # ss -H columns (combined -tu): Netid State RecvQ SendQ Local:Port Peer Process
  # Netid is the proto (tcp|udp). Pull proto/addr/port/comm/pid, then resolve
  # the listener's owning user and exe from /proc and keep only wildcard binds.
  ss -tulpnH 2>/dev/null | awk '
    {
      proto=$1; local=$5; rest=$0
      n=split(local, a, ":")
      port=a[n]
      addr=substr(local, 1, length(local)-length(port)-1)
      if (addr=="") addr="*"
      comm="-"; pid="-"
      if (match(rest, /users:\(\("[^"]+"/)) comm=substr(rest, RSTART+8, RLENGTH-8-1)
      if (match(rest, /pid=[0-9]+/))        pid=substr(rest, RSTART+4, RLENGTH-4)
      print proto, addr, port, comm, pid
    }' | sort -u | while read -r proto addr port comm pid; do
    _wl_is_wildcard "$addr" || continue
    local user="-" exe="-"
    if [ "$pid" != "-" ] && [ -e "/proc/$pid" ]; then
      user=$(stat -c '%U' "/proc/$pid" 2>/dev/null || printf '?')
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null || printf '?')
      [ -n "$exe" ] || exe="?"
    fi
    printf 'wildcard %s %s %s %s %s %s %s\n' \
      "$proto" "$port" "$comm" "$pid" "$user" "$addr" "$exe"
  done | sort -u
}

# _wl_load_allow -> echo the normalised allow set, one `comm:port:proto` per
# line. Strips `#`-comments (full-line and inline), trims, and keeps only lines
# that are exactly three non-empty colon-separated fields.
_wl_load_allow() {
  local file=$1 raw key c p pr
  [ -f "$file" ] || return 0
  while IFS= read -r raw || [ -n "$raw" ]; do
    raw=${raw%%#*}                      # drop comment (full-line or inline)
    raw=$(printf '%s' "$raw" | tr -d '[:space:]')
    [ -n "$raw" ] || continue
    # exactly three fields, all non-empty
    IFS=: read -r c p pr extra <<< "$raw"
    [ -n "$c" ] && [ -n "$p" ] && [ -n "$pr" ] && [ -z "${extra:-}" ] || continue
    case "$raw" in *:*:*) printf '%s\n' "$c:$p:$pr" ;; esac
  done < "$file"
}

wildcard_listener_analyze() {
  local base_file=$1 cur_file=$2

  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" wildcard_bind "ss not available"
    return 0
  fi

  # Anchor to a trusted baseline, like every other check: assert wildcard binds
  # only once a baseline has been *captured* for this check. A real captured
  # baseline always has a `wildcard_listener.state` (onionwarden-baseline writes
  # one per check, even empty), so this gate is satisfied on every deployed host
  # — the check then runs ABSOLUTELY against the allowlist (it does NOT diff the
  # baseline, so a wildcard that was already present when the baseline was taken
  # is still CRIT). The gate only suppresses on a host with no established
  # baseline (the dispatcher passes /dev/null), where it would otherwise be
  # asserting against an untrusted/unknown world — exactly the
  # bootstrapping/nobaseline state where the dispatcher already withholds alerts.
  if [ "$base_file" = "/dev/null" ] || [ ! -e "$base_file" ]; then
    emit_na "$CHECK_NAME" wildcard_bind \
      "no baseline captured for this check yet — inactive until a baseline exists"
    return 0
  fi

  local allow_file allow
  allow_file="${ONIONWARDEN_WILDCARD_ALLOW:-$WILDCARD_ALLOW_DEFAULT}"
  allow=$(_wl_load_allow "$allow_file")

  local line proto port comm pid user bind exe key hint
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in 'wildcard '*) ;; *) continue ;; esac
    # fields: wildcard PROTO PORT COMM PID USER BIND EXE  (exe = remainder)
    read -r _ proto port comm pid user bind exe <<< "$line"
    # Defence in depth: only wildcard binds are findings. collect() already
    # filters to these, but re-checking keeps a specific-IP line (1.2.3.4:179)
    # from ever being flagged and makes analyze() self-contained.
    _wl_is_wildcard "$bind" || continue
    key="$comm:$port:$proto"
    if [ -n "$allow" ] && printf '%s\n' "$allow" | grep -Fxq "$key"; then
      continue                          # operator-permitted wildcard bind
    fi
    hint="Configure $comm to bind only a specific interface IP, not $bind"
    case "$comm" in
      bgpd|*bgp*) hint="$hint (FRR bgpd: set a bound listen address, e.g. \`bgpd -l <ip>\` / \`listenon <ip>\` in frr.conf)" ;;
      *)          hint="$hint (e.g. a \`-l <ip>\` / \`bind <ip>\` daemon option)" ;;
    esac
    emit_finding "$CHECK_NAME" wildcard_bind "CRIT" \
      "$comm (pid $pid, user $user) listens on wildcard $bind:$port/$proto — $hint" \
      "no wildcard binds permitted (allowlist $allow_file: $comm:$port:$proto)" \
      "proto=$proto port=$port comm=$comm pid=$pid user=$user bind=$bind exe=$exe" \
      false
  done < "$cur_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
