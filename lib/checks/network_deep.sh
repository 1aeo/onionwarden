#!/usr/bin/env bash
# lib/checks/network_deep.sh — deep network checks (PLAN §2.2).
#
# Outbound connections (ROLE-AWARE — §0.6), nftables ruleset, routes, gateway
# MAC, DNS resolvers, interface set. On a tor-relay the outbound check excludes
# connections owned by the tor.service cgroup (verified via /proc/<pid>/cgroup,
# not process name or uid — both forgeable, H2) and flags anything else.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="network_deep"
CHECK_CADENCE="slow"

# _proc_in_unit PID UNIT -> 0 if PID's cgroup belongs to systemd UNIT.
_proc_in_unit() {
  local cg
  cg=$(cat "/proc/$1/cgroup" 2>/dev/null || true)
  case "$cg" in *"$2"*) return 0 ;; *) return 1 ;; esac
}

network_deep_collect() {
  local mode exclude_unit
  mode=$(cfg_get outbound_mode allowlist)
  exclude_unit=$(cfg_get outbound_exclude_unit tor.service)

  # Outbound established connections.
  if command -v ss >/dev/null 2>&1; then
    ss -tunpH state established 2>/dev/null | while IFS= read -r line; do
      local remote pid pname
      remote=$(printf '%s' "$line" | awk '{print $5}')
      pid=$(printf '%s' "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
      pname=$(printf '%s' "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
      [ -n "$pname" ] || pname="-"
      # tor-relay: drop connections owned by the tor.service cgroup.
      if [ "$mode" = "exclude-process" ] && [ -n "$pid" ] \
         && _proc_in_unit "$pid" "$exclude_unit"; then
        continue
      fi
      printf 'outbound %s %s\n' "$pname" "$remote"
    done | sort -u
  else
    printf 'outbound na no-ss\n'
  fi

  # nftables ruleset hash.
  if command -v nft >/dev/null 2>&1; then
    printf 'nft %s\n' "$(nft list ruleset 2>/dev/null | sha256_string "$(cat)")"
  fi
  # Routes, DNS, ARP gateway, interface set.
  if command -v ip >/dev/null 2>&1; then
    ip route show 2>/dev/null | sed 's/^/route /' | sort -u
    ip -br link show 2>/dev/null | awk '{print "iface", $1}' | sort -u
    ip neigh show 2>/dev/null | awk '/router|REACHABLE/{print "arp", $1, $5}' | sort -u
  fi
  if [ -r /etc/resolv.conf ]; then
    awk '/^nameserver/{print "dns", $2}' /etc/resolv.conf | sort -u
  fi
}

network_deep_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^outbound na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" network_deep "ss not available"
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" network_deep "no baseline network state"
    return 0
  fi

  local line rec
  # Outbound connections not seen at baseline.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    emit_finding "$CHECK_NAME" outbound WARN \
      "outbound connection not seen at baseline: $(printf '%s' "$line" | sed 's/^outbound //')" \
      "absent" "$line" false
  done <<< "$(comm -13 \
      <(grep '^outbound ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^outbound ' "$cur_file" 2>/dev/null | sort -u))"

  # nft ruleset.
  local bn cn
  bn=$(awk '$1=="nft"{print $2}' "$base_file" | head -n1)
  cn=$(awk '$1=="nft"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bn" ] && [ "$bn" != "$cn" ]; then
    emit_finding "$CHECK_NAME" nft_ruleset CRIT \
      "nftables ruleset changed since baseline" "$bn" "$cn" false
  fi

  # Routes / DNS / interfaces / ARP — new entries.
  for rec in route dns iface; do
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      local sev=WARN
      [ "$rec" = dns ] && sev=CRIT
      [ "$rec" = route ] && case "$line" in *"default "*) sev=CRIT ;; esac
      emit_finding "$CHECK_NAME" "$rec" "$sev" \
        "new $rec since baseline: $(printf '%s' "$line" | sed "s/^$rec //")" \
        "absent" "$line" false
    done <<< "$(comm -13 \
        <(grep "^$rec " "$base_file" 2>/dev/null | sort -u) \
        <(grep "^$rec " "$cur_file" 2>/dev/null | sort -u))"
  done
  # Gateway MAC change (ARP spoof / new router).
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    emit_finding "$CHECK_NAME" arp WARN \
      "gateway ARP entry changed: $(printf '%s' "$line" | sed 's/^arp //')" "baseline" "changed" false
  done <<< "$(comm -13 \
      <(grep '^arp ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^arp ' "$cur_file" 2>/dev/null | sort -u))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
