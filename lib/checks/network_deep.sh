#!/usr/bin/env bash
# lib/checks/network_deep.sh — deep network checks (PLAN §2.2).
#
# Outbound connections (ROLE-AWARE — §0.6), nftables ruleset, routes, gateway
# MAC, DNS resolvers, interface set. On a tor-relay the outbound check excludes
# connections owned by the tor.service cgroup (verified via /proc/<pid>/cgroup,
# not process name or uid — both forgeable, H2) and flags anything else.
#
# Relay-scale: the outbound collector reads /proc/net/{tcp,tcp6,udp,udp6} once
# each, builds a single inode->pid map from one walk of /proc/<pid>/fd, and
# reads each PID's comm + cgroup ONCE (cached). It is O(connections + pids) —
# never per-connection /proc reads. ONIONWARDEN_PROC overrides /proc for tests.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="network_deep"
CHECK_CADENCE="slow"

# _network_deep_outbound PROC MODE UNIT — emit `outbound <comm> <remote>` for
# every established/connected socket, excluding (when MODE=exclude-process)
# those owned by a cgroup containing UNIT.
_network_deep_outbound() {
  local proc=$1 mode=$2 unit=$3 d p
  # inode->pid pairs from one `ls -l` per PID over its fd/ dir (portable — no
  # GNU `find -printf`, so the fixture-based perf test runs on the macOS host).
  {
    for d in "$proc"/[0-9]*/fd; do
      [ -d "$d" ] || continue
      p=${d%/fd}; p=${p##*/}
      ls -l "$d" 2>/dev/null | sed -n "s|.*-> socket:\[\([0-9]*\)\].*|\1 $p|p" || true
    done
  } | awk -v proc="$proc" -v mode="$mode" -v unit="$unit" '
    function h2d(s,   i,n,v) {
      n = 0
      for (i = 1; i <= length(s); i++) {
        v = index("0123456789abcdef", tolower(substr(s, i, 1))) - 1
        if (v < 0) v = 0
        n = n * 16 + v
      }
      return n
    }
    function ip4(h) {
      return h2d(substr(h,7,2)) "." h2d(substr(h,5,2)) "." \
             h2d(substr(h,3,2)) "." h2d(substr(h,1,2))
    }
    function ip6(h,   w,b,out) {
      out = ""
      for (w = 0; w < 4; w++) {
        b = substr(h,w*8+7,2) substr(h,w*8+5,2) substr(h,w*8+3,2) substr(h,w*8+1,2)
        out = out (w ? ":" : "") substr(b,1,4) ":" substr(b,5,4)
      }
      return tolower(out)
    }
    function rstr(ap,   c,a) {
      c = index(ap, ":"); a = substr(ap, 1, c-1)
      if (length(a) <= 8) return ip4(a) ":" h2d(substr(ap, c+1))
      return "[" ip6(a) "]:" h2d(substr(ap, c+1))
    }
    function comm_of(pid,   c) {
      if (pid in commc) return commc[pid]
      c = "-"
      if ((getline c < (proc "/" pid "/comm")) > 0) sub(/[ \t\r\n]+$/, "", c)
      else c = "-"
      close(proc "/" pid "/comm")
      commc[pid] = c
      return c
    }
    # 0 if the cgroup belongs to UNIT — matched on a path SEGMENT so the
    # exclusion also covers systemd template instances (tor.service excludes
    # tor@0.service, tor@1.service, ... the real shape of a multi-instance relay).
    function in_unit(pid,   cg,line,np,parts,i,seg,stem,sl) {
      if (pid in unitc) return unitc[pid]
      cg = ""
      while ((getline line < (proc "/" pid "/cgroup")) > 0) cg = cg "/" line
      close(proc "/" pid "/cgroup")
      unitc[pid] = 0
      stem = unit; sub(/\.service$/, "", stem)
      sl = length(stem)
      np = split(cg, parts, "/")
      for (i = 1; i <= np; i++) {
        seg = parts[i]
        if (seg == unit) { unitc[pid] = 1; break }
        if (substr(seg, 1, sl + 1) == stem "@" \
            && substr(seg, length(seg) - 7) == ".service") { unitc[pid] = 1; break }
      }
      return unitc[pid]
    }
    # phase 1 (stdin): inode -> pid
    { inopid[$1] = $2 }
    END {
      n = split("net/tcp net/tcp6 net/udp net/udp6", files, " ")
      for (fi = 1; fi <= n; fi++) {
        f = proc "/" files[fi]
        is_tcp = (files[fi] ~ /tcp/)
        while ((getline line < f) > 0) {
          c = split(line, F, " ")
          if (c < 10 || F[1] !~ /:$/) continue          # header / short line
          st = F[4]; rem = F[3]; ino = F[10]
          if (is_tcp) { if (st != "01") continue }       # TCP: established only
          else { if (rem ~ /:0000$/) continue }          # UDP: connected only
          if (ino == "" || ino == "0") continue
          pid = (ino in inopid) ? inopid[ino] : ""
          if (mode == "exclude-process" && pid != "" && in_unit(pid) == 1) continue
          pname = (pid == "") ? "-" : comm_of(pid)
          print "outbound", pname, rstr(rem)
        }
        close(f)
      }
    }
  ' | sort -u
}

network_deep_collect() {
  local proc mode exclude_unit
  proc="${ONIONWARDEN_PROC:-/proc}"
  mode=$(cfg_get outbound_mode allowlist)
  exclude_unit=$(cfg_get outbound_exclude_unit tor.service)

  # Outbound established connections — relay-scale (O(conns + pids)).
  if [ -r "$proc/net/tcp" ]; then
    _network_deep_outbound "$proc" "$mode" "$exclude_unit"
  else
    printf 'outbound na no-procnet\n'
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
    emit_na "$CHECK_NAME" network_deep "outbound connections unavailable"
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
