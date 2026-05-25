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
#
# Normalization (parallel-snapshot byte-identity): the per-connection 5-tuple
# from /proc/net/tcp* churns on a busy guard — ephemeral src_port rotates per
# socket, TCP state cycles ESTABLISHED→TIME_WAIT→CLOSE within milliseconds. Two
# parallel snapshots a few seconds apart see DIFFERENT 5-tuple sets for the
# same stable peers. To get byte-identical `.current` across runs while keeping
# the tamper signal ("is there a new outbound destination? a new program
# initiating outbound?"), each outbound row is canonicalized to (comm, dst:port)
# — DROPPING src_port (ephemeral) and TCP fine-state (transient) — then sort -u'd.
# The verbose 5-tuple form with src_port + fine state goes to `RAW:`-prefixed
# lines that the snapshot tool relocates to `raw/network_deep.raw` (NOT
# compared) for forensic deep-dives.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="network_deep"
CHECK_CADENCE="slow"

# _network_deep_outbound PROC MODE UNIT — emit two parallel streams for every
# outbound socket, excluding (when MODE=exclude-process) those owned by a
# cgroup containing UNIT:
#
#   `outbound <comm> <remote>`                       — normalized, sort -u
#       Canonical tamper-detection row. Source port and TCP fine-state are
#       DROPPED so a stable peer set produces byte-identical output across
#       parallel snapshot runs even when ephemeral src_port and state churn.
#
#   `RAW: outbound_raw <proto> <state> <comm> <src> <remote>`  — sort -u
#       Verbose forensic detail (proto + fine TCP state + src_port).
#       Snapshot tool relocates `RAW:`-prefixed lines to raw/<check>.raw, so
#       these are NOT part of `.current` — `network_deep.raw` is NOT compared
#       for tamper detection. May legitimately differ across snapshots.
#
# TCP state coverage was widened from `ESTABLISHED only` to
# ESTABLISHED+CLOSING-bucket+SYN-bucket so a destination that's briefly in
# TIME_WAIT (very common during peer rotation) still shows up as outbound.
# LISTEN (no remote) and CLOSE (transient dead socket) are skipped.
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
    # Map /proc/net/tcp hex state (01..0B) to a coarse bucket. Buckets are the
    # state_class — fine states within the same bucket are TREATED AS THE SAME
    # for forensic raw lines, so a peer in TIME_WAIT (06) vs CLOSE_WAIT (08)
    # produces the same RAW row.
    #   01           -> ESTABLISHED
    #   02, 03       -> SYN          (SYN_SENT, SYN_RECV)
    #   04,05,06,08,09,0B -> CLOSING (FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT, CLOSE_WAIT, LAST_ACK, CLOSING)
    #   0A           -> LISTEN       (no remote — skipped upstream)
    #   07           -> CLOSE        (transient dead socket — skipped upstream)
    function state_class(st) {
      if (st == "01") return "ESTABLISHED"
      if (st == "02" || st == "03") return "SYN"
      if (st == "04" || st == "05" || st == "06" \
          || st == "08" || st == "09" || st == "0B") return "CLOSING"
      if (st == "0A") return "LISTEN"
      return "OTHER"
    }
    # phase 1 (stdin): inode -> pid
    { inopid[$1] = $2 }
    END {
      n = split("net/tcp net/tcp6 net/udp net/udp6", files, " ")
      for (fi = 1; fi <= n; fi++) {
        f = proc "/" files[fi]
        proto = files[fi]; sub(/^net\//, "", proto)
        is_tcp = (proto ~ /tcp/)
        while ((getline line < f) > 0) {
          c = split(line, F, " ")
          if (c < 10 || F[1] !~ /:$/) continue          # header / short line
          st = F[4]; loc = F[2]; rem = F[3]; ino = F[10]
          if (is_tcp) {
            sc = state_class(st)
            # LISTEN: no remote endpoint, not an outbound. CLOSE: transient
            # dead socket. OTHER: unknown state, skip rather than emit noise.
            if (sc == "LISTEN" || sc == "OTHER" || st == "07") continue
          } else {
            if (rem ~ /:0000$/) continue                # UDP: connected only
            sc = "ESTABLISHED"                          # UDP has no states
          }
          if (ino == "" || ino == "0") continue
          pid = (ino in inopid) ? inopid[ino] : ""
          if (mode == "exclude-process" && pid != "" && in_unit(pid) == 1) continue
          pname = (pid == "") ? "-" : comm_of(pid)
          remote = rstr(rem)
          # Normalized row — DROP src + state, de-dup by (comm, remote). One
          # row per (comm, dst:port) regardless of fine state or src ephemerals.
          print "outbound", pname, remote
          # Raw row — KEEP proto + state_class bucket + src for forensics.
          # state_class (not fine state) means TIME_WAIT vs CLOSE_WAIT both
          # appear as CLOSING — within-bucket churn is invisible in raw too.
          # Across-bucket churn (ESTABLISHED -> CLOSING) is legitimately
          # captured: raw is for forensic context, NOT byte-identicalness.
          print "RAW: outbound_raw", proto, sc, pname, rstr(loc), remote
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
