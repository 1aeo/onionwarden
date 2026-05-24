#!/usr/bin/env bash
# lib/checks/kernel_state.sh — eBPF / kexec / lockdown / sysctls (PLAN §2.1).
#
# A staged kexec image you didn't load is a boot-bypass persistence path (CRIT).
# modules_disabled dropping 1->0 undoes Phase-4 hardening (CRIT). Restrict-style
# sysctls or kernel lockdown weakening is WARN. A new eBPF program of a tracing/
# networking type (kprobe/tracepoint/xdp/cgroup) is CRIT.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="kernel_state"
CHECK_CADENCE="slow"

# Restrict-style sysctls. For most, higher value = more restrictive so a DROP
# is a weakening. Two exceptions are explicitly tracked as "this value must
# stay" (rp_filter and tcp_syncookies — a drop to 0 is a clear regression but
# raising past the recommended is not a weakening). lockdown ordering: none <
# integrity < confidentiality.
#
# Source set: the existing 5 originally tracked + 7 added per the CIS Debian
# 12 / STIG benchmarks: fs.suid_dumpable, kernel.randomize_va_space, plus the
# core IP-spoofing / redirect / source-route protections every server should
# carry. Multi-family entries are kept distinct (e.g. v4 vs v6 accept_redirects)
# so a drift on one family doesn't get masked.
#
# Recommended values (REFERENCE ONLY — onionwarden does not auto-apply; the
# operator decides per-host whether to harden). A snapshot report-writer
# surfaces "current value vs recommended" as an INFO finding for the operator;
# this collector's analyze() only fires on drift FROM the signed baseline.
# Sources: CIS Debian 12 Benchmark §3, RHEL 9 STIG, Linux kernel docs.
#
#   kernel.kptr_restrict           = 2     (hide /proc/kallsyms from all)
#   kernel.dmesg_restrict          = 1     (non-root can't read dmesg)
#   kernel.unprivileged_bpf_disabled = 2   (BPF disabled including admin)
#   kernel.kexec_load_disabled     = 1     (bare metal only; guest leaves to host)
#   kernel.yama.ptrace_scope       = 1     (parent-only ptrace)
#   kernel.randomize_va_space      = 2     (full ASLR)
#   fs.suid_dumpable               = 0     (no SUID coredumps)
#   fs.protected_hardlinks         = 1
#   fs.protected_symlinks          = 1
#   fs.protected_fifos             = 2
#   fs.protected_regular           = 2
#   net.ipv4.tcp_syncookies        = 1
#   net.ipv4.conf.*.rp_filter      = 2     (loose for multi-IP tor relays;
#                                           strict=1 drops asymmetric paths)
#   net.ipv4.conf.*.accept_redirects = 0
#   net.ipv4.conf.*.send_redirects   = 0
#   net.ipv4.conf.*.accept_source_route = 0
#   net.ipv4.conf.*.log_martians     = 1
#   net.ipv6.conf.*.accept_redirects = 0
#   net.ipv6.conf.*.accept_source_route = 0
#   lockdown                       = integrity  (kernel cmdline; reboot to apply)
_KS_SYSCTLS="kernel.kptr_restrict kernel.dmesg_restrict \
kernel.unprivileged_bpf_disabled kernel.kexec_load_disabled \
kernel.yama.ptrace_scope kernel.randomize_va_space \
fs.suid_dumpable fs.protected_hardlinks fs.protected_symlinks \
fs.protected_fifos fs.protected_regular \
net.ipv4.tcp_syncookies \
net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter \
net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route \
net.ipv4.conf.all.log_martians \
net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects \
net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route"

kernel_state_collect() {
  local v
  # R10-3: a container shares the host kernel — out of scope for a guest.
  if prof_bool is_container; then
    printf 'na container\n'
    return 0
  fi
  # eBPF programs grouped by type.
  if command -v bpftool >/dev/null 2>&1; then
    local types t n
    types=$(bpftool prog show 2>/dev/null | sed -n 's/.*[0-9]*: \([a-z_]*\) .*/\1/p' \
            | sort -u)
    if [ -z "$types" ]; then
      printf 'bpf none 0\n'
    else
      while IFS= read -r t; do
        [ -n "$t" ] || continue
        n=$(bpftool prog show 2>/dev/null | grep -c " $t " || true)
        printf 'bpf %s %s\n' "$t" "${n:-0}"
      done <<< "$types"
    fi
  else
    printf 'bpf na no-bpftool\n'
  fi

  # kexec state.
  if [ -r /sys/kernel/kexec_loaded ]; then
    printf 'kexec loaded %s\n' "$(cat /sys/kernel/kexec_loaded 2>/dev/null || printf 0)"
  fi
  if [ -r /proc/sys/kernel/kexec_load_disabled ]; then
    printf 'kexec disabled %s\n' \
      "$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null || printf 0)"
  fi

  # Module-load lockout.
  if [ -r /proc/sys/kernel/modules_disabled ]; then
    printf 'modules_disabled %s\n' \
      "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || printf 0)"
  fi

  # Kernel lockdown — file content looks like "none [integrity] confidentiality".
  if [ -r /sys/kernel/security/lockdown ]; then
    v=$(sed -n 's/.*\[\([a-z]*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null)
    [ -n "$v" ] || v=$(cat /sys/kernel/security/lockdown 2>/dev/null || printf none)
    printf 'lockdown %s\n' "$v"
  fi

  # Security sysctls.
  if command -v sysctl >/dev/null 2>&1; then
    local key
    for key in $_KS_SYSCTLS; do
      v=$(sysctl -n "$key" 2>/dev/null) || v=""
      [ -n "$v" ] && printf 'sysctl %s %s\n' "$key" "$v"
    done
  fi
}

# _ks_lockdown_rank LEVEL -> integer order of a lockdown level.
_ks_lockdown_rank() {
  case "$1" in
    none) printf 0 ;;
    integrity) printf 1 ;;
    confidentiality) printf 2 ;;
    *) printf 0 ;;
  esac
}

kernel_state_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" kernel_state "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" kernel_state "no baseline kernel state"
    return 0
  fi

  local bv cv line key
  # kexec_loaded becoming 1 unexpectedly.
  bv=$(awk '$1=="kexec"&&$2=="loaded"{print $3}' "$base_file" | head -n1)
  cv=$(awk '$1=="kexec"&&$2=="loaded"{print $3}' "$cur_file" | head -n1)
  if [ -n "$cv" ] && [ "${bv:-0}" = "0" ] && [ "$cv" = "1" ]; then
    emit_finding "$CHECK_NAME" kexec_state CRIT \
      "a kexec image was staged since baseline (boot-bypass persistence)" \
      "${bv:-0}" "$cv" true
  fi

  # modules_disabled dropping 1 -> 0.
  bv=$(awk '$1=="modules_disabled"{print $2}' "$base_file" | head -n1)
  cv=$(awk '$1=="modules_disabled"{print $2}' "$cur_file" | head -n1)
  if [ "${bv:-0}" = "1" ] && [ "${cv:-0}" = "0" ]; then
    emit_finding "$CHECK_NAME" modules_disabled CRIT \
      "kernel.modules_disabled dropped from 1 to 0 — module-load lockout undone" \
      "$bv" "$cv" true
  fi

  # Kernel lockdown weakening.
  bv=$(awk '$1=="lockdown"{print $2}' "$base_file" | head -n1)
  cv=$(awk '$1=="lockdown"{print $2}' "$cur_file" | head -n1)
  if [ -n "$bv" ] && [ -n "$cv" ] && [ "$bv" != "$cv" ]; then
    if [ "$(_ks_lockdown_rank "$cv")" -lt "$(_ks_lockdown_rank "$bv")" ]; then
      emit_finding "$CHECK_NAME" lockdown WARN \
        "kernel lockdown weakened since baseline" "$bv" "$cv" false
    else
      emit_finding "$CHECK_NAME" lockdown INFO \
        "kernel lockdown level changed since baseline" "$bv" "$cv" false
    fi
  fi

  # Security sysctls weakening (numeric decrease = weakening).
  while IFS= read -r line; do
    case "$line" in 'sysctl '*) ;; *) continue ;; esac
    key=$(printf '%s' "$line" | awk '{print $2}')
    cv=$(printf '%s' "$line" | awk '{print $3}')
    bv=$(awk -v k="$key" '$1=="sysctl"&&$2==k{print $3}' "$base_file" | head -n1)
    [ -n "$bv" ] || continue
    [ "$bv" = "$cv" ] && continue
    case "$bv$cv" in
      *[!0-9-]*)
        emit_finding "$CHECK_NAME" sysctls INFO \
          "sysctl '$key' changed since baseline" "$bv" "$cv" false ;;
      *)
        if [ "$cv" -lt "$bv" ]; then
          emit_finding "$CHECK_NAME" sysctls WARN \
            "security sysctl '$key' weakened since baseline" "$bv" "$cv" false
        else
          emit_finding "$CHECK_NAME" sysctls INFO \
            "security sysctl '$key' tightened since baseline" "$bv" "$cv" false
        fi ;;
    esac
  done < "$cur_file"

  # New eBPF program types vs baseline.
  if grep -q '^bpf na' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" ebpf_programs "bpftool not available"
  else
    local t
    while IFS= read -r t; do
      [ -n "$t" ] || continue
      case "$t" in
        kprobe|tracepoint|raw_tracepoint|perf_event|xdp|cgroup*|sched*|sk_*|lsm)
          emit_finding "$CHECK_NAME" ebpf_programs CRIT \
            "new eBPF program of type '$t' since baseline" "absent" "$t" false ;;
        *)
          emit_finding "$CHECK_NAME" ebpf_programs WARN \
            "new eBPF program of type '$t' since baseline" "absent" "$t" false ;;
      esac
    done <<< "$(comm -13 \
        <(awk '$1=="bpf"&&$2!="na"&&$2!="none"{print $2}' "$base_file" | sort -u) \
        <(awk '$1=="bpf"&&$2!="na"&&$2!="none"{print $2}' "$cur_file" | sort -u))"
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
