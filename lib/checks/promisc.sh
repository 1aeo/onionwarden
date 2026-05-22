#!/usr/bin/env bash
# lib/checks/promisc.sh — promiscuous-interface check (PLAN §2.2, fatal #9).
#
# Fatal #9 is scoped narrowly: a *physical* NIC that is *not* a bridge member
# entering promiscuous mode. veth/tap/vnet/bridge/wireguard/macvtap/ifb and
# anything tolerated by allow_virt_churn go promiscuous legitimately and are
# excluded. Promiscuity is cross-read from `ip -d link` and the sysfs flag so a
# tool lying about one view is caught.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="promisc"
CHECK_CADENCE="fast"

# Virtual link kinds reported by `ip -d link`. A NIC with any of these is not
# a physical uplink and is excluded from fatal #9.
_PROMISC_VIRT_KINDS="bridge veth vlan vxlan bond dummy macvlan macvtap ifb \
wireguard ipip gre gretap sit vrf geneve ip6tnl ppp tun bond_slave team \
nlmon ip6gre vti vti6 xfrm bareudp"

promisc_collect() {
  if ! command -v ip >/dev/null 2>&1; then
    printf 'na no-iproute2\n'
    return 0
  fi
  local line name promisc master kind word flagval flagprom
  # `ip -o -d link` emits one physical/logical line per interface.
  while IFS= read -r line; do
    name=$(printf '%s' "$line" | awk '{print $2}' | sed 's/:$//' | sed 's/@.*//')
    [ -n "$name" ] || continue
    promisc=$(printf '%s' "$line" | sed -n 's/.*promiscuity \([0-9]*\).*/\1/p')
    [ -n "$promisc" ] || promisc=0
    master=$(printf '%s' "$line" | sed -n 's/.* master \([^ ]*\) .*/\1/p')
    [ -n "$master" ] || master="-"
    kind="physical"
    case "$name" in lo) kind="loopback" ;; esac
    for word in $_PROMISC_VIRT_KINDS; do
      case " $line " in *" $word "*) kind="virtual:$word"; break ;; esac
    done
    # Cross-check: sysfs IFF_PROMISC bit (0x100).
    flagprom=0
    if [ -r "/sys/class/net/$name/flags" ]; then
      flagval=$(cat "/sys/class/net/$name/flags" 2>/dev/null || printf 0x0)
      if [ $(( flagval & 0x100 )) -ne 0 ]; then flagprom=1; fi
    fi
    printf 'iface %s %s %s %s %s\n' "$name" "$kind" "$promisc" "$flagprom" "$master"
  done <<< "$(ip -o -d link show 2>/dev/null || true)"
}

# _promisc_on PROMISCUITY FLAGPROM -> 0 if either source says promiscuous.
_promisc_on() { [ "${1:-0}" -gt 0 ] || [ "${2:-0}" -eq 1 ]; }

promisc_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" promiscuous_iface "iproute2 not available"
    return 0
  fi

  local line name kind promisc flagprom master
  local b_promisc b_flagprom sev fatal summary virt_ok
  virt_ok=false
  cfg_bool allow_virt_churn && virt_ok=true

  while IFS= read -r line; do
    case "$line" in iface\ *) ;; *) continue ;; esac
    name=$(printf '%s' "$line" | awk '{print $2}')
    kind=$(printf '%s' "$line" | awk '{print $3}')
    promisc=$(printf '%s' "$line" | awk '{print $4}')
    flagprom=$(printf '%s' "$line" | awk '{print $5}')
    master=$(printf '%s' "$line" | awk '{print $6}')

    # Cross-check disagreement between ip and sysfs — possible hiding.
    if { [ "${promisc:-0}" -gt 0 ] && [ "${flagprom:-0}" -eq 0 ]; } \
       || { [ "${promisc:-0}" -eq 0 ] && [ "${flagprom:-0}" -eq 1 ]; }; then
      emit_finding "$CHECK_NAME" promisc_xcheck CRIT \
        "interface '$name' promiscuity disagrees between ip(-d link) and sysfs flags — possible hiding" \
        "consistent" "ip=$promisc sysfs=$flagprom" true
    fi

    _promisc_on "$promisc" "$flagprom" || continue

    # Was it already promiscuous at baseline? Then it is not a *new* event.
    b_promisc=$(awk -v n="$name" '$1=="iface"&&$2==n{print $4}' "$base_file" 2>/dev/null | head -n1)
    b_flagprom=$(awk -v n="$name" '$1=="iface"&&$2==n{print $5}' "$base_file" 2>/dev/null | head -n1)
    if [ -s "$base_file" ] && _promisc_on "${b_promisc:-0}" "${b_flagprom:-0}"; then
      continue
    fi

    case "$kind" in
      physical)
        if [ "$master" != "-" ]; then
          sev="WARN"; fatal=false
          summary="physical NIC '$name' is promiscuous but is a bridge member (master $master) — expected for a bridge port"
        else
          sev="CRIT"; fatal=true
          summary="physical NIC '$name' entered promiscuous mode and is not a bridge member — LAN sniffing"
        fi ;;
      loopback)
        sev="INFO"; fatal=false
        summary="loopback '$name' promiscuous (benign)" ;;
      *)
        if [ "$virt_ok" = true ]; then
          sev="INFO"
        else
          sev="WARN"
        fi
        fatal=false
        summary="virtual interface '$name' ($kind) promiscuous — excluded from fatal #9" ;;
    esac
    emit_finding "$CHECK_NAME" promiscuous_iface "$sev" "$summary" "not-promiscuous" "promiscuous" "$fatal"
  done < "$cur_file"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
