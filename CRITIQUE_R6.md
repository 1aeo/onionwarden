# CRITIQUE R6 — PROMISC detection

**Lens:** bridge-member exclusion correctness; libvirt/lxc/docker veth/tap edge
cases; IFB/macvtap/wireguard interfaces. **File read:** `lib/checks/promisc.sh`
(whole), plus how `allow_virt_churn` / `is_hypervisor` reach it.

## Findings

### R6-1 (HIGH) — A macvtap/macvlan parent NIC is a false fatal #9
Creating a macvlan or macvtap on a physical NIC puts that lower device into
promiscuous mode — legitimately. The check classified the physical parent as
`physical`, no `master`, promiscuous → CRIT + fatal #9 ("LAN sniffing"). On a
virtualization host a macvtap created after baseline (a new VM/container with a
macvtap NIC) would trip an armed `poweroff`. PLAN §3.7 #9 says "anything under
`allow_virt_churn` [is] excluded", but the code applied `allow_virt_churn` only
to the `virtual:*` branch, never to a physical NIC promiscuous for a virtual
reason.

### R6-2 (MEDIUM) — The ip-vs-sysfs cross-check is CRIT+fatal for *all* kinds
The promiscuity cross-check (`ip -d link` vs the sysfs `IFF_PROMISC` flag) fired
CRIT + fatal for every interface. A veth/tap that flaps during container or VM
churn — or one that disappears between the `ip` read and the sysfs read — can
momentarily disagree. That produced a false fatal-class CRIT on a flapping
veth, where a disagreement is churn, not hiding. The "possible hiding" reading
is only meaningful for a physical uplink.

### R6-3 (MEDIUM) — `is_hypervisor` does not enable virt-churn tolerance
The check consulted only the `allow_virt_churn` host.conf flag. PLAN §0.2 says a
*hypervisor host* ("if true, tolerate `virbr*/tap*/vnet*` churn") should tolerate
the churn by virtue of being a hypervisor. A hypervisor where the operator
forgot to set `allow_virt_churn=true` still got physical-promisc fatals and
noisy virtual-interface WARNs.

## Non-findings (examined, no issue)

- veth/tap/vnet/bridge/wireguard/ifb/macvtap/vlan are all in
  `_PROMISC_VIRT_KINDS` and classified `virtual:*` — none can trip fatal #9.
  libvirt `vnet*` show kind `tun`; `virbr*` show `bridge`; docker veths show
  `veth` — all covered.
- A physical bridge/bond *member* (`master` set) going promiscuous is correctly
  WARN, not fatal.
- Device identity is the interface name (sysfs key), with `@peer` stripped — a
  veth peer suffix does not corrupt the sysfs `flags` path.

## Fixes applied

- **R6-1:** a physical NIC going promiscuous on a virt-churn-tolerant host is
  WARN ("macvtap/bridge-uplink?"), not CRIT/fatal.
- **R6-2:** the cross-check is CRIT+fatal only for a `physical` interface; a
  disagreement on a virtual interface is WARN, not fatal.
- **R6-3:** virt-churn tolerance is now `allow_virt_churn` **or** the
  `is_hypervisor` profile bit.
