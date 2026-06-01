# onionwarden — Ubuntu/Debian fleet tamper-monitoring plan

## Execution TODO

Execution checklist — work top-to-bottom; check items off as they ship. Each item cites the PLAN.md section that specifies it (the design reference). The **Operator decisions** block must be answered before the phase work it blocks. This list reflects the *post-critique* plan (CRITIQUE.md, 2026-05-21).

### Operator decisions — needed before / during Phase 0
- [x] Confirm `relay-a` as the default rollout canary (§8 Q1) (default kept — OPERATOR_DECISIONS.md §1)
- [x] Confirm role assignments — 8 relays `tor-relay`, `relay-b` `eval-host` (§8 Q14) (default kept — OPERATOR_DECISIONS.md §2)
- [x] Choose & provision the off-box **receiver host** — always-on, off-fleet (§4, §8 Q2) (deferred-input — OPERATOR_DECISIONS.md §3, **HIGH-RISK flag**)
- [x] Decide **signing-key custody** — offline machine or hardware token (§5, §8 Q5) (operator encrypted-laptop store — OPERATOR_DECISIONS.md §4)
- [x] Pick `ntfy_url` (ntfy.sh vs self-hosted) and `deadman_provider` + `deadman_url` (§4, §8 Q3/Q4) (Healthchecks.io + ntfy.sh — OPERATOR_DECISIONS.md §5)
- [x] Inventory the 8 relays' **virtualization type** (VM vs bare metal) — Appendix A is relay-b-only (§5, H7) (deferred to Phase-0 inventory — OPERATOR_DECISIONS.md §6, **HIGH-RISK flag**)
- [x] Decide the **sustainable offline-scan cadence**; if not monthly, downgrade the §1 backstop-(c) claim (§1, §5, H7) (quarterly — OPERATOR_DECISIONS.md §7)
- [x] Decide per-host `fatal_action` policy — relays use `alert`/`poweroff`, never `freeze` (§3.7, H6) (all hosts `alert` initially — OPERATOR_DECISIONS.md §8)
- [x] Set per-host `physical_access_allowed` (default `false`); confirm any permanently-attached IPMI/KVM USB keyboard is captured at baseline so it doesn't trip fatal #10 (§2.8, §8) (`false` fleet-wide — OPERATOR_DECISIONS.md §9)

### Phase 0 — Bootstrap (off-host)
- [x] Generate the fleet Ed25519 signing keypair; store the private key per the custody decision (§5) (file: bin/onionwarden-sign keygen, lib/ed25519.py)
- [x] Stand up the receiver host with an append-only restricted SSH key for `events.log` (§4) (file: receiver/receiver-setup.sh, receiver/receiver-append.sh)
- [x] Build receiver self-hash + `onionwarden.pub`-hash automated comparison, CRIT-on-mismatch (§4, C2/H5) (file: receiver/onionwarden-receiver verify-record|verify-check)
- [x] Build receiver one-per-day fleet-rollup digest; per-host push only on WARN/CRIT (§4, H8) (file: receiver/onionwarden-receiver digest)
- [x] Build receiver `events.log` sequence-gap detection + append rate-limiting (§4, M7) (file: receiver/onionwarden-receiver seqcheck; receiver-append.sh rate limit)
- [x] Register the dead-man provider; one check per host (§4) (file: lib/alert.sh deadman_ping; provider registration is an operator step — OPERATOR_DECISIONS.md §5)
- [x] Per host: run the strongest-available offline trust-establishment scan, then capture + sign the initial baseline (§5) (file: bin/onionwarden-baseline collect, bin/onionwarden-sign; scan is an operator step)
- [x] Record each host's known-good self-hash + pubkey-hash off-box on the receiver (§3.5, C2) (file: receiver/onionwarden-receiver verify-record)

### Phase 1 — Quick-win watchdog (zero installs; includes critique fixes)
- [x] Implement `onionwarden-detect-profile` — OS, virt, EFI, hypervisor, immutable-FS capability probes (§0.2) (file: bin/onionwarden-detect-profile, lib/profile.sh)
- [x] Implement the 11 Phase-1 checks: taint, modules, ports, SSH keys + `sshd -T`, accounts/sudoers, ld.so.preload, watchdog meta, **promiscuous-interface, local input-device hotplug, local-console login** (§7, §2.8) (file: lib/checks/{taint,modules,ports,ssh,accounts,ld_preload,watchdog_meta,promisc,input_devices,console_login,profile}.sh)
- [x] Implement `verify.sh` Ed25519 verification; embed the `onionwarden.pub` hash as a literal in the scripts (§3.5, C2) (file: lib/verify.sh; install.sh pins ONIONWARDEN_PUBKEY_SHA256_PIN)
- [x] Implement the `bootstrapping` state suppressing signature-CRIT until the first signed round-trip (§2.6, M2) (file: bin/onionwarden-run trust logic; install.sh writes state/bootstrapping)
- [x] Install the systemd `fast`/`slow`/`daily` timers + oneshot services (§3.2) (file: systemd/onionwarden-*.{timer,service})
- [x] Apply `chattr +i` immutability to the protected set incl. `fatal-action.sh`; FS-probe fallback (§3.6, L2) (file: install.sh; lib/profile.sh immutable_fs_supported probe)
- [x] Build `install.sh` to consume a reviewable per-host answers file; generate + sign `host.conf` (§3.4, M9) (file: install.sh; examples/answers-*.example; host.conf signed off-box via onionwarden-sign)
- [x] Implement the heartbeat + dead-man ping (§4) (file: lib/alert.sh deadman_ping; bin/onionwarden-run fast-run heartbeat)
- [x] Phase-1 acceptance: mandatory dead-man self-test — pause heartbeats, confirm the provider alerts (§6, M9) (file: bin/onionwarden-fatal test exercises the off-box path; the live heartbeat-pause test is an operator step — IMPLEMENTATION_NOTES.md)
- [x] Roll out to canary `relay-a` with `alert_push_level=warn` (§6) (deferred: build-and-test task — no real-host deploy; examples/answers-canary.example is rollout-ready)

### Phase 2 — SSH hardening + full coverage + kill-switch infrastructure
- [x] Deploy the fleet-wide SSH hardening drop-in (keys-only, no-root); re-baseline `sshd -T` (§6, Q9) (file: ssh-hardening/sshd_hardening.conf, apply-ssh-hardening.sh — not deployed: build-and-test task)
- [x] `apt install debsums aide`; set the AIDE scope incl. `/var/lib/dpkg/` (§2.4, H1) (deferred: package install is a real-host op — lib/checks/packages.sh detect-and-skips when absent)
- [x] Implement the `[slow]`/`[daily]` checks: SUID/caps, network-deep, hardware, eBPF, cron/units, world-writable (§2.3–2.5) (file: lib/checks/{suid,network_deep,hardware,kernel_state,scheduled,filesystem,boot_integrity,packages,auth_log,clock}.sh)
- [x] Implement the Nested-VM-layer check — guest set, QEMU argv, qcow2 backing chain — always-on for hypervisors (§2.4, C4) (file: lib/checks/nested_vm.sh)
- [x] Implement snap coverage — scan `/snap` mounts, baseline the snap set + snapd revision (§2.3/2.4, H3) (file: lib/checks/snap.sh)
- [x] Scope the process-ancestry check to service daemons; exclude sshd/cron/systemd logins (§2.3, H4) (file: lib/checks/process_ancestry.sh)
- [x] Implement per-file apt-correlation (hash-match anchor; mtime as hint only) (§5, M5) (file: lib/apt_correlate.sh)
- [x] Add NTP-server config + the legacy-BIOS GRUB core image to the integrity scope (§2.1/2.6, M4/M5) (file: lib/checks/clock.sh NTP config; lib/checks/boot_integrity.sh grubcore)
- [x] Install kill-switch infrastructure: `onionwarden-fatal`, `onionwarden-suppress` maintenance-window, the C3-scoped fatal-signal evaluator (post-allowlist/post-correlation, incl. PROMISC #9 / input-device #10 / console-login #11), cooldown, off-box-first protocol — ships disarmed (§3.7, C3) (file: lib/fatal.sh, bin/onionwarden-fatal, bin/onionwarden-suppress, lib/suppress.sh)
- [x] Implement deterministic freeze-ruleset recompute + off-box corroboration; snapshot the pre-freeze ruleset (§3.7/§2.2, C5/M10) (file: lib/fatal.sh fatal_freeze_ruleset + pre_freeze_ruleset snapshot)
- [x] Implement the re-baseline workflow with the offline-scan precondition for trust-expanding deltas (§5, C1) (file: bin/onionwarden-baseline diff, --offline-scan-attested gate)
- [x] Implement `onionwarden-baseline-suggest` (§5) (file: bin/onionwarden-baseline-suggest)
- [x] Enable `freeze` + high-confidence-subset `poweroff` arming (CRIT-bit taint, PROMISC, physical-access, `ld.so.preload`, UID-0) per-host once the off-box first-arm checklist passes and OOB is verified (§3.7, M3) (file: bin/onionwarden-fatal arm --action/--scope + 7-item checklist; arming itself is a per-host operator op)

### Phase 3 — Real-time layer + cross-fleet
- [ ] `apt install auditd`; deploy the curated audit rules (§6)
- [ ] Off-box journal shipping via `systemd-journal-upload` — closes the log-vacuum gap (§6, L6)
- [ ] Build `onionwarden fleet-diff` — the operator-side role-grouped baseline report (§6)
- [x] Build receiver cross-host correlation — worm spread, IP spraying, simultaneous dead-man (§4, M6)

### Phase 4 — Active hardening
- [ ] GRUB password, security sysctls, evaluate `lockdown=integrity`, host firewall (§6)
- [ ] Enable `poweroff` arming for the remaining lower-confidence fatal signals + `custom` arming, per-host (§3.7)

### Phase 5 — Fleet config management
- [ ] Ansible role wrapping `install.sh` + `onionwarden-upgrade`; version fact + drift report (§6)

### Ongoing
- [ ] Run the periodic offline out-of-band scan at the agreed cadence — backstop (c) (§5)

---

**Status:** PLAN ONLY. Nothing has been installed or changed on any host. Review before any build.
**Goal:** a portable, watchdog-style tamper-monitoring tool deployable to **any Ubuntu 24.04 host** — bare metal, KVM/QEMU guest, or cloud VM — that periodically checks tamper indicators and raises off-box alerts.
**Design rule:** one repo, identical code everywhere. Each host differs only by (a) a small human-edited per-host config file and (b) a per-host baseline captured at bootstrap. `relay-b` (the shadow-judge eval host) is **one deployment target, not the design center** — see Appendix A. The current rollout fleet is listed in §0.5.
**Author run date:** 2026-05-20.
**Critique pass:** CRITIQUE.md (2026-05-21) — all CRITICAL + HIGH findings folded in; see §8 and inline `C#`/`H#`/`M#`/`L#` citations.

---

## 0. Design principles & portability model

### 0.1 One repo, identical install everywhere
The deliverable is a single repo (`onionwarden`) installed by **one bootstrap script — `install.sh`** (decision Q6; no Ansible role until Phase 5 — §6). It lays down the identical scripts/units on every host, generates `host.conf` interactively, and enables the systemd timers. It is standalone — no config-management dependency.
- Consequence at fleet scale: a code update means re-running `install.sh` on each of the 9 hosts by hand, with no central view of which host runs which version. Mitigations: §6 (code-version line in the daily digest) and §3.5 (per-host self-hash).

Nothing about a host is hard-coded in the code. The only host-specific artifacts are two files (§0.3).

### 0.2 Host capability detection — *detect-and-skip*, never assume
At bootstrap (and re-verified each run) the tool builds a **host profile** by probing capabilities. Every check consults the profile and either runs or **no-ops with a logged `N/A: <reason>`** — it never alerts merely because a feature is absent.

| Probe | Command | Drives |
|---|---|---|
| OS & version | `. /etc/os-release` → `ID`, `VERSION_ID` | `os_id` (`ubuntu`/`debian`); gates distro-specific logic (§0.5); the tool **refuses to run on an unsupported OS** (e.g. FreeBSD) |
| Virtualization | `systemd-detect-virt` | `virt_type` (`none`/`kvm`/`qemu`/`vmware`/`amazon`/…); container → kernel/boot group no-ops |
| EFI present | `[ -d /sys/firmware/efi ]` | Secure Boot check runs only if true; else `N/A: legacy BIOS` |
| Secure Boot tooling | `command -v mokutil` + EFI | SB state check; else logged N/A |
| Kernel lockdown | `[ -r /sys/kernel/security/lockdown ]` | lockdown check availability |
| Hypervisor host | running `qemu-system*` / `libvirtd` / consumers of `/dev/kvm` | if true, tolerate `virbr*/tap*/vnet*` churn and nested-VM processes |
| Cloud instance | DMI vendor strings / `[ -d /run/cloud-init ]` | baseline-allow metadata route `169.254.169.254` + cloud-init units/cron |
| Optional tooling | `command -v auditd debsums aide bpftool nft getcap` | which checks/phases are active on this host |
| Immutable-attr support | `stat -f` on the install prefix → FS type | whether `chattr +i` works; an unsupported FS (ZFS/tmpfs/overlay) → `immutable_scripts` no-ops with a logged N/A (§3.6) |

The host profile is itself **captured into the signed baseline** — so a *change* (EFI suddenly appears, `virt_type` changes, a host becomes a hypervisor) is a signal, not a silent skip.

**Worked example:** on a legacy-BIOS host, `check_secureboot()` finds `/sys/firmware/efi` absent → logs `N/A: legacy BIOS — Secure Boot not applicable` and returns clean. On an EFI host it runs `mokutil --sb-state` and diffs vs baseline. Same code, both hosts.

### 0.3 The two — and only two — per-host artifacts

| Artifact | What it holds | Who writes it | Format |
|---|---|---|---|
| **Per-host config** `/etc/onionwarden/host.conf` | Identity + policy: alerting endpoints, allowlists of *expected* listening ports / modules / admin users, check toggles | **Human**, edited deliberately, signed off-box | declarative `key=value` (§3.4) |
| **Per-host baseline** `/var/lib/onionwarden/baseline/` | Captured *actual* state: module set, SUID hashes, `/boot` hashes, `sshd -T`, host profile, … | **Machine**, captured at bootstrap on that host | signed JSON manifests |

There is **no fleet-wide golden image**. Each host captures its own baseline from its own known-good state (§5). The config expresses human intent ("port 3000 is *meant* to be LAN-exposed"); the baseline records reality. A finding is an alert when it deviates from the baseline *and* is not allowlisted by the config.

### 0.4 What is identical vs per-host

| Identical on every host | Per-host |
|---|---|
| All check logic, the dispatcher, systemd units, alerting code, signing/verification, role profiles | `host.conf` (endpoints + allowlists + `role`), the captured baseline, the host profile |

### 0.5 Rollout targets & OS support

The in-scope fleet — 10 hosts, 9 monitored, 1 out of scope:

| Host | OS | Kernel | Role | Tier |
|---|---|---|---|---|
| relay-b | Ubuntu 24.04 (KVM guest, legacy BIOS) | 6.17 generic | `eval-host` | 1 |
| relay-d | Ubuntu 24.04 | 6.8 stock | `tor-relay` | 1 |
| relay-e | Ubuntu 24.04 | 6.8 stock | `tor-relay` | 1 |
| relay-a | Ubuntu 24.04 | 6.8 stock | `tor-relay` | 1 |
| relay-f | Ubuntu 24.04 | OEM (6.14/6.17) | `tor-relay` | 1 |
| relay-g | Ubuntu 24.04 | OEM (6.14/6.17) | `tor-relay` | 1 |
| relay-h | Ubuntu 24.04 | OEM (6.14/6.17) | `tor-relay` | 1 |
| relay-c | Debian 13 (trixie) | 6.12+deb13 | `tor-relay` | 2 (see below) |
| relay-d | Debian 13 (trixie) | 6.12+deb13 | `tor-relay` | 2 |
| freebsd-relay | FreeBSD 15 | — | — | **out of scope** |

(Role assignments assume the 8 relays are `tor-relay` and `relay-b` is `eval-host` — confirm, Q14.)

**Kernel-flavor handling.** Stock (`linux-image-generic`), HWE, and OEM (`linux-image-oem-24.04*`) kernels need no special-casing: `/boot` hashes and the module set are per-host captured baselines, and the running-vs-installed check compares `uname -r` against the highest-versioned installed `linux-image-*` package of *any* flavor. No code branches per kernel.

**Debian 13 — recommendation: SUPPORT it (tier-2), do not skip.** Debian 13 (trixie) is the same systemd + apt + dpkg world `onionwarden` already targets — `systemd` timers, `journalctl`, `dpkg --verify`/`debsums`, `/var/log/apt/history.log`, `ss`, `ip`, `nft`, AIDE, `auditd` all present and behaving identically. The only Ubuntu-specific logic in the plan is OEM-kernel meta-package naming and a few Ubuntu-isms (`ubuntu-advantage`, `update-notifier`); these are already isolated behind capability/`os_id` probes and simply log `N/A` on Debian. Incremental cost of covering `relay-c`/`relay-d`: one `os_id` branch plus a validation pass on one Debian host. Skipping them would leave 2 of 9 monitored hosts dark for no architectural saving. **Decision: Ubuntu 24.04 = tier-1 (primary, fully tested); Debian 13 = tier-2 (officially supported, validated on one host before fleet rollout).** Detect-and-skip means one codebase, not two.

**FreeBSD 15 (`freebsd-relay`) — out of scope, confirmed.** No systemd, no apt/dpkg, different `/proc`, different `ss`/`ip`/`procstat`. Supporting it would be a separate tool, not a branch. If `freebsd-relay` needs tamper monitoring, treat it as a distinct workstream.

### 0.6 Role profiles — role-aware check tuning

A check that is correct for one host class is noise on another. The clearest case: **"unexpected outbound connections"** is high-value on an eval host (it should mostly talk to a known LAN) but **useless on a tor relay** — a relay's entire job is opening outbound connections to thousands of arbitrary world IPs. A naive outbound check would either fire constantly or be switched off, and a switched-off check catches nothing.

The fix: **role profiles.** The repo ships `roles/<role>.conf` files (`generic`, `eval-host`, `tor-relay`) that set role-appropriate check tunings. `host.conf` names a `role`; at runtime the watchdog loads `roles/<role>.conf` first, then `host.conf` overrides it. Role logic stays DRY — the tor-relay tuning is written once, not copied into 8 host files. Role profiles live in the signed `/opt/onionwarden/` tree.

What a role profile tunes (examples):

| Tuning | `eval-host` | `tor-relay` |
|---|---|---|
| Outbound-connection check mode | `allowlist` — strict `process→remote`; non-LAN remote → CRIT | `exclude-process` — connections owned by the **specific `tor` PID(s), verified via the `tor.service` systemd cgroup** (not by process name or `debian-tor` uid — both forgeable, H2) are **not** evaluated; outbound from any *other* process → CRIT |
| Established-connection count alerting | enabled, low threshold | disabled (a relay sustains thousands) |
| Extra integrity-scope paths | — | `/etc/tor/torrc`, `/etc/tor/` (hashed every `[slow]`) |
| Tor binary integrity | — | `debsums tor` every `[daily]` — the **primary** tor-integrity check; works because all relays run the stock `tor` package (Q16) |
| Extra expected processes | — | `tor` daemon expected to listen on its ORPort/DirPort bound `0.0.0.0` |
| Pluggable transports (`tor-relay`) | — | `obfs4proxy`/PT processes (from the `tor.service` cgroup) make their own outbound connections and bind a **random high port** `expected_lan_ports` cannot enumerate (H2) — both are baselined as belonging to the PT process under tor's cgroup, not flagged |
| `workload_integrity_check` default | `none` — disk-image *content* hashing off (live overlays churn); the **Nested-VM-layer check (§2.4) stays on regardless** — guest set, QEMU argv, backing chains monitored | `hashes` — scoped to the relay's stable identity key `/var/lib/tor/keys/ed25519_master_id_secret_key` |
| Fatal-signal extensions (§3.7) | base list only | base list + tor identity-key change + `torrc` change |
| `fatal_action` guidance (§3.7) | `freeze` viable — an eval host's job is not outbound | **`freeze` = service outage** (H6): dropping new outbound kills circuit-building. Recommend `alert`, or `poweroff` only where OOB access exists — *not* `freeze` |

**Why `exclude-process` is the right call, stated plainly:** on a relay we cannot meaningfully monitor *where tor connects* — that is the service working as designed. So the outbound check is re-scoped to the question it *can* answer: "is anything **other than tor** making outbound connections it shouldn't?" A backdoor, miner, or reverse shell is not the tor daemon, so it is still caught. The risk this gives up — the `tor` binary itself being trojaned — is covered by other signals: **`debsums tor`** verifies the `tor` binary against dpkg hashes — reliable because all relays run the stock `tor` package (Q16) — plus `torrc` integrity, the tor listener set, and the installed-package diff. Connection monitoring was never the right tool for that. **Accepted residual (H2):** code injected *into* the `tor` process (LD_PRELOAD, ptrace, a malicious pluggable-transport plugin) is inside the exclusion — `tor` is the most-attacked process on an internet-facing relay and outbound monitoring structurally cannot catch a backdoor that *is* tor; that residual is covered, imperfectly, by `debsums tor`, `torrc`/PT-binary integrity, and the `LD_PRELOAD` / `/proc/<torpid>` checks, never by the outbound check. Per-host `role` is set in `host.conf` (§3.4); ORPort/DirPort numbers stay per-host in `expected_lan_ports` since they vary per relay.

---

## 1. Threat model & assumptions

### Assets
1. **Integrity of whatever the host is responsible for** — an eval/CI pipeline, production services, served model endpoints. Silent tampering that biases outputs is worse than an outage, because bad output is trusted and acted on. *(On `relay-b` this is the shadow-judge eval results — see Appendix A.)*
2. **The host itself and its credentials** — admin SSH keys, sudo, the host's standing on its LAN.
3. **Workloads the host runs** — services, containers, or nested VMs.

### Adversaries
- **A1 — Remote attacker** reaching the host over the network: SSH or any service the host exposes beyond localhost. Acute for the public-facing tor relays, which accept inbound connections from the entire internet by design.
- **A2 — Malicious workload** — a job, container, or nested VM that escapes its sandbox, or a compromised dependency running as a service account.
- **A3 — Operator error** — an admin's own accidental misconfiguration (a bad sudoers edit, a stray world-writable chmod, an unintended cron job). Explicitly in scope.

### Trust boundaries — resolved per host by the profile
- The watchdog runs **as root, inside the host OS**. It defends that OS's userspace + kernel-visible state.
- **If the host is a guest VM:** the hypervisor sits above it and is **out of scope** — a guest cannot defend itself from a malicious host.
- **If the host is a hypervisor / runs nested VMs or containers:** those workloads are adversary class **A2**.
- **If bare metal:** only hardware/firmware sits below; firmware drift is monitored (DMI), deeper firmware attack is out of scope.

### Assumptions
- **A-TOFU (recurring, not one-time):** the host is clean *at every baseline-capture time* — the initial bootstrap **and every re-baseline**. Each re-baseline is a fresh trust event; §5's offline-scan precondition for trust-expanding deltas (C1) is what keeps a re-baseline from laundering a resident compromise into the signed baseline.
- The baseline signing private key never touches any monitored host.
- The off-box receiver host(s) and the signing key are trusted; keep them minimal and hardened.
- Network to the alerting services is *usually* available; gaps are themselves alertable.

### Honest limitations
- **A kernel-level rootkit can lie to every userspace tool.** No on-box agent is trustworthy once root/kernel is owned. This design optimizes for catching the **transition into a compromised state** and for making an attacker's actions **noisy** — not for defeating an already-resident competent rootkit.
- Three backstops compensate: **(a) cross-checks** — read a fact two ways and alert on disagreement (`lsmod` vs `/proc/modules` vs `/sys/module`; `ss` vs `/proc/net/tcp`); **(b) the dead-man's switch** — a compromised box cannot satisfy it without *also* faking every other signal forever; **(c) periodic out-of-band scans** (§5) — whose *real* cadence is operator-constrained: backstop (c) is only as strong as the scan cadence actually sustained (see the H7 cost caveat in §5).
- **A compromised root can forge "all-clear" alerts** (the outbound key is on the box). The trust anchors are the dead-man's switch and the off-box scan, not the on-box agent's word.

### Out of scope
Hypervisor/host compromise (for guests), physical attacks, DoS, upstream distro supply-chain compromise, defending workload internals, and any OS outside the §0.5 supported set (FreeBSD, etc.).

---

## 2. Signals to monitor

Each signal lists the **exact command/file**, and where relevant a **detect-and-skip** rule. Cadence tags: `[boot]` `[fast]` (~1 min) `[slow]` (~hourly) `[daily]`. Severity: **CRIT** = near-certain tamper, page now; **WARN** = needs human eyes, may be benign churn; **INFO** = recorded only. "Diff vs baseline" always means *the per-host baseline*, with deviations suppressed if allowlisted in `host.conf`.

### 2.1 Kernel & boot integrity

| Signal | Command / file | Notes & skip rule |
|---|---|---|
| Kernel taint flag `[fast]` | `cat /proc/sys/kernel/tainted` | Integer, decoded per-bit (table below). Rise from baseline → ≥WARN; bits 0/1/12/13 → CRIT. |
| Loaded modules `[fast]` | `lsmod`, cross-checked with `cat /proc/modules` and `ls /sys/module` | Sorted-name diff vs baseline; modules in `host.conf:expected_extra_modules` suppressed. New module → CRIT. Cross-check disagreement → CRIT (hiding). Container → `N/A: container shares host kernel`. |
| Module-load lockout `[slow]` | `cat /proc/sys/kernel/modules_disabled` | If hardened to `1` (Phase 4), a drop to `0` → CRIT. |
| Kernel lockdown `[boot]` | `cat /sys/kernel/security/lockdown` | Skip if file absent. Change that *weakens* → WARN. |
| Secure Boot `[boot]` | `mokutil --sb-state` | **Skip if `/sys/firmware/efi` absent → log `N/A: legacy BIOS` — a *coverage gap*, not a clean skip (M4); legacy hosts get the GRUB-core check below instead.** Skip if `mokutil` not installed → `N/A: mokutil missing`. If enabled→disabled → CRIT. |
| EFI presence `[boot]` | `[ -d /sys/firmware/efi ]` | Baselined boolean; a *change* either direction → WARN (VM reconfigured). |
| Kernel cmdline `[boot]` | `cat /proc/cmdline` | Exact-string diff. Change → CRIT (injected `init=`, removed `module.sig_enforce`). |
| `/boot` file hashes `[boot]` | `sha256sum /boot/vmlinuz-* /boot/initrd.img-* /boot/grub/grub.cfg /boot/grub/grubenv /boot/config-* /boot/System.map-*` | Skip if `/boot` empty (some cloud images) → `N/A`. Uncorrelated change → CRIT; post-kernel-upgrade expected (apt correlation, §5). |
| GRUB core image (legacy BIOS) `[boot]` | hash the boot-disk gap: `dd if=<bootdev> bs=512 count=2048 \| sha256sum` | The `i386-pc` GRUB core lives in the MBR gap — it is **not a file**, so `/boot` hashing misses it and a bootkit there is invisible (M4). Baseline it on legacy-BIOS hosts; EFI hosts → `N/A` (covered by Secure Boot + the EFI binaries under `/boot`). |
| Running vs installed kernel `[slow]` | `uname -r` vs newest `dpkg -l 'linux-image-*'`; `test -e /var/run/reboot-required` | Older kernel running after upgrade → WARN. |
| Kernel ring buffer `[fast]` | `journalctl -k --cursor-file=…/state/kmsg.cursor` | Cursor-based (ring buffer wraps). Grep: `taint`, `module verification failed`, `Loading.*module`, `BPF`, `Oops`, `BUG:`, `segfault`, `protection fault`, `kexec`. |
| eBPF programs `[slow]` | `bpftool prog show` + `bpftool link show` | Skip if `bpftool` absent. New `kprobe`/`tracepoint`/`xdp`/`cgroup` prog not from a known loader → CRIT. |
| kexec state `[slow]` | `cat /sys/kernel/kexec_loaded`, `/proc/sys/kernel/kexec_load_disabled` | A staged kexec image you didn't load → CRIT (boot-bypass persistence). |
| Security sysctls `[slow]` | `sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled kernel.kexec_load_disabled kernel.yama.ptrace_scope kernel.modules_disabled` | Diff vs baseline; any *weakening* → WARN/CRIT. |

**Kernel taint bit decoder** — report *which* bits, not just the integer:

| Bit | Val | Letter | Meaning | Severity if newly set |
|---|---|---|---|---|
| 0 | 1 | P | Proprietary module loaded | **CRIT** |
| 1 | 2 | F | Module **force-loaded** | **CRIT** |
| 2 | 4 | S | SMP kernel, CPU out of spec | WARN |
| 3 | 8 | R | Module force-unloaded | **CRIT** |
| 4 | 16 | M | Machine check | WARN |
| 5 | 32 | B | Bad page detected | WARN |
| 6 | 64 | U | Userspace-requested taint | WARN |
| 7 | 128 | D | Kernel died (oops/BUG) | WARN (investigate) |
| 9 | 512 | W | Kernel warning issued | INFO/WARN |
| 10 | 1024 | C | Staging driver loaded | WARN |
| 11 | 2048 | I | Firmware-bug workaround | INFO |
| 12 | 4096 | O | **Out-of-tree** module loaded | **CRIT** |
| 13 | 8192 | E | **Unsigned** module loaded | **CRIT** |
| 14 | 16384 | L | Soft lockup occurred | WARN |
| 15 | 32768 | K | Kernel **live-patched** | **CRIT** (unless you applied it) |
| 16 | 65536 | X | Auxiliary (distro-defined) | WARN |
| 18 | 262144 | N | In-kernel test (kunit) ran | INFO |

### 2.2 Network

| Signal | Command / file | Notes & skip rule |
|---|---|---|
| Promiscuous interfaces `[fast]` | `ip -d link show` → per-link `promiscuity`; cross-check `/sys/class/net/*/flags` (`0x100`) | Non-zero promiscuity not on a known bridge → CRIT. |
| Listening ports `[fast]` | `ss -tulpnH` normalized to `proto/addr/port/process`, diff vs baseline | New listener → CRIT. New listener bound `0.0.0.0`/`*` and **not** in `host.conf:expected_lan_ports` → CRIT. |
| Outbound connections `[slow]` | `ss -tunpH state established` | **Role-aware (§0.6).** `eval-host`: strict `process→remote` allowlist; non-allowlisted binary → WARN, non-LAN remote → CRIT. `tor-relay`: connections owned by the `tor` daemon excluded entirely; outbound from any *other* process → WARN/CRIT. Mode set by the role profile. |
| nftables / iptables ruleset `[slow]` | `nft list ruleset`; `iptables-save`; `ip6tables-save` | Hash + structural diff. New DNAT/redirect → CRIT. `allow_virt_churn` tolerates libvirt-managed chains. When `fatal_action=freeze` has fired, the expected ruleset is the baseline ruleset **or** the deterministically-regenerated freeze ruleset corroborated by an off-box `events.log` freeze event — never an unsigned `state/` record (§3.7, C5). |
| Routes `[slow]` | `ip route show`; `ip -6 route show` | Diff vs baseline; cloud metadata route `169.254.169.254` auto-allowed if `is_cloud`. New default route → CRIT. |
| ARP / gateway MAC `[slow]` | `ip neigh show` | Pin `gateway-IP→MAC`; change → WARN (ARP spoof / new router). |
| DNS resolvers `[slow]` | `cat /etc/resolv.conf`; `resolvectl status`; `resolvectl dns` | Diff vs baseline. New nameserver → CRIT. |
| Interface set `[slow]` | `ip -br link` | Diff vs baseline; `virbr*/tap*/vnet*` churn tolerated when `allow_virt_churn`. New `tun`/`veth` → WARN. |

### 2.3 Process & userspace

| Signal | Command / file | Notes |
|---|---|---|
| SUID/SGID binaries `[slow]` | `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f` + sha256 each, **plus an explicit pass over snap mounts** | `-xdev` skips other mounts incl. `/snap` squashfs — those are scanned separately (Snap row, §2.4 — H3). New entry or hash change → CRIT. |
| File capabilities `[slow]` | `getcap -r /usr /bin /sbin /opt` | Skip if `getcap` absent. New `cap_*` on a binary → CRIT. |
| Account files `[fast]` | sha256 of `/etc/passwd /etc/shadow /etc/group /etc/gshadow`; list UID-0 accounts vs `host.conf:expected_uid0`; empty-password check | New account, new UID-0, removed password → CRIT. |
| sudoers `[fast]` | sha256 `/etc/sudoers` + `/etc/sudoers.d/*`; `visudo -cf` syntax | Any change → CRIT. Admin-group membership diffed vs `expected_admins`. |
| SSH `authorized_keys` `[fast]` | sha256 + key-count of `~/.ssh/authorized_keys{,2}` for **all** users incl. `root` | New key → CRIT. |
| sshd config (effective) `[fast]` | `sshd -T` (not just the file) | Catches drop-ins + defaults. Weakening (`permitrootlogin yes`, `passwordauthentication yes` when locked) → CRIT. |
| `ld.so.preload` `[fast]` | `cat /etc/ld.so.preload` | Non-empty → CRIT (library-injection rootkit). |
| `LD_PRELOAD` / `LD_AUDIT` `[fast]` | scan `/proc/*/environ` | On a long-running daemon → CRIT; on a fresh shell → WARN. |
| Cron jobs `[slow]` | `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, `/var/spool/cron/crontabs/*`, `crontab -l -u <user>` per user | Hash + diff. New job → CRIT. cloud-init jobs auto-allowed if `is_cloud`. |
| systemd units & timers `[slow]` | `systemctl list-unit-files`, `list-timers --all`, `list-units --state=running`; hash `/etc/systemd/system`, `/run/systemd/system`, `~/.config/systemd/user` | New enabled service/timer → CRIT; new running service → WARN. |
| Process ancestry `[fast]` | `ps -eo pid,ppid,user,comm,args` | A shell/interpreter parented to a **service daemon that should never spawn one** (`nginx`, the `node` listeners, `tor`, `vllm`) → CRIT. **Excluded as normal** (H4): shells under `sshd` *login* sessions, `cron`/`atd`, `systemd`/`systemd --user`, `login`/`getty` — these legitimately parent shells. `qemu-system` parentage tolerated when `is_hypervisor`. |
| Exec from temp dirs `[fast]` | `find /tmp /var/tmp /dev/shm -xdev -type f -perm -111` | Executable in world-writable temp → WARN; running such a file → CRIT. |

### 2.4 Filesystem & package integrity

| Signal | Command / file | Notes & skip rule |
|---|---|---|
| Package file integrity `[daily]` | `debsums -c`; fallback `dpkg --verify` (built-in, weaker) | Use `dpkg --verify` if `debsums` absent. Changed packaged file → CRIT unless apt-correlated (§5). |
| AIDE check `[daily]` | `aide --check` over `/etc /usr/bin /usr/sbin /bin /sbin /boot /usr/lib /lib /etc/systemd /var/lib/dpkg` | Scope includes `/var/lib/dpkg/` so `debsums`' own reference data (`info/*.md5sums`, `info/*.list`) is integrity-checked — otherwise a root attacker edits a `.md5sums` and `debsums -c` happily reports "OK" (H1). Skip if `aide` absent (Phase 1) → `N/A: AIDE not installed`. Added/changed file → CRIT/WARN by path. |
| Immutable / append-only bits `[slow]` | `lsattr` on critical files | New `i`/`a` attr → WARN/CRIT (locks a malicious file, or blocks updates). |
| World-writable files/dirs `[slow]` | `find / -xdev -type f -perm -0002`; dirs `-type d -perm -0002 ! -perm -1000` in system paths | New world-writable in `/usr`,`/etc`,`/bin`,`/sbin` → CRIT. |
| New files in system bin dirs `[slow]` | `find /usr/bin /usr/sbin /bin /sbin -newer …/state/baseline.marker` | Fast pre-AIDE tripwire. |
| dpkg DB & package set `[daily]` | sha256 `/var/lib/dpkg/status`; `dpkg --get-selections` diff; tail `/var/log/apt/history.log` | Unexpected install/removal → WARN; apt-correlate to confirm intent. |
| APT sources & keys `[slow]` | `/etc/apt/sources.list`, `sources.list.d/*`, `trusted.gpg.d/*`, `keyrings/*` | New repo or signing key → CRIT (supply-chain persistence). |
| Snap packages `[daily]` | `snap list --all` + revisions; `snapd` version; explicit SUID / world-writable scan over `/snap` squashfs mounts | `find / -xdev` deliberately skips other mounts and would hide everything under `/snap/*` (H3). Snap content is scanned separately; a new snap or `snapd`/`lxd` revision → software-install finding (WARN — apt-correlation does **not** cover snap; refreshes are their own channel). Skip if `snapd` absent → `N/A`. |
| Workload disk-image content `[slow]` | sha256 of paths in `host.conf:workload_paths` | Governs **disk-image content hashing only**. Mode = `workload_integrity_check`: `none` (don't hash live image content) / `hashes` (at-rest/template images) / `full` (deep scan). `none` does **not** mean "VM layer unmonitored" — see next row. |
| Nested-VM layer `[slow]` | per running guest: `virsh list` / `pgrep -a qemu`; QEMU argv (`-drive`, `-netdev`, `-cpu`, `-device`); qcow2 backing chain (`qemu-img info --backing-chain`) | **Always on when `is_hypervisor`, independent of `workload_integrity_check`.** The running-guest set, each guest's argv, and the backing-file chain are *stable* — they do not churn like the writable overlay. New guest, changed `-netdev` (an exfil path), or an altered backing chain → CRIT. Closes the C4 gap: the #1 asset is produced inside the VM layer, so the VM layer is never invisible. |

### 2.5 Hardware / firmware

| Signal | Command / file | Notes |
|---|---|---|
| USB devices `[slow]` | `lsusb` | Diff vs baseline. New device → WARN. |
| PCI devices `[slow]` | `lspci -nn` | Diff vs baseline. New device → WARN (hot-plug). |
| DMI / BIOS `[slow]` | `dmidecode -s bios-version,bios-vendor,system-uuid,baseboard-product-name` | Drift → WARN. |
| Block devices `[slow]` | `lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,UUID,FSTYPE` | New disk / changed UUID → CRIT. |
| CPU topology `[slow]` | `nproc`; `lscpu` | Change → INFO (VM resize). |
| Mounts `[fast]` | `findmnt --json` | New mount with `exec`/`suid`, or bind-mount over a system path → CRIT. |

### 2.6 Watchdog self / meta (see §3.5)

| Signal | Command / file | Notes |
|---|---|---|
| Timer/service health `[fast]` | `systemctl is-enabled/is-active/show` for watchdog units | Masked/disabled/failed → CRIT. |
| Self-hash `[fast]` | sha256 of `/opt/onionwarden/**` + `/etc/onionwarden/*` vs the signed manifest | On-box mismatch → CRIT — **but a tampered `onionwarden-run` can fake its own check (H5)**; the authoritative check is the receiver's automated off-box comparison of the reported self-hash + `onionwarden.pub` hash (§3.5, §4). |
| Baseline + config signature `[every run]` | Ed25519 verify of each manifest and `host.conf` vs `onionwarden.pub` | Bad/missing signature → CRIT — **except** during the explicit `bootstrapping` state (before the first off-box-signed baseline + `host.conf` round-trip), which suppresses signature-CRIT and ends, recorded in `events.log`, when the first signed artifacts verify (M2). |
| Clock sanity + NTP source `[fast]` | `timedatectl show -p NTPSynchronized`; hash `/etc/systemd/timesyncd.conf` + `/etc/chrony/*` | Unsynced / large jump → WARN. NTP-server config is in the integrity scope — an attacker repointing the time source to skew `apt_correlation_window` is caught (M5). |
| Heartbeat `[fast]` | outbound ping (§4) | Absence drives the dead-man's switch. |

### 2.7 Auth & log integrity

| Signal | Command / file | Notes |
|---|---|---|
| Journald integrity `[daily]` | `journalctl --verify` | Corruption → WARN. Catches corruption, **not** a clean `journalctl --vacuum-time=1s` wipe — off-box journal shipping (Phase 3) closes that; a Phase 1–2 residual gap (L6). |
| SSH logins `[fast]` | `journalctl -u ssh --cursor-file=…` | New source IP, failed-auth burst, root attempt → WARN/CRIT. |
| sudo / su usage `[fast]` | `journalctl _COMM=sudo _COMM=su --cursor-file=…` | sudo by a non-`expected_admins` identity → CRIT. |
| Off-box log shipping `[Phase 3]` | `systemd-journal-upload` → receiver | Makes on-box log-wiping detectable. |

### 2.8 Physical-access indicators

A remote-managed fleet: nobody should be at the keyboard under normal operation, so a *new* local input device or console session is a strong tampering signal — a crash cart, a plugged-in USB keyboard, a hypervisor adding a virtual input device. Baseline captures the input devices and tty sessions **present at install**, so a host that already has (e.g.) an IPMI/KVM-over-IP USB-keyboard dongle does not trip on the first tick. Every row below is downgraded CRIT→INFO when `host.conf:physical_access_allowed = true` (§3.4).

| Signal | Command / file | Notes |
|---|---|---|
| Local input-device hotplug `[fast]` | snapshot `/sys/bus/usb/devices/*/bInterfaceClass`+`SubClass`+`Protocol` and `/sys/class/input/event*`; also `/sys/bus/serio/devices/` (PS/2) | A USB HID **keyboard** (`03/01/01`) or **mouse** (`03/01/02`), or a PS/2 input device, appearing post-baseline → CRIT (fatal #10). For a VM this also catches the hypervisor hot-plugging a *virtual* keyboard/mouse into the running guest — visible to the guest exactly like physical hotplug. |
| Local-console login `[fast]` | `who` filtered to `tty[0-9]*`; new `last`/wtmp tty entries since cursor | A login session on a physical/virtual console (`tty1..N`) opened post-baseline, any UID → CRIT (fatal #11). |
| Display-connector hotplug `[slow]` | `/sys/class/drm/card*/status` diff | A VGA/DP connector going `connected` → **CRIT alert, not fatal** — some firmware flaps connector status on idle, so the false-positive rate is too high to drive `poweroff`. A complementary signal, not load-bearing. |

**VM limitation (honest).** A guest cannot see its hypervisor opening a console *window* on it — `/dev/console` reads happen outside the guest, so detecting that a hypervisor operator is *watching* a VM needs hypervisor-side observation and is out of scope for this host-internal watchdog. What the guest *can* see — and does — is a virtual input device hot-plugged into it (row 1) and a console *login* inside it (row 2).

---

## 3. Watchdog architecture

### 3.1 Timer-driven, not a daemon — and why
**Recommendation: systemd `oneshot` services driven by `.timer` units. No long-running daemon.**
- **Re-spawn for free** — killing a run buys an attacker one interval, not permanent silence; a killed daemon stays dead.
- **Tamper-evidence built in** — a masked/disabled/stopped timer is a detectable state *and* it stops the heartbeat → the off-box dead-man's switch fires.
- **No long-lived state to corrupt** — each run reads signed baselines fresh.
- **journald captures every run** with start/stop/exit-code.

**Cost, stated honestly:** timers miss sub-interval events. Covered by (a) journald/dmesg **cursor** checks — they read everything since the last cursor, so nothing logged is missed between ticks; (b) **auditd** (Phase 3) for real-time syscall capture. The watchdog stays timer-based; auditd is the complementary layer.

### 3.2 Units & cadence

| Unit | Trigger | Runs |
|---|---|---|
| `onionwarden-fast.timer` → `.service` | `OnBootSec=2min`, `OnUnitActiveSec=1min` | §2 `[fast]` checks + **heartbeat** |
| `onionwarden-slow.timer` → `.service` | `OnBootSec=4min`, `OnUnitActiveSec=1h`, `Persistent=true` | §2 `[slow]` checks |
| (boot checks) | first post-boot `onionwarden-slow` run | §2 `[boot]` checks |
| `onionwarden-daily.timer` → `.service` | `OnCalendar=daily` + randomized delay | `debsums`/`dpkg --verify`, `aide --check`, `journalctl --verify`, **daily digest** |

`Persistent=true` makes a tick missed while powered off run at next boot.

### 3.3 On-disk layout (identical on every host)
```
/opt/onionwarden/                  # scripts — root:root, dirs 0755, files 0744
  bin/onionwarden                  #   operator CLI dispatcher (upgrade|arm-fatal|fleet-diff|…)
  bin/onionwarden-run              #   timer-invoked dispatcher (fast|slow|daily)
  bin/onionwarden-baseline         #   collector for (re)baselining
  bin/onionwarden-baseline-suggest #   proposes host.conf allowlist additions (human approves)
  bin/onionwarden-detect-profile   #   host capability probe (§0.2)
  bin/onionwarden-upgrade          #   applies signed updates; handles chattr -i/+i (§3.6)
  bin/onionwarden-fatal            #   arm/disarm/status/test/dry-run for the kill-switch (§3.7)
  bin/onionwarden-suppress         #   open a time-boxed maintenance window (§3.7)
  bin/onionwarden-fleet-diff       #   cross-fleet baseline diff report (§6 Phase 3)
  lib/checks/*.sh               #   one file per signal group
  lib/verify.sh                 #   Ed25519 verification via openssl
  roles/*.conf                  #   role profiles: generic, eval-host, tor-relay (§0.6)
  onionwarden.pub                  #   embedded baseline public key (fleet-wide)
/etc/onionwarden/host.conf         # the per-host config (§3.4) — signed
/var/lib/onionwarden/baseline/     # per-host signed JSON manifests + .sig
/var/lib/onionwarden/profile.json  # captured host profile (part of baseline)
/var/lib/onionwarden/state/        # journald/dmesg cursors, last-run marker
/var/log/onionwarden/              # structured JSON, one object per check per run
```

### 3.4 Per-host config file — `/etc/onionwarden/host.conf`
The **only** human-edited per-host file. `role` selects a role profile (§0.6) loaded *before* this file; `host.conf` overrides the profile. All endpoints are runtime-configurable — nothing is hardcoded. Annotated example (an eval host):
```ini
# Identity
host_id            = "relay-b"
role               = "eval-host"            # selects roles/eval-host.conf; also alert context
canary             = false                  # Q1 — true ONLY on the onionwarden rollout-canary host (§6 Phase 1)

# Alerting — every endpoint is a per-host value, not hardcoded (Q2/Q3/Q4)
ntfy_url           = "https://ntfy.example.net/onionwarden"   # ntfy.sh or self-hosted; tradeoffs in §4
deadman_provider   = "healthchecks-saas"     # healthchecks-saas | healthchecks-selfhost | http-ping
deadman_url        = "https://hc-ping.com/UUID-PER-HOST"
offbox_log_target  = "receiver-host:~/onionwarden/relay-b/events.log"
email_to           = "alerts@example.net"
alert_push_level   = "crit"                  # crit = only CRIT pushes; warn = push everything (Q11)

# Allowlists — human intent, hand-curated by the operator (Q7). Baseline captures
# ACTUAL state; these mark which deviations are expected. `onionwarden-baseline-suggest`
# proposes additions from observed state, but a human approves every entry.
expected_lan_ports     = [22, 3000, 18789]   # listeners intentionally non-localhost
expected_uid0          = ["root"]
expected_admins        = ["operator"]            # users expected in the sudo group
expected_extra_modules = []                  # modules that may load late w/o alert
allow_virt_churn       = true                # tolerate libvirt tap/vnet/virbr churn
physical_access_allowed = false               # false (fleet default): keyboard/mouse/console = CRIT + fatal (§2.8)

# Workload integrity (Q10) — eval-host role default is `none`: live nested-VM
# disks churn every run (§2.4). Opt into `hashes` only with AT-REST paths.
workload_integrity_check = "none"            # none | hashes | full
# workload_paths         = ["/var/lib/libvirt/images/templates/*.qcow2"]  # only if hashes

# Fatal-action kill-switch (§3.7) — ships disarmed; arm per-host after testing
fatal_action         = "alert"               # alert | poweroff | freeze | custom
fatal_action_armed   = false                 # MUST be explicitly armed via `onionwarden arm-fatal`
fatal_cooldown_hours = 24                     # max one poweroff/freeze per host per window
fatal_ack_timeout_s  = 10                     # wait this long for off-box ack, then act anyway
fatal_signals_extra  = []                     # per-host additions to the role fatal-signal list (§3.7)

# Baseline / signing / churn / retention
verify_pubkey_path     = "/opt/onionwarden/onionwarden.pub"   # default embedded key; override on rotation
apt_correlation_window = "5m"                # churn-correlation window (§5)
offbox_log_retention   = "365d"              # Q13 default
immutable_scripts      = true                # chattr +i on watchdog code/units/config (§3.6); v1 default ON

# Check toggles (rarely needed — detect-and-skip handles capability gaps)
disable_checks         = []                  # e.g. ["ebpf"] to silence a noisy check
```
A tor-relay host differs only in `role` and relay-specific values — everything role-wide (the outbound `exclude-process` mode, connection-count tuning, `/etc/tor` integrity scope, `debsums tor`) comes from `roles/tor-relay.conf`, not repeated per host:
```ini
host_id            = "relay-a"             # the default canary (Q1)
role               = "tor-relay"             # selects roles/tor-relay.conf
canary             = true                    # Q1 — picking the canary is a config change, not code
expected_lan_ports = [22, 9001, 9030]         # SSH + this relay's ORPort + DirPort
expected_admins    = ["operator"]
workload_integrity_check = "none"             # canary override; tor-relay role default is `hashes`
alert_push_level   = "warn"                   # canary: push everything to learn the noise floor
fatal_action_armed = false                    # canary stays disarmed while learning the noise floor
deadman_provider   = "healthchecks-saas"
# ntfy_url / deadman_url / offbox_log_target / email_to as above
```
`install.sh` generates this file from a **reviewable per-host answers file** (not blind interactive prompts — M9: a typo'd `deadman_url` must be catchable on review); it is then signed off-box (§5).

### 3.5 Tamper-evident self-checks
- **Signed baselines & config.** Every baseline manifest and `host.conf` is Ed25519-signed *off-box*. The watchdog verifies each against `onionwarden.pub` (embedded in `/opt/onionwarden/`) **every run** via `openssl pkeyutl` — no extra package on Ubuntu 24.04. Bad/unsigned → CRIT, that artifact is not trusted. One fleet-wide keypair; private half never on a monitored host.
- **Self-hash — on-box check, off-box anchor.** The signed manifest includes sha256 of every file under `/opt/onionwarden/` and `/etc/onionwarden/` (scripts, role profiles, `host.conf`, `onionwarden.pub`); the fast run recomputes and compares. **On its own this catches only non-root / accidental tampering** — a root attacker can edit a script, swap `onionwarden.pub` for their own key, and re-sign every manifest *and* the self-hash manifest, after which all on-box checks pass (C2/H5: the verifier verifying itself is circular). The real anchor is **off-box and automated**: every run reports its computed self-hash *and the hash of `onionwarden.pub`* to the receiver, which compares both against an off-box known-good captured at Phase-0 bootstrap and **alerts on any mismatch** (§4) — the on-box attacker cannot reach the receiver, so a pubkey swap surfaces there. The pubkey's hash is additionally embedded as a literal in the watchdog scripts, so even a naïve `.pub`-file swap trips the on-box self-hash.
- **Meta-check + dead-man's switch.** The fast run verifies its own timer/service are enabled & active, and emits a heartbeat. Stopping the watchdog stops the heartbeat → off-box alert (§4).
- **Unit hardening.** `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=/var/lib/onionwarden /var/log/onionwarden`, `NoNewPrivileges=true`, `PrivateTmp=true`, `CapabilityBoundingSet` limited to what's needed. Unit files are in the AIDE/baseline scope.
- **Script & unit immutability.** The watchdog code, the 6 systemd unit files, the signed `host.conf`, and the baseline-verification public key are made immutable (`chattr +i`) at install — **default ON** in v1. The full path list, the `onionwarden-upgrade` update workflow, and edge cases are in §3.6.
- **Privileged-surface note.** Runs as root (needs `/etc/shadow`, `nft`, `bpftool`, kmsg). Mitigations: signature-verify scripts before exec, no parsing of untrusted/network input, ShellCheck-clean, base-tool dependencies only.

### 3.6 Script & unit immutability — `immutable_scripts`, default ON

`install.sh` sets the **immutable attribute** (`chattr +i`) on the watchdog's own code and trust anchors. A `+i` file cannot be modified, deleted, renamed, or hard-linked until the attribute is cleared — *execution and reading are unaffected*. **v1 default: ON** (`immutable_scripts = true`); set `false` to fall back to detection-only.

**Protected paths (set `+i` at install, on every host):**
- `/opt/onionwarden/bin/*` — all watchdog binaries/scripts (`onionwarden-run`, `onionwarden-baseline`, `onionwarden-baseline-suggest`, `onionwarden-detect-profile`, `onionwarden-upgrade`)
- `/opt/onionwarden/lib/**` — check modules and `verify.sh`
- `/opt/onionwarden/roles/*.conf` — role profiles
- `/opt/onionwarden/onionwarden.pub` — the Ed25519 **public key** that verifies every baseline and config signature (protecting this is critical — swap the pubkey and an attacker can forge "valid" baselines)
- `/etc/systemd/system/onionwarden-{fast,slow,daily}.{timer,service}` — the 6 unit files
- `/etc/onionwarden/host.conf` — the signed per-host config
- `/etc/onionwarden/fatal-action.sh` — the operator `custom`-action script, when present (§3.7, L2)

**Deliberately *not* immutable:** `/var/lib/onionwarden/baseline/*` (re-baselined regularly — protected by Ed25519 signature instead), and `/var/lib/onionwarden/state/*` + `/var/log/onionwarden/*` (written every run).

**What it buys you — and what it does not.** `chattr +i` is enforced only against actors lacking the `CAP_LINUX_IMMUTABLE` capability. It stops a **non-root attacker** and **accidental operator error** (`rm -rf`, a stray editor save, a botched script) cold. A **root attacker can `chattr -i` and proceed** — this is *not* a root-containment boundary. Its value is raising the bar: it eliminates self-inflicted breakage entirely, and most automated post-exploit toolkits neither expect nor handle immutable files, so they fail noisily (→ detected by the self-hash check) rather than silently disabling the watchdog. Bonus: `+i` on the unit files also blocks `systemctl mask onionwarden-*` by anyone without `CAP_LINUX_IMMUTABLE` — a common "kill the watchdog" move.

**Legitimate updates — `onionwarden-upgrade`, no manual `chattr` dance.** Every change to the protected set (code, unit files, *or* `host.conf`) is applied by the `onionwarden-upgrade` helper, never by hand-editing. Fed a signed update bundle, it:
1. verifies the bundle's Ed25519 signature against `onionwarden.pub` — aborts on failure;
2. runs `chattr -i` on the protected paths;
3. applies the update (replaces files);
4. re-applies `chattr +i` to the protected paths;
5. emits an **audit entry** — to `/var/log/onionwarden/` *and* the off-box `events.log` — with timestamp, operator, old→new version + self-hash, and the bundle signer.

The operator never runs `chattr` directly. If `onionwarden-upgrade` is interrupted mid-update, the next watchdog run sees a self-hash mismatch on a partially-immutable tree → CRIT — a failed upgrade is loud, not silent.

**Edge cases:**
- **apt/dpkg clobber — confirmed non-issue.** A package manager writing to a `+i` path would fail, but none of our protected paths are package-managed: `/opt/onionwarden` is self-installed (`/opt`, by FHS convention, is never written by dpkg); our 6 unit files live in `/etc/systemd/system/` (dpkg ships units to `/usr/lib/systemd/system/`, never `/etc/systemd/system/`); `/etc/onionwarden/` is our own directory, owned by no package. apt/dpkg therefore never has cause to write a protected path. (`systemctl enable` only creates `.wants/` symlinks elsewhere — unaffected.)
- **Backup tools.** *Reading*/copying `+i` files for backup is unaffected. The failure mode is on the *write* side: a tool that **restores onto** a protected path, or that updates mtime/atime on an existing `+i` file (`rsync --times`, `tar -x` over it, `touch`), fails with `EPERM`. A same-host restore of the watchdog must `chattr -i` first (or go through `onionwarden-upgrade`) — note this in any backup runbook.
- **Filesystem support.** `+i` works identically on **ext4, btrfs, and xfs**. It is **not** supported on tmpfs, ZFS (which has its own `zfs set immutable`), overlayfs, or most network filesystems. `install.sh` probes the filesystem of the install prefix (§0.2); on an unsupported FS the feature **no-ops with a logged `N/A: immutable unsupported on <fs>`** and the host falls back to detection-only — consistent with detect-and-skip.

**Debian 13 (`relay-c` / `relay-d`).** `chattr +i` behaves identically on Debian 13 — same kernel inode-flag interface, same `e2fsprogs` `chattr`/`lsattr`. The only dependency is the *filesystem*, not the distro: Debian 13's installer defaults to **ext4** (fully supported); btrfs/xfs are also fine. *Caveat:* the actual root filesystem of `relay-c`/`relay-d` was **not** inventoried — the authorized read-only inventory covered only `relay-b` — so `install.sh`'s FS probe confirms it automatically at install time; a non-ext4/btrfs/xfs root degrades gracefully rather than breaking.

### 3.7 Fatal-action kill-switch — `fatal_action`, ships disarmed

By default the watchdog only *reports*. Optionally it can take a containment action when a **fatal** tampering signal fires. This is opt-in, checklist-gated, rate-limited, and deliberately blunt.

**Config (all in `host.conf`, §3.4):**
- `fatal_action` — `alert` (default; report-only) · `poweroff` (halt the host) · `freeze` (install an nftables ruleset that drops *new* outbound connections, allowing established + inbound SSH) · `custom` (run `/etc/onionwarden/fatal-action.sh`, baseline-hashed and, with `immutable_scripts`, immutable — §3.6). Two corrections from the 2026-05-21 critique apply to `freeze`: **(C5)** the §2.2 nftables check does **not** trust a stored `state/` record to recognise the freeze ruleset — an unsigned file must never suppress a CRIT check; instead it **deterministically regenerates** the expected freeze ruleset from the watchdog's fixed template and treats the live ruleset as benign *only* if it matches that byte-for-byte **and** a `freeze` event for this host exists in the off-box `events.log` (an attacker's DNAT-to-C2 ruleset matches neither test). **(H6)** on a `tor-relay` host `freeze` is a **full service outage**, not a soft landing — dropping new outbound stops circuit-building and the relay is functionally dead within minutes — and it leaves *established* connections up, so a pre-existing reverse shell survives it; for relays use `alert` or `poweroff`, not `freeze` (the `tor-relay` role profile says so, §0.6).
- `fatal_action_armed` — default **`false`**. `install.sh` always ships disarmed. Even with `fatal_action = poweroff` set, nothing happens until the operator explicitly arms the host with `onionwarden arm-fatal`, which **refuses unless the first-arm checklist passes** (below). Belt-and-suspenders against an accidental self-shutdown the first time a legitimate change lands before its baseline settles.
- `fatal_cooldown_hours` — default `24`. At most one `poweroff`/`freeze` per host per window (flap protection, below).
- `fatal_ack_timeout_s` — default `10`. How long to wait for an off-box acknowledgement before acting.

**What counts as "fatal" — a deliberately short, high-confidence list.** *Not every CRIT is fatal.* A fatal signal must clear two bars: a false positive is very unlikely, *and* the tamper is severe. **Fatal evaluation consumes only post-allowlist, post-apt-correlation findings** (C3) — a deviation already suppressed by an `expected_*` allowlist or demoted by apt-correlation (§5) is never fatal, even before its baseline catches up. Base list:
1. a `/boot` hash change that is still **CRIT after apt-correlation** (§5) — i.e. not a verified package update;
2. a new **SUID-root** (or SGID to a privileged group) binary **not** in the dpkg database — a non-root user can only create a binary SUID to *themselves*, which is a CRIT finding but not fatal;
3. non-empty `/etc/ld.so.preload` (writing it requires root);
4. kernel taint newly sets a **CRIT taint bit** — `P`(0), `F`(1), `R`(3), `O`(12), `E`(13), or `K`(15) unless `K` is an operator-applied livepatch. Hardware bits `M`(4)/`B`(5) are **not** fatal — a failing DIMM is not tamper (C3 fix: the old "any flag other than K" wording contradicted the §2.1 taint table);
5. a loaded kernel module that is **unsigned or out-of-tree** and not in baseline — *not* every non-baseline module: in-tree signed demand-loaded modules (`nf_conntrack_ftp`, a filesystem module on first mount) are normal;
6. a new SSH `authorized_keys` entry on an account in `expected_admins` or with UID 0 — a key on an *unprivileged* user's own file is a CRIT finding but not fatal (it is no privilege gain, and making it fatal would hand any local user a `poweroff` DoS oracle);
7. a UID-0 entry added to `/etc/passwd` and not in `expected_uid0` (writing `/etc/passwd` requires root);
8. `chattr -i` cleared on a watchdog-protected file (§3.6) — someone is dismantling the watchdog itself.
9. **a physical NIC entering promiscuous mode** — scoped to a *physical* interface that is **not** a bridge member; `veth`/`tap`/`vnet`/container interfaces and anything under `allow_virt_churn` are excluded (they go promiscuous legitimately). Enabling PROMISC on an uplink to sniff the LAN is textbook tampering;
10. **a new local input device** — a USB HID keyboard/mouse or PS/2 input device attached after baseline and not present at install (§2.8). Suppressed if `physical_access_allowed`, or during a `onionwarden suppress` maintenance window;
11. **a new local-console login** — a `tty1..N` session opened post-baseline by any UID (§2.8). Suppressed if `physical_access_allowed`, or during a `onionwarden suppress` maintenance window.

Items 1–8 require root or an equivalent capability. Items 9–11 are the **physical-access** signals — a different axis: they need physical or console contact, not root, but on a remote-managed fleet (no one should be at the keyboard) they are equally anomalous. The §8 "requires root" note refers to 1–8.

The list is **extensible per role** — `roles/<role>.conf` adds entries (e.g. `tor-relay` adds "tor identity-key change"), and `host.conf:fatal_signals_extra` adds per-host. A role profile may also *remove* a base entry for a documented reason.

**Pre-action protocol — off-box first, always.** Before any `poweroff`/`freeze`/`custom` action the run:
1. **sends the event off-box first** — a CRIT message tagged `fatal_action=<action>` to ntfy + the receiver `events.log` — so the record survives the host going down;
2. **waits up to `fatal_ack_timeout_s`** (default 10 s) for the receiver to acknowledge; if no ack, it **proceeds anyway** (a network cut must not veto containment). The ack is primarily a receipt confirmation — an operator who wants a genuine human-abort window can configure the receiver to withhold ack / return an explicit `abort`, and raise the timeout;
3. **emits a `wall` message** to all logged-in TTYs plus a last-gasp line to `/var/log/onionwarden/` and the kernel log;
4. **then** performs the action.

**Flap protection.** A `poweroff`/`freeze` is recorded in `/var/lib/onionwarden/state/`. After a reboot, if the same finding recurs within `fatal_cooldown_hours` the action is **suppressed** (still logged + pushed, no second action) — otherwise reboot → same finding → poweroff would loop the host into the ground. Re-arming after a cooldown-suppressed event requires explicit `onionwarden arm-fatal`.

**Recovery — out-of-band only, by design.** After a `poweroff` the host returns **only** via console / OOB management: hypervisor `virsh start` for a VM (e.g. `relay-b`), IPMI/iDRAC/physical for bare metal. The watchdog deliberately exposes **no remote power-on or remote-unfreeze path** — such a channel would be a remote-controllable shutoff oracle for an attacker. Operational consequence: **do not arm `poweroff` on a host without OOB access** — and note (H6) `freeze` is not a safe fallback on relays. A `poweroff` also stops the heartbeat, so the dead-man's switch (§4) fires too — an expected second, independent record.

**Recovery runbook specifics (M10).** `onionwarden-fatal` **snapshots the pre-freeze nftables ruleset** before installing the freeze ruleset; recovery restores that snapshot surgically and does **not** blanket-`nft flush` (which would also drop the Phase-4 host firewall). After a `poweroff`: **remediate offline before re-powering** — flap-protection means a rebooted-still-compromised host runs armed-but-inert for `fatal_cooldown_hours`, and a host that legitimately tripped `poweroff` cannot re-arm until checklist item 1's 7-quiet-day window passes. Both are intended; documented here so neither is a surprise during an incident.

**Maintenance window — `onionwarden suppress`, the escape valve for legitimate physical access.** Before an operator legitimately touches a host's console — a planned crash-cart visit, a hardware swap — they run `onionwarden suppress --reason="…" --duration=30m` from their existing remote SSH session. For that window the physical-*contact* fatal signals (#10 input-device, #11 console-login — **not** #9 PROMISC, which maintenance never needs) are downgraded to WARN: the box still records and pushes the event, but does not `poweroff`. The window is signed, logged off-box to `events.log` (operator identity, reason, duration), auto-expires, and can also be opened **receiver-side** as a signed push the host reads on its next run — necessary when the box is already unreachable and that is *why* a crash cart is coming. It never suppresses the root-level signals #1–#8. Honest limit: if the host is already down, opening the window over SSH is impossible — open it receiver-side, or expect the physical-access signal to fire and follow the OOB runbook.

**Threat-model honesty.** The kill-switch **deters and contains; it does not prevent** a root-level attacker. Root can set `fatal_action_armed=false`, `systemctl mask` the watchdog, or `chattr -i` and edit it. `chattr +i` on the unit files (§3.6, default ON) raises the bar — and clearing it is itself fatal-signal #8. Realistic value: it closes the window on automated post-exploit toolkits and on a slow human attacker, and caps exfiltration time. One more layer, not a guarantee.

**Phase placement & per-action arming.** The kill-switch *infrastructure* — this mechanism, `onionwarden-fatal`, the fatal-signal evaluator, cooldown, and the off-box-first protocol — installs in **Phase 2**, alongside SSH hardening (§6). It belongs in Phase 2 because (a) two fatal signals depend on Phase-2 checks (the dpkg-backed SUID scan and the apt-correlation window) and (b) Phase 2 is the first phase that already changes the host, so a behaviour-capable mechanism belongs there rather than in the deliberately zero-change Phase 1. **Installing it arms nothing** — `fatal_action_armed` still ships `false`; arming is always a separate, per-host, operator decision. Which action may be armed, and when:
- **`alert`** — always; it is the default and needs no arming.
- **`freeze`** — armable from **Phase 2**, once the host clears the first-arm checklist. `freeze` is fully reversible (`nft flush` undoes it), needs no out-of-band access, and stops exfiltration/C2 — it is the right early-availability action and serves the "threat is now" concern directly. (In practice the checklist's 7-quiet-day item means the earliest a host can actually arm is ~a week into Phase 2.)
- **`poweroff`** — split by signal set. For the **high-confidence subset** — fatal signals #3 (`ld.so.preload`), #4 (CRIT-bit kernel taint), #7 (new UID-0), #9 (physical-NIC PROMISC), #10 (local input-device hotplug), #11 (local-console login) — `poweroff` is armable from **Phase 2** on any host whose OOB recovery path is verified (checklist item 6). These six have a near-zero false-positive shape and map directly to the operator's "turn the server off on tampering" goal, so they do not wait for Phase 4. For the **remaining fatal signals** (#1 `/boot`, #2 SUID, #5 module, #6 `authorized_keys`, #8 `chattr -i`) `poweroff` arming stays **Phase 4** — higher-churn or needing the longer baseline track record. `custom` — Phase 4. In every case `onionwarden arm-fatal --action=poweroff` hard-refuses unless the OOB checklist item is attested; the real gate is the checklist, the phase is recommended sequencing.

**First-arm checklist — what makes "ships disarmed" safe to flip on.** `onionwarden arm-fatal` runs this checklist and refuses to arm until it passes. Items 1–3 and 5 are auto-verified **from the off-box `events.log`** — never from on-box logs, which a compromised host controls and could forge into "7 quiet days" (M3); 4, 6, 7 are operator-attested (recorded with identity + timestamp to `events.log`):
1. **Quiet baseline** — ≥ 7 consecutive days since the most recent baseline re-sign on this host, with **zero CRIT** and zero un-dispositioned WARN findings. (Auto.)
2. **apt-correlation proven** — at least one real apt / unattended-upgrade cycle on this host was correctly demoted WARN→INFO by per-file correlation (§5); proves the dominant false-positive source is being absorbed. (Auto.)
3. **Fatal dry-run clean** — `onionwarden fatal-dry-run` evaluates current (known-good) state against the fatal-signal list and shows **zero** would-trigger hits, catching a baseline that would instantly self-trip. (Auto.)
4. **Off-box-first proven** — `onionwarden fatal-test` sends a synthetic `fatal_action` event through the full pre-action protocol; the receiver `events.log` recorded it and an ack returned within `fatal_ack_timeout_s`. (Attested.)
5. **Dead-man's switch proven** — heartbeats were deliberately paused and the configured `deadman_provider` actually alerted. (Auto, from the test record.)
6. **OOB recovery verified for THIS host** — operator has tested and documented the out-of-band path to power-cycle / console this specific host. **Mandatory for `poweroff`/`custom`; `onionwarden arm-fatal` refuses those actions without it.** Not required for `freeze`. (Attested.)
7. **Host is past Phase 2** — SSH hardening applied and the host re-baselined to its hardened state, so the baseline is not mid-transition. (Attested.)

`onionwarden arm-fatal` / `onionwarden disarm-fatal` / `onionwarden fatal-status` manage the armed state; `onionwarden fatal-test` and `onionwarden fatal-dry-run` support the checklist. Every arm/disarm is logged to `events.log`.

---

## 4. Alerting

**Principle:** the alert path must survive the host being fully compromised *or* offline. A compromised root *can* forge "all-clear" messages — so the trust anchors are the **dead-man's switch** and the **off-box scan** (§5), not the on-box agent's word. Outbound HMAC is for in-transit integrity, not sender trust.

Endpoints come from `host.conf`, so each host can route independently while running identical code.

1. **Dead-man's switch — PRIMARY trust anchor (configurable: `deadman_provider`).** Each fast run sends a heartbeat; the *provider* raises the alarm when heartbeats stop. **The defining property is alerting-on-absence — not merely "a URL that accepts a POST."** `deadman_provider` is therefore constrained to providers that genuinely alert on staleness — the untenable `ntfy-scheduled` idea was **dropped** (see §8). Supported providers:
   - `healthchecks-saas` — Healthchecks.io. **Documented default** (free, battle-tested, alerts natively on a missed ping). Recommended for the canary.
   - `healthchecks-selfhost` — self-hosted Healthchecks; identical ping protocol, different base URL.
   - `http-ping` — any service that **(a) accepts a periodic POST AND (b) alerts when the POST stops** — e.g. Cronitor, Dead Man's Snitch, an Uptime-Kuma push monitor. The staleness-alert property is mandatory; a plain webhook receiver or a bare ntfy topic does **not** qualify (it receives heartbeats forever and never notices silence). There is no "plain URL" escape hatch — `install.sh` records the provider type so the property is explicit.
   On success the run pings the provider's OK endpoint; on any WARN/CRIT it pings the `/fail` endpoint. Fully off-box, independent of every monitored host. Grace ≈ 4 min (3 missed 1-min heartbeats).
2. **Rich findings push — channel: ntfy (`ntfy_url`, configurable).** Works with `ntfy.sh` or a self-hosted ntfy; the plan does not pick. Tradeoff: `ntfy.sh` is zero-ops but the topic name is the only secret — use an unguessable topic + access token; self-hosting removes that exposure at an ops cost. WARN/CRIT POST a structured message: `host_id`, `role`, run-id, severity, signal, check, `baseline → observed`, timestamp. Pushed only when severity ≥ `alert_push_level`; priority `max` for CRIT → phone push.
3. **Forensic backup — append-only log on a receiver host (`offbox_log_target`, configurable).** Not hardcoded — point it at any reachable host. Recommended properties: always-on, **off-fleet** (not one of the monitored hosts — a fleet-internal receiver shares the blast radius), and certificate-pinned if reached over HTTPS. Every alert + daily digest is appended as signed JSON over SSH using a **restricted key** (`command="…append-only…",no-pty,no-port-forwarding`) so a compromised host can append but not read or rewrite history. Survives the other channels being unreachable; tamper-evident audit trail.
4. **Tertiary — email via external SMTP (`email_to`)** for CRIT only; survives a receiver-host outage.

**Severity routing:** INFO → logs only. WARN/CRIT → events.log + provider `/fail`. A **push** (ntfy; email too for CRIT) fires when severity ≥ `alert_push_level` — default `crit` (only CRIT pushes; WARN rides the daily digest), set `warn` to push everything (used on the canary to learn the noise floor).

**Receiver topology:** for a fleet, a single shared off-fleet receiver host is fine; with Healthchecks, one project with one check per monitored host. The receiver host should itself run `onionwarden`. **Scale ceiling (H8):** Healthchecks.io's free tier caps checks (~20) — fine for 9 hosts, exceeded before ~25; beyond that, self-hosted Healthchecks and the Phase 5 Ansible layer become prerequisites, not finales.

**Receiver-side verification & rollup — the receiver actively checks, it does not just store** (built in Phase 0, extended in Phase 3):
- **Self-hash + pubkey anchor (C2/H5).** The receiver holds each host's Phase-0 known-good self-hash + `onionwarden.pub` hash and **automatically compares** every run's reported values, raising a CRIT push on mismatch. This is the anchor the on-box self-check structurally cannot be — a swapped pubkey or a tampered `onionwarden-run` surfaces here. An automated comparison, never "a sha256 a human eyeballs on a phone."
- **One fleet-rollup digest (H8).** The receiver emits a **single** daily fleet digest (every host on one line); per-host *pushes* fire only for WARN/CRIT. Nine "all-clear" pushes a day train operators to swipe away the tenth that says "1 CRIT"; one rollup does not.
- **`events.log` integrity (M7).** Each host stamps every append with a per-host **monotonic sequence number**; the receiver alerts on a gap (an omitted CRIT) and rate-limits appends (flood resistance). HMAC alone does not help — the compromised host holds the key.
- **Cross-host correlation (M6, Phase 3).** The receiver correlates across the 8 near-identical relays — the same new module on three within an hour (worm), one source IP spraying all eight, all heartbeats stopping together (upstream outage vs. compromise) — distinguished from single-host noise. At 8 identical hosts this is the highest-signal detection available.
- **Disabled / N-A surfacing (M1).** The rollup counts *ran-clean*, *N/A* (detect-and-skip), and *disabled* (`disable_checks`) separately and names any non-empty `disable_checks` prominently — a silenced check must never read as a clean one.

---

## 5. Baseline & state management

### Host-agnostic by design
There is **no fleet-wide golden baseline**. The *code* is identical everywhere; the *baseline data* is captured per host at bootstrap from that host's own known-good state. A baseline is a set of signed JSON manifests: module set, listener set, SUID list + hashes, `/boot` hashes, `sshd -T`, account/sudoers/key hashes, nft ruleset, hardware inventory, host profile, AIDE DB, watchdog self-hash.

### Where it lives
- **Authoritative copy: off-box** on the receiver host (`~/onionwarden/<host_id>/baseline/`). A host is never the sole authority on its own known-good state.
- **Working copy: on the host** at `/var/lib/onionwarden/baseline/`, **signature-verified every run**.

### Signing & key custody
One **fleet-wide Ed25519 keypair**. The **private key never touches a monitored host** — custody is the operator's choice; the plan documents best practice but does not dictate (Q5): keep it on an offline/air-gapped machine or a hardware token (e.g. YubiKey PIV, or a `minisign`/`age` key on removable media), used only during the deliberate off-box re-baseline step. The public half `onionwarden.pub` is embedded in `/opt/onionwarden/`; `host.conf:verify_pubkey_path` (default the embedded copy) lets a host be pointed at an alternate verification key on rotation. Re-baselining is a deliberate, signed, off-box act.

### Re-baseline workflow (when you make a legitimate change)
A re-baseline is a **fresh trust event**, not a formality (C1).
1. On the host: `onionwarden-baseline collect` → candidate manifests in a scratch dir (the host has no signing capability).
2. Pull candidates to the trusted host; `onionwarden-baseline diff` shows what changed vs the signed baseline **and classifies each delta**: a *contraction* (something removed) or a **trust-expanding delta** — a newly-present module, listener, SUID/SGID or file-capability binary, account, UID-0 entry, or `authorized_keys` entry.
3. **Human reviews the diff.** For trust-expanding deltas eyeballing is *not enough* — a human cannot distinguish a malicious module or planted SUID binary from a legitimate one.
4. **Offline-scan precondition for trust-expanding deltas (C1).** Any re-baseline that adds a trust-expanding delta requires the strongest-available out-of-band scan (the Bootstrap table below) backing *those specific deltas* before signing. `onionwarden-baseline diff` refuses to emit a signable manifest containing trust-expanding deltas without an `--offline-scan-attested` flag; contractions need no scan.
5. Sign off-box → push signed manifests to the receiver host *and* the monitored host.
6. Log the signing event to `events.log` — timestamp, one-line reason, and, for any trust-expanding delta, which deltas the offline scan covered.

**Why (C1):** without step 4, every re-baseline is a recurring trust-on-first-use event with the host as its own witness — an attacker resident at re-baseline time gets their backdoor signed into the authoritative baseline, and `onionwarden-baseline-suggest` would *actively propose* allowlisting it. The precondition makes *expanding* trust a deliberate, externally-witnessed act; *contracting* trust (removals) needs no scan.

`host.conf` allowlists are hand-curated by the operator (Q7); `onionwarden-baseline-suggest` inspects observed state/traffic and prints proposed `expected_lan_ports` / `expected_admins` / etc. additions for a human to paste in — it never edits `host.conf` itself, and a proposal matching a trust-expanding delta still requires the step-4 offline scan before it can be signed in.

### Churn handling — apt-correlation logic
apt/unattended-upgrades regularly changes `/boot`, modules, and packaged-file hashes. The watchdog does **both** things the operator asked for (Q8): every such change is still *detected and recorded*, AND it is auto-correlated to decide whether it **pushes**.

Correlation is **per file, not per time-window**. A `/boot`, module, or packaged-file change is detected → recorded as a finding regardless, and is **demoted WARN→INFO** (rolled into the daily digest, no push) only if **all** hold:
1. the changed file's **mtime** is within `apt_correlation_window` (default **5 min**) of an entry in `/var/log/apt/history.log`;
2. that apt run is **legitimate** — packages from an expected, configured source, apt/dpkg signature-verified (not a third-party or unknown repo);
3. the file now **matches the dpkg-recorded hash of a package updated in that run** (`debsums`/`dpkg --verify` confirms it is the *new package's* file, not an arbitrary edit).

Anything failing those — uncorrelated, wrong source, or a hash matching *no* package — stays **CRIT** and pushes. The per-file hash match in (3) is what makes this safe: a blanket "any change within 5 min of apt → INFO" rule would let an attacker run *any* apt command as cover and have unrelated tampering demoted. The window is `host.conf`-tunable — widen it on slow-storage hosts where a large kernel upgrade straddles 5 min. Condition (1)'s mtime is **forgeable by root** (`touch`) — treat it as a hint that narrows the search, never as a gate; condition (3)'s hash match against the actually-updated package is the sole real anchor (M5).

A `onionwarden-baseline collect --after-apt` mode streamlines the post-upgrade re-baseline (still off-box-signed, reason pre-filled from apt history) — the manual alternative to per-file correlation when you'd rather just re-baseline.

### Transient state
journald/dmesg cursors + last-run markers in `/var/lib/onionwarden/state/` — unsigned bookmarks, not security-critical. **Nothing in `state/` may suppress a security check (C5)** — it holds cursors and counters only; freeze-ruleset recognition is done by deterministic recompute + off-box `events.log` corroboration (§3.7), never by a stored `state/` record.

### Bootstrap — capturing a *trustworthy* initial baseline (per host)
You can only baseline cleanly from a known-good state. The `onionwarden-baseline collect` step is **identical on every host**; only the *trust-establishment step before it* varies by host type — pick the strongest available:

| Host situation | Trust-establishment step |
|---|---|
| **Fresh install** | Baseline immediately post-install, before network exposure — strongest. |
| **Existing VM guest** | Snapshot the disk at the hypervisor, mount it read-only on a trusted host, scan offline (`debsums`, `aide --init`, `rkhunter`, manual review). An in-guest rootkit cannot lie to a scanner outside the guest. |
| **Existing bare metal** | Boot from live USB / recovery, scan the mounted FS the same way. |
| **No offline option** | Baseline from single-user/recovery boot; accept residual TOFU risk; document it. |

Then: `onionwarden-baseline collect` → **manually review every artifact** (module list, listeners, SUID set, `sshd -T`, keys) → sign off-box → store on receiver + push to host → record creation in `events.log`. **Re-run the strongest available out-of-band scan periodically** as ground truth — backstop (c) from §1.

**Cost caveat (H7).** For the 8 internet-facing relays one scan cycle means 8 disk-snapshot-mount scans (if VMs) or 8 physical / IPMI sessions (if bare metal) — and the relays' virtualization type has **not** been inventoried (Appendix A is relay-b-only; inventorying it is a Phase-0 task). Pick a cadence the operator will *actually* sustain; if monthly is unrealistic, say so and downgrade §1's backstop-(c) claim to the real cadence rather than an aspirational one. A trust anchor that does not happen is not a trust anchor.

### Log retention & review
- **On-box:** JSON to `/var/log/onionwarden/`; `logrotate` 30 days, total size-capped (default ~200 MB — important on space-constrained hosts).
- **Off-box:** `events.log` keeps alerts + digests; retention default **365 days** (tiny on disk). Retention runs **on the receiver**, so `offbox_log_retention` is shipped to the receiver in each host's event stream (or set directly in receiver config) — it is not enforced on-box (L5).
- **Review (fleet-aware — H8):** the receiver emits **one fleet-rollup digest** per day (all hosts, one line each); per-host *pushes* fire only for WARN/CRIT. The rollup distinguishes *ran-clean* / *N/A* / *disabled* counts and names any non-empty `disable_checks` (M1). Weekly → skim `events.log`. Every WARN/CRIT needs explicit disposition — *re-baseline* (legit) or *investigate* (tamper). Nothing auto-clears.

---

## 6. Phased rollout & packaging

### Packaging & deployment
Single repo `onionwarden`: `bin/` + `lib/` + `roles/` scripts and systemd unit templates, installed by **`install.sh`** — the one and only install path through Phases 0–4 (Q6; an Ansible role arrives in Phase 5). `install.sh` copies the identical tree to `/opt/onionwarden`, generates `/etc/onionwarden/host.conf` interactively, and enables the timers.

**Fleet drift — known limitation through Phase 4.** With `install.sh` and no config-management layer, a code update means re-running `install.sh` on each of the 9 hosts by hand, and there is no central "which host runs which version" view. Interim mitigations: (a) the daily digest includes each host's `onionwarden` code-version + self-hash, so drift is visible across digests; (b) per-host self-hash (§3.5) still catches a host whose code diverges from *its own* signed manifest. The hand fan-out and the drift blind-spot are removed in **Phase 5** by an Ansible role + version-drift report.

### Phase 0 — Bootstrap (off-host)
Generate the fleet Ed25519 keypair (private key off-box, §5). Stand up the receiver host (`events.log` + restricted SSH key) and the dead-man provider (per `deadman_provider`). For *each* target host: run the trust-establishment step (§5), capture + sign its baseline.

### Phase 1 — Quick-win watchdog (≈1 day per host, see §7) — **zero package installs**
The 11 highest-value checks + timers + heartbeat + alerting. Base tools + `curl` only. **After Phase 1, plugging a keyboard or mouse into the server, or opening a local console session, triggers a within-minute off-box alert** — alongside the kernel-taint, promiscuous-interface, new-module, new-port and SSH/account checks. **Roll out to the canary first — `relay-a` (Q1):** a stock-6.8-kernel relay (the most-replicated config, 3 of 8 relays), lowest-stakes by name, and not a directory-authority peer — so a watchdog misfire there is cheap. Run it with `alert_push_level=warn` and `workload_integrity_check=none` to surface the noise floor before any fleet-wide rollout. **Phase 1 acceptance includes a mandatory dead-man's-switch self-test (M9):** pause heartbeats and confirm the configured `deadman_provider` actually alerts — a typo'd `deadman_url` must be caught here, not discovered during a real outage.

### Phase 2 — SSH hardening + full signal coverage
**First action — SSH hardening, fleet-wide (moved up from Phase 4, Q9).** Deploy an `sshd_config.d` drop-in: keys-only (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`), `PermitRootLogin no`. *Why moved earlier:* SSH is the primary remote-attacker (A1) entry point and the 8 relays are internet-facing — leaving password/root SSH open until Phase 4 keeps the single biggest hole open through most of the rollout. It is *not* in Phase 1 only because Phase 1 is deliberately monitoring-only / zero-change so it can ship same-day with no risk; Phase 2 is the first phase that already modifies hosts. After this change, re-baseline `sshd -T` on every host — the Phase 1 baseline will intentionally mismatch.
Then: `apt install debsums aide` (+ `libcap2-bin`, `mokutil` where applicable). Add `[slow]`/`[daily]` checks: full SUID + capability scan, network deep checks, hardware diff, eBPF, cron/unit scanning, world-writable + immutable-bit audit, `debsums`/AIDE (incl. `debsums tor` on relays), workload-image integrity. Wire the apt-correlation logic (§5).
Finally, install the **fatal-action kill-switch infrastructure** (§3.7) — the mechanism, `onionwarden-fatal`, the fatal-signal evaluator, cooldown, and off-box-first protocol — moved up from Phase 4 at the operator's request because the threat is present now, not after hardening completes. It installs **disarmed** (`fatal_action_armed=false` — installing it arms nothing). From here, once a host clears the first-arm checklist (§3.7): `freeze` is armable, and **`poweroff` is armable for the high-confidence fatal subset** — CRIT-bit kernel taint, physical-NIC PROMISC, local input-device hotplug, local-console login, `ld.so.preload`, new UID-0 — on any host with a verified OOB recovery path. `poweroff` for the remaining fatal signals, and `custom`, stay gated to Phase 4. The phase number is sequencing, not the safety control — the disarmed default + checklist are.

### Phase 3 — Real-time layer + cross-fleet comparison
`apt install auditd`. Curated rules: `init_module`/`finit_module`/`delete_module`, writes to `/etc/passwd|shadow|sudoers|ssh`, `execve` from `/tmp`/`/dev/shm`, `ld.so.preload` writes. Ship the journal off-box (`systemd-journal-upload`).

**`onionwarden fleet-diff` — build it here**, alongside the role profiles (§0.6) it depends on. It is an **operator-side** tool — run from the receiver host or an admin box with reach to the fleet, *not* a per-host check. It pulls each host's current signed baseline manifest (loaded modules, listening ports, SUID set, `sshd -T`-derived posture, kernel/taint, package set), normalizes them, and emits a **Markdown diff report grouped by host and role**. It is explicitly **not** a convergence tool: a `tor-relay` and an `eval-host` *should* differ, and even two relays differ in ORPort etc. Its job is to surface **deltas within a role** so anomalies stand out — one `tor-relay` carrying a kernel module the other seven lack, one `eval-host` listening on a port its peers don't. Grouping by role turns "9 different hosts" into "expected role baseline + per-host exceptions," which a human can actually scan. Use cases: vetting a freshly-installed canary box against the fleet before a release, and periodic fleet anomaly sweeps.

### Phase 4 — Active hardening (monitoring → prevention)
Per-host, capability-gated: GRUB password; security sysctls (`kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`, `kexec_load_disabled=1`, `kernel.modules_disabled=1` late in boot); evaluate `lockdown=integrity`; host firewall (nftables) restricting non-`expected_lan_ports`. (SSH hardening already shipped in Phase 2.) **`poweroff` arming for the lower-confidence fatal signals, and `custom` arming, are gated to this phase** (§3.7): the kill-switch *mechanism* shipped in Phase 2, and `freeze` + `poweroff` for the high-confidence subset (CRIT-bit taint, PROMISC, physical-access, `ld.so.preload`, UID-0) are armable from then — Phase 4 adds `poweroff` for the remaining signals once GRUB/console hardening has firmed up the recovery path. Each item is monitored *before* enforced.

### Phase 5 — Fleet config management
An Ansible role wrapping the proven `install.sh` + `onionwarden-upgrade` flow — it does not replace them, it *invokes* them idempotently across the fleet. Adds a `version` fact reported in each host's daily digest, and a **drift report** comparing every host's pinned `onionwarden` version against the fleet head.
*Why last:* automation should wrap a flow that is already operationally mature. Introducing Ansible before the manual `install.sh` / `onionwarden-upgrade` / re-baseline loop is proven would propagate immature procedures fleet-wide and add a second moving part to debug during early rollout. Once Phases 0–4 have run on the real fleet and the workflow is stable, Phase 5 removes the hand fan-out and the drift blind-spot called out in the packaging note above.

---

## 7. Phase 1 quick-win — highest-value subset, ≈1 day, zero package installs

All checks below are sub-second and need only coreutils / iproute2 / systemd / `curl`. `curl` is a documented prerequisite — present on stock Ubuntu/Debian and on relay-b; `install.sh` verifies it and installs it (or falls back to `wget` / bash `/dev/tcp`) if a minimal image lacks it (L3). Identical on every host; detect-and-skip handles capability gaps.

| # | Check | Command | Catches |
|---|---|---|---|
| 1 | **Heartbeat + dead-man's switch** | `curl` heartbeat to the configured `deadman_provider` each fast run | Watchdog killed, host dead/offline, network cut. *Build first — nothing else is trustworthy without it.* |
| 2 | **Kernel taint** | `cat /proc/sys/kernel/tainted` (bit-decoded) | Rootkit/forced/unsigned/out-of-tree module, oops. |
| 3 | **Loaded module diff** | `lsmod` vs baseline (cross-checked w/ `/proc/modules`) | New kernel module — the primary kernel-tamper vector. |
| 4 | **Listening port diff** | `ss -tulpnH` vs baseline + `expected_lan_ports` | New backdoor / newly LAN-exposed service. |
| 5 | **SSH keys + effective sshd config** | sha256 `authorized_keys` (all users) + `sshd -T` | The #1 SSH persistence vector. |
| 6 | **Account & sudoers integrity** | sha256 `/etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/*`; UID-0 vs `expected_uid0` | New account, new root-equivalent, privesc. |
| 7 | **Library-injection check** | `cat /etc/ld.so.preload` + scan `/proc/*/environ` for `LD_PRELOAD` | Classic userland rootkit. |
| 8 | **Watchdog meta-check** | `systemctl is-enabled/is-active` for own units + script self-hash | Attacker disabling/masking/editing the watchdog. |
| 9 | **Promiscuous interface** | `ip -d link show` / `/sys/class/net/*/flags` vs baseline | An interface in PROMISC mode — traffic sniffing. |
| 10 | **Local input-device hotplug** | `/sys/bus/usb/devices/*` HID class + `/sys/class/input/event*` + `/sys/bus/serio` vs baseline | A keyboard/mouse plugged into a remote-managed server — physical access (§2.8). |
| 11 | **Local-console login** | `who` filtered to `tty[0-9]*` + wtmp tty entries vs baseline | A login at a physical/virtual console — crash-cart-style access (§2.8). |

Plus: the `onionwarden-fast.timer`/`.service` skeleton, `onionwarden-detect-profile`, signed baseline capture for checks 2–11, `host.conf`, ntfy alerting, and the receiver-host `events.log` backup. Delivers a self-defending, off-box-alerting watchdog covering kernel, network, SSH, accounts, library injection, and physical access — in a day, with no installs.

---

## 8. Decisions (resolved) & remaining ambiguity

All 16 open questions were resolved by the operator on 2026-05-20 and folded into the plan. A follow-up round the same day also added two capabilities beyond the original 16 — the opt-in **fatal-action kill-switch** (§3.7) and **Phase 5** fleet config management — whose residual risks are tracked in the flags below. An adversarial critique pass (`CRITIQUE.md`, 2026-05-21) was then folded in: its 5 CRITICAL + 8 HIGH findings produced real design changes throughout, cited inline as `C#`/`H#`/`M#`/`L#`; the **Execution TODO** at the top of this doc reflects the post-critique plan. "Needs a value" means the *design* is fixed but a concrete per-deploy input must still be supplied before that host goes live — it is not an open design question.

| # | Topic | Decision (folded in at §) | Status |
|---|---|---|---|
| 1 | Rollout order | Canary one host first. Default canary `relay-a` (stock-6.8 relay, lowest-stakes, most-replicated config, not a dir-auth peer); selection is a `host.conf:canary` boolean — picking the canary is config, not code (§3.4, §6 Phase 1). | RESOLVED pending operator confirmation (L1) |
| 2 | Receiver host | Not hardcoded — `offbox_log_target` in `host.conf`; recommended properties always-on / off-fleet / cert-pinned (§4). | RESOLVED — needs a value |
| 3 | ntfy | Configurable `ntfy_url`; ntfy.sh or self-hosted; tradeoffs documented, plan does not pick (§4). | RESOLVED — needs a value |
| 4 | Dead-man's switch | Configurable `deadman_provider`: `healthchecks-saas` (default) / `healthchecks-selfhost` / `http-ping` — all constrained to alert-on-absence; `ntfy-scheduled` **dropped** as untenable (§4). | RESOLVED |
| 5 | Signing key custody | Configurable; private key off-box, operator's choice of offline machine / hardware token; `verify_pubkey_path` for rotation (§5). | RESOLVED — needs a custody decision |
| 6 | Config management | `install.sh` is the sole install path through Phases 0–4; an Ansible role wrapping it lands in **Phase 5** (§0.1, §6). | RESOLVED |
| 7 | Allowlist ownership | 1aeo hand-curates `host.conf`; `onionwarden-baseline-suggest` proposes, human approves (§5). | RESOLVED |
| 8 | Upgrade churn | Detect every change AND apt-correlate; demote WARN→INFO only **per-file** when provably part of a verified apt run within `apt_correlation_window` (§5). | RESOLVED |
| 9 | SSH posture | Enforce fleet-wide (keys-only, no-root, no-password); **moved up to Phase 2** (§6). | RESOLVED |
| 10 | Workload scope | `workload_integrity_check = none\|hashes\|full`. Role defaults: `eval-host` → `none` (live VM disks churn), `tor-relay` → `hashes` (relay identity key); `workload_paths` scopes it (§0.6, §2.4, §3.4). | RESOLVED |
| 11 | Alert volume | `alert_push_level = warn\|crit`; default `crit`, canary `warn` (§3.4, §4). | RESOLVED |
| 12 | Re-baseline & immutability | Manual-signed AND `--after-apt` both available. `immutable_scripts` (chattr +i on watchdog code/units/config/pubkey) **default ON**, configurable off; legitimate updates go through `onionwarden-upgrade` — no manual `chattr` (§3.6). | RESOLVED |
| 13 | Retention | `offbox_log_retention`, default 365d (§3.4, §5). | RESOLVED |
| 14 | Role assignments | 8 relays `tor-relay`, `relay-b` `eval-host`; `role` is a pluggable string → `roles/<role>.conf`, new roles need no code change (§0.6). | RESOLVED pending operator confirmation (L1) |
| 15 | Debian 13 | In scope, tier-2 (§0.5). | RESOLVED |
| 16 | Tor binary | Stock package on all relays → `debsums tor` is the primary tor-binary integrity check (§0.6, §6). | RESOLVED |

### Still needs a concrete value before deploy (inputs, not design questions)
- The receiver host, `ntfy_url`, `deadman_url`, and the signing-key custody location (Q2/Q3/Q5) are per-deploy inputs for `host.conf` / the Phase 0 bootstrap.
- Confirm `relay-a` as the default `canary` (Q1).
- Per host, set `physical_access_allowed` — `false` fleet-wide; `true` only where someone legitimately works at the keyboard (§2.8/§3.4).
- For any host with a permanently-attached input device (IPMI / KVM-over-IP USB-keyboard dongle): confirm it is present and captured at baseline so it does not trip fatal-signal #10 on the first tick — and decide whether *unplugging* such a dongle should itself alert.

### Design concerns — earlier flags resolved, one new one

Resolved from earlier rounds:
- **Dead-man's-switch "just a URL" footgun** — resolved: `ntfy-scheduled` dropped; `deadman_provider` is constrained to providers with real alert-on-absence semantics, no plain-URL escape hatch (§4).
- **`workload_integrity_check = hashes` noise on live-VM hosts** — resolved: the `eval-host` role now defaults to `none`; `tor-relay` defaults to `hashes` over a tiny at-rest fileset (§0.6).
- **No Ansible / fleet drift** — resolved: Phase 5 adds an Ansible role + version-drift report (§6).

**Flagged — the kill-switch, now that the mechanism lands earlier (Phase 2, §3.7).**
- **Earlier availability raises the "armed too soon" temptation.** Pulling the infrastructure to Phase 2 (operator's call — the threat is now) means an operator *can* arm while a host's baseline is still young and settling — the window in which a legitimate-but-un-baselined change (a new admin SUID tool, a hand-added SSH key, a manually loaded module) trips a fatal signal and, if `poweroff` is armed, drops the host. **The phase number is not the safety control** — the disarmed default, per-host opt-in, and the machine-enforced first-arm checklist are. Checklist item 1 (≥ 7 quiet CRIT-free days since the last baseline change) is the specific guard against arming on an immature baseline; `onionwarden arm-fatal` refuses until it passes. Residual risk is real: the checklist is only as good as its thresholds, and an operator can still mis-attest the manual items (4/6/7).
- **A false positive becomes an outage.** Even checklist-gated, an armed `poweroff` converts a missed-baseline change into a host-down event. `freeze` (reversible, no OOB needed) is the recommended early action and is what `freeze`-from-Phase-2 makes available; `poweroff` arming stays gated to Phase 4 behind the OOB-verified checklist item — the recovery-cost asymmetry is the reason for the split.
- **Recovery cost.** A powered-off host returns only via console/OOB; a bare-metal relay without IPMI means a physical visit. §3.7 forbids arming `poweroff` without an attested OOB path.
- **Attacker abuse of the trigger — bounded but real.** Tripping a *root-level* fatal signal (#1–#8) requires root (writing SUID, `ld.so.preload`, a UID-0 line, loading a module); such an attacker can already `poweroff` directly, so the kill-switch adds little *new* DoS surface. The genuine residual: it hands that attacker a *timed* outage lever. `freeze` over `poweroff` blunts it — deter-and-contain, not a prevention boundary. The physical-access signals (#9–#11) sit on a different axis — console/physical contact, not root — and for a remote-managed fleet that contact is itself the anomaly; `physical_access_allowed` and the `onionwarden suppress` maintenance window cover the legitimate cases (see the new flag below).

**Flagged — physical-access auto-poweroff + the maintenance-window escape valve.**
- **Forgetting to suppress is a self-DoS.** With `poweroff` armed for the physical-access subset (available from Phase 2), an operator who walks up to a host and plugs in a keyboard *without first running `onionwarden suppress`* trips fatal #10 and powers the box off under their own hands. The 30-minute window is the intended workflow, but it depends on the operator remembering — and the consequence of forgetting is exactly the outage they came to prevent. Mitigations: the pre-action `wall` warns any console session, the off-box-first protocol gives a brief ack window, and `physical_access_allowed=true` exists for hosts where keyboard work is routine. Residual: real and operator-discipline-dependent.
- **The receiver-side maintenance window widens the receiver's trust role.** Allowing the window to be opened receiver-side (needed when the host is already unreachable) means whoever controls the receiver can mute the physical-access poweroff. The receiver is already a trust anchor (it holds baselines and the self-hash known-good), so this is within the existing trust model — but it concentrates one more capability there; the receiver's own hardening matters more, not less.
- **`onionwarden suppress` covers only the physical-contact signals.** It deliberately cannot mute #1–#9 — a maintenance window is expected-physical-contact relief, not a blanket "stop alerting." There is no escape valve for the root-level signals, by design.

---

## Appendix A — Reference inventory: `relay-b` (one example target)

The following is a read-only inventory of **one** deployment target, captured 2026-05-20. It is included to show *how detect-and-skip resolves on a real host* — it is **not** the design center, and no other host should be assumed to look like this.

| Property | Observed on relay-b | How the portable tool handles it |
|---|---|---|
| Virtualization | QEMU/KVM guest (i440FX, virtio, `vmgenid`) | `virt_type=kvm`; hypervisor is out of scope for this host. |
| Firmware/boot | Legacy BIOS — `/sys/firmware/efi` absent, GRUB `i386-pc` | Secure Boot check → `N/A: legacy BIOS`. `/boot` hashing + GRUB password used instead. |
| Kernel | `6.17.0-29-generic`, running == newest installed | Running-vs-installed check active. |
| Taint | `/proc/sys/kernel/tainted` = `0` | Baseline = 0; any rise alerts. |
| Lockdown | `[none]` | Phase 4 hardening candidate. |
| Modules | 67 loaded (`kvm_amd`, `nf_tables`, libvirt `bridge`) | Captured into relay-b's baseline. |
| Users | One human: `operator` (uid 1000, `sudo`), 2 SSH keys; `/etc/sudoers.d` clean | `expected_admins=["operator"]`, `expected_uid0=["root"]`. |
| Listeners | SSH `:22`; `:3000` + `:18789` (node) bound `0.0.0.0`; rest `127.0.0.1` | `expected_lan_ports=[22,3000,18789]` after confirming intent (Q7). |
| Firewall | `nft`/`iptables` present, host ruleset effectively empty | Monitored now; Phase 4 candidate. |
| Nested VMs | `qemu-system-x86` processes running inside relay-b | `is_hypervisor=true`, `allow_virt_churn=true`. |
| Security tooling | `aide`, `debsums`, `auditd`, `mokutil`, `rkhunter` absent; `bpftool`, `nft`, `iptables`, `curl` present | Phase 1 needs no installs; AIDE/debsums/auditd arrive Phase 2/3. |
| Disk | `/` 88% full, ~18 GB free; unattended-upgrades enabled | Log size cap matters here; apt churn correlation matters here. |

On a different target — say a bare-metal EFI server with Secure Boot on, no nested VMs, and `auditd` preinstalled — the *same code* would run the Secure Boot check, set `is_hypervisor=false`, and activate auditd-backed checks immediately. Nothing in §§1–8 changes.
