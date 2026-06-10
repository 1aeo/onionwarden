# Architecture

The component reference, the full check inventory, and the phased-rollout model.
For the front-door summary start with the [README](../README.md); for the
complete design and threat model see [PLAN.md](../PLAN.md).

```
┌──────────────────┐                ┌───────────────────────┐
│ monitored host   │                │ off-box receiver      │
│   onionwarden    │ ── ssh ──>     │   /var/lib/onionwarden │
│   (collector)    │  forced-cmd    │   events.log per host │
└─────────┬────────┘                └──────────┬────────────┘
          │                                    │
          │  ntfy push on WARN/CRIT            │  digest, seqcheck,
          │  + dead-man heartbeat              │  verify-check (cron)
          ▼                                    ▼
       operator                          operator
```

## Components

### Collector

A tiny pure-bash watchdog (`/opt/onionwarden`) driven by three systemd timers
(`fast`, `slow`, `daily`). On each tick it verifies the signed baseline and
`host.conf`, detects the host capability profile, runs the checks for that
cadence under a per-check timeout and memory cap, logs structured findings,
drives the dead-man heartbeat, and routes alerts off-box.

The collector is **not a trust anchor** (PLAN §3.5). It can detect and report,
but it cannot authorize: every baseline it verifies was signed off-box by a
human.

### Signed baseline

Every host has a per-host baseline (`onionwarden baseline collect`) signed
off-box with the fleet Ed25519 key. Collectors verify the signature on every
run (`lib/verify.sh`). Allowlists in `host.conf` encode *human intent* (what
deviations are expected); the baseline records *actual state*. See PLAN §5 for
how to capture a trustworthy first baseline — the single most important step,
because it is the trust anchor everything else compares against.

### Receiver

A separate, off-fleet host that receives events over a forced-command SSH key
(`receiver/onionwarden-receiver`), appends them per-host to an append-only
`events.log`, runs cron-based `verify-check` / `seqcheck` / `digest`, and pushes
to ntfy on WARN/CRIT. The receiver is **not a daemon** — the always-on piece is
cron and the ingest piece is a forced command behind sshd. Each per-host SSH key
is pinned to one `host_id` so a key stolen from host A cannot write host B's log.
Full runbook: [receiver/RECEIVER.md](../receiver/RECEIVER.md).

### Kill-switch (optional, ships disarmed)

`lib/fatal.sh` evaluates compound conditions and can escalate from `alert` to
`poweroff` or `freeze` (a deterministic ruleset replace). It **ships disarmed**
and must be armed per host with `onionwarden arm-fatal` — which refuses until a
seven-item checklist passes (quiet baseline, proven apt-correlation, clean
dry-run, off-box-first proven, dead-man's switch proven, per-host OOB recovery
verified, host past Phase 2). See PLAN §3.7 and the
[onboarding runbook](ONBOARDING.md#first-arm-checklist--when-does-this-host-become-armable).

## What the collector checks

Roughly 25 checks run across the three cadences. Capability gaps degrade a check
to `N/A` (detect-and-skip, PLAN §0.2) rather than failing the run:

- kernel taint and loaded modules
- listening sockets and deep network state (outbound, promiscuous interfaces)
- `sshd` config, accounts / sudoers, UID-0 set
- `ld.so.preload`, scheduled units (cron/systemd timers)
- SUID and file-capability deltas
- package integrity (debsums / AIDE)
- nested-VM layer and snap revisions
- hardware inventory and process ancestry
- input-device hotplug and local-console login

The full signal catalogue and the rationale for each is in PLAN §2.

## Phased rollout

onionwarden is designed to be rolled out in stages, not flipped on fleet-wide.
The phase you are in determines which layers are active.

| Phase | Goal |
|-------|------|
| 0 | Bootstrap — generate the signing key, stand up the receiver, capture initial baselines |
| 1 | Quick-win watchdog — highest-value checks + timers + heartbeat + alerting |
| 2 | SSH hardening + full check coverage + kill-switch infrastructure |
| 3 | Snapshot bundle (offline scan) + fleet diff |
| 4 | Dry-run + canary rollout (first canary host, `alert_push_level=warn`) |
| 5 | Fleet-wide rollout |

The per-host journey through Phase 0 and Phase 1 is the
[onboarding runbook](ONBOARDING.md). Phase 2 and arming the kill-switch each
get their own runbook (PLAN §6, §3.7). The full phase breakdown and packaging
plan is PLAN §6.
