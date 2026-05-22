# OPERATOR_DECISIONS.md

The PLAN's "Operator decisions" TODO block lists 9 inputs the design leaves to
the operator. This build picked a sensible default for each so the tree is
complete and installable. **Every default below is overridable** — most live in
the per-host answers file (`examples/answers-*.example` → `/etc/onionwarden/host.conf`).

`⚠ HIGH-RISK` marks a default the operator **must re-confirm before any real
deploy** — leaving it as-is would ship something materially wrong.

---

## §1 — Rollout canary
**Default:** `relay-a` (the plan's recommendation — a stock-6.8 relay, the
most-replicated config, not a directory-authority peer).
**Rationale:** kept the plan default; selection is just `canary = true` in one
host's config, so changing it is a config edit, not code.
**Risk:** low. `examples/answers-canary.example` is written for `relay-a`.

## §2 — Role assignments
**Default:** the 8 relays → `tor-relay`, `eval-host` → `eval-host`.
**Rationale:** kept the plan default (§8 Q14). `role` is a pluggable string →
`roles/<role>.conf`; a new role needs no code change.
**Risk:** low. Confirm each host's role in its answers file before install.

## §3 — Off-box receiver host  ⚠ HIGH-RISK
**Default:** **deferred — `offbox_log_target` ships as a placeholder.**
**Rationale:** the receiver must be a real, always-on, **off-fleet** host; it
cannot be guessed. The build provides `receiver/` (append handler, verifier,
digest, seqcheck, setup) ready to drop onto whatever host the operator picks.
**Risk:** HIGH. The receiver is a trust anchor — it holds the off-box self-hash
known-good and the events.log. **Provision and harden it before Phase 0.** Do
not co-locate it on a monitored host (it would share the blast radius). Until a
real `offbox_log_target` is set, the events.log channel is inert and the
receiver-side self-hash anchor (C2/H5) does not exist — the on-box self-check
alone is *not* sufficient (H5).

## §4 — Signing-key custody
**Default:** the fleet Ed25519 private key lives in the **operator's encrypted
store on an offline/personal machine** (e.g. an `age`- or password-manager-
encrypted file on removable media) — **never in this repo, never on a monitored
host.** `bin/onionwarden-sign keygen` generates the pair; only `onionwarden.pub` is
distributed.
**Rationale:** the plan (§5) leaves custody to the operator and only documents
best practice. An encrypted offline file is the minimum acceptable bar.
**Risk:** medium. **Recommended upgrade before fleet-wide arming of any
`poweroff`:** move the private key to a hardware token (YubiKey PIV). Whoever
holds this key can forge any baseline — treat it like a root CA key.

## §5 — Alerting endpoints (`ntfy_url`, `deadman_provider`/`deadman_url`)
**Default:** `deadman_provider = healthchecks-saas` (Healthchecks.io free tier —
battle-tested, alerts natively on a missed ping); `ntfy_url` → `ntfy.sh` with an
**unguessable topic name** + access token.
**Rationale:** zero-ops, satisfies the mandatory alert-on-absence property, fine
for 9 hosts (Healthchecks.io free tier caps ~20 checks — H8).
**Risk:** low-medium. **Swap to self-hosted Healthchecks + self-hosted ntfy
before the fleet exceeds ~20 hosts**, or sooner if routing alert metadata
through SaaS is unacceptable. The per-host `deadman_url` UUID and the ntfy topic
are secrets — a typo is caught at install (M9) and by the mandatory Phase-1
dead-man self-test.

## §6 — Relay virtualization-type inventory  ⚠ HIGH-RISK
**Default:** **deferred — Appendix A inventoried `eval-host` only.**
**Rationale:** the 8 relays' VM-vs-bare-metal status was never inventoried; it
drives (a) the offline trust-establishment method (§5 — disk-snapshot scan vs
IPMI/live-USB) and (b) whether `chattr +i` works (FS-dependent — `install.sh`
probes this automatically and degrades gracefully).
**Risk:** HIGH for *process*, low for *code*. The code detect-and-skips, so it
will not break — but the **Phase-0 offline scan cannot be planned** without this
inventory. Inventory all 8 relays before Phase 0.

## §7 — Offline-scan cadence
**Default:** **quarterly** (not monthly).
**Rationale:** H7 — one scan cycle is 8 disk-snapshot or IPMI sessions; monthly
is unrealistic to sustain, and "a trust anchor that does not happen is not a
trust anchor." Quarterly is honestly sustainable.
**Risk:** medium. Backstop (c) in §1 is **downgraded from monthly to
quarterly** — the window in which a competent resident rootkit stays
externally-unverified is correspondingly ~3 months. If that is unacceptable,
the operator must commit the resources for a tighter cadence.

## §8 — Per-host `fatal_action` policy
**Default:** **every host ships `fatal_action = alert`** (report-only) and
`fatal_action_armed = false`. No host is armed by this build.
**Rationale:** the kill-switch ships disarmed by design (§3.7). `alert` is the
safe universal default. Relays must **never** use `freeze` (H6 — it is a full
service outage on a relay).
**Risk:** low (conservative). Arming `freeze`/`poweroff` is a deliberate,
later, per-host operator action gated by `onionwarden arm-fatal`'s 7-item
checklist. Recommended progression: `alert` → (after a quiet baseline) `freeze`
on eval-host / `poweroff` on hosts with verified OOB → never `freeze` on relays.

## §9 — `physical_access_allowed`
**Default:** `false` fleet-wide.
**Rationale:** a remote-managed fleet — nobody should be at a keyboard, so a new
input device or console login is a real signal (fatal #10/#11).
**Risk:** low. Set `true` only on a host where keyboard work is genuinely
routine. **Per-host action item:** if any host has a permanently-attached
IPMI/KVM USB-keyboard dongle, confirm it is present *at baseline capture* so it
does not trip fatal #10 on the first tick (§8), and decide whether *unplugging*
it should alert.
