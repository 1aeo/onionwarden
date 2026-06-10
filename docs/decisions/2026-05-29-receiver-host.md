# Decision record: off-box receiver host (OPERATOR_DECISIONS §3, ⚠ HIGH-RISK)

- **Status:** OPEN — decision needed from the operator.
- **Date:** 2026-05-29
- **Resolves:** `OPERATOR_DECISIONS.md` §3 (`offbox_log_target` placeholder),
  which blocks Phase 0 and the canary rollout (`docs/PHASE4_CANARY_PLAYBOOK.md`).
- **Owner to decide:** the operator.

This record **does not pick the host.** It lays out what onionwarden actually
requires of a receiver, the candidate options, and the trade-offs, so the
operator can choose. Once chosen, set `offbox_log_target` (and the journal
target, L6) per host and run `receiver/RECEIVER.md`.

---

## Why this is HIGH-RISK

The receiver is onionwarden's **trust anchor** (OPERATOR_DECISIONS §3, PLAN §3.5
H5). It holds:

- the off-box, append-only `events.log` per host (the record a compromised host
  cannot rewrite),
- the **known-good self-hash + pubkey-hash** anchor that `verify-check` compares
  every run against — the one check the on-box watchdog *structurally cannot be*
  (a host that swapped its own `onionwarden.pub` would still self-verify; only the
  off-box anchor catches it),
- the cross-host correlation view (M6) and, if L6 is enabled, the off-box journal
  copy.

Until a real receiver exists, the events.log channel is inert and the off-box
anchor does not exist — **the on-box self-check alone is not sufficient (H5).**
So this must be provisioned and hardened *before* Phase 0. And it must **not**
share blast radius with a monitored host: if the receiver sits on (or inside the
same failure domain as) a relay, an attacker who takes the relay also takes the
evidence and the anchor.

---

## Requirements

Hard requirements (a candidate that fails any of these is out):

| # | Requirement | Why |
|---|-------------|-----|
| R1 | **Off-fleet / off-net.** Not a monitored host, not in the same hypervisor, rack, provider account, or trust domain as any relay. | A shared blast radius defeats the entire point — the anchor must survive the compromise of any single relay (OPERATOR_DECISIONS §3). |
| R2 | **Always-on.** Reachable 24/7 for SSH appends + the cron verify/seq/digest/correlate loop. | A trust anchor that is down is not an anchor; staleness is itself an alert. |
| R3 | **Forced-command SSH terminus.** Runs `sshd` accepting per-host restricted keys (`command="receiver-append.sh <host>",restrict`). | This is the ingest mechanism (PLAN §4); the receiver is not a daemon beyond sshd + cron. |
| R4 | **Low blast radius if itself compromised.** Minimal attack surface; ideally only sshd (append) + outbound ntfy. No co-tenant services, no inbound web app. | The receiver holds evidence but the *private signing key is never on it* (§4) — so a receiver compromise must not let an attacker forge baselines, only (at worst) tamper with stored events, which `chattr +a` + seq numbers + the verify_record audit trail resist. |
| R5 | **Independent failure + provider diversity.** Different provider/AS from the relays where feasible. | Survive a provider-wide outage or account takeover that hits the fleet. |

Soft requirements (preferred, not disqualifying):

| # | Requirement | Why |
|---|-------------|-----|
| S1 | **Persistent disk** sized for events.log growth (~1/min selfreport/host) + journal copies (L6) over the retention window (`offbox_log_retention`, default 365d). | Off-box journal shipping (L6) can be sizeable; see capacity note below. |
| S2 | **OOB / console access** (provider rescue, IPMI). | Recover the receiver without trusting its own SSH. |
| S3 | **A second inbound port** for `systemd-journal-remote` (L6, default 19532), firewalled to fleet source IPs. | Off-box journal shipping lands here. |
| S4 | **Operator-controlled, low-cost, boring.** Long-lived, patchable, not tied to a side project that might get torn down. | A trust anchor should outlive everything it watches. |

Explicit **non-requirements:** big CPU/RAM (the workload is tiny — sshd + a few
cron Python scripts), a public hostname, or any inbound service beyond sshd
(+ optional journal-remote).

---

## Candidates

### A. Off-fleet VPS at a *different* provider (e.g. a small cloud instance away from the relays' provider)

- **Pros:** clean provider/AS diversity (R5); cheapest path to always-on (R2);
  trivially off-fleet (R1); easy OOB via provider console (S2); disposable +
  reproducible (S4).
- **Cons:** SaaS/VPS provider is now in the trust path (can snapshot disk, see
  traffic metadata); shared-tenancy host; you must harden it yourself; another
  bill + another thing to patch.
- **Best when:** you want diversity and low cost and accept a cloud provider in
  the trust path (events are not secret — they're integrity records — and the
  signing key is never here, which bounds the damage).

### B. A dedicated existing 1aeo host that is **not** a monitored relay

- **Pros:** already under your control, no new provider, no new bill; you know
  its posture.
- **Cons:** **must verify it is genuinely off-fleet** — not in the same provider
  account, hypervisor, or rack as any relay (R1/R5). If 1aeo hosts cluster at one
  provider, this fails diversity. Re-using a host with other roles violates R4
  (blast radius / attack surface).
- **Best when:** you have a 1aeo host in a *different* failure domain from the
  relays whose only job can become "be the receiver."

### C. Bring up a **new, dedicated** box solely as the receiver (VPS or small bare-metal at a diverse location)

- **Pros:** purpose-built → smallest attack surface (R4); you control the full
  posture; can be the long-lived boring anchor (S4); pick a provider/location for
  max diversity (R5).
- **Cons:** the most upfront work (provision, harden, OOB); a new thing to own
  and patch; cost (small).
- **Best when:** you want the strongest answer and are willing to stand one up —
  this is the textbook trust-anchor posture.

### D. Home / on-prem box (off-net, behind your own connection)

- **Pros:** no third-party provider in the trust path at all; full physical
  control; effectively free.
- **Cons:** residential uptime/IP churn threatens R2; inbound SSH to home is its
  own exposure; no provider OOB (S2); you become the SRE for it.
- **Best when:** you have a genuinely reliable home connection + UPS and prefer
  zero third parties — accept the uptime/availability risk.

---

## Recommendation

**Option C (a new dedicated box) — or Option A if minimizing effort/cost —
provisioned at a provider/AS distinct from the relays, doing nothing but being
the receiver.**

Rationale: the receiver's value is entirely in being a *separate, surviving*
observer. C maximizes that (purpose-built, diverse, minimal surface) for a small
cost; A gets ~80% of the benefit for near-zero effort and is a fine starting
point you can later migrate off (RECEIVER.md has a documented host-migration
procedure). **Avoid B unless you can prove the candidate 1aeo host is in a
different failure domain from every relay** — co-location silently reintroduces
the shared blast radius this whole control exists to avoid. Avoid D unless home
uptime is genuinely carrier-grade.

Whichever is picked:
- the fleet **signing private key stays off the receiver** (§4) — the receiver is
  an *observer*, not an *authority*;
- harden to R4: sshd (forced-command keys only, no password auth) + outbound
  ntfy + optional journal-remote port firewalled to fleet IPs, nothing else;
- enable `chattr +a` on the events.logs (RECEIVER.md) so a receiver-side shell
  still cannot rewrite history;
- record the choice by replacing the §3 placeholder and updating this record's
  status to RESOLVED with the chosen option.

---

## Open questions for the operator

1. **Provider diversity vs. simplicity:** are the relays concentrated at one
   provider/AS? If so, the receiver must be elsewhere (rules B in/out).
2. **Cloud provider in the trust path — acceptable?** Events are integrity
   records, not secrets, and the signing key is never on the receiver — does that
   bound the risk enough to use a VPS (A/C), or do you want on-prem (D)?
3. **Capacity:** will L6 off-box journal shipping be enabled fleet-wide? That
   drives disk sizing (S1) far more than events.log does — estimate per-host
   journal volume × hosts × retention before sizing.
4. **OOB recovery:** which candidates give you a way back in if the receiver's
   sshd is the thing that breaks (S2)?
5. **Ownership longevity:** is there a host/budget line that will outlive the
   fleet it watches (S4)? A trust anchor that gets decommissioned mid-rollout is
   worse than none.

---

## Decision

> _To be completed by the operator._
>
> - **Chosen option:** ____
> - **Host / provider (failure domain):** ____
> - **Date / who:** ____
> - Then: set `offbox_log_target` per host, run `receiver/RECEIVER.md`, flip
>   `OPERATOR_DECISIONS.md` §3 to RESOLVED, and set this record's Status to
>   RESOLVED.
