# Phase 4 — Canary rollout playbook

The operator runbook for deploying onionwarden to its **first real host** — the
canary — and the gate that must pass before it expands to the rest of the fleet.

> **Phase numbering.** This playbook is "Phase 4" per the README phase table
> (dry-run + canary rollout). Note PLAN.md §6 labels its *Phase 4* "active
> hardening"; the canary-rollout *step* itself is specified in PLAN §7 / §3.4 /
> §8 Q1+Q11. Same activity, two numbering schemes — this doc is the canary
> rollout, whatever you call it. It runs **after** the receiver exists
> (`receiver/RECEIVER.md`) and a fleet signing key is provisioned
> (`OPERATOR_DECISIONS.md` §3, §4).

## Why a canary

A watchdog's first failure mode is **its own false positives**. Run it report-only
on one low-stakes host first, learn that host's noise floor, and you find the
misfires before they page you nine times over. The default canary is `relay-a`
(PLAN §8 Q1): a stock-6.8 relay, the most-replicated config, **not** a
directory-authority peer — a misfire there is cheap. `examples/answers-canary.example`
is written for it.

The canary runs with two deliberate settings:

| setting | value | why |
|---------|-------|-----|
| `alert_push_level` | `warn` | push *everything* (WARN + CRIT) so the noise floor is visible, not buried in the daily digest |
| `fatal_action_armed` | `false` | the kill-switch stays disarmed while learning — a canary never auto-acts |
| `workload_integrity_check` | `none` | canary override; surface the base signal first |

`relay-a` (the PLAN doc name) is a placeholder — substitute your real canary
host_id (e.g. `relay-host-1`) everywhere below.

---

## Pre-flight

- [ ] Receiver is up, hardened, and its cron (`verify-check` / `seqcheck` /
      `digest`) is running — see `receiver/RECEIVER.md`.
- [ ] Fleet signing keypair exists; `onionwarden.pub` is on the canary, private
      key is **offline** (`OPERATOR_DECISIONS.md` §4).
- [ ] The canary's `offbox_log_target` points at a **real** receiver host — the
      `⚠ HIGH-RISK` §3 placeholder must be resolved first
      (`docs/decisions/2026-05-29-receiver-host.md`).
- [ ] You can SSH to the canary non-interactively and have root there.
- [ ] The canary's row is in the receiver's per-host tree + `authorized_keys`
      (pinned forced command — RECEIVER.md §"Per-host authorized_keys entries").

---

## Step 1 — dry-run (no install, no writes)

Capture the canary's live state read-only and eyeball it before anything is
installed, so the first baseline isn't built blind:

```sh
# from your admin box / the receiver:
onionwarden snapshot relay-a               # read-only remote capture, writes nothing on relay-a
#  -> snapshots/relay-a-<UTC>/ ; review the per-check .current files
```

This is the Mode-A dry-run (IMPLEMENTATION_NOTES "Offline snapshot mode"). Look
for anything you'd want in the allowlist *before* it becomes a "new finding"
flood (unexpected listeners, extra modules, admin accounts).

## Step 2 — install (report-only)

```sh
# on the canary, from the cloned repo:
cp onionwarden.pub onionwarden/
sudo bash onionwarden/install.sh \
    --answers examples/answers-canary.example \   # edit host_id + endpoints first!
    --pubkey  onionwarden.pub
```

`install.sh` lays the tree, generates `/etc/onionwarden/host.conf`, stages the
timers, and leaves the host in the **bootstrapping** state (signature-CRIT
suppressed until the first signed baseline verifies). Confirm:

```sh
systemctl list-timers 'onionwarden-*'      # fast/slow/daily present
sudo onionwarden run fast                  # one manual tick, exits clean
```

## Step 3 — baseline + sign (off-box)

```sh
sudo onionwarden baseline collect          # writes an UNSIGNED candidate
# pull the candidate to the trusted signing host, then:
onionwarden baseline diff --baseline <current> --candidate <candidate>   # C1 gate
onionwarden sign sign --key <priv> --file <candidate>/manifest.json
# push manifest.json + .sig + state/ back to the canary
```

The next dispatch verifies the signature and leaves bootstrapping → `trusted`.

## Step 4 — mandatory dead-man self-test (M9)

**Do not skip.** A typo'd `deadman_url` must be caught here, not during a real
outage (PLAN §7 Phase-1 acceptance):

```sh
sudo onionwarden fatal-test                # exercises the off-box path
# then pause heartbeats and confirm the configured provider actually alerts:
sudo systemctl stop onionwarden-fast.timer
#  ... wait past the provider's grace period; confirm you get the dead-man page ...
sudo systemctl start onionwarden-fast.timer
```

## Step 5 — (optional) off-box journal shipping

If shipping the canary's journal off-box (L6), configure it now so the canary
window also validates that pipeline — see `journal/README.md`.

---

## Success criteria (the watch window)

The canary must run **≥ 7 days with zero *unexplained* WARN alerts and zero
CRIT alerts** to PASS. The verdict has **three states** (Option D):

| verdict | meaning | exit |
|---------|---------|------|
| **PASS** | ≥ require-days observed, zero unexplained WARN, not stale, **zero CRIT** | 0 |
| **HOLD** | any gate unmet, **or a CRIT that is not validly acknowledged** | 1 |
| **WARN** | would PASS but for a CRIT the operator **acked with a reason** — "rolling forward with eyes open", **never** PASS | 3 |

- *Unexplained* ≠ *zero alerts.* On `alert_push_level=warn` you **expect** some
  WARN noise (clock-not-yet-synced on first boot, snap-revision churn during an
  apt week). Each one you investigate and judge benign becomes an
  **acknowledgement**, not a failure.
- Record **WARN** acknowledgements in an ack-file (one pattern per line), which
  doubles as the seed for the host's `host.conf` allowlist / `disable_checks`
  tuning:

  ```sh
  # acks/relay-a.acks
  clock/unsynced          # NTP settles a few min after boot — benign
  snap                    # snap auto-refresh revision churn (apt week)
  ```

- An unexplained **WARN resets the clock** — fix the root cause (real issue) or
  add the allowlist entry (false positive), then the window restarts.
- A **CRIT** is different. A pattern in the WARN ack-file does **not** clear a
  CRIT. A CRIT can only be acknowledged through the audited ack store (next
  section), and even a valid ack **never promotes the verdict to PASS** — it
  downgrades HOLD → **WARN**. The intent: a CRIT on the canary is always
  surfaced in the verdict, even when the operator has consciously decided to
  roll forward anyway.

### Acknowledging a CRIT (Option D)

A CRIT ack is a deliberate, audited, expiring decision — not a silent suppress.
Use the `ack` subcommand; `--reason` is **mandatory**:

```sh
# the status output prints each blocking CRIT's finding-id (the alert hash):
#   CRIT seq=2 modules/new-module  module nfsd   [ack: a8dabdc6ebe8cebf --reason ...]
onionwarden canary ack \
    --finding-id a8dabdc6ebe8cebf \
    --reason "nfsd is expected on this NFS-backed canary; reviewed w/ infra" \
    --signer  <operator-username> \
    --ttl-hours 72            # default 72h; the ack expires and HOLD returns
```

Each ack appends one audit record to **`/var/lib/onionwarden/canary/acks.jsonl`**
(override with `--ack-store` / `$ONIONWARDEN_CANARY_ACK_STORE`):

```json
{"finding_id":"a8dabdc6ebe8cebf","alert_hash":"a8dabdc6ebe8cebf",
 "ts":"2026-05-28T11:00:00Z","signer":"<operator-username>",
 "reason":"nfsd is expected ...","ttl_hours":72}
```

Ack lifecycle / policy:

- **Reason required.** No `--reason` → the ack is rejected at parse time
  (exit 2), nothing is written.
- **Expires.** After `ttl_hours` (default 72), the ack is stale and the CRIT
  blocks again (HOLD) until re-acked — a forcing function to actually fix it.
- **No self-acks.** An ack whose `signer` equals the identity that *triggered*
  the alert (the finding's `host_id`) is recorded for the audit trail but is
  **never gate-valid** — the alerting host can't clear its own CRIT.
- The signer comes from `--signer`, else `$ONIONWARDEN_CANARY_SIGNER`, else the
  local user. Records are append-only; the store is the audit log.

### Checking the gate

`onionwarden-canary-status` turns the window into one verdict. Run it on the
receiver (authoritative copy) or against the canary's `events.log`:

```sh
# on the receiver:
onionwarden canary status --host relay-a \
    --require-days 7 --ack-file acks/relay-a.acks
# or against a copied events.log:
onionwarden canary status --events relay-a/events.log --ack-file acks/relay-a.acks
```

```text
=== onionwarden canary status: relay-a ===
verdict:        WARN
observed:       8.0 / 7 clean days required
findings:       1 CRIT  3 WARN  412 INFO  (window)
unexplained:    0  (acked WARN patterns: 2)
acked CRITs:    1  (eyes-open — see below)
last event:     1 min ago
--- acknowledged CRITs (eyes open, expire) ---
  CRIT seq=2 modules/new-module  by <operator-username>: nfsd is expected ...
GATE: WARN — 1 acknowledged CRIT(s) — rolling forward with eyes open (WARN, not PASS)
```

PASS requires **all** of: `observed_days ≥ --require-days`, **zero** unexplained
WARN, the canary **not stale**, and **zero CRIT**. A validly-acked CRIT yields
WARN instead. Exit codes: `0 = PASS`, `3 = WARN`, `1 = HOLD`, `2 = usage`. It's
cron-friendly — wire it to a daily check during the window.

### Fleet auto-rollout gate

When the canary verdict feeds an automated fleet rollout, the operator chooses
**per fleet wave** what counts as "go":

| `--rollout-gate` | rolls forward on | use when |
|------------------|------------------|----------|
| `pass-only` (default) | PASS only | conservative; the first/sensitive waves |
| `pass-warn` | PASS **or** WARN | later waves where an acked-CRIT "eyes-open" roll-forward is an accepted, audited risk |

The flag only sets `gate_pass` (and the printed guidance) — it does **not**
change the verdict or exit code, so the audit trail of *why* a wave proceeded is
explicit. Default is conservative: an acked CRIT (WARN) **holds** unless the
wave was explicitly configured `pass-warn`.

---

## Signoff gate (before expanding to host #2)

Do not touch a second host until **every** box is checked:

- [ ] `onionwarden canary-status` reports **PASS** (≥7 clean days, 0 unexplained,
      not stale, 0 CRIT). A **WARN** (acked-CRIT, eyes-open) is *not* a clean
      signoff: only an automated `pass-warn` wave may proceed on WARN, and only
      with the ack reason captured in this log.
- [ ] The receiver's `verify-check` shows the canary's self-hash + pubkey-hash
      matching known-good (run `verify-record` once, early, then it self-checks).
- [ ] `seqcheck` shows no events.log sequence gaps for the canary.
- [ ] The dead-man self-test (Step 4) demonstrably paged.
- [ ] Every acknowledgement in the ack-file has either a root-cause fix or a
      reviewed allowlist entry now baked into `host.conf` — the next host should
      **not** inherit unexplained noise.
- [ ] Operator **sign-off recorded** (date + name) in the rollout log.

Only then proceed to Phase 5 (fleet-wide rollout), repeating Steps 1–4 per host.
Tighten `alert_push_level` from `warn` → `crit` on the canary once its noise
floor is understood (WARN then rides the daily digest instead of paging).

---

## Rollback

The canary is monitoring-only (disarmed), so rollback is low-risk. To back out:

```sh
# 1. stop + disable the timers (no more checks/alerts):
sudo systemctl disable --now onionwarden-fast.timer onionwarden-slow.timer \
    onionwarden-daily.timer

# 2. if onionwarden-onboard was used, it has a one-shot:
sudo onionwarden/bin/onionwarden-onboard --rollback        # disables timers + removes /opt/onionwarden
#    (dry-run it first: add --dry-run)

# 3. otherwise remove the tree by hand (lift immutability first if set):
sudo chattr -i -R /opt/onionwarden 2>/dev/null || true
sudo rm -rf /opt/onionwarden /etc/onionwarden /var/lib/onionwarden /var/log/onionwarden

# 4. on the RECEIVER, stop trusting the canary's stream:
#    - remove its authorized_keys line
#    - (optional) archive its <host>/ events tree
```

Because the kill-switch ships disarmed (`fatal_action_armed=false`), there is no
armed action to unwind — removing the timers is sufficient to make onionwarden
inert on the canary. If you armed anything during the canary (you shouldn't have),
`sudo onionwarden disarm-fatal` first.

A **partial** rollback — just silencing a noisy check while keeping the watchdog —
is usually better than a full back-out: add the check to `disable_checks` in
`host.conf` (it then shows as *disabled*, never as *clean* — M1) or add the
specific item to the relevant allowlist, re-sign `host.conf` off-box, and let the
window continue.
