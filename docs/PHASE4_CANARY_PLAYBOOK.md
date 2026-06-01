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

The canary must run **≥ 7 days with zero *unexplained* WARN/CRIT alerts.**

- *Unexplained* ≠ *zero alerts.* On `alert_push_level=warn` you **expect** some
  WARN noise (clock-not-yet-synced on first boot, snap-revision churn during an
  apt week). Each WARN you investigate and judge benign becomes an
  **acknowledgement**, not a failure. CRIT findings cannot be acknowledged away;
  they always block the gate.
- Record acknowledgements in an ack-file (one pattern per line), which doubles as
  the seed for the host's `host.conf` allowlist / `disable_checks` tuning:

  ```sh
  # acks/relay-a.acks
  clock/unsynced          # NTP settles a few min after boot — benign
  snap                    # snap auto-refresh revision churn (apt week)
  ```

- Any **CRIT**, or any WARN you cannot explain, **resets the clock** — fix the
  root cause (real issue) or add the allowlist entry (false positive), then the
  7-day window restarts from the change.

### Checking the gate

`onionwarden-canary-status` turns the window into one PASS/HOLD verdict. Run it
on the receiver (authoritative copy) or against the canary's `events.log`:

```sh
# on the receiver:
onionwarden canary-status --host relay-a \
    --require-days 7 --ack-file acks/relay-a.acks
# or against a copied events.log:
onionwarden canary-status --events relay-a/events.log --ack-file acks/relay-a.acks
```

```
=== onionwarden canary status: relay-a ===
verdict:        PASS
observed:       8.0 / 7 clean days required
findings:       0 CRIT  3 WARN  412 INFO  (window)
unexplained:    0  (acked patterns loaded: 2)
last event:     1 min ago
GATE: PASS — canary is clean. Proceed to operator signoff...
```

PASS requires **all** of: `observed_days ≥ --require-days`, **zero** unexplained
WARN/CRIT, and the canary **not stale** (still reporting). Exit 0 = PASS, 1 =
HOLD. It's cron-friendly — wire it to a daily check during the window.

---

## Signoff gate (before expanding to host #2)

Do not touch a second host until **every** box is checked:

- [ ] `onionwarden canary-status` reports **PASS** (≥7 clean days, 0 unexplained,
      not stale).
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
