# ONBOARDING.md — formal onboarding for one onionwarden host

This runbook is the *operator's* end-to-end checklist for bringing a single
host into the watchdog fleet. The script `bin/onionwarden-onboard` automates
the typo-prone parts; this document is the contract — what the script does
and does not do, in what order, and what you do in between.

It is deliberately **per-host**. Adding nine hosts is nine runs of this
runbook, by design (PLAN §3.5: the on-box agent is not a trust anchor; a
human reviewer is).

---

## Audience & scope

Operators who already understand `onionwarden`'s architecture. If you have
never read it, start with [`README.md`](../README.md) and at minimum the
PLAN sections referenced below — this document does not re-derive them.

**This runbook covers Phase 0 and Phase 1 for one host:** standing up the
watchdog code, signing the first per-host artifacts, and proving the
off-box receiver round-trip works. **It does not cover** Phase 2 (SSH
hardening + full coverage) or arming `fatal_action` — those each get their
own runbook (PLAN §6, §3.7).

---

## Prerequisites

### On the operator's laptop
- A checkout of this repo (`git clone https://github.com/1aeo/onionwarden`).
- `python3` (only used by the bundled Ed25519 fallback when OpenSSL Ed25519
  is unavailable; see `lib/ed25519.py`).
- `openssh-client`, `rsync`, `scp`.
- The fleet pubkey at `./onionwarden.pub` (generate with
  `bin/onionwarden sign keygen --priv operator.priv --pub onionwarden.pub`,
  then keep `operator.priv` **off this laptop's network-attached storage** —
  the README+PLAN are clear on this).
- An operator signing key (`operator.priv`). The script never asks for the
  private key. Signing happens off-box, by you, between phases.

### On the receiver
- Receiver is healthy: `cron`, `onionwarden-receiver` running, per-host
  `events.log` paths in place. See [`receiver/RECEIVER.md`](../receiver/RECEIVER.md).
- Authorized-keys file ready to accept a new restricted line for the
  incoming host (see "Step 4 — wire the receiver" below).
- Receiver is reachable from the target host (this runbook does **not**
  open new firewall rules).

### On the target host
- Ubuntu 24.04 or Debian 13 (tier-1 + tier-2 per PLAN §0.5). Other OSes
  will work in degraded mode but are not supported by this runbook.
- Reachable over SSH, key-only, with a sudo-capable login.
- A roughly-clean state: this is the moment you are establishing the
  baseline against. Anything dirty here becomes "expected" forever unless
  you re-baseline. See PLAN §5 "Bootstrap — capturing a *trustworthy*
  initial baseline" — strongest is a fresh install with no network
  exposure yet; weakest is single-user/recovery boot accepting TOFU.

### Local artifacts the runbook expects per host
By convention this runbook keeps per-host artifacts under `./hosts/`:

```
hosts/<HOST>.conf            # signed source of truth (PLAN §3.4 schema)
hosts/<HOST>.conf.sig        # Ed25519 signature, operator key
hosts/<HOST>.baseline/       # Phase-0 baseline candidate + manifest + .sig
hosts/<HOST>.snapshot/       # output of `onionwarden snapshot` (review material)
```

`hosts/` is gitignored — these contain endpoint URLs and the operator's
hand-curated allowlists, not fleet-wide values.

---

## When to use the script vs. do it by hand

Use the script for the **repeatable** parts:
- pre-flight pings + tool checks
- staging the code tree (rsync)
- running `install.sh` on the target
- pasting back the receiver authorized_keys line
- forcing a first heartbeat
- round-tripping the dead-man's switch
- printing the first-arm checklist + the operator-decisions punch list

Do these **by hand**, with your eyes on every line (the script will not):
- Edit and review `hosts/<HOST>.conf` (PLAN §3.4 — "the only human-edited
  per-host file"; M9: a typo'd `deadman_url` must be catchable on review).
- Sign `hosts/<HOST>.conf` off-box (`bin/onionwarden sign sign`).
- Sign the baseline `manifest.json` off-box, after `onionwarden baseline
  diff` shows you what you are signing. PLAN §5 C1: a candidate with
  trust-expanding deltas is not signable without an out-of-band scan
  (`--offline-scan-attested`).
- Add the per-host authorized_keys line into the receiver (the script
  prints it; you paste it — pinning is the whole point per CRITIQUE_RECEIVER_R1).

Never let the script generate, store, or transport the operator private key.
Never let the script auto-arm `fatal_action` (PLAN §3.7 ships disarmed by
default and the script honors that).

---

## Step-by-step — the formal onboarding sequence

### Step 1 — pre-flight (`--check`)

```sh
./bin/onionwarden-onboard --check <HOST>
```

What it does:
- non-interactive SSH (BatchMode) to the target
- confirms OS is Ubuntu 24.04 or Debian 13 (warns on other Ubuntu/Debian)
- confirms `sudo -n true` works
- confirms `cron`, `python3`, `tcpdump`, `bpftool` are present (warns per
  missing tool — checks degrade to `N/A` via `detect-and-skip`, PLAN §0.2)
- confirms `hosts/<HOST>.conf` exists locally and is signed (verifies
  against `./onionwarden.pub`)
- if `--receiver` given, confirms the receiver name resolves from target

Stop and fix any `[FAIL]` line before continuing. A `[warn]` is acceptable
as long as you understand the tradeoff (e.g. a relay with no `bpftool`
just means the eBPF check is `N/A`, not broken).

### Step 2 — draft the host.conf (`--draft-host-conf`)

If you are onboarding a host that already has a real workload, you want
the actual listening ports / module set / sudoers contents to inform the
allowlists. The script's `--draft-host-conf` runs `onionwarden snapshot`
(read-only) and writes a pre-filled `hosts/<HOST>.conf.draft`:

```sh
./bin/onionwarden-onboard --draft-host-conf --with-sudo <HOST>
```

You then:
1. Open `hosts/<HOST>.conf.draft` in `$EDITOR`.
2. Fill every `CHANGE-ME` (`ntfy_url`, `deadman_url`, `offbox_log_target`,
   `email_to`, optionally `ntfy_token`).
3. Compare against `hosts/<HOST>.snapshot/` — confirm `expected_lan_ports`,
   the UID-0 set in `accounts.current`, the admin group set, etc. reflect
   what you actually intend (PLAN §3.4: allowlists encode human intent,
   the baseline encodes actual state).
4. Sign it off-box:
   ```sh
   ./bin/onionwarden sign sign \
     --key /path/to/operator.priv \
     --file hosts/<HOST>.conf.draft \
     --out  hosts/<HOST>.conf.sig
   mv hosts/<HOST>.conf.draft hosts/<HOST>.conf
   ```

If you skipped this step because the host is a fresh install with no
workload of its own, write `hosts/<HOST>.conf` by hand from
[`.env.example`](../.env.example) + [`examples/answers-canary.example`](../examples/answers-canary.example).

### Step 3 — install (`--install`)

```sh
./bin/onionwarden-onboard \
  --install \
  --receiver onionwarden@receiver.example.net:22922 \
  <HOST>
```

The script:
1. Re-runs the full pre-flight (same as `--check`).
2. `rsync`s the repo tree to `/tmp/onionwarden-src/` on the target
   (excluding `.git` and `hosts/`).
3. `scp`s `hosts/<HOST>.conf`, `.sig`, and `onionwarden.pub` to `/tmp/`.
4. Runs `install.sh --answers /tmp/onionwarden-host.conf --pubkey
   /tmp/onionwarden.pub` via `sudo`. This is the **only path** through
   Phase 0–4 (PLAN §6, Q6) — embedding the pubkey-hash pin (C2),
   applying `chattr +i` per `immutable_scripts` (PLAN §3.6, default ON),
   and leaving the host in the `bootstrapping` state (M2).
5. Installs the signed `host.conf.sig` next to the conf.
6. Adds the per-minute cron entry (`* * * * * /opt/onionwarden/bin/onionwarden run fast`).
7. **Prints** the target's per-host SSH pubkey line for you to paste into
   the receiver's authorized_keys (see Step 4). The script does not push
   it for you — receiver `authorized_keys` is a privileged edit and you
   own it.
8. Fires the first run synchronously and exits.

Exit code 0 means the install ran. It does **not** mean the host is
"protected" yet — the first off-box-signed baseline is still pending
(Step 5).

### Step 4 — wire the receiver (manual)

The receiver enforces the per-host pin (CRITIQUE_RECEIVER_R1 — a stolen
key from host A cannot append to host B's `events.log`). The line the
script prints looks like:

```
restrict,command="/opt/onionwarden/receiver/receiver-append.sh <HOST>" ssh-ed25519 AAAA... onionwarden@<HOST>
```

Add it to `/var/lib/onionwarden/.ssh/authorized_keys` on the receiver and
confirm the next heartbeat from `<HOST>` lands in
`/var/lib/onionwarden/data/<HOST>/events.log`.

### Step 5 — first baseline (manual; PLAN §5)

The host is currently in the `bootstrapping` state — signature-CRIT is
suppressed until a real signed baseline is in place. Capture, review,
sign, push:

```sh
# on the target:
ssh <HOST> 'sudo /opt/onionwarden/bin/onionwarden baseline collect'

# pull to laptop:
scp -r <HOST>:/var/lib/onionwarden/baseline.candidate/ hosts/<HOST>.baseline/

# review (PLAN §5 C1 — trust-expanding deltas need an out-of-band scan):
./bin/onionwarden baseline diff \
  --baseline <prev-or-empty> \
  --candidate hosts/<HOST>.baseline

# sign off-box:
./bin/onionwarden sign sign \
  --key /path/to/operator.priv \
  --file hosts/<HOST>.baseline/manifest.json \
  --out  hosts/<HOST>.baseline/manifest.json.sig

# push back:
scp hosts/<HOST>.baseline/manifest.json{,.sig} <HOST>:/tmp/
ssh <HOST> 'sudo install -m0644 /tmp/manifest.json /tmp/manifest.json.sig /var/lib/onionwarden/baseline/'
ssh <HOST> 'sudo rm /var/lib/onionwarden/state/bootstrapping'
```

The next `onionwarden run` will exit `bootstrapping` (M2). From this
moment the 7-quiet-day countdown for first-arm starts (PLAN §3.7).

### Step 6 — verify (`--verify`)

```sh
./bin/onionwarden-onboard \
  --verify \
  --receiver onionwarden@receiver.example.net:22922 \
  <HOST>
```

What it does:
- Confirms the timer/cron entry exists on target.
- Forces a `run fast` and tails `events.log` on the receiver (expects the
  new event near the top).
- Walks the dead-man's switch round-trip: pauses the heartbeat, waits
  `--stale-window` seconds (default 240 = 3 missed 1-min beats + slack),
  expects the receiver's `verify-check` to fire `stale-host`, then
  re-arms. Per PLAN §3.7 item 5 / PLAN §4: this is the only way to prove
  `deadman_provider` is actually wired — a typo'd `deadman_url` will not
  fire and *must* be caught here, not during a real outage.
- Prints the first-arm checklist (PLAN §3.7) as a punch-list. Nothing
  is auto-checked off — checklist items 4, 6, 7 are attested manually,
  and items 1, 2, 3, 5 are computed by `onionwarden arm-fatal` against
  the off-box `events.log` when you eventually run it.
- Counts `CHANGE-ME` placeholders in `hosts/<HOST>.conf` and flags any
  still present (silent-no-op alerting is the dominant onboarding bug).

---

## First-arm checklist — when does this host become "armable"?

Copied here for visibility. `onionwarden arm-fatal` will refuse until
every item passes; this runbook puts you at item 0.

1. **Quiet baseline** — ≥ 7 consecutive days since the most recent
   baseline re-sign on this host, with zero CRIT and zero un-dispositioned
   WARN findings. *Auto-verified from the off-box `events.log` — never
   from on-box logs (M3).*
2. **apt-correlation proven** — at least one real apt /
   unattended-upgrade cycle on this host was correctly demoted WARN→INFO
   by per-file correlation (§5). *Auto.*
3. **Fatal dry-run clean** — `onionwarden fatal-dry-run` shows zero
   would-trigger hits against current (known-good) state. *Auto.*
4. **Off-box-first proven** — `onionwarden fatal-test` sends a synthetic
   `fatal_action` event through the full pre-action protocol; the
   receiver `events.log` recorded it and an ack returned within
   `fatal_ack_timeout_s`. *Operator-attested.*
5. **Dead-man's switch proven** — heartbeats were deliberately paused
   and the configured `deadman_provider` actually alerted. *Auto, from
   the test record `--verify` produces.*
6. **OOB recovery verified for THIS host** — operator has tested and
   documented the out-of-band path to power-cycle / console this specific
   host. **Mandatory for `poweroff`/`custom`; not required for `freeze`.**
   *Attested.*
7. **Host is past Phase 2** — SSH hardening applied and the host
   re-baselined to its hardened state, so the baseline is not
   mid-transition. *Attested.*

---

## Per-host `host.conf` template (the shape)

Lives at `hosts/<HOST>.conf` on the operator's laptop, becomes
`/etc/onionwarden/host.conf` on the target. Full schema at PLAN §3.4;
a working example at [`examples/answers-canary.example`](../examples/answers-canary.example).
Minimum operator-required fields (the script's `--verify` flags any
`CHANGE-ME` it finds):

```ini
host_id            = "<short-id>"            # MUST match the HOST positional
role               = "tor-relay"             # or "eval-host" / "generic"
canary             = false                    # true only on the canary

ntfy_url           = "https://ntfy.sh/<unguessable-topic>"
ntfy_token         = ""
deadman_provider   = "healthchecks-saas"     # see PLAN §4 — alerts-on-absence is mandatory
deadman_url        = "https://hc-ping.com/<per-host-UUID>"
offbox_log_target  = "onionwarden@receiver.example.net:~/onionwarden/<host>/events.log"
offbox_ssh_key     = "/etc/onionwarden/keys/offbox_ed25519"
email_to           = "alerts@example.net"
alert_push_level   = "warn"                  # canary; "crit" for steady-state

expected_lan_ports = [22, 9001, 9030]        # SSH + service ports
expected_uid0      = ["root"]
expected_admins    = ["operator"]
physical_access_allowed = false              # fleet default

fatal_action       = "alert"                  # PLAN §3.7 — see relay/eval/generic role caveats
fatal_action_armed = false                    # MUST stay false; arm with onionwarden arm-fatal later
```

---

## Post-install verification checklist

After `--install` and the first signed baseline (Step 5), confirm each:

- [ ] `--verify` exits 0 with no `[FAIL]` lines.
- [ ] `tail -n5` on the receiver's `data/<HOST>/events.log` shows the
      first heartbeat with the new host's `host_id`.
- [ ] Cron timer fires every minute on target (`sudo journalctl -u cron
      --since '-5min'` shows the wakeups).
- [ ] Receiver's `verify-check` shows `OK` for `<HOST>` (see
      `receiver/RECEIVER.md`).
- [ ] Dead-man's switch round-trip succeeded — `events.log` recorded a
      `stale-host` CRIT during the pause window.
- [ ] No CRIT findings on the first real run after Step 5.
- [ ] `host.conf` has zero `CHANGE-ME` placeholders.
- [ ] `fatal_action_armed = false` — confirmed.
- [ ] First-arm checklist printed; you know which items are pending.

---

## Troubleshooting

### `--check` reports "cannot SSH non-interactively"
The script uses `-o BatchMode=yes`. Either your key isn't loaded into the
agent, or the target prompts for a passphrase. Fix at the OS level
(`ssh-add`, `~/.ssh/config`); the script never falls back to interactive
prompts (we will not let an operator's typo'd password land in `events.log`).

### `--check` reports signature INVALID
- Confirm `./onionwarden.pub` is the pubkey for the **operator key** you
  used to sign `hosts/<HOST>.conf` (it is easy to mix the fleet pubkey
  with an operator's personal pubkey).
- Re-run: `./bin/onionwarden sign verify --pub ./onionwarden.pub --file
  hosts/<HOST>.conf --sig hosts/<HOST>.conf.sig` — same error?
- Re-sign: `./bin/onionwarden sign sign --key operator.priv --file
  hosts/<HOST>.conf --out hosts/<HOST>.conf.sig`.

### First heartbeat does not appear in the receiver's `events.log`
1. On target: `sudo /opt/onionwarden/bin/onionwarden run fast` exits 0?
2. On target: `sudo cat /etc/onionwarden/host.conf | grep offbox_log_target`
   — is the receiver hostname correct?
3. From target: `ssh -i /etc/onionwarden/keys/offbox_ed25519 -p <PORT>
   onionwarden@<receiver> < /tmp/test.json` — does it return cleanly? If
   `Permission denied`, the receiver's `authorized_keys` line is missing
   or not pinned to this host's pubkey (Step 4).
4. On receiver: `sudo journalctl -u ssh --since '-5min'` for forced-command
   errors.

### Dead-man's switch round-trip never fires `stale-host`
- Confirm the receiver's `verify-check` cron entry is installed (it is
  the thing that promotes silence to CRIT — see `receiver/RECEIVER.md`).
- Confirm `deadman_provider` in `hosts/<HOST>.conf` is one of the
  supported alert-on-absence providers (PLAN §4 — plain ntfy does **not**
  qualify; it accepts pings forever and never notices silence).
- Increase `--stale-window` (default 240 s). If your receiver's
  `verify-check` cron is `*/10` you need at least 660 s.

### `--rollback` leaves files behind
- Files might be `chattr +i` even after the recursive `chattr -i` if
  `CAP_LINUX_IMMUTABLE` is gated on the target. Re-run the rollback as a
  sudo-capable user with full capabilities, then `lsattr` to confirm.
- `/var/lib/onionwarden` and `/var/log/onionwarden` are intentionally
  retained — they contain the host's recent events and you almost
  certainly want them for the post-mortem before deleting.

### `install.sh` reports "FS … — falling back to detection-only"
Your install prefix is on a filesystem that does not support `chattr +i`
(tmpfs, ZFS, overlayfs, NFS). The watchdog runs fine; it just loses the
script-immutability layer (PLAN §3.6). For Phase 1 canaries this is
acceptable; for steady-state hosts move `/opt/onionwarden` to ext4/xfs/btrfs.

---

## What's risky here, on purpose

- **`chattr +i` defaults ON** (PLAN §3.6) — if you have never operated an
  immutable-attribute fleet before, the first thing that will surprise
  you is that `rsync --times`, `tar -x` over an existing file, or even
  `touch` will fail `EPERM` on protected paths. Always go through
  `onionwarden-upgrade`; use `--no-chattr` only in test setups.
- **The first baseline is the trust anchor** (PLAN §5). The script will
  cheerfully install onto a compromised host; nothing in the watchdog
  catches that for you. Use the strongest available trust-establishment
  step before signing (fresh install > offline scan of mounted disk >
  single-user-mode TOFU).
- **`fatal_action_armed=false` is non-negotiable through Phase 1** — the
  script does not let you flip it, and you should not either until the
  full first-arm checklist passes. PLAN §3.7 spells out the recovery
  cost of getting this wrong (a `poweroff` host returns only via OOB; a
  flap-protected reboot loop is permanent until the cooldown clears).
- **The receiver authorized_keys edit is yours.** The script prints the
  line; you paste it. A wrong paste here (forgetting `restrict` /
  forgetting the per-host `command="…"`) silently widens the receiver's
  attack surface to "any host with this key can write any host's log."
  The pin is the security control (CRITIQUE_RECEIVER_R1).
