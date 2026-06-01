# onionwarden

**Tamper-detection watchdog for Ubuntu 24.04 / Debian 13 fleets.**

Runs a set of local integrity checks on every monitored host, ships findings to
an off-box receiver over a forced-command SSH key, and pages an oncall via ntfy
+ a dead-man's-switch when something changes (or stops reporting). Designed for
small, identity-critical fleets — Tor relays, exit nodes, BGP peers, eval
hosts — where silent tampering is worse than an outage.

## Architecture

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

- **collector** — a tiny pure-bash watchdog (`/opt/onionwarden`) driven by
  three systemd timers (`fast`, `slow`, `daily`). Runs ~25 checks: kernel
  taint, loaded modules, listening sockets, sshd config, accounts/sudoers,
  ld.so.preload, scheduled units, SUID/cap deltas, deep network state,
  nested-VM layer, snap revisions, hardware, process ancestry, package
  integrity (debsums/AIDE), promiscuous interfaces, input-device hotplug,
  local-console login, and more.
- **signed baseline** — every host has a per-host baseline (`onionwarden
  baseline collect`) signed off-box with the fleet Ed25519 key; collectors
  verify the signature on every run (`lib/verify.sh`).
- **receiver** — receives events over a forced-command SSH key
  (`receiver/onionwarden-receiver`), appends per-host to an append-only
  `events.log`, runs cron-based `verify-check` / `seqcheck` / `digest`, and
  pushes to ntfy on WARN/CRIT. The receiver itself runs `onionwarden`.
- **kill-switch** — `lib/fatal.sh` evaluates compound conditions and can
  trigger `alert`, `poweroff`, or `freeze` (deterministic ruleset replace).
  Ships disarmed; arm per host with `onionwarden arm-fatal` after rollout.

See [`PLAN.md`](PLAN.md) for the full design, threat model, and phase
breakdown (~104 KB; it's the spec). [`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md)
captures build-time decisions. [`OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md)
records the configurable knobs and their fleet defaults.
[`receiver/RECEIVER.md`](receiver/RECEIVER.md) is the operator runbook for
the off-box receiver, including install, key rotation, and host migration.

## Phases

| Phase | Goal |
|-------|------|
| 0 | bootstrap — generate signing key, stand up receiver, capture initial baselines |
| 1 | quick-win watchdog: 11 highest-value checks + timers + heartbeat + alerting |
| 2 | SSH hardening + full check coverage + kill-switch infrastructure |
| 3 | snapshot-bundle (offline scan) + fleet diff |
| 4 | dry-run + canary rollout (`relay_a` first, `alert_push_level=warn`) — see [`docs/PHASE4_CANARY_PLAYBOOK.md`](docs/PHASE4_CANARY_PLAYBOOK.md) |
| 5 | fleet-wide rollout |

Phase 4 is an operator runbook, not new collector code: [`docs/PHASE4_CANARY_PLAYBOOK.md`](docs/PHASE4_CANARY_PLAYBOOK.md)
covers deploy → 7-day watch window → signoff gate → rollback, and
`onionwarden canary-status` reports the canary's PASS/HOLD verdict against the gate.

## Quickstart

```sh
# 1. fork this repo, then on a trusted laptop:
git clone git@github.com:<you>/onionwarden.git && cd onionwarden
cp .env.example .env                       # fill in receiver host, ntfy, etc.

# 2. generate the fleet signing keypair (once, store priv offline):
python3 lib/ed25519.py keygen onionwarden.priv onionwarden.pub

# 3. stand up the receiver (on a separate, off-fleet box).
#    Full operator runbook in receiver/RECEIVER.md.
ssh receiver-host
sudo useradd -r -m -d /var/lib/onionwarden -s /bin/bash onionwarden
sudo git clone https://github.com/<you>/onionwarden.git /opt/onionwarden
sudo /opt/onionwarden/scripts/generate-receiver-key.sh
sudo -u onionwarden ONIONWARDEN_RECEIVER_ROOT=/var/lib/onionwarden/data \
    /opt/onionwarden/receiver/receiver-setup.sh \
    --hosts "relay_a relay_b ..."
# add the cron entries from receiver/RECEIVER.md and per-host
# authorized_keys lines (each pinned to its host_id; see R1 in
# CRITIQUE_RECEIVER_R1.md for the stolen-key threat that pin defends).

# 4. on each monitored host:
git clone https://github.com/<you>/onionwarden.git
cp onionwarden.pub onionwarden/
# edit a per-host answers file (see examples/answers-canary.example)
sudo bash onionwarden/install.sh \
  --answers examples/answers-canary.example \
  --pubkey  onionwarden.pub

# 5. capture + sign the per-host baseline (off-box):
onionwarden baseline collect
# scp the bundle to the laptop, sign with onionwarden-sign, scp back
```

Per-host config lives in `host.conf` (generated from the answers file by
`install.sh`); fleet-wide overrides go in `.env`. Neither is committed.

## Stage output

Long-running commands (`onionwarden-run`, `onionwarden-baseline collect`) emit a
hierarchical, greppable progress stream on **stderr** — the fleet-wide
convention shared with `onionleak` and `onionarmor` ([`lib/stage_tracker.sh`](lib/stage_tracker.sh)):

```text
[onionwarden] <tool> [<grandparent>] <parent>, n/N. <stage> : <status>
```

* Every line starts with `[onionwarden] ` (grep the whole run with
  `grep '^\[onionwarden\] '`).
* `n/N name` is the stage marker (1-based index out of the total at that level).
* A stage's **immediate parent** is comma-joined; any **grandparent** is bracketed.
* `: <status>` is `ok (0.2s)`, `skipped: <reason>`, or `failed: <reason>`.

```text
[onionwarden] 1/1 run checks (fast), 1/24 check accounts : ok (0.0s)
[onionwarden] 1/1 run checks (fast), 9/24 check kernel_state : skipped: cadence slow != fast
[onionwarden] 1/1 collect baseline, 22/24 collect suid : ok (0.3s)
```

Nesting propagates across processes via the `ONIONWARDEN_STAGE_PARENT` env var,
so a child process's stages render underneath the parent's hierarchy. Set
`ONIONWARDEN_STAGES=0` to suppress the stream.

## Tests

```sh
python3 -m pytest tests/ -q       # 154 tests; collector + receiver + crypto
bats tests/bats/                  # shell regression tests (incl. stage output)
```

CI runs the same suite on every push to `main` and every PR
(`.github/workflows/test.yml`).

## License

MIT — see [`LICENSE`](LICENSE).
