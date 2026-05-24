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
[`receiver/MIGRATION_TO_PROXMOX.md`](receiver/MIGRATION_TO_PROXMOX.md) is the
runbook for moving the receiver between hosts.

## Phases

| Phase | Goal |
|-------|------|
| 0 | bootstrap — generate signing key, stand up receiver, capture initial baselines |
| 1 | quick-win watchdog: 11 highest-value checks + timers + heartbeat + alerting |
| 2 | SSH hardening + full check coverage + kill-switch infrastructure |
| 3 | snapshot-bundle (offline scan) + fleet diff |
| 4 | dry-run + canary rollout (`relay_a` first, `alert_push_level=warn`) |
| 5 | fleet-wide rollout |

## Quickstart

```sh
# 1. fork this repo, then on a trusted laptop:
git clone git@github.com:<you>/onionwarden.git && cd onionwarden
cp .env.example .env                       # fill in receiver host, ntfy, etc.

# 2. generate the fleet signing keypair (once, store priv offline):
python3 lib/ed25519.py keygen onionwarden.priv onionwarden.pub

# 3. stand up the receiver (on a separate, off-fleet box):
ssh receiver-host
git clone git@github.com:<you>/onionwarden.git
bash onionwarden/scripts/generate-receiver-key.sh
bash onionwarden/receiver/receiver-setup.sh --hosts "relay_a relay_b ..."

# 4. on each monitored host:
git clone git@github.com:<you>/onionwarden.git
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

## Tests

```sh
python3 -m pytest tests/ -q       # 154 tests; collector + receiver + crypto
```

CI runs the same suite on every push to `main` and every PR
(`.github/workflows/test.yml`).

## License

MIT — see [`LICENSE`](LICENSE).
