# onionwarden

**A tamper-detection watchdog for small Ubuntu 24.04 / Debian 13 fleets.**

onionwarden runs ~25 read-only integrity checks on each host, ships what it
finds to a separate off-box receiver, and pages you the moment something
changes — or a host goes quiet. It is built for small, identity-critical fleets
(Tor relays, exit nodes, BGP peers, eval hosts) where *silent* tampering is
worse than an outage.

- **Nothing on the box is trusted.** Baselines are signed on your laptop; the
  on-host collector can only verify and report, never authorize.
- **Silence is an alert.** A host that stops reporting pages you exactly like
  one that has been tampered with (dead-man's switch).
- **No daemons, no PPAs, no pip.** Pure-bash collector; standard-library Python
  receiver.

**New here?** Run the [5-minute first watch](#quick-start-5-minutes) below — it
shows you what onionwarden reports on a host without installing anything.

## How it works

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

- **Collector** — a pure-bash watchdog on each monitored host, run by three
  systemd timers. Runs the checks, verifies the signed baseline, heartbeats,
  and routes alerts off-box.
- **Receiver** — a separate off-fleet host that ingests events over a
  locked-down SSH key, keeps an append-only `events.log` per host, and pushes to
  ntfy on WARN/CRIT. Not a daemon — just sshd + cron.
- **Kill-switch** *(optional, ships disarmed)* — can escalate from alert to
  `freeze` / `poweroff` on compound conditions. Armed per host, only after a
  host is proven stable.

Component reference, the full check inventory, and the rollout phases:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start (5 minutes)

You need three things: a trusted **laptop** (with `git`, `python3`, and SSH),
one off-fleet **receiver** host, and one **monitored** host (Ubuntu 24.04 /
Debian 13, SSH-reachable with key auth).

### 1. See it work — read-only, no install

On your laptop:

```sh
git clone https://github.com/1aeo/onionwarden && cd onionwarden
./bin/onionwarden-quickstart <monitored-host>
```

This SSHes into the host, runs every check **read-only** (nothing is written on
the target, no root required), and prints the inventory — your first watch, at
zero risk:

```text
onionwarden quickstart · read-only first watch of relay-a
  -> snapshotting (read-only; nothing is written on the target) ...
  -> analysing offline against an empty baseline (everything is "new") ... 24 checks captured

  SEVERITY  CHECK                  SUMMARY
  INFO      listening_sockets      4 listeners: 22, 9001, 9030, 9051
  INFO      kernel_taint           taint flags: none (0)
  INFO      sshd_config            PasswordAuthentication=no PermitRootLogin=no
  ...
  24 checks analysed - 0 CRIT - 0 WARN - 24 INFO
```

(Full sample: [examples/first-watch-output.txt](examples/first-watch-output.txt).)
Under the hood that is two existing commands, if you prefer to run them yourself:

```sh
./bin/onionwarden snapshot <monitored-host> --out /tmp/ow-snap
./bin/onionwarden run --from-snapshot /tmp/ow-snap
```

### 2. Wire up continuous monitoring

Once the inventory looks right, set up the real collector → receiver → alert
pipeline:

| Step | What | Guide |
|------|------|-------|
| Make the fleet signing key (once) | `python3 lib/ed25519.py keygen onionwarden.priv onionwarden.pub` — keep `.priv` **offline** | — |
| Stand up the receiver (once) | An off-fleet host: two users, cron, one pinned SSH key per host | [receiver/RECEIVER.md](receiver/RECEIVER.md) |
| Onboard each host | Install the collector, sign its first baseline, prove the round-trip | [docs/ONBOARDING.md](docs/ONBOARDING.md) |

`onionwarden-onboard` automates the typo-prone parts of onboarding; the runbook
is the contract for the steps you do by hand in between. Hit a snag? See
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Common commands

```sh
onionwarden run [fast|slow|daily]      # run the watchdog now at a cadence
onionwarden snapshot HOST              # read-only remote state capture (no install)
onionwarden baseline collect|diff      # capture / compare a host baseline
onionwarden sign ...                   # off-box Ed25519 signing of baselines/configs
onionwarden suppress ...               # open a physical-access maintenance window
onionwarden upgrade BUNDLE             # apply a signed update bundle
onionwarden fleet-diff ...             # cross-host baseline diff (operator-side)
onionwarden arm-fatal | fatal-status | fatal-dry-run   # kill-switch (ships disarmed)
onionwarden version | help
```

## Configuration

- **Per-host** settings live in `host.conf`, generated by `install.sh` from a
  reviewable answers file — see
  [examples/answers-canary.example](examples/answers-canary.example).
- **Fleet-wide** defaults go in `.env` — copy [.env.example](.env.example).
- Neither file is committed. The tunable knobs and their fleet defaults are in
  [OPERATOR_DECISIONS.md](OPERATOR_DECISIONS.md).

## Documentation

| Doc | What's in it |
|-----|--------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, the full check inventory, the rollout phases |
| [docs/ONBOARDING.md](docs/ONBOARDING.md) | End-to-end runbook for onboarding one host |
| [receiver/RECEIVER.md](receiver/RECEIVER.md) | Receiver install, key/log rotation, host migration |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common first-run failures and fixes |
| [examples/](examples/) | Answers-file templates + a sample first watch |
| [PLAN.md](PLAN.md) | Full design, threat model, and phase breakdown (the spec, ~104 KB) |
| [OPERATOR_DECISIONS.md](OPERATOR_DECISIONS.md) · [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) | Configurable knobs · build-time decisions |

## Stage output

Long-running commands (`onionwarden-run`, `onionwarden-baseline collect`) emit a
hierarchical, greppable progress stream on **stderr** — the fleet-wide
convention shared with `onionleak` and `onionarmor` ([`lib/stage_tracker.sh`](lib/stage_tracker.sh)):

```text
[onionwarden] [<grandparent>] <parent>, n/N. <stage> : <status>
```

* Every line starts with the literal prefix `[onionwarden]` followed by a
  space — grep the whole run with `grep -E '^\[onionwarden\] '`.
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

CI runs the same suite on Ubuntu 24.04 and 22.04 for every push to `main` and
every PR (`.github/workflows/test.yml`).

## License

MIT — see [LICENSE](LICENSE).
