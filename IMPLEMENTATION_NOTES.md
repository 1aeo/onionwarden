# IMPLEMENTATION_NOTES.md

What the Phase 0–2 build of `onionwarden` actually ships, what is stubbed, and the
known limitations. Read alongside `PLAN.md` (design) and `OPERATOR_DECISIONS.md`.

## What works end-to-end

- **Check framework** — `lib/check_runtime.sh` defines the `collect`/`analyze`
  contract; every check is a `collect` (Linux-only state gather) + a *pure*
  `analyze` (baseline vs current → structured findings). 24 checks under
  `lib/checks/`, all unit-tested from fixtures.
- **Dispatcher** (`bin/onionwarden-run`) — verifies the signed baseline +
  `host.conf`, detects the host profile, runs cadence-matched checks under a
  per-check `timeout` + `ulimit -v` memory cap, writes NDJSON findings, drives
  the dead-man heartbeat, routes alerts, and invokes the fatal evaluator.
  Trust states (`trusted` / `bootstrapping` / `nobaseline` / `badbaseline`)
  and the bootstrapping→trusted transition all verified by `test_dispatcher.py`.
- **Signing chain** — `lib/ed25519.py` is a dependency-free RFC 8032
  implementation (cross-checked against `pyca/cryptography`). `lib/verify.sh`
  verifies with `openssl pkeyutl` on Ubuntu/Debian and falls back to the Python
  verifier; the `onionwarden.pub` hash is pinned into `verify.sh` at install (C2).
- **Baselines** — `onionwarden-baseline collect|diff`, signed off-box with
  `onionwarden-sign`. The C1 offline-scan gate on trust-expanding deltas is
  enforced by `diff` (`--offline-scan-attested`).
- **Alerting** — dead-man heartbeat, ntfy push, append-only `events.log` with
  per-host monotonic sequence numbers, CRIT email. All four have a dry-run
  sink seam (`ONIONWARDEN_ALERT_SINK`).
- **Off-box receiver** — `receiver/receiver-append.sh` (append-only forced
  command, host_id sanitisation, rate limiting) + `receiver/onionwarden-receiver`
  (self-hash/pubkey known-good comparison, sequence-gap detection, fleet-rollup
  digest).
- **Kill-switch** — `lib/fatal.sh` + `onionwarden-fatal`: ships disarmed, signed
  master veto + armed-state file + in-scope `fatal_candidate` finding all
  required; off-box-first; cooldown; 7-item first-arm checklist; dry-run.
- **Suppression** — `onionwarden-suppress`: the maintenance window is an
  Ed25519-signed, time-bounded, replay-guarded token (C5-compliant).
- **install.sh** — lays the tree from a reviewable answers file, pins the
  pubkey hash, stages systemd units, applies `chattr +i` where the FS supports
  it, leaves the host bootstrapping. Tested into a scratch prefix.

## What is stubbed or deferred (and why)

- **No real-host deployment.** This was a build-and-local-test task. `install.sh`,
  `apply-ssh-hardening.sh`, and `onionwarden-baseline` are all *capable* of
  deploying but were never run against a real host. The canary rollout
  (`relay-a`) is therefore not executed — `examples/answers-canary.example`
  is rollout-ready.
- **`onionwarden-fleet-diff`** — a documented Phase-3 stub (`bin/onionwarden-fleet-diff`
  exits 64 with an explanation). Cross-fleet diff is explicitly Phase 3.
- **Receiver cross-host correlation** (§4 M6) — Phase 3, not built.
- **Off-box journal shipping** (`systemd-journal-upload`, L6) — Phase 3.
- **`apt install debsums aide auditd`** — package installs are real-host
  operations. The checks detect-and-skip when these tools are absent
  (`packages.sh` falls back `debsums`→`dpkg --verify`; AIDE logs N/A).
- **Dead-man self-test & OOB-recovery test** — `onionwarden-fatal test` exercises
  the off-box path; the *live* heartbeat-pause test and the per-host OOB test
  are operator steps (they need the real provider / real host).

## Known limitations

- **`collect()` is not unit-tested.** The collectors run Linux-only commands
  (`ss`, `ip`, `lsmod`, `/proc`, …) and are exercised only on a real host;
  the build/test host is macOS. The *analysis* logic — the security-relevant
  half — is fully fixture-tested. Collectors are deliberately thin.
- **apt-correlation for `/boot`** — initrd is generated, not a packaged file,
  so the per-file dpkg hash anchor (M5) cannot apply to it; `boot_integrity`
  uses the coarser `apt_correlate_kernel` signal (was a linux-image/initramfs
  package touched by apt) for generated `/boot` files. Vmlinuz/config/System.map
  *are* packaged and get the strong per-file anchor.
- **`events.log` selfreport volume.** The dispatcher appends a `selfreport`
  event every fast run (~1/min) so the receiver can verify continuously. At
  9 hosts this is well within the receiver's rate limit; an operator on a much
  larger fleet may downgrade selfreport to the slow cadence.
- **`heartbeat`/`process_ancestry` baseline semantics.** `process_ancestry`'s
  `svcshell` signal fires on *presence* (any daemon-spawned shell is bad), so it
  needs no baseline; `tmpexec` is baseline-diffed. `auth_log` treats the
  baseline as the known-good set of SSH source IPs / sudo users since logs are
  time-windowed.
- **`filesystem.sh` watchdog-path hardcoding** — the immutable-bit fatal-#8
  watch hardcodes `/opt/onionwarden/...`; correct for a standard install, but a
  relocated install would not be watched. (Flagged in CRITIQUE_R2.)

## Test & build environment

- Built and tested on macOS with system `/bin/bash` **3.2** — a passing run
  proves bash-3.2 compatibility (the Linux targets run bash 5; the 3.2 subset
  is a safe lower bound). No bash-4 features (`declare -A`, `${v,,}`, `mapfile`).
- **`bats` and `shellcheck` were not available** in the build environment, so
  the shell test suite is driven by **pytest** invoking the checks through
  their `analyze` CLI — every check still gets a positive, a negative, and an
  allowlist/suppression test (`tests/test_checks.py`). The code is written to
  be shellcheck-clean by discipline; `tests/` would accept real `bats` tests
  unchanged since the checks expose a clean CLI.
- macOS `openssl` is LibreSSL 3.3.6, which lacks Ed25519 — so the test suite
  uses the pure-Python verifier backend (`ONIONWARDEN_VERIFY_BACKEND=python`).
  Production on Ubuntu 24.04 / Debian 13 uses `openssl pkeyutl` (OpenSSL 3.x).
- Run the suite: `cd secure-server && python3 -m pytest tests/ -q` (115 tests).
