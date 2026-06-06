# Security policy

`onionwarden` is a root-resident, read-only watchdog that detects drift in a
host's kernel + network posture and ships signed event lines off-box. This
document is the canonical statement of its threat model, its DNS posture, the
trust boundaries it ships hardened by default, and how to report a
vulnerability.

The threat model below is extracted from `PLAN.md §1` ("Threat model &
assumptions") and is kept in sync with it.

## Threat model & assumptions

### Assets

1. **Integrity of whatever the host is responsible for** — an eval/CI
   pipeline, production services, served model endpoints. Silent tampering
   that biases outputs is worse than an outage, because bad output is trusted
   and acted on.
2. **The host itself and its credentials** — admin SSH keys, sudo, the host's
   standing on its LAN.
3. **Workloads the host runs** — services, containers, or nested VMs.

### Adversaries

- **A1 — Remote attacker** reaching the host over the network: SSH or any
  service the host exposes beyond localhost. Acute for public-facing tor
  relays, which accept inbound connections from the entire internet by design.
- **A2 — Malicious workload** — a job, container, or nested VM that escapes
  its sandbox, or a compromised dependency running as a service account.
- **A3 — Operator error** — an admin's own accidental misconfiguration (a bad
  sudoers edit, a stray world-writable chmod, an unintended cron job).
  Explicitly in scope.

### Trust boundaries — resolved per host by the profile

- The watchdog runs **as root, inside the host OS**. It defends that OS's
  userspace + kernel-visible state.
- **If the host is a guest VM:** the hypervisor sits above it and is **out of
  scope** — a guest cannot defend itself from a malicious host.
- **If the host is a hypervisor / runs nested VMs or containers:** those
  workloads are adversary class **A2**.
- **If bare metal:** only hardware/firmware sits below; firmware drift is
  monitored (DMI), deeper firmware attack is out of scope.

### Assumptions

- **A-TOFU (recurring, not one-time):** the host is clean *at every
  baseline-capture time* — the initial bootstrap **and every re-baseline**.
  Each re-baseline is a fresh trust event; the offline-scan precondition for
  trust-expanding deltas keeps a re-baseline from laundering a resident
  compromise into the signed baseline.
- The baseline signing private key never touches any monitored host.
- The off-box receiver host(s) and the signing key are trusted; keep them
  minimal and hardened.
- Network to the alerting services is *usually* available; gaps are themselves
  alertable.

### Honest limitations

- **A kernel-level rootkit can lie to every userspace tool.** No on-box agent
  is trustworthy once root/kernel is owned. This design optimizes for catching
  the **transition into a compromised state** and for making an attacker's
  actions **noisy** — not for defeating an already-resident competent rootkit.
- Three backstops compensate: **(a) cross-checks** — read a fact two ways and
  alert on disagreement (`lsmod` vs `/proc/modules` vs `/sys/module`; `ss` vs
  `/proc/net/tcp`); **(b) the dead-man's switch** — a compromised box cannot
  satisfy it without *also* faking every other signal forever; **(c) periodic
  out-of-band scans** — whose *real* cadence is operator-constrained: this
  backstop is only as strong as the scan cadence actually sustained.
- **A compromised root can forge "all-clear" alerts** (the outbound key is on
  the box). The trust anchors are the dead-man's switch and the off-box scan,
  not the on-box agent's word.

### Out of scope

Hypervisor/host compromise (for guests), physical attacks, DoS, upstream
distro supply-chain compromise, defending workload internals, and any OS
outside the supported set.

## DNS posture

`onionwarden` depends on DNS for three of its functions:

- **Alert delivery** — resolving the `ntfy` push endpoint (`lib/alert.sh`).
- **Receiver SSH host resolution** — resolving the off-box receiver that
  ingests signed event lines over the forced-command SSH channel.
- **Remote integrity checks** — `debsums` / AIDE / APT-source reachability for
  packaged-file verification (`lib/checks/packages.sh`).

Because a poisoned resolver can silently redirect alerts or starve the
receiver channel, `onionwarden` assumes the host runs DNS through a local
validating resolver, not plain UDP/53 to the network operator. Recommended
posture:

1. **Local validator**: `unbound` listening on `127.0.0.1:53` with
   `tls-upstream: yes` and `do-tcp: yes`.
2. **DoT upstreams** (port 853, TLS-pinned hostnames): pick two or more from
   diverse providers (e.g. `1.1.1.1@853#cloudflare-dns.com` +
   `9.9.9.9@853#dns.quad9.net` + `8.8.8.8@853#dns.google`).
3. **DNSSEC**: trust anchor pinned at `/var/lib/unbound/root.key`
   (auto-bootstrapped via `unbound-anchor` then ownership-fixed to
   `unbound:unbound`).
4. **`/etc/resolv.conf` is a real file** pointing only to `127.0.0.1` — not a
   symlink to `systemd-resolved`. Fleet-specific observation: on our Ubuntu
   24.04 hosts, `systemd-resolved` 255.4-1ubuntu8.15 leaked memory and stopped
   answering on `127.0.0.53` under sustained high parallel DNS load (surfaced
   2026-05-27 during onionleak's parallel ExoneraTor enrichment, where 711 of
   833 lookups timed out). Treat this as an observed incident on that specific
   stack, not a universal claim about `systemd-resolved`.
5. **`systemd-resolved` stopped and masked** (`systemctl stop systemd-resolved
   && systemctl mask systemd-resolved`). Prefer this deterministic
   stop-then-mask over a broad `pkill -f`, which can match unrelated processes.
6. **No fallback to plain Do53** — confirm via `unbound-control list_forwards`
   showing only `853` ports.

This is the exact posture onionleak's fleet rolled out across all 6 hosts
after a `systemd-resolved` leak under parallel ExoneraTor enrichment. A relay
running `onionwarden` benefits identically: alert and receiver name
resolution stay tamper-evident and leak-free.

## Hardened defaults

`onionwarden` ships these trust boundaries enabled or pinned by default — an
operator does not have to opt in to get them:

- **Signed-baseline checks.** Every baseline manifest and `host.conf` is
  Ed25519-signed off-box; the watchdog verifies the signature before trusting
  any baseline value (`lib/verify.sh`). An unsigned or mis-signed baseline is
  refused.
- **Forced-command SSH receiver.** Each host ships event lines over an SSH key
  pinned to a forced command (`command="…/receiver-append.sh <host>",restrict`).
  A host can only **append to its own** `events.log`; it never gets an
  interactive shell on the receiver (`receiver/receiver-append.sh`,
  `receiver/receiver-setup.sh`).
- **`chattr +i` on critical paths.** The installer applies the immutable
  attribute to the protected tree (code, unit files, `host.conf`) where the
  filesystem supports it (`install.sh`). The **only** supported way to change
  the protected set is the signed `onionwarden-upgrade` flow, which brackets
  every write in `chattr -i` → apply → `chattr +i`; the operator never runs
  `chattr` by hand. Clearing the `i` bit on a watchdog file is itself a fatal
  signal (`lib/checks/filesystem.sh`).
- **`lib/fatal.sh` kill-switch — ships DISARMED.** The fatal-action evaluator
  acts only when *all* of: `host.conf:fatal_action_armed = true` (a signed
  master veto), a `state/fatal_armed` marker set by `onionwarden-fatal arm`, a
  finding carrying `"fatal_candidate":true` (already post-allowlist /
  post-apt-correlation), the finding's signal within the armed scope, and no
  cooldown in effect. Off-box-first: the event is shipped to `events.log`
  before any action so the record survives the host going down.
- **Pubkey-hash pin in the installer (C2).** `install.sh` computes the SHA-256
  of the fleet public key and embeds that hash into the installed `verify.sh`,
  so a swapped-out `onionwarden.pub` is detected rather than silently trusted.

## Reporting a vulnerability

Report security issues privately through either channel:

- **GitHub private vulnerability reporting** — open the repository's **Security**
  tab and choose **Report a vulnerability**. This is the preferred channel: it
  is always available on the repo and keeps the report private until disclosure.
- **Email** — **security@1aeo.com**.

Please include:

- the affected component (file/path) and version (`VERSION`),
- a description of the issue and its impact under the threat model above,
- reproduction steps or a proof-of-concept where possible.

Do not open a public issue for an unfixed vulnerability.

We aim to meet the following response targets:

- **Acknowledgement** — within 72 hours of receipt.
- **Initial triage / severity assessment** — within 7 days, with a first status
  update to the reporter.
- **Mitigation / patch** — severity-based, as a target rather than a guarantee:
  critical within 14 days, high within 30 days, medium/low on a best-effort
  basis.
- **Coordinated disclosure** — we coordinate public disclosure timing with the
  reporter, normally after a fix is available, or within 90 days of the report
  if no fix has shipped.

Status updates are sent to the reporting channel used (the GitHub private
advisory thread, or the email thread). These targets accompany the rule above:
do not open a public issue for an unfixed vulnerability.
