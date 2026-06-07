# `wildcard_listener` check — no process should bind a wildcard address

`lib/checks/wildcard_listener.sh` flags **any** process listening on a wildcard
address — `0.0.0.0`, `*`, `[::]`, or bare `::` — as a **CRIT** finding, one alert per
offending `process + port`.

## Why

On a relay-fleet host nothing should listen on a wildcard address. Every daemon
should bind a specific interface/IP so a port is offered only to the network the
operator intends. A wildcard bind silently exposes the service on every network
the host is attached to.

This check exists because the **BGP audit** found FRR `bgpd` listening on
`0.0.0.0:179` on three hosts — **relay-host-3, relay-host-5, relay-host-6** — and
onionwarden did **not** catch it. The pre-existing bind-IP check in
[`ports.sh`](../lib/checks/ports.sh) (`listener_binding`) is *opt-in*: it only
fires when the operator has declared an `expected_listen_binding_<port>_<proto>`
for that exact port. No declaration → no check. This check inverts the default:
**a wildcard bind is CRIT unless explicitly allowlisted.**

## When it runs

Like every other check, this one asserts only against a **trusted, captured
baseline**. `onionwarden-baseline collect` writes a `wildcard_listener.state`
for the host (one per check, even when empty), so the check is active on every
deployed host. Until a baseline exists (bootstrapping / `nobaseline`, or a host
that has never been baselined) it emits `NA` and never a CRIT — matching the
dispatcher, which withholds alerts in those states anyway.

It does **not** diff the baseline: a wildcard bind that was already present when
the baseline was captured is still CRIT (this is the whole point — `ports.sh`'s
opt-in `listener_binding` is what let a pre-existing `bgpd:0.0.0.0:179` slip
through). The baseline is only an "is this a trusted host" gate; the verdict is
absolute against the **allowlist**.

## Finding payload

Each finding carries (in `observed`): `proto`, `port`, `comm`, `pid`, `user`,
the `bind` address (`0.0.0.0` / `*` / `[::]` / `::`), and the binary path (`exe`, from
`readlink /proc/<pid>/exe`). The `summary` adds a one-line remediation hint
(FRR bgpd gets an FRR-specific hint).

## Allowlist

Some daemons legitimately have to bind a wildcard (e.g. an SSH server you
intend to reach from anywhere). Grant those **explicitly**:

- **Path:** `/etc/onionwarden/wildcard-listener.allow`
  (override for tests / alternate roots with `$ONIONWARDEN_WILDCARD_ALLOW`).
- **Shipped default: empty.** Nothing is permitted until the operator adds it —
  permit only what you actually intend to expose.
- **Format:** one exception per line, exactly `<comm>:<port>:<proto>`:

  ```text
  # Each entry MUST carry a SECURITY justification comment.
  # SECURITY: management SSH is reachable fleet-wide by policy (reviewed 2026-06-06).
  sshd:22:tcp
  ```

### Matching rules

- **All three fields must match exactly.** Proto specificity matters: an entry
  for `sshd:22:tcp` does **not** permit a UDP bind on the same port — that stays
  CRIT.
- Lines starting with `#` are comments. A `#` later on a line is an inline
  comment (everything after it is dropped) — so a SECURITY justification can sit
  on the same line as the entry.
- Blank lines are ignored.
- **Malformed lines** (not exactly three non-empty colon-separated fields) are
  silently skipped — they never allowlist anything and never abort the parse.

### Justify every entry

Every allowlist entry is a deliberate decision to expose a service to every
attached network. Treat each one as a security exception: precede (or inline) it
with a `# SECURITY: <who reviewed it, why it must be wildcard, when>` comment so
the next operator — and any audit — can see the rationale.

## Relationship to the canary CRIT-ack model (Option D)

A `wildcard_bind` CRIT behaves like any other CRIT under the Phase-4 canary
rollout gate ([`PHASE4_CANARY_PLAYBOOK.md`](PHASE4_CANARY_PLAYBOOK.md), Option
D): it **blocks** the gate (verdict HOLD) until it is either **remediated**
(bind to a specific IP, or add a justified allowlist entry) or **signed-acked**
by the operator — which only downgrades it to **WARN** ("rolling forward with
eyes open"), never to PASS. A wildcard exposure is therefore always surfaced,
never silently cleared.
