# Critique R2 — Append-only `events.log` integrity

**Scope:** can `events.log` (and related state files) be tampered with
or truncated by an attacker who is *not* root on the receiver?
**Files:** `receiver/receiver-append.sh`, `receiver/receiver-setup.sh`,
`receiver/onionwarden-receiver`.

## Threat model

Three attackers:

- **A** — controls a monitored host. Channel: the per-host SSH key with
  `command="…receiver-append.sh <host>",restrict`. Cannot read other
  hosts' data; cannot get a shell.
- **B** — has a shell on the receiver as the unprivileged `onionwarden`
  user (post-compromise). Has write access to `$ONIONWARDEN_RECEIVER_ROOT`.
- **C** — has root on the receiver. Out of scope; defeats every defence.

## What's already strong against A

- `restrict` + `ForceCommand` — only the appender script runs.
- `chattr +a` on `events.log` — even root can only append, not
  truncate, rewrite, or delete.
- Strict host_id sanitisation + receiver-side reserved-namespace
  quarantine; per-host pin (R1).
- Per-host per-minute rate limit; over-long line truncation.

## Findings against B

### F1 — `known_good.json` is unprotected (real, fixable)

`cmd_verify_record` writes `known_good.json` with a plain `open(…,'w')`
— it has no `chattr +i`, no signature, no log-of-record. Attacker B can
`echo '{"selfhash":"forged","pubkeyhash":"forged"}' > known_good.json`
and the next `verify-check` will compare each host's reported state
against the forged baseline, silently making mismatch detection a
no-op.

**Fix:** after writing `known_good.json`, the script should
`chattr +i` it (immutable — even root cannot edit without `chattr -i`).
Operator re-runs `verify-record` are guarded by an explicit
`--re-record` flag that first removes the +i flag (requires CAP_LINUX_IMMUTABLE
= sudo). Same trade-off as `events.log` +a: the protection is real if
the receiver runs as a non-root account and the +i was applied by a
one-time root setup.

A best-effort version (no sudo, no chattr) can checkpoint the
`known_good.json` content into a freshly-appended `verify-record` event
in `events.log`. That gives a tamper-evident audit trail (the append
is +a-protected) even if the JSON file is later forged.

### F2 — `events.log` mtime can be touched without appending (real, fixable)

`events_log_age_seconds()` uses `os.path.getmtime` to decide whether a
host has gone silent. `chattr +a` blocks `truncate`/`rewrite` but NOT
`utime()` — Attacker B can run `touch /var/lib/onionwarden/data/relay_a/events.log`
and the staleness check will read "0 seconds ago" even with zero actual
appends. Staleness alerting is effectively defeated.

**Fix:** record receiver-side append-time in a sidecar that Attacker B
cannot trivially update, or — simpler and stronger — derive freshness
from the **latest event's `seq` plus a receiver-stamped append-time**
the appender writes into the JSON line itself (e.g. inject a
`recv_ts: <utc-iso>` field). The event timestamps remain host-controlled,
but the appender adds a server-side timestamp that the host cannot forge
and that doesn't move under a `touch`.

Round 2 implements the receiver-stamped recv_ts: the appender adds
`"recv_ts":"<iso8601>"` to each accepted line; `events_log_age_seconds`
prefers the highest-seq event's `recv_ts` and falls back to mtime when
the new field is missing (rolling-update compatibility).

### F3 — `receiver.log` is not append-only (minor, defence in depth)

`receiver-append.sh` writes to `$RECVROOT/receiver.log` for rate-limit
+ reject events. The file is created on first write and never `chattr
+a`-ed by `receiver-setup.sh`. Attacker B can erase rate-limit /
reject history — useful for hiding a flood from an `onionwarden`-shell
incident.

**Fix:** receiver-setup.sh now `touch`es `receiver.log` and applies
`chattr +a` to it alongside each host's `events.log`.

### F4 — Unbounded `events.log` growth (operational, fixable)

The rate limit caps lines/host/minute but the file has no rotation
policy. With +a in place, `logrotate` cannot work without an `chattr
-i`-style root maintenance pre-hook. A persistent loud host can grow
its `events.log` indefinitely; eventually disk fills and the receiver
silently stops appending (which `verify-check`'s staleness flag will
catch via F2 once fixed, but only after the gap).

**Fix:** ship a `scripts/rotate-receiver-logs.sh` that an operator can
`sudo` weekly: `chattr -a`, `mv events.log → events.log.YYYYMM`,
`gzip`, `: > events.log`, `chattr +a`. Document a cron entry in
`MIGRATION_TO_PROXMOX.md`.

### F5 — `.rate.$minute` files are user-writable (no impact)

Attacker B can edit per-host `.rate.<minute>` counters to bypass rate
limit. That's the same Attacker B who can rm `.rate.*` outright.
Already in their privilege envelope; not worth defending.

## Fix application

R2 applies F1 (best-effort: checkpoint known-good into +a events.log),
F2 (receiver-side `recv_ts`), F3 (+a on receiver.log), and ships F4 as
a runbook + helper script.

New tests:
- `test_appender_stamps_recv_ts` — every accepted line carries a fresh
  `recv_ts`.
- `test_events_log_age_uses_recv_ts_over_mtime` — touching the file
  doesn't reset the freshness signal.
- `test_verify_record_writes_audit_event` — `verify-record` leaves a
  +a-protected audit trail in events.log alongside the JSON checkpoint.
