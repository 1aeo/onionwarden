# Receiver critique log

Five rounds of focused critique-and-fix on the receiver code only
(`receiver/`, `scripts/` helpers, `tests/test_receiver.py`,
operator-facing docs).

## R1 — Forced-command SSH lockdown
See `CRITIQUE_RECEIVER_R1.md`.

- **F1** (real, fixed): per-host SSH keys now pin a host_id via the
  forced-command first arg (`command="…/receiver-append.sh relay_a"`).
  Stolen key cannot impersonate another host; mismatched lines are
  rewritten + logged.
- **F2** (defence in depth): `umask 077` in receiver-append.sh and
  receiver-setup.sh.
- **F3** (operator footgun): receiver-setup.sh refuses `--root` with
  whitespace (would break the printed authorized_keys line).
- **F4** (minor DoS): a per-host `mkdir -p` failure now skips that
  line and logs, instead of aborting the SSH session.
- **F5** (operator hazard): chattr +a failure classifies
  Operation-not-permitted vs FS-limitation; final WARN if any +a was
  skipped.
- **Tests:** +2 (host-pin enforcement positive/negative).

## R2 — `events.log` tamper resistance
See `CRITIQUE_RECEIVER_R2.md`.

- **F1** (real, fixed): `cmd_verify_record` now also appends a
  `kind:"verify_record"` audit-trail event into the +a `events.log`;
  if `known_good.json` is forged, an operator can reconstruct from
  the audit trail.
- **F2** (real, fixed): receiver-append.sh injects a server-stamped
  `recv_ts`; `events_log_age_seconds` prefers the highest-seq event's
  `recv_ts` over file mtime. `touch events.log` no longer masks
  staleness. (Also fixed a latent DST bug in the existing mtime math
  by switching to `calendar.timegm`.)
- **F3** (defence in depth): `receiver.log` also gets `chattr +a`
  from receiver-setup.sh.
- **F4** (operational): `scripts/rotate-receiver-logs.sh` ships as
  the root weekly-cron helper for safe rotation of +a events.log
  files (chattr -a → mv → gz → chattr +a).
- **Tests:** +3 (recv_ts stamping, staleness vs touch, verify_record
  audit trail).

## R3 — Cron-loop scalability + accuracy
See `CRITIQUE_RECEIVER_R3.md`.

- **F2** (real, fixed): per-host stale-minutes override via
  `<hd>/.stale_minutes` (lets a daily-cadence host coexist with a
  5-min-cadence host).
- **F3** (DoS-grade scaling, fixed): seqcheck is now seek-based with
  `<hd>/.seqcheck.state.json` (last_seq, last_offset). Constant
  memory + work per run; rotation-aware.
- **F4** (false positive, fixed): a legitimate appender restart
  WARNs once and is acked through `ack_resets_through_seq`.
- **F5** (noise, fixed): verify-check dedup — at most one ntfy push
  per host per run; body lists all triggers.
- **F7** (visibility, fixed): digest reports per-host parse-failure
  counts so in-progress corruption is surfaced.
- **Bugfix:** `OSError: telling position disabled by next() call` —
  the seek-based reader uses `fh.readline()` instead of
  `for line in fh`.
- **Tests:** +3 (seqcheck resume, reset ack, per-host stale override).

## R4 — Receiver signing-key custody + rotation
See `CRITIQUE_RECEIVER_R4.md`.

The receiver keypair is currently inert (no live signing consumer),
so today's rotation is zero-risk. The contract here protects the
inert-to-active switchover.

- **F1** (friction, fixed): `scripts/rotate-receiver-key.sh` —
  verifies the pair pair-matches first, generates new in a `.new`
  sidecar, atomic mv to live name, prints sha256 of both old + new.
- **F2** (future-real, documented): MIGRATION_TO_PROXMOX.md now
  documents the 4-step dual-pin rotation protocol (generate →
  publish both → roll collectors → drop .prev after TTL). The
  forward-looking config knob `verify_pubkey_paths = [a, b]` is
  named so future signing code uses it.
- **F3** (defensive, fixed): generate + rotate scripts accept
  `--owner USER:GROUP` (default `onionwarden:onionwarden`).
- **F4** (nice-to-have, fixed): both scripts print
  `pubkey sha256: <hex>` for operator-verified file-copy integrity.
- **Tests:** unchanged (rotation is operator-shell, not in-app).

## R5 — Public-repo readiness
See `CRITIQUE_RECEIVER_R5.md`.

- **F1** (real, fixed): added `receiver/RECEIVER.md` — generic,
  deployment-agnostic operator runbook. `MIGRATION_TO_PROXMOX.md`
  retained as a wrapper for the provider-specific bits + the rotation
  protocol. Stale `secure-server/receiver/` reference fixed.
- **F2** (UX, fixed): `receiver/README.md` orients a public visitor
  to what each file does.
- **F3** (operator-actionable, fixed): verify-check messages now
  include the canonical "run as: …" hint.
- **F4** (UX, fixed): `onionwarden-receiver` docstring has an
  "Examples" block (first-time bootstrap + cron line templates).
- **F5** (footgun, fixed): root README quickstart now shows `sudo`
  for the receiver-side scripts.

## Totals

- 17 findings raised; 17 fixed (or documented, for forward-looking
  contracts).
- Receiver-side test count: 11 → 20 (+9 new tests).
- All 165+ tests pass (one unrelated `test_snapshot_bundle` flake under
  full-suite parallel load; passes in isolation).
- 4 new operator helper scripts: `generate-receiver-key.sh`,
  `rotate-receiver-key.sh`, `rotate-receiver-logs.sh`, plus
  `receiver/RECEIVER.md` + `receiver/README.md`.
