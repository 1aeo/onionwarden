# CRITIQUE R2 — TOCTOU + race conditions

**Lens:** anywhere state is read and a fix/decision happens later — can the
state change in the window? **Files read:** `bin/onionwarden-run` (whole),
`lib/baseline.sh` (whole), `lib/alert.sh` (`events_append`,
`events_flush_buffer`, `next_event_seq`), `bin/onionwarden-upgrade` (whole),
`lib/fatal.sh` (cooldown path), `lib/suppress.sh` (`suppress_last` write).

## Findings

### R2-1 (HIGH) — TOCTOU between `baseline_verify` and check use
The dispatcher called `baseline_verify "$BASELINE_DIR"` (which hashes every
`state/*.state` against the signed manifest), and *then later* the check loop
read those same on-disk files via `baseline_state_file "$BASELINE_DIR"`. The
baseline directory is intentionally **not** immutable (it is re-baselined). An
attacker who can write it could let `baseline_verify` pass on the honest files,
then swap `state/<check>.state` before the check reads it — verified bytes ≠
used bytes. The whole point of the signature is defeated by the gap.

### R2-2 (MEDIUM) — `onionwarden-upgrade` has no concurrency lock
`onionwarden-upgrade` does `chattr -i` → replace files → `chattr +i`. Two
overlapping invocations (operator fat-fingers it, or a config-management retry)
would interleave those windows: one upgrade's `chattr +i` could re-lock files
the other is mid-write on, leaving a half-applied, partly-immutable tree. A
single watchdog fast-run during the window is fine (the plan's "loud not
silent" self-hash CRIT covers it), but two upgrades racing is genuine
corruption.

### R2-3 (MEDIUM) — `events_flush_buffer` send-then-truncate race
`events_flush_buffer` shipped `pending.ndjson` to the receiver and then did
`: > buf` to empty it. `events_append` (called by the dispatcher AND by
`onionwarden-fatal` / `onionwarden-suppress`) appends to that same file on an ssh
failure. An event appended in the window between "ssh send" and "truncate" is
silently destroyed — and the lost event could be the CRIT that mattered.

## Non-findings (examined, no issue)

- `next_event_seq` does read-increment-write but is `flock`-protected, and the
  dispatcher already holds `run.lock` so only one dispatch runs at a time —
  the residual cross-process case (a dispatch + an operator CLI both appending)
  is covered by the `flock` inside `next_event_seq` itself.
- Per-check point-in-time snapshotting (collect at T1, the *next* check collects
  at T2) is inherent to a timer-based watchdog and explicitly accepted by the
  design (§3.1); auditd (Phase 3) is the real-time complement. Not a defect.
- `fatal_evaluate`'s cooldown read-check-act sequence runs entirely inside one
  `run.lock`-held dispatch — not racy.

## Fixes applied

- **R2-1:** the dispatcher now copies the baseline into its private 0700
  `mktemp` run directory, and verifies + uses that copy. A swap during the copy
  is caught because `baseline_verify` runs against the copy; a swap after is
  not possible (the copy is transient, root-owned, in a private tmpdir).
- **R2-2:** `onionwarden-upgrade` takes a non-blocking `flock` on
  `state/upgrade.lock` and aborts if another upgrade holds it.
- **R2-3:** `events_flush_buffer` now `mv`s the buffer aside before sending, so
  a concurrent `events_append` writes to a fresh `pending.ndjson`; on a still-
  failed send the set-aside file is appended back (the receiver re-orders by
  sequence number).
