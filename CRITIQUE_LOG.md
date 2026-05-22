# CRITIQUE_LOG.md

One paragraph per critique round — what the lens found and what changed.
Full findings are in `CRITIQUE_R<N>.md`.

## Round 1 — Signing chain
Looked at whether the pubkey, a signature, or a signed bundle could be swapped,
forged, or replayed. The Ed25519 primitive itself held up (non-canonical-S and
on-curve checks present, cross-checked against `pyca/cryptography`), but the
*freshness* of signed artifacts was unguarded: a validly-signed but **old**
baseline, `host.conf`, or upgrade bundle could simply be replayed, rolling the
host back to weaker trust state or known-buggy code. Two structural gaps too —
`baseline_verify` only hash-checked state files *named in the manifest*, so an
attacker could drop an extra unlisted `state/<check>.state` and have a check
diff against attacker-chosen "known-good"; and a failed pin substitution left
C2 silently inactive. Fixes: `baseline_verify` now enforces anti-rollback via
the signed `captured_at` and refuses any unlisted state file; the dispatcher
enforces a `config_epoch` anti-rollback on `host.conf` and surfaces an unset
pubkey pin; `onionwarden-upgrade` refuses a bundle older than the installed
version unless `--allow-downgrade`. All 115 tests pass.

## Round 2 — TOCTOU + race conditions
Traced every read-state-then-act-later window. The serious one: the dispatcher
hash-verified the on-disk baseline and *then later* let each check read those
same files — and the baseline directory is deliberately not immutable, so an
attacker who can write it could pass verification on honest files and swap a
`state/<check>.state` before the check read it (verified bytes ≠ used bytes).
Fixed by copying the baseline into the run's private 0700 tmpdir and
verifying + using the copy. Two smaller races: `onionwarden-upgrade` had no lock,
so two overlapping upgrades could interleave their `chattr -i`/apply/`chattr +i`
windows into a corrupt tree (now `flock`-guarded); and `events_flush_buffer`
emptied the local buffer with a send-then-truncate that could destroy an event
appended concurrently by `onionwarden-fatal` (now renames the buffer aside first).
All 115 tests pass.

## Round 3 — Fatal-action arming logic
Audited the first-arm checklist, cooldown, and disarmed default. The checklist
auto-items read the *on-box* `runs.ndjson` and `stat`'d the on-box manifest — a
direct violation of M3 ("never from on-box logs, which a compromised host
controls"); a compromised host could forge "7 quiet days". The cooldown was not
signal-scoped, so one cooldowned signal muted the kill-switch for *every*
signal, and `state/fatal_cooldown` is an unsigned attacker-writable file. The
fatal action was read from the unsigned `state/fatal_armed` file, letting an
attacker on an operator-`freeze`-armed host escalate to `poweroff scope=all`.
And a crashed dry-run (zero output) passed the "baseline does not self-trip"
item. Fixes: `arm` requires an off-box `--events-log` and verifies item 1
against it; the cooldown is per-signal and every suppression is loudly logged
off-box; the action is read from the signed `host.conf` (the armed file carries
only scope); item 3 requires the dry-run's positive `clean` result line. All
115 tests pass.

## Round 4 — Suppression workflow
Probed whether `onionwarden suppress` can silence real alerts and whether a stale
token can be replayed. Scope held up — only `input_devices`/`console_login`
consult `physical_access_mode`, so PROMISC and the root signals genuinely
cannot be muted, and suppression downgrades to WARN rather than silencing. But
`onionwarden-suppress clear` turned out to be cosmetic: it only `rm`d the local
token file, so a captured copy could be re-installed and honored until its
natural expiry — an operator who "closed" a window early had not. Fixed by
stamping `suppress_last` to now on `clear`, so the monotonic anti-replay guard
rejects the cleared token on re-install (covered by a new test). Also fixed a
literal-string bug in the nonce fallback (`"$$RANDOM"`). The remaining residual
— a root clock-rollback can resurrect an expired token — is documented; the
honest fix is receiver-side (trusted clock) and the on-box `clock` check's
unsynced-clock WARN is the partial detection. 116 tests pass.

## Round 5 — Input-device + console-login detection
Examined false positives and false negatives in the physical-access checks.
The replug FP and serial-console FP were already handled (vid:pid identity,
`^tty[0-9]+$` excludes `ttyS*`). Three real gaps: input_devices had no
per-device allowlist, so a legitimate post-baseline device (uinput/KVM/synergy)
forced the all-or-nothing `physical_access_allowed`; the sysfs snapshot is
point-in-time, so a seconds-long BadUSB plug-attack-unplug vanishes before the
next ~1-min tick; and console_login only read `who` (current sessions), missing
a console login that closed within the interval — PLAN §2.8 explicitly asked
for the `last`/wtmp half too. Fixes: added an `expected_input_devices`
allowlist; input_devices now also diffs `journalctl -k` input-registration
lines (durable for the boot, so a since-unplugged device is still caught);
console_login now also parses `last` for closed `tty[0-9]` sessions. Three new
tests; 119 pass.
