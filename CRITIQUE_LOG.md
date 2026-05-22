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
