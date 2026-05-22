# CRITIQUE R1 — Signing chain

**Lens:** can the pubkey, signature, or signed bundle be swapped, forged, or
replayed? **Files read:** `lib/ed25519.py` (whole), `lib/verify.sh` (whole),
`lib/baseline.sh` (whole), `bin/onionwarden-sign` (whole), `bin/onionwarden-upgrade`
(whole), `install.sh` pin-embedding block (lines ~95-110), `bin/onionwarden-run`
trust block (lines ~95-140).

## Findings

### R1-1 (HIGH) — No anti-rollback on the signed baseline
`baseline_verify` checks the Ed25519 signature and the per-state-file hashes —
but nothing rejects an *old, validly-signed* baseline. An attacker who keeps a
previous `manifest.json` + `.sig` + `state/` (e.g. from before a re-baseline
that tightened an allowlist, or from a window when a backdoor was wrongly
baselined-as-normal) can swap the whole signed set back in. Every signature and
hash still verifies, so the watchdog runs happily against stale trust state.
The same applies to `host.conf` (an old signed `host.conf` with weaker
allowlists or a `disable_checks` entry).

### R1-2 (MEDIUM) — `onionwarden-upgrade` has no downgrade protection
`onionwarden-upgrade` verifies the bundle signature but will apply *any* validly
signed bundle, including an older one. An attacker with an old signed bundle
(known-buggy code) can roll the watchdog's own code backwards. The audit entry
records `old_version -> new_version` but the tool never refuses `new < old`.

### R1-3 (MEDIUM) — A botched pin substitution silently disables C2
`install.sh` rewrites `@PUBKEY_SHA256@` in `verify.sh` with the real hash. If
that `sed` ever fails (or the file is installed by hand), the literal
placeholder survives and `_onionwarden_pubkey_pin_ok` treats it as "unpinned" and
returns success — the C2 on-box pubkey-swap guard is silently absent, with no
log line. A degraded security control that looks identical to a healthy one.

### R1-4 (HIGH) — `baseline_verify` ignores state files absent from the manifest
`baseline_verify` iterates only the `state.<check>` keys *inside* the signed
manifest. A `state/<check>.state` file present on disk but **not** named in the
manifest is never hash-checked — yet `baseline_state_file` will hand it to the
check, which trusts it. The baseline dir is deliberately not immutable (it is
re-baselined), so an attacker who can write it can drop a crafted
`network_deep.state` (a check that did not exist when this baseline was signed)
and have the watchdog diff against attacker-chosen "known-good" state — turning
a real deviation into a silent non-finding.

## Non-findings (examined, no issue)

- `ed25519.py` rejects non-canonical `S` (`s >= _L`) and validates points are
  on-curve in `_decodepoint` — cross-checked against `pyca/cryptography` over
  20 keypairs (`test_crypto_signing.py`). Forgery via malformed sig/point is
  closed.
- `onionwarden_verify_sig` distinguishes "no backend" (die) from "bad signature"
  (return 1), so a genuine rejection is never downgraded to a skip.
- The H5 circularity (a root attacker re-signs everything on-box) is a known,
  documented residual — the off-box receiver anchor is the answer, not an R1
  bug.

## Fixes applied

- **R1-1:** `baseline_verify` now enforces anti-rollback via the signed
  `captured_at` timestamp — the host records the newest accepted value in
  `state/baseline_captured_at` and refuses an older one. `host.conf` gained an
  optional signed `config_epoch`; the dispatcher refuses a lower epoch.
- **R1-2:** `onionwarden-upgrade` refuses a bundle whose `VERSION` is `<=` the
  installed version unless `--allow-downgrade` is passed explicitly.
- **R1-3:** the dispatcher emits an INFO finding (rides the daily digest;
  does not trip the dead-man every minute) when `verify.sh` is running with the
  unsubstituted `@PUBKEY_SHA256@` placeholder on a non-bootstrapping host.
- **R1-4:** `baseline_verify` now fails if any `state/*.state` file on disk is
  absent from the signed manifest.
