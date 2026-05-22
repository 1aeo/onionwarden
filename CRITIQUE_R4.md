# CRITIQUE R4 — Suppression workflow

**Lens:** can `onionwarden suppress` be abused to silence real alerts? What about
a stale/replayed suppression token? **Files read:** `lib/suppress.sh` (whole),
`bin/onionwarden-suppress` (whole), `lib/check_runtime.sh:physical_access_mode`,
`lib/checks/input_devices.sh`, `lib/checks/console_login.sh`, the dispatcher's
`ONIONWARDEN_SUPPRESS_PHYSICAL` wiring.

## Findings

### R4-1 (MEDIUM, residual) — Window expiry trusts the host clock
`suppress_physical_active` decides "expired" by comparing `now_iso` (the host's
clock) against the token's `expires_at`. A root attacker who rolls the system
clock back into an old token's validity window resurrects an expired
suppression token, re-silencing the physical-access fatal signals (#10/#11).
The monotonic `suppress_last` guard is itself in attacker-writable `state/`.
This is a root-scoped attack and root can already disarm the kill-switch, so it
adds little — but it is a genuine residual.

### R4-2 (HIGH) — `onionwarden-suppress clear` does not revoke the token
`clear` only `rm`s `suppress.token{,.sig}` from the host. A token captured
before clearing can simply be re-installed: the signature still verifies, and
because the anti-replay rule allows `opened_at == suppress_last`, the re-install
is honored — the window stays effectively open until the token's natural
`expires_at`. "Clear" was cosmetic; an operator who clears a window early
believing they have closed it has not.

### R4-3 (LOW) — Predictable nonce on the `/dev/urandom` fallback path
`onionwarden-suppress request`'s nonce fallback is `printf '%s' "$$RANDOM"` — the
literal string `RANDOM`, not the variable, glued to the PID. If `/dev/urandom`
is unavailable the nonce becomes a near-constant `<pid>RANDOM`. The nonce is
audit metadata (the signature is the real control), so impact is low, but it is
a plain bug.

## Non-findings (examined, no issue)

- **Scope is correctly bounded.** `suppress_physical_active` honors only a
  `scope=physical` token, and only `input_devices` + `console_login` consult
  `physical_access_mode`. PROMISC (#9) and the root signals (#1-#8) never read
  it — suppression genuinely cannot mute them.
- Suppression **downgrades**, it does not silence: a physical signal during a
  window still emits WARN, still hits `events.log`. It only drops the
  `fatal_candidate` flag — matching §3.7 ("records and pushes, does not
  poweroff").
- A future-dated `opened_at` is rejected ("not yet active"); a token cannot be
  pre-staged.
- The token is parsed only *after* its Ed25519 signature verifies, so field
  injection via the token body is not possible; `--reason` is `json_escape`d.

## Fixes applied

- **R4-2:** `onionwarden-suppress clear` now stamps `state/suppress_last` with the
  current time, so the cleared token (and any older one) fails the monotonic
  anti-replay guard on any re-install. `clear` genuinely revokes.
- **R4-3:** the nonce fallback is now a real composite of PID + `$RANDOM` +
  epoch instead of the literal-string bug.
- **R4-1:** documented as a residual in this file and `IMPLEMENTATION_NOTES.md`.
  The honest fix is receiver-side (the receiver's clock is trusted) and is
  noted as a Phase-3 enhancement; the on-box `clock` check's unsynced-clock
  WARN is the partial detection in the meantime.
