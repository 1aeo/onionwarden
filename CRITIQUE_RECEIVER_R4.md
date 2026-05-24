# Critique R4 — Receiver signing key custody + rotation

**Scope:** key custody, rotation safety, and the question "does the
rotation procedure leave a window where verification fails?"
**Files:** `scripts/generate-receiver-key.sh`,
`receiver/MIGRATION_TO_PROXMOX.md`, `receiver/receiver.pub.example`.

## Current state of play

Per `MIGRATION_TO_PROXMOX.md` §"Deviations" + §"Rotate or keep":
> "Receiver signing keypair generated at `/var/lib/onionwarden/receiver.{priv,pub}`
>  (PEM) but no current code path consumes it. Upgrade path: kept ready so a
>  future signing-of-digests change is drop-in."

So today the keypair is **provisioned but inert**. Rotation today is
zero-risk for verification (nothing verifies). But the rotation
procedure must be safe **before** the inert-to-active switchover, or
the first signing-aware deploy will trip on the same race the rotation
procedure has now.

## Findings

### F1 — `generate-receiver-key.sh` refuses to rotate (real friction)

The current generate script:

```bash
if [[ -e "$PRIV" || -e "$PUB" ]]; then
  echo "refuse: receiver key already exists" >&2
  exit 1
fi
```

That's correct for initial provisioning but blocks rotation: the
operator has to manually `mv`, `chmod`, etc. before re-running.
A separate `rotate-receiver-key.sh` is cleaner and keeps the safety
copy.

**Fix:** ship `scripts/rotate-receiver-key.sh` that:
1. Verifies the old keypair pair-matches before any rotation.
2. Generates the new keypair in a `.new` sidecar.
3. `mv` the old to `.YYYYMMDD-HHMMSS.bak`, then `mv .new` to live name
   atomically (single mv operation, so collectors that pin the path
   see either the old or the new — never half-written).
4. Prints the new public key fingerprint to stdout AND the operator
   should copy it back to the laptop + commit.

R4 ships this script.

### F2 — The published rotation runbook leaves a verification gap (future-real)

Tomorrow's signing flow: receiver signs each digest with `receiver.priv`;
monitored hosts pin `receiver.pub` and verify on download.

The runbook in MIGRATION_TO_PROXMOX.md §"Rotate or keep":

```sh
openssl genpkey -algorithm ed25519 -out /var/lib/onionwarden/receiver.priv
openssl pkey -in /var/lib/onionwarden/receiver.priv -pubout -out /var/lib/onionwarden/receiver.pub
chmod 600 /var/lib/onionwarden/receiver.priv
# then copy receiver.pub back to the laptop and commit
```

Two real problems once signing is live:

1. **Sign-then-publish gap**: between `genpkey` (priv changes) and
   the operator committing the new `receiver.pub` to the repo and
   collectors pulling it, any signed digest is unverifiable. The
   pinned-on-collector `receiver.pub` is the OLD one.

2. **No grace period for in-flight signed messages**: a digest signed
   with the old key just before rotation will still be in transit;
   collectors that fetch it after rotation can't verify it (the old
   pubkey is no longer the live one). Until the collector's pinned
   pubkey is rotated too, EITHER the old- OR new-signed messages will
   fail verification.

**Fix (forward-looking):** when signing goes live, the protocol should
support two simultaneous trusted pubkeys (a "previous" pin alongside
the "current" pin) for a defined overlap window. Document the rotation
as a 4-step protocol:

1. Generate new keypair (the rotation script's job).
2. Publish new `receiver.pub` to the repo AND keep the previous one as
   `receiver.pub.prev`.
3. Roll collectors to pin BOTH pubkeys (config knob:
   `verify_pubkey_paths = ["receiver.pub", "receiver.pub.prev"]`).
4. After the slowest in-flight signed-message TTL has elapsed (24h is
   ample given today's digest cadence), drop `.prev`.

This means the rotation window is "as long as it takes to roll
collectors", which is a controlled-and-monitored operation, not a
race. R4 updates MIGRATION_TO_PROXMOX.md with this 4-step protocol
and adds a `verify_pubkey_paths` design note pointing future
implementers at the right shape.

### F3 — `.priv` mode + ownership not asserted after generation (defensive)

`scripts/generate-receiver-key.sh` sets `chmod 0600` on the priv and
`0644` on the pub, but does NOT `chown`. On the deployed receiver,
that means whoever-ran-the-script owns the file — typically `root` if
run via sudo. Fine if the consuming code path also runs as root (or
the file is chmod'd group-readable). Today no consumer, so dormant —
but worth pinning before activation.

**Fix:** add a `--owner USER:GROUP` flag to both generate + rotate
scripts. Default: `onionwarden:onionwarden` (matches
`/var/lib/onionwarden` ownership in the deploy runbook).

### F4 — Pubkey-fingerprint output for human verification (nice-to-have)

The scripts don't print the SHA-256 fingerprint of the new `.pub`,
which is what the operator should compare across receiver-vs-laptop
to confirm the file was copied without corruption. Today the operator
has to remember to `openssl dgst -sha256 receiver.pub` themselves.

**Fix:** both generate + rotate scripts print
`pubkey sha256: <hex>` on success.

## Fix application

R4 ships:
- `scripts/rotate-receiver-key.sh` (new).
- Updates `scripts/generate-receiver-key.sh` to:
  - accept `--owner USER:GROUP`
  - print `pubkey sha256: <hex>` on success
- Updates `receiver/MIGRATION_TO_PROXMOX.md` §"Rotate or keep" with
  the 4-step dual-pin rotation protocol that closes the
  verification gap, and pointers to the new scripts.
- No code in the receiver itself changes — the keypair remains inert
  by design until a separate, deliberate signing-of-digests change.
