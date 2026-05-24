#!/usr/bin/env bash
# scripts/rotate-receiver-key.sh — rotate the receiver Ed25519 keypair safely.
#
# Step 1 of the 4-step rotation protocol (see MIGRATION_TO_PROXMOX.md
# §"Rotate the receiver signing key").
#
# Procedure:
#   1. verify the existing pair matches (refuse to rotate a broken pair)
#   2. generate a new keypair in <PRIV>.new / <PUB>.new
#   3. mv old to <PRIV>.YYYYMMDD-HHMMSS.bak / <PUB>.YYYYMMDD-HHMMSS.bak
#   4. mv .new into live names (single mv, atomic on the same filesystem)
#   5. print the new sha256 fingerprint
#
# After this script: the OLD pubkey is renamed to *.bak, the NEW pubkey is
# live. The receiver immediately uses the new keypair for any future
# signing. Collectors will continue to verify against the OLD pubkey until
# the new one is committed to the repo + rolled out (the dual-pin window).
#
# Usage: rotate-receiver-key.sh [PRIV] [PUB] [--owner USER:GROUP]

set -euo pipefail
umask 077

PRIV="/var/lib/onionwarden/receiver.priv"
PUB="/var/lib/onionwarden/receiver.pub"
OWNER="onionwarden:onionwarden"

positional=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --owner) OWNER="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) positional+=("$1"); shift ;;
  esac
done
[[ ${#positional[@]} -ge 1 ]] && PRIV="${positional[0]}"
[[ ${#positional[@]} -ge 2 ]] && PUB="${positional[1]}"

[[ -f "$PRIV" && -f "$PUB" ]] || {
  echo "refuse: no existing keypair at $PRIV / $PUB — use generate-receiver-key.sh first" >&2
  exit 1
}

# Verify the existing pair matches before we touch anything.
exp_pub=$(openssl pkey -in "$PRIV" -pubout 2>/dev/null)
cur_pub=$(cat "$PUB")
if [[ "$exp_pub" != "$cur_pub" ]]; then
  echo "refuse: $PRIV does not match $PUB — rotate manually after investigating" >&2
  exit 1
fi

stamp=$(date -u +%Y%m%d-%H%M%S)

# Generate new pair in a sidecar.
openssl genpkey -algorithm ED25519 -out "$PRIV.new"
openssl pkey -in "$PRIV.new" -pubout -out "$PUB.new"
chmod 0600 "$PRIV.new"
chmod 0644 "$PUB.new"

# Move old aside; activate new. Each mv is atomic on the same filesystem.
mv "$PRIV" "$PRIV.$stamp.bak"
mv "$PUB"  "$PUB.$stamp.bak"
mv "$PRIV.new" "$PRIV"
mv "$PUB.new"  "$PUB"

chown "$OWNER" "$PRIV" "$PUB" "$PRIV.$stamp.bak" "$PUB.$stamp.bak" 2>/dev/null || \
  echo "WARN: chown $OWNER failed (need root?)" >&2

new_fp=$(openssl dgst -sha256 -binary "$PUB" | xxd -p -c 256)
old_fp=$(openssl dgst -sha256 -binary "$PUB.$stamp.bak" | xxd -p -c 256)

cat <<EOF
rotated keypair:
  old pubkey backed up to: $PUB.$stamp.bak  (sha256: $old_fp)
  new pubkey is now LIVE:  $PUB              (sha256: $new_fp)
  old priv backed up to:   $PRIV.$stamp.bak (delete when overlap window closes)

next steps — DO NOT skip these or signed messages will fail verification:
  1. copy $PUB to your laptop. Verify sha256 matches: $new_fp
  2. in your repo fork: commit BOTH:
       receiver/receiver.pub       <- new pubkey
       receiver/receiver.pub.prev  <- old pubkey ($PUB.$stamp.bak)
  3. roll the dual-pin config to every collector. Confirm the rollout.
  4. after the overlap window (>= longest signed-message TTL; 24h is ample
     for digest cadence), commit a follow-up that removes
     receiver/receiver.pub.prev. Then rm $PUB.$stamp.bak from the receiver.
EOF
