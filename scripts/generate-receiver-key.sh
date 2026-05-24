#!/usr/bin/env bash
# scripts/generate-receiver-key.sh — generate the receiver Ed25519 keypair.
#
# Run ONCE on the receiver host (for rotation, use rotate-receiver-key.sh).
# Produces:
#   /var/lib/onionwarden/receiver.priv   (0600, owner --owner)
#   /var/lib/onionwarden/receiver.pub    (0644, owner --owner; copy back + commit)
#
# Usage: generate-receiver-key.sh [PRIV] [PUB] [--owner USER:GROUP]
# Default owner is onionwarden:onionwarden (matches /var/lib/onionwarden).
#
# Refuses to overwrite an existing key — for rotation, run rotate-receiver-key.sh.

set -euo pipefail
umask 077

PRIV="/var/lib/onionwarden/receiver.priv"
PUB="/var/lib/onionwarden/receiver.pub"
OWNER="onionwarden:onionwarden"

positional=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --owner) OWNER="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) positional+=("$1"); shift ;;
  esac
done
[[ ${#positional[@]} -ge 1 ]] && PRIV="${positional[0]}"
[[ ${#positional[@]} -ge 2 ]] && PUB="${positional[1]}"

if [[ -e "$PRIV" || -e "$PUB" ]]; then
  echo "refuse: receiver key already exists at $PRIV / $PUB" >&2
  echo "        to rotate, use scripts/rotate-receiver-key.sh" >&2
  exit 1
fi

mkdir -p "$(dirname "$PRIV")"

openssl genpkey -algorithm ED25519 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"

chmod 0600 "$PRIV"
chmod 0644 "$PUB"
chown "$OWNER" "$PRIV" "$PUB" 2>/dev/null || \
  echo "WARN: chown $OWNER failed (need root?); files left with default ownership" >&2

fp=$(openssl dgst -sha256 -binary "$PUB" | xxd -p -c 256)
echo "wrote $PRIV (0600) and $PUB (0644) owned by $OWNER"
echo "pubkey sha256: $fp"
echo
echo "next:"
echo "  1. copy $PUB back to your laptop and commit to your fork at"
echo "     receiver/receiver.pub — collectors will pin its sha256 at install."
echo "  2. verify the sha256 matches before pinning: openssl dgst -sha256 $PUB"
