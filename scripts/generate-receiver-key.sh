#!/usr/bin/env bash
# scripts/generate-receiver-key.sh — generate the receiver Ed25519 keypair.
#
# Run ONCE on the receiver host. Produces:
#   /var/lib/onionwarden/receiver.priv   (root:root, 0600 — keep on the box)
#   /var/lib/onionwarden/receiver.pub    (copy back to your laptop + commit)
#
# Idempotent: refuses to overwrite an existing key. Rotate via
# scripts/rotate-receiver-key.sh (or follow MIGRATION_TO_PROXMOX.md).

set -euo pipefail

PRIV="${1:-/var/lib/onionwarden/receiver.priv}"
PUB="${2:-/var/lib/onionwarden/receiver.pub}"

if [[ -e "$PRIV" || -e "$PUB" ]]; then
  echo "refuse: receiver key already exists at $PRIV / $PUB" >&2
  echo "        to rotate, move the old keys aside and re-run" >&2
  exit 1
fi

mkdir -p "$(dirname "$PRIV")"
umask 077

openssl genpkey -algorithm ED25519 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"

chmod 0600 "$PRIV"
chmod 0644 "$PUB"

echo "wrote $PRIV (0600) and $PUB (0644)"
echo
echo "next: copy $PUB back to your laptop and commit to your fork at"
echo "      receiver/receiver.pub — collectors pin its sha256 at install."
