#!/usr/bin/env bash
# receiver/receiver-setup.sh — prepare the off-box receiver host (PLAN §4, Phase 0).
#
# Run ONCE on the trusted, off-fleet receiver host. Creates the per-host
# events.log tree, makes each events.log append-only (chattr +a) as defence in
# depth, installs the append handler, and prints the restricted authorized_keys
# line each monitored host's outbound key must be added under.
#
# Usage: receiver-setup.sh --hosts "relay-a eval-host ..." [--root DIR] [--pubkey FILE]
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT="${ONIONWARDEN_RECEIVER_ROOT:-$HOME/onionwarden}"
HOSTS=""
PUBKEY=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)   ROOT=$2; shift 2 ;;
    --hosts)  HOSTS=$2; shift 2 ;;
    --pubkey) PUBKEY=$2; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "receiver-setup: unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$HOSTS" ] || { echo "receiver-setup: --hosts is required" >&2; exit 1; }

BINDIR="$ROOT/.bin"
mkdir -p "$ROOT" "$BINDIR"
cp -p "$SRC_DIR/receiver-append.sh" "$BINDIR/receiver-append.sh"
cp -p "$SRC_DIR/onionwarden-receiver" "$BINDIR/onionwarden-receiver"
chmod 0755 "$BINDIR/receiver-append.sh" "$BINDIR/onionwarden-receiver"

for h in $HOSTS; do
  hd="$ROOT/$h"
  mkdir -p "$hd"
  [ -f "$hd/events.log" ] || : > "$hd/events.log"
  # Append-only attribute: even on the receiver, events.log can only be
  # appended, never rewritten. Best-effort (skips silently on an FS without it).
  chattr +a "$hd/events.log" 2>/dev/null \
    && echo "receiver-setup: $hd/events.log -> append-only" \
    || echo "receiver-setup: chattr +a unavailable for $hd/events.log (FS limitation)"
done

cat <<EOF

receiver-setup: tree ready under $ROOT
Append handler: $BINDIR/receiver-append.sh
Verifier:       $BINDIR/onionwarden-receiver  (verify-record|verify-check|seqcheck|digest)

Add ONE line per monitored host to the receiver account's ~/.ssh/authorized_keys,
pinning the forced command so a host can only APPEND, never read or rewrite:

  command="$BINDIR/receiver-append.sh",restrict <ssh-ed25519 PUBKEY> onionwarden-<host>

Then schedule on the receiver (cron):
  */5 * * * *  $BINDIR/onionwarden-receiver verify-check
  */5 * * * *  $BINDIR/onionwarden-receiver seqcheck
  0 7 * * *    $BINDIR/onionwarden-receiver digest
Capture the known-good ONCE, from trusted hosts:
  $BINDIR/onionwarden-receiver verify-record
EOF

if [ -n "$PUBKEY" ] && [ -f "$PUBKEY" ]; then
  echo
  echo "Supplied host key — ready-to-paste authorized_keys line:"
  echo "command=\"$BINDIR/receiver-append.sh\",restrict $(cat "$PUBKEY")"
fi
