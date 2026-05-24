#!/usr/bin/env bash
# receiver/receiver-setup.sh — prepare the off-box receiver host (PLAN §4, Phase 0).
#
# Run ONCE on the trusted, off-fleet receiver host. Creates the per-host
# events.log tree, makes each events.log append-only (chattr +a) as defence in
# depth, installs the append handler, and prints the restricted authorized_keys
# line each monitored host's outbound key must be added under.
#
# Usage: receiver-setup.sh --hosts "relay-a relay-b ..." [--root DIR] [--pubkey FILE]
#
# Best run as root so chattr +a (CAP_LINUX_IMMUTABLE) succeeds — re-run as the
# onionwarden user if you have already set the +a attribute and only need to
# refresh the tree.
set -euo pipefail
umask 077

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
# R1-F3: whitespace in ROOT would break the printed authorized_keys line.
case "$ROOT" in *[[:space:]]*) echo "receiver-setup: --root must not contain whitespace" >&2; exit 1 ;; esac

BINDIR="$ROOT/.bin"
mkdir -p "$ROOT" "$BINDIR"
cp -p "$SRC_DIR/receiver-append.sh" "$BINDIR/receiver-append.sh"
cp -p "$SRC_DIR/onionwarden-receiver" "$BINDIR/onionwarden-receiver"
chmod 0755 "$BINDIR/receiver-append.sh" "$BINDIR/onionwarden-receiver"

chattr_ok=1
for h in $HOSTS; do
  hd="$ROOT/$h"
  mkdir -p "$hd"
  [ -f "$hd/events.log" ] || : > "$hd/events.log"
  # R1-F5: classify the chattr failure mode rather than always blaming the FS.
  if chattr +a "$hd/events.log" 2>/tmp/cw.err; then
    echo "receiver-setup: $hd/events.log -> append-only"
  else
    err=$(cat /tmp/cw.err 2>/dev/null || true); rm -f /tmp/cw.err
    case "$err" in
      *"Operation not permitted"*) echo "receiver-setup: chattr +a needs root (CAP_LINUX_IMMUTABLE) — re-run via sudo for $hd"; chattr_ok=0 ;;
      *) echo "receiver-setup: chattr +a unavailable for $hd/events.log (FS limitation: $err)"; chattr_ok=0 ;;
    esac
  fi
done

cat <<EOF

receiver-setup: tree ready under $ROOT
Append handler: $BINDIR/receiver-append.sh
Verifier:       $BINDIR/onionwarden-receiver  (verify-record|verify-check|seqcheck|digest)

Add ONE line per monitored host to the receiver account's ~/.ssh/authorized_keys,
pinning the forced command so a host can only APPEND to ITS OWN events.log,
never read or rewrite:

  command="$BINDIR/receiver-append.sh <host>",restrict <ssh-ed25519 PUBKEY> onionwarden-<host>

The "<host>" argument (R1-F1) binds this key to that host_id; any line whose
JSON host_id is different is rewritten to "<host>" and logged.

Then schedule on the receiver (cron):
  */5 * * * *  $BINDIR/onionwarden-receiver verify-check
  */5 * * * *  $BINDIR/onionwarden-receiver seqcheck
  0 7 * * *    $BINDIR/onionwarden-receiver digest
Capture the known-good ONCE, from trusted hosts:
  $BINDIR/onionwarden-receiver verify-record
EOF

[ "$chattr_ok" = "1" ] || echo "WARN: chattr +a did not apply to every events.log — append-only defence in depth is OFF on those files."

if [ -n "$PUBKEY" ] && [ -f "$PUBKEY" ]; then
  echo
  echo "Supplied host key — ready-to-paste authorized_keys line (substitute <host> with the host_id this key serves):"
  echo "command=\"$BINDIR/receiver-append.sh <host>\",restrict $(cat "$PUBKEY")"
fi
