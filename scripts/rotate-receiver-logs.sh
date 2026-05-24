#!/usr/bin/env bash
# scripts/rotate-receiver-logs.sh — weekly rotation for append-only events.log.
#
# Must run as root (chattr -a needs CAP_LINUX_IMMUTABLE). Suggested cron:
#   0 4 * * 0  root  /opt/onionwarden/scripts/rotate-receiver-logs.sh
#
# For each per-host events.log under $ROOT:
#   1. chattr -a              (lift the append-only attribute)
#   2. mv events.log events.log.YYYYMMDD-HHMMSS
#   3. gzip the rotated file
#   4. : > events.log         (recreate empty)
#   5. chattr +a              (re-arm)
#
# A failure mid-rotation leaves the file un-append-only momentarily; we
# always try to chattr +a in a trap to minimize that window.

set -euo pipefail
ROOT="${ONIONWARDEN_RECEIVER_ROOT:-/var/lib/onionwarden/data}"
STAMP=$(date -u +%Y%m%d-%H%M%S)

if [[ $EUID -ne 0 ]]; then
  echo "rotate-receiver-logs: must run as root (chattr -a requires CAP_LINUX_IMMUTABLE)" >&2
  exit 1
fi

[[ -d "$ROOT" ]] || { echo "rotate-receiver-logs: ROOT not found: $ROOT" >&2; exit 1; }

rotate_one() {
  local f=$1
  [[ -f "$f" ]] || return 0
  trap 'chattr +a "$f" 2>/dev/null || true' RETURN
  chattr -a "$f" 2>/dev/null || true
  mv "$f" "$f.$STAMP"
  gzip "$f.$STAMP"
  : > "$f"
  chattr +a "$f" 2>/dev/null || true
  trap - RETURN
  echo "rotated $f -> $f.$STAMP.gz"
}

for hd in "$ROOT"/*/; do
  [[ -d "$hd" ]] || continue
  rotate_one "$hd/events.log"
done

# Also rotate the receiver-wide log.
rotate_one "$ROOT/receiver.log"

# Optional retention (uncomment to enable, defaults disabled — operator policy):
# find "$ROOT" -name 'events.log.*.gz' -mtime +365 -delete
