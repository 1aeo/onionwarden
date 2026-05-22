#!/usr/bin/env bash
# receiver/receiver-append.sh — append-only events.log handler (PLAN §4).
#
# This is the FORCED COMMAND behind the restricted SSH key in the receiver's
# authorized_keys (see receiver-setup.sh). A monitored host can therefore only
# *append* event lines — it can neither read history nor rewrite it. The key
# entry pins this command, so SSH_ORIGINAL_COMMAND is irrelevant and ignored.
#
# Hardening:
#  - host_id is extracted with a strict [A-Za-z0-9_-] character class, so a
#    malicious host_id cannot traverse out of the receiver root;
#  - per-host per-minute rate limiting (M7 flood resistance);
#  - over-long lines are truncated (a host cannot exhaust disk with one line);
#  - the per-host events.log carries the chattr +a append-only attribute
#    (set by receiver-setup.sh) as defence in depth.
set -euo pipefail

RECVROOT="${ONIONWARDEN_RECEIVER_ROOT:-$HOME/onionwarden}"
RATE_MAX="${ONIONWARDEN_APPEND_RATE_MAX:-180}"     # max lines / host / minute
MAX_LINE="${ONIONWARDEN_APPEND_MAX_LINE:-16384}"   # bytes
mkdir -p "$RECVROOT"

minute=$(date -u +%Y%m%dT%H%M)
recvlog="$RECVROOT/receiver.log"

while IFS= read -r line; do
  [ -n "$line" ] || continue
  # Only accept lines that look like our JSON events.
  case "$line" in
    '{'*) ;;
    *) printf '%s reject malformed line\n' "$(date -u +%FT%TZ)" >> "$recvlog"; continue ;;
  esac
  # Truncate an over-long line.
  if [ "${#line}" -gt "$MAX_LINE" ]; then
    line="${line:0:$MAX_LINE}"
  fi
  # Extract + sanitise host_id.
  host=$(printf '%s' "$line" | sed -n 's/.*"host_id":"\([A-Za-z0-9_-]\{1,64\}\)".*/\1/p')
  [ -n "$host" ] || host="_unknown"
  case "$host" in *[!A-Za-z0-9_-]*) host="_invalid" ;; esac

  hd="$RECVROOT/$host"
  mkdir -p "$hd"

  # Per-host per-minute rate limit.
  rlf="$hd/.rate.$minute"
  rc=$(cat "$rlf" 2>/dev/null || printf 0)
  rc=$(( rc + 1 ))
  printf '%s\n' "$rc" > "$rlf"
  if [ "$rc" -gt "$RATE_MAX" ]; then
    if [ "$rc" -eq $(( RATE_MAX + 1 )) ]; then
      printf '%s RATE-LIMIT host=%s exceeded %s/min\n' "$(date -u +%FT%TZ)" "$host" "$RATE_MAX" >> "$recvlog"
    fi
    continue
  fi

  printf '%s\n' "$line" >> "$hd/events.log"
done

# Drop stale per-minute counters.
find "$RECVROOT" -name '.rate.*' -mmin +10 -delete 2>/dev/null || true
