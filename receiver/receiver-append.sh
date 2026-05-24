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
#    (set by receiver-setup.sh) as defence in depth;
#  - if invoked as `receiver-append.sh <expected_host>` (R1-F1), the script
#    binds this key's events to <expected_host>. A line whose JSON host_id
#    differs is rewritten to <expected_host> and logged. This contains the
#    blast radius of a stolen per-host key.
set -euo pipefail
umask 077   # R1-F2: keep events.log + counters off other local users

RECVROOT="${ONIONWARDEN_RECEIVER_ROOT:-$HOME/onionwarden}"
RATE_MAX="${ONIONWARDEN_APPEND_RATE_MAX:-180}"     # max lines / host / minute
MAX_LINE="${ONIONWARDEN_APPEND_MAX_LINE:-16384}"   # bytes
EXPECTED_HOST="${1:-}"                              # R1-F1: optional pin

mkdir -p "$RECVROOT"

minute=$(date -u +%Y%m%dT%H%M)
recvlog="$RECVROOT/receiver.log"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >> "$recvlog"; }

while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "$line" in
    '{'*) ;;
    *) log "reject malformed line"; continue ;;
  esac
  if [ "${#line}" -gt "$MAX_LINE" ]; then
    line="${line:0:$MAX_LINE}"
  fi
  host=$(printf '%s' "$line" \
    | sed -n 's/.*"host_id"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9_-]\{1,64\}\)".*/\1/p')
  [ -n "$host" ] || host="_unknown"
  case "$host" in *[!A-Za-z0-9_-]*) host="_invalid" ;; esac
  case "$host" in [._]*) host="_invalid" ;; esac

  # R1-F1: if the key is pinned to a specific host, enforce.
  if [ -n "$EXPECTED_HOST" ] && [ "$host" != "$EXPECTED_HOST" ]; then
    log "host-pin MISMATCH key=$EXPECTED_HOST line-host=$host -> routed to $EXPECTED_HOST"
    host="$EXPECTED_HOST"
  fi

  hd="$RECVROOT/$host"
  # R1-F4: don't abort the whole connection if mkdir fails for one host.
  if ! mkdir -p "$hd" 2>/dev/null; then
    log "skip mkdir-failed host=$host"
    continue
  fi

  rlf="$hd/.rate.$minute"
  rc=$(cat "$rlf" 2>/dev/null || printf 0)
  rc=$(( rc + 1 ))
  printf '%s\n' "$rc" > "$rlf"
  if [ "$rc" -gt "$RATE_MAX" ]; then
    if [ "$rc" -eq $(( RATE_MAX + 1 )) ]; then
      log "RATE-LIMIT host=$host exceeded $RATE_MAX/min"
    fi
    continue
  fi

  printf '%s\n' "$line" >> "$hd/events.log"
done

# Drop stale per-minute counters.
find "$RECVROOT" -name '.rate.*' -mmin +10 -delete 2>/dev/null || true
