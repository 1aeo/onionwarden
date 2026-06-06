#!/usr/bin/env bash
# scripts/journal-ship-setup.sh — configure off-box journal shipping on a
# MONITORED host (PLAN §2.7 / §6, L6). Renders three drop-ins from the templates
# in journal/ and (optionally) enables systemd-journal-upload so the host's
# journal streams to the receiver's systemd-journal-remote. Closes the
# log-vacuum gap: a `journalctl --vacuum-time=1s` wipe is now detectable because
# the receiver already holds the copy.
#
# Usage:
#   journal-ship-setup.sh --receiver-url https://recv.example.net:19532 [opts]
#   journal-ship-setup.sh --receiver-host recv.example.net [--port 19532] [opts]
# Options:
#   --cert-dir DIR   mTLS material dir        (default /etc/onionwarden/journal)
#   --http           INSECURE: plain http, no client/server certs (lab only)
#   --root DIR       write under DIR (scratch/test root; default /)
#   --print          render every drop-in to stdout, write nothing
#   --enable         systemctl enable --now systemd-journal-upload (needs systemd)
#   --dry-run        print actions, change nothing
#
# Rendering is deterministic — re-running overwrites each drop-in with identical
# content (idempotent). Provision the mTLS files (upload.key/crt, ca.crt) into
# --cert-dir out-of-band before going live; see journal/README.md.
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
TMPL="$SRC_DIR/journal"

RECEIVER_URL="" RECEIVER_HOST="" PORT="19532"
CERT_DIR="/etc/onionwarden/journal"
HTTP=0 ROOT="" PRINT=0 ENABLE=0 DRY=0
SYSTEMCTL=${SYSTEMCTL:-systemctl}

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --receiver-url)  RECEIVER_URL=$2; shift 2 ;;
    --receiver-host) RECEIVER_HOST=$2; shift 2 ;;
    --port)          PORT=$2; shift 2 ;;
    --cert-dir)      CERT_DIR=$2; shift 2 ;;
    --http)          HTTP=1; shift ;;
    --root)          ROOT=$2; shift 2 ;;
    --print)         PRINT=1; shift ;;
    --enable)        ENABLE=1; shift ;;
    --dry-run)       DRY=1; shift ;;
    -h|--help)       usage 0 ;;
    *) echo "journal-ship-setup: unknown argument: $1" >&2; usage 1 ;;
  esac
done

say() { printf 'journal-ship: %s\n' "$*" >&2; }

# Resolve the upload URL.
if [ -z "$RECEIVER_URL" ]; then
  [ -n "$RECEIVER_HOST" ] || { say "need --receiver-url or --receiver-host"; usage 1; }
  case "$PORT" in ''|*[!0-9]*) say "bad --port: $PORT"; exit 1 ;; esac
  if [ "$HTTP" = 1 ]; then RECEIVER_URL="http://$RECEIVER_HOST:$PORT"
  else RECEIVER_URL="https://$RECEIVER_HOST:$PORT"; fi
fi
# Keep the scheme and the --http escape hatch in lockstep: an http:// URL must
# be an explicit opt-in, and --http must not be paired with an https:// URL
# (which would leave the mTLS config blocks in place over a cleartext intent).
case "$RECEIVER_URL" in
  http://*)
    [ "$HTTP" = 1 ] || { say "http:// receiver URLs require --http (cleartext, lab only)"; exit 1; }
    ;;
  https://*)
    [ "$HTTP" = 0 ] || { say "--http cannot be combined with an https:// receiver URL"; exit 1; }
    ;;
esac
if [ "$HTTP" = 1 ]; then
  say "WARNING: --http ships journals in CLEARTEXT with no peer auth — lab use only"
fi

# render TEMPLATE -> stdout (substitute placeholders; strip cert lines for --http).
render() {
  local t=$1 base
  base=$(basename "$t")
  if [ "$HTTP" = 1 ]; then
    case "$base" in
      journal-upload.conf.tmpl)
        grep -vE '^(ServerKeyFile|ServerCertificateFile|TrustedCertificateFile)=' "$t"
        ;;
      upload.service.d.conf)
        sed '/^# BEGIN_MTLS_CREDENTIALS$/,/^# END_MTLS_CREDENTIALS$/d' "$t"
        ;;
      *)
        cat "$t"
        ;;
    esac
  else
    cat "$t"
  fi | sed -e "s|@URL@|$RECEIVER_URL|g" \
           -e "s|@CERT_DIR@|$CERT_DIR|g" \
           -e "s|@PORT@|$PORT|g"
}

# Destination paths (under ROOT, which is "" for a real install = absolute /).
JOURNALD_D="$ROOT/etc/systemd/journald.conf.d/10-onionwarden.conf"
UPLOAD_D="$ROOT/etc/systemd/journal-upload.conf.d/10-onionwarden.conf"
UPLOAD_SVC_D="$ROOT/etc/systemd/system/systemd-journal-upload.service.d/10-onionwarden.conf"

emit() {  # SRC_TEMPLATE DEST
  local content dir
  content=$(render "$1")
  if [ "$PRINT" = 1 ]; then
    printf '=== %s ===\n%s\n\n' "$2" "$content"
    return 0
  fi
  dir=$(dirname "$2")
  if [ "$DRY" = 1 ]; then say "[dry] write $2"; return 0; fi
  mkdir -p "$dir"
  printf '%s\n' "$content" > "$2"
  say "wrote $2"
}

emit "$TMPL/journald-onionwarden.conf" "$JOURNALD_D"
emit "$TMPL/journal-upload.conf.tmpl"  "$UPLOAD_D"
emit "$TMPL/upload.service.d.conf"     "$UPLOAD_SVC_D"

if [ "$PRINT" = 1 ]; then exit 0; fi

if [ "$HTTP" != 1 ] && [ "$DRY" != 1 ] && [ "$PRINT" != 1 ]; then
  cd_real="${ROOT}${CERT_DIR}"
  if [ ! -f "$cd_real/upload.key" ] || \
     [ ! -f "$cd_real/upload.crt" ] || \
     [ ! -f "$cd_real/ca.crt" ]; then
    say "NOTE: mTLS material not found in $CERT_DIR (upload.key/upload.crt/ca.crt)"
    say "      provision it out-of-band before enabling — see journal/README.md"
  fi
fi

if [ "$ENABLE" = 1 ]; then
  if [ -n "$ROOT" ] && [ "$DRY" != 1 ] && [ "$SYSTEMCTL" = systemctl ]; then
    say "--enable cannot be combined with --root (would restart live host units"
    say "instead of using the files rendered under $ROOT)"
    exit 1
  fi
  if command -v "$SYSTEMCTL" >/dev/null 2>&1 && [ "$DRY" != 1 ]; then
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" restart systemd-journald
    "$SYSTEMCTL" enable systemd-journal-upload.service
    "$SYSTEMCTL" restart systemd-journal-upload.service
    say "systemd-journal-upload enabled and restarted"
  else
    say "skipping systemctl enable (systemctl absent or --dry-run)"
  fi
else
  say "rendered drop-ins; not enabled. Re-run with --enable (or: systemctl"
  say "daemon-reload && systemctl enable --now systemd-journal-upload.service)"
fi
