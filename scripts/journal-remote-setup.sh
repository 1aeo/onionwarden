#!/usr/bin/env bash
# scripts/journal-remote-setup.sh — configure the off-box RECEIVER to ingest
# journals from the fleet via systemd-journal-remote (PLAN §6, L6). The passive
# counterpart to scripts/journal-ship-setup.sh: it renders the listen-socket +
# remote drop-ins, creates the per-host journal store, and (optionally) enables
# the listener. SplitMode=host gives one journal per relay under
# /var/log/journal/remote/remote-<host>.journal.
#
# Usage:
#   journal-remote-setup.sh [--port 19532] [--cert-dir DIR] [--http]
#                           [--journal-dir DIR] [--root DIR]
#                           [--print] [--enable] [--dry-run]
#
# Idempotent: re-running renders byte-identical drop-ins and re-creates the same
# tree, so it is safe to run on every receiver-config change. Run as root on the
# receiver for the real install (socket + journal store need privilege).
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
TMPL="$SRC_DIR/journal"

PORT="19532"
CERT_DIR="/etc/onionwarden/journal"
JOURNAL_DIR="/var/log/journal/remote"
HTTP=0 ROOT="" PRINT=0 ENABLE=0 DRY=0

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)        PORT=$2; shift 2 ;;
    --cert-dir)    CERT_DIR=$2; shift 2 ;;
    --http)        HTTP=1; shift ;;
    --journal-dir) JOURNAL_DIR=$2; shift 2 ;;
    --root)        ROOT=$2; shift 2 ;;
    --print)       PRINT=1; shift ;;
    --enable)      ENABLE=1; shift ;;
    --dry-run)     DRY=1; shift ;;
    -h|--help)     usage 0 ;;
    *) echo "journal-remote-setup: unknown argument: $1" >&2; usage 1 ;;
  esac
done

say() { printf 'journal-remote: %s\n' "$*" >&2; }
case "$PORT" in ''|*[!0-9]*) say "bad --port: $PORT"; exit 1 ;; esac
[ "$HTTP" = 1 ] && say "WARNING: --http accepts journals with no peer auth — lab only"

render() {
  local t=$1
  if [ "$HTTP" = 1 ]; then
    grep -vE '^(ServerKeyFile|ServerCertificateFile|TrustedCertificateFile)=' "$t"
  else
    cat "$t"
  fi | sed -e "s|@CERT_DIR@|$CERT_DIR|g" -e "s|@PORT@|$PORT|g"
}

REMOTE_D="$ROOT/etc/systemd/journal-remote.conf.d/10-onionwarden.conf"
SOCKET_D="$ROOT/etc/systemd/system/systemd-journal-remote.socket.d/10-onionwarden.conf"

emit() {  # TEMPLATE DEST
  local content dir
  content=$(render "$1")
  if [ "$PRINT" = 1 ]; then printf '=== %s ===\n%s\n\n' "$2" "$content"; return 0; fi
  dir=$(dirname "$2")
  if [ "$DRY" = 1 ]; then say "[dry] write $2"; return 0; fi
  mkdir -p "$dir"
  printf '%s\n' "$content" > "$2"
  say "wrote $2"
}

emit "$TMPL/journal-remote.conf.tmpl"   "$REMOTE_D"
emit "$TMPL/remote.socket.d.conf.tmpl"  "$SOCKET_D"

if [ "$PRINT" = 1 ]; then exit 0; fi

# per-host journal store (idempotent: mkdir -p, chown only if the user exists).
JDIR="$ROOT$JOURNAL_DIR"
if [ "$DRY" = 1 ]; then
  say "[dry] mkdir -p $JDIR (mode 2755, owner systemd-journal-remote)"
else
  mkdir -p "$JDIR"
  chmod 2755 "$JDIR" 2>/dev/null || true
  if id systemd-journal-remote >/dev/null 2>&1; then
    chown systemd-journal-remote:systemd-journal-remote "$JDIR" 2>/dev/null || true
  else
    say "NOTE: user systemd-journal-remote absent (install systemd-journal-remote pkg)"
  fi
  say "journal store ready: $JDIR"
fi

if [ "$HTTP" != 1 ] && [ "$DRY" != 1 ]; then
  cd_real="$ROOT$CERT_DIR"
  if [ ! -f "$cd_real/remote.key" ] || \
     [ ! -f "$cd_real/remote.crt" ] || \
     [ ! -f "$cd_real/ca.crt" ]; then
    say "NOTE: mTLS material not found in $CERT_DIR (remote.key/remote.crt/ca.crt)"
    say "      provision it out-of-band before enabling — see journal/README.md"
  fi
fi

if [ "$ENABLE" = 1 ]; then
  if [ -n "$ROOT" ]; then
    say "--enable cannot be combined with --root (would toggle the live host unit"
    say "against on-host config, not the files rendered under $ROOT)"
    exit 1
  fi
  if command -v systemctl >/dev/null 2>&1 && [ "$DRY" != 1 ]; then
    systemctl daemon-reload
    systemctl enable --now systemd-journal-remote.socket
    say "systemd-journal-remote.socket enabled on port $PORT"
  else
    say "skipping systemctl enable (systemctl absent or --dry-run)"
  fi
else
  say "rendered drop-ins; not enabled. Re-run with --enable (or: systemctl"
  say "daemon-reload && systemctl enable --now systemd-journal-remote.socket)"
fi
