#!/usr/bin/env bash
# ssh-hardening/apply-ssh-hardening.sh — fleet SSH hardening (PLAN §6 Phase 2).
#
# Installs the keys-only / no-root / no-password sshd drop-in, validates it
# with `sshd -t` BEFORE reloading (so a bad config never locks anyone out),
# and reminds the operator to re-baseline `sshd -T` afterwards.
#
# Usage: apply-ssh-hardening.sh --confirm [--dry-run] [--sshd-config-dir DIR]
#
# SAFETY: refuses to proceed unless the invoking (or target) account has at
# least one SSH public key — applying keys-only auth with no keys present is a
# guaranteed lockout. Override that guard only with --i-have-console.
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
CONFD="/etc/ssh/sshd_config.d"
DROPIN="60-onionwarden-hardening.conf"
CONFIRM=0 DRY=0 FORCE_NOKEYS=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --confirm)          CONFIRM=1; shift ;;
    --dry-run)          DRY=1; shift ;;
    --sshd-config-dir)  CONFD=$2; shift 2 ;;
    --i-have-console)   FORCE_NOKEYS=1; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "apply-ssh-hardening: unknown argument: $1" >&2; exit 1 ;;
  esac
done

say() { printf 'ssh-hardening: %s\n' "$*" >&2; }

if [ "$CONFIRM" != 1 ]; then
  say "this DISABLES password + root SSH login fleet-wide. Re-run with --confirm."
  exit 1
fi

# Lockout guard: at least one authorized_keys must exist somewhere.
if [ "$FORCE_NOKEYS" != 1 ]; then
  found=0
  while IFS=: read -r _ _ _ _ _ home _; do
    [ -n "$home" ] || continue
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -s "$f" ] && found=1
    done
  done < /etc/passwd
  if [ "$found" != 1 ]; then
    say "REFUSING: no authorized_keys found on this host — keys-only auth would lock you out."
    say "Add your key first, or pass --i-have-console if you have console/OOB access."
    exit 2
  fi
fi

target="$CONFD/$DROPIN"
if [ "$DRY" = 1 ]; then
  say "[dry-run] would install $SRC_DIR/sshd_hardening.conf -> $target"
  say "[dry-run] would run: sshd -t  then  systemctl reload ssh"
  exit 0
fi

mkdir -p "$CONFD"
cp "$SRC_DIR/sshd_hardening.conf" "$target"
chmod 0644 "$target"
say "installed $target"

# Validate BEFORE reload — a syntax error must not break sshd.
if command -v sshd >/dev/null 2>&1; then
  if ! sshd -t 2>/dev/null; then
    say "sshd -t FAILED — removing drop-in, NOT reloading"
    rm -f "$target"
    exit 3
  fi
  say "sshd -t passed"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
    say "could not reload ssh — reload it manually"
fi

say "SSH hardening applied. NEXT: re-baseline this host so sshd -T matches:"
say "  onionwarden-baseline collect  ->  sign off-box  ->  push signed baseline"
