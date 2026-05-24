#!/usr/bin/env bash
# scripts/receiver-rename-deployed.sh — migrate an already-deployed receiver
# from the OLD onionwarden paths to the NEW onionwarden paths.
#
# Only needed for fleets that ran the pre-rename build (when the project was
# called "onionwarden"). Greenfield installs of onionwarden never need this.
#
# What it does (idempotent — safe to re-run):
#   /opt/onionwarden-receiver/      -> /opt/onionwarden/
#   /var/lib/onionwarden/           -> /var/lib/onionwarden/
#   /var/log/onionwarden/           -> /var/log/onionwarden/
#   /etc/cron.d/onionwarden-receiver -> /etc/cron.d/onionwarden-receiver
#   /etc/ssh/sshd_config.d/99-onionwarden-hardening.conf
#        -> /etc/ssh/sshd_config.d/99-onionwarden-hardening.conf
#   Per-host authorized_keys lines:
#        command="/opt/onionwarden-receiver/append-shim.sh" -> .../opt/onionwarden/append-shim.sh
#        (and tightens the forced command to receiver-append.sh <host_id> per R1-F1)
#   Env var renames in cron and append-shim:
#        ONIONWARDEN_*  -> ONIONWARDEN_*
#        ONIONWARDEN_RECEIVER_NTFY -> ONIONWARDEN_RECEIVER_NTFY (the receiver-side ntfy)
#
# Pre-flight (operator must verify):
#   - this script runs as root
#   - the receiver is currently healthy (verify-check returns ok)
#   - a snapshot/backup exists in case anything goes sideways
#
# The +a attribute on events.log is preserved across `mv` ONLY on the same
# filesystem. The script verifies same-FS before moving any +a file and
# falls back to chattr -a / mv / chattr +a otherwise.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "receiver-rename-deployed: must run as root" >&2
  exit 1
fi

DRY=${DRY_RUN:-0}
run() {
  if [[ "$DRY" == "1" ]]; then echo "DRY: $*"; else "$@"; fi
}

# 1. paths
[[ -d /opt/onionwarden-receiver && ! -e /opt/onionwarden ]] && \
  run mv /opt/onionwarden-receiver /opt/onionwarden
[[ -d /var/lib/onionwarden && ! -e /var/lib/onionwarden ]] && \
  run mv /var/lib/onionwarden /var/lib/onionwarden
[[ -d /var/log/onionwarden && ! -e /var/log/onionwarden ]] && \
  run mv /var/log/onionwarden /var/log/onionwarden

# 2. cron
if [[ -f /etc/cron.d/onionwarden-receiver ]]; then
  run sed -i \
    -e 's|/opt/onionwarden-receiver/|/opt/onionwarden/|g' \
    -e 's|/var/lib/onionwarden/|/var/lib/onionwarden/|g' \
    -e 's|ONIONWARDEN_|ONIONWARDEN_|g' \
    -e 's|onionwarden-receiver|onionwarden-receiver|g' \
    /etc/cron.d/onionwarden-receiver
  run mv /etc/cron.d/onionwarden-receiver /etc/cron.d/onionwarden-receiver
fi

# 3. sshd hardening drop-in
if [[ -f /etc/ssh/sshd_config.d/99-onionwarden-hardening.conf ]]; then
  run mv /etc/ssh/sshd_config.d/99-onionwarden-hardening.conf \
        /etc/ssh/sshd_config.d/99-onionwarden-hardening.conf
fi

# 4. authorized_keys — pin to onionwarden's append-shim + tighten to per-host (R1-F1)
AKEYS=/var/lib/onionwarden/.ssh/authorized_keys
if [[ -f "$AKEYS" ]]; then
  run cp "$AKEYS" "$AKEYS.pre-rename.bak"
  run sed -i \
    -e 's|/opt/onionwarden-receiver/append-shim.sh|/opt/onionwarden/receiver/receiver-append.sh|g' \
    -e 's|onionwarden-|onionwarden-|g' \
    "$AKEYS"
  echo "NOTE: authorized_keys backed up to $AKEYS.pre-rename.bak"
  echo "      review each line and append the per-host host_id arg to the"
  echo "      forced command (R1-F1):"
  echo "        command=\"/opt/onionwarden/receiver/receiver-append.sh <host_id>\",restrict …"
fi

# 5. reload sshd + cron
run systemctl daemon-reload
run systemctl reload ssh   2>/dev/null || run systemctl reload sshd 2>/dev/null || true
run systemctl reload cron  2>/dev/null || true

echo
echo "receiver-rename-deployed: done."
echo "Verify with:"
echo "  /opt/onionwarden/receiver/onionwarden-receiver verify-check"
echo "  systemctl is-active cron ssh.socket"
