#!/usr/bin/env bash
# install.sh — the one and only bootstrap path through Phases 0-4 (PLAN §0.1, §6).
#
# Lays the identical onionwarden tree onto a host, generates /etc/onionwarden/host.conf
# from a reviewable answers file (M9 — not blind prompts), installs the systemd
# timers, embeds the pubkey-hash pin (C2), applies chattr +i where the FS allows
# it (§3.6), and leaves the host in the `bootstrapping` state (M2) ready for its
# first off-box-signed baseline.
#
# Usage:
#   install.sh --answers FILE --pubkey onionwarden.pub [options]
# Options:
#   --prefix DIR        code root           (default /opt/onionwarden)
#   --conf-dir DIR      per-host config     (default /etc/onionwarden)
#   --var-dir DIR       state + baseline    (default /var/lib/onionwarden)
#   --log-dir DIR       structured logs     (default /var/log/onionwarden)
#   --systemd-dir DIR   unit directory      (default /etc/systemd/system)
#   --no-systemd        skip systemctl (non-systemd host / test)
#   --no-immutable      skip chattr +i regardless of FS
#   --dry-run           print actions, change nothing
set -euo pipefail

SRC_DIR=$(cd "$(dirname "$0")" && pwd)

PREFIX="/opt/onionwarden"
CONF_DIR="/etc/onionwarden"
VAR_DIR="/var/lib/onionwarden"
LOG_DIR="/var/log/onionwarden"
SYSTEMD_DIR="/etc/systemd/system"
ANSWERS="" PUBKEY=""
DO_SYSTEMD=1 DO_IMMUTABLE=1 DRY=0

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --answers)     ANSWERS=$2; shift 2 ;;
    --pubkey)      PUBKEY=$2; shift 2 ;;
    --prefix)      PREFIX=$2; shift 2 ;;
    --conf-dir)    CONF_DIR=$2; shift 2 ;;
    --var-dir)     VAR_DIR=$2; shift 2 ;;
    --log-dir)     LOG_DIR=$2; shift 2 ;;
    --systemd-dir) SYSTEMD_DIR=$2; shift 2 ;;
    --no-systemd)  DO_SYSTEMD=0; shift ;;
    --no-immutable) DO_IMMUTABLE=0; shift ;;
    --dry-run)     DRY=1; shift ;;
    -h|--help)     usage 0 ;;
    *) echo "install.sh: unknown argument: $1" >&2; usage 1 ;;
  esac
done

say()  { printf 'install: %s\n' "$*" >&2; }
run()  { if [ "$DRY" = 1 ]; then printf 'install[dry]: %s\n' "$*" >&2; else eval "$@"; fi; }
die()  { printf 'install: FATAL: %s\n' "$*" >&2; exit 1; }

[ -n "$ANSWERS" ] || die "missing --answers FILE (the reviewed per-host answers)"
[ -f "$ANSWERS" ] || die "answers file not found: $ANSWERS"
[ -n "$PUBKEY" ]  || die "missing --pubkey onionwarden.pub (the fleet public key)"
[ -f "$PUBKEY" ]  || die "pubkey file not found: $PUBKEY"

# --- preflight ------------------------------------------------------------
if [ -r /etc/os-release ]; then
  os_id=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-unknown}")
  case "$os_id" in
    ubuntu|debian) say "OS: $os_id — supported" ;;
    *) say "WARNING: OS '$os_id' is not a supported target (ubuntu/debian)" ;;
  esac
fi
if ! command -v curl >/dev/null 2>&1; then
  if command -v wget >/dev/null 2>&1; then
    say "WARNING: curl absent — alerting will fall back to wget (L3)"
  else
    say "WARNING: neither curl nor wget present — install one before going live (L3)"
  fi
fi

# Required answers-file keys (M9: a typo'd endpoint must be catchable on review).
for key in host_id role deadman_provider deadman_url ntfy_url offbox_log_target; do
  if ! grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$ANSWERS"; then
    say "WARNING: answers file has no '$key' — host.conf will be incomplete"
  fi
done

# --- FS probe for chattr +i (§3.6) ----------------------------------------
IMMUTABLE_OK=0
if [ "$DO_IMMUTABLE" = 1 ]; then
  fs=$(stat -f -c %T "$(dirname "$PREFIX")" 2>/dev/null || printf unknown)
  case "$fs" in
    ext2/ext3|ext4|btrfs|xfs)
      if command -v chattr >/dev/null 2>&1; then IMMUTABLE_OK=1; say "immutable FS '$fs' — chattr +i will be applied"
      else say "N/A: chattr not installed — immutability skipped"; fi ;;
    *) say "N/A: immutable unsupported on FS '$fs' — falling back to detection-only" ;;
  esac
fi

# --- lay down the code tree ----------------------------------------------
say "installing code -> $PREFIX"
run "mkdir -p '$PREFIX'"
for d in bin lib lib/checks roles systemd; do
  run "mkdir -p '$PREFIX/$d'"
done
run "cp -p '$SRC_DIR'/bin/* '$PREFIX/bin/'"
run "cp -p '$SRC_DIR'/lib/*.sh '$SRC_DIR'/lib/*.py '$PREFIX/lib/'"
run "cp -p '$SRC_DIR'/lib/checks/*.sh '$PREFIX/lib/checks/'"
run "cp -p '$SRC_DIR'/roles/*.conf '$PREFIX/roles/'"
run "cp -p '$SRC_DIR'/systemd/* '$PREFIX/systemd/'"
run "cp -p '$SRC_DIR/VERSION' '$PREFIX/VERSION'"
[ -f "$SRC_DIR/PLAN.md" ] && run "cp -p '$SRC_DIR/PLAN.md' '$PREFIX/PLAN.md'"
run "cp -p '$PUBKEY' '$PREFIX/onionwarden.pub'"

# Permissions (§3.3): dirs 0755, files 0744, code root-owned.
if [ "$DRY" != 1 ]; then
  find "$PREFIX" -type d -exec chmod 0755 {} +
  find "$PREFIX" -type f -exec chmod 0744 {} +
  chmod 0644 "$PREFIX/onionwarden.pub" "$PREFIX/VERSION"
  [ "$(id -u)" = 0 ] && chown -R root:root "$PREFIX" 2>/dev/null || true
fi

# --- C2: embed the pubkey-hash pin into the installed verify.sh -----------
PUB_SHA=$(sha256sum "$PUBKEY" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$PUBKEY" | awk '{print $1}')
say "pinning pubkey sha256 = $PUB_SHA into lib/verify.sh (C2)"
if [ "$DRY" != 1 ]; then
  tmp=$(mktemp)
  sed "s/@PUBKEY_SHA256@/$PUB_SHA/" "$PREFIX/lib/verify.sh" > "$tmp"
  cat "$tmp" > "$PREFIX/lib/verify.sh"
  rm -f "$tmp"
fi

# --- per-host config ------------------------------------------------------
say "generating $CONF_DIR/host.conf from answers file"
run "mkdir -p '$CONF_DIR' '$CONF_DIR/keys'"
if [ "$DRY" != 1 ]; then
  {
    printf '# /etc/onionwarden/host.conf — generated by install.sh on %s\n' "$(date -u +%FT%TZ)"
    printf '# Source answers file: %s\n' "$ANSWERS"
    printf '# Review, then sign OFF-BOX: onionwarden-sign sign --key <priv> --file host.conf\n\n'
    cat "$ANSWERS"
  } > "$CONF_DIR/host.conf"
  chmod 0600 "$CONF_DIR/host.conf"
  chmod 0700 "$CONF_DIR/keys"
fi

# --- runtime dirs ---------------------------------------------------------
run "mkdir -p '$VAR_DIR/baseline' '$VAR_DIR/state' '$LOG_DIR'"
if [ "$DRY" != 1 ]; then
  chmod 0750 "$VAR_DIR" "$LOG_DIR" 2>/dev/null || true
fi

# M2: ship in the bootstrapping state — signature-CRIT suppressed until the
# first off-box-signed baseline + host.conf verify on a real run.
run "touch '$VAR_DIR/state/bootstrapping'"
say "host left in BOOTSTRAPPING state — capture + sign the baseline next (PLAN §5)"

# --- systemd units --------------------------------------------------------
say "installing systemd units -> $SYSTEMD_DIR"
run "mkdir -p '$SYSTEMD_DIR'"
for u in "$SRC_DIR"/systemd/*; do
  run "cp -p '$u' '$SYSTEMD_DIR/$(basename "$u")'"
done
if [ "$DO_SYSTEMD" = 1 ] && command -v systemctl >/dev/null 2>&1; then
  run "systemctl daemon-reload"
  run "systemctl enable --now onionwarden-fast.timer onionwarden-slow.timer onionwarden-daily.timer"
else
  say "skipping systemctl enable (--no-systemd or systemctl absent)"
fi

# --- immutability (§3.6) — applied LAST so installation can write freely --
if [ "$IMMUTABLE_OK" = 1 ]; then
  say "applying chattr +i to the protected set"
  for p in "$PREFIX"/bin/* "$PREFIX"/lib/*.sh "$PREFIX"/lib/*.py \
           "$PREFIX"/lib/checks/*.sh "$PREFIX"/roles/*.conf \
           "$PREFIX/onionwarden.pub" "$PREFIX/VERSION" \
           "$CONF_DIR/host.conf"; do
    [ -e "$p" ] && run "chattr +i '$p'"
  done
  for u in "$SYSTEMD_DIR"/onionwarden-*.timer "$SYSTEMD_DIR"/onionwarden-*.service; do
    [ -e "$u" ] && run "chattr +i '$u'"
  done
fi

say "install complete."
say "next: run 'onionwarden-baseline collect', sign it off-box, push the signed"
say "baseline, then the first dispatch will leave the bootstrapping state."
