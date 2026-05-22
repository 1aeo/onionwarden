# shellcheck shell=bash
# lib/verify.sh — Ed25519 signature verification (PLAN §3.5, C2).
#
# Every baseline manifest and host.conf is Ed25519-signed off-box; the watchdog
# verifies them against onionwarden.pub on every run. Primary backend is `openssl
# pkeyutl` (OpenSSL 3.x on Ubuntu 24.04 / Debian 13 — no extra package).
# Fallback is the bundled pure-Python verifier (lib/ed25519.py) for hosts whose
# openssl predates Ed25519, and for the test host.
#
# C2 hardening: a literal pin of sha256(onionwarden.pub) is baked in here by
# install.sh. If the pin is set, verification refuses a pubkey whose hash does
# not match — so a naive on-box `.pub` swap fails even before the off-box
# receiver anchor (§4) catches it.

if [ -n "${_ONIONWARDEN_VERIFY_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_VERIFY_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# install.sh rewrites the next line, replacing the token with the real hash.
# Until then it stays as the literal placeholder and the pin check is skipped.
ONIONWARDEN_PUBKEY_SHA256_PIN="@PUBKEY_SHA256@"

_onionwarden_verify_backend=""

# Decide once whether openssl can handle Ed25519. Probe is read-only: if
# openssl can parse the Ed25519 public-key PEM, it supports the algorithm.
_onionwarden_pick_backend() {
  local pubkey=$1
  if [ -n "$_onionwarden_verify_backend" ]; then return 0; fi
  if [ -n "${ONIONWARDEN_VERIFY_BACKEND:-}" ]; then
    _onionwarden_verify_backend="$ONIONWARDEN_VERIFY_BACKEND"
    return 0
  fi
  if command -v openssl >/dev/null 2>&1 \
     && openssl pkey -pubin -in "$pubkey" -noout >/dev/null 2>&1; then
    _onionwarden_verify_backend="openssl"
  elif command -v python3 >/dev/null 2>&1; then
    _onionwarden_verify_backend="python"
  else
    _onionwarden_verify_backend="none"
  fi
}

onionwarden_verify_backend_name() {
  printf '%s' "${_onionwarden_verify_backend:-unknown}"
}

# Internal: confirm the pubkey file's hash matches the baked-in pin.
_onionwarden_pubkey_pin_ok() {
  local pubkey=$1 got
  case "$ONIONWARDEN_PUBKEY_SHA256_PIN" in
    @PUBKEY_SHA256@|"") return 0 ;;  # unpinned (pre-install / dev)
  esac
  got=$(sha256_file "$pubkey")
  [ "$got" = "$ONIONWARDEN_PUBKEY_SHA256_PIN" ]
}

# onionwarden_verify_sig PUBKEY FILE SIGFILE -> 0 valid, 1 invalid/error.
# Distinguishes "no backend" (die) from "bad signature" (return 1) so a
# genuine rejection is never silently downgraded.
onionwarden_verify_sig() {
  local pubkey=$1 file=$2 sig=$3
  [ -f "$pubkey" ] || { log_err "verify: pubkey missing: $pubkey"; return 1; }
  [ -f "$file" ]   || { log_err "verify: file missing: $file"; return 1; }
  [ -f "$sig" ]    || { log_err "verify: signature missing: $sig"; return 1; }

  if ! _onionwarden_pubkey_pin_ok "$pubkey"; then
    log_err "verify: pubkey hash does not match the embedded pin (C2) — refusing"
    return 1
  fi

  _onionwarden_pick_backend "$pubkey"
  case "$_onionwarden_verify_backend" in
    openssl)
      openssl pkeyutl -verify -pubin -inkey "$pubkey" \
        -rawin -in "$file" -sigfile "$sig" >/dev/null 2>&1
      ;;
    python)
      python3 "$(onionwarden_root)/lib/ed25519.py" verify "$pubkey" "$file" "$sig" >/dev/null 2>&1
      ;;
    *)
      die "verify: no Ed25519 backend (need openssl 3.x or python3)"
      ;;
  esac
}

# onionwarden_verify_artifact PUBKEY FILE — expects FILE.sig alongside FILE.
onionwarden_verify_artifact() {
  onionwarden_verify_sig "$1" "$2" "$2.sig"
}
