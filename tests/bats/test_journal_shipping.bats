#!/usr/bin/env bats
# Off-box journal shipping (PLAN §6, L6): scripts/journal-ship-setup.sh (relay)
# and scripts/journal-remote-setup.sh (receiver). Covers drop-in RENDERING (URL
# / port / cert substitution, --http cert stripping) and the IDEMPOTENCY of the
# receiver setup. All runs are scratch-rooted; no systemctl, no real host.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  SHIP="$REPO/scripts/journal-ship-setup.sh"
  REMOTE="$REPO/scripts/journal-remote-setup.sh"
  ROOT=$(mktemp -d "${TMPDIR:-/tmp}/owarden-journal.XXXXXX")
}

teardown() {
  rm -rf "$ROOT"
}

fp() {  # fingerprint every file under $1 (path + content), order-stable
  ( cd "$1" && find . -type f | LC_ALL=C sort | while read -r f; do
      printf '%s\n' "$f"; cat "$f"; done )
}

stub_systemctl() {
  mkdir -p "$ROOT/bin"
  cat > "$ROOT/bin/systemctl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
if [ "$1" = "is-active" ] && [ "${2:-}" = "--quiet" ]; then
  case " ${SYSTEMCTL_ACTIVE_UNITS:-} " in
    *" ${3:-} "*) exit 0 ;;
    *) exit 3 ;;
  esac
fi
SH
  chmod +x "$ROOT/bin/systemctl"
  export SYSTEMCTL="$ROOT/bin/systemctl"
  export SYSTEMCTL_LOG="$ROOT/systemctl.calls"
}

# --- relay: rendering ------------------------------------------------------

@test "relay --print renders all three drop-ins with the receiver URL" {
  run "$SHIP" --receiver-host recv.example.net --port 19532 --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"journald.conf.d/10-onionwarden.conf"* ]]
  [[ "$output" == *"journal-upload.conf.d/10-onionwarden.conf"* ]]
  [[ "$output" == *"systemd-journal-upload.service.d/10-onionwarden.conf"* ]]
  [[ "$output" == *"URL=https://recv.example.net:19532"* ]]
  [[ "$output" == *"Storage=persistent"* ]]
}

@test "relay --receiver-url is used verbatim" {
  run "$SHIP" --receiver-url https://r.invalid:5555 --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"URL=https://r.invalid:5555"* ]]
}

@test "relay mTLS mode emits the three cert *File= lines" {
  run "$SHIP" --receiver-host recv.example.net --cert-dir /etc/onionwarden/journal --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"ServerKeyFile=/etc/onionwarden/journal/upload.key"* ]]
  [[ "$output" == *"ServerCertificateFile=/etc/onionwarden/journal/upload.crt"* ]]
  [[ "$output" == *"TrustedCertificateFile=/etc/onionwarden/journal/ca.crt"* ]]
}

@test "relay mTLS service drop-in loads certs through systemd credentials" {
  run "$SHIP" --receiver-host recv.example.net --cert-dir /etc/onionwarden/journal --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"LoadCredential=upload.key:/etc/onionwarden/journal/upload.key"* ]]
  [[ "$output" == *"LoadCredential=upload.crt:/etc/onionwarden/journal/upload.crt"* ]]
  [[ "$output" == *"LoadCredential=ca.crt:/etc/onionwarden/journal/ca.crt"* ]]
  [[ "$output" == *'--key=${CREDENTIALS_DIRECTORY}/upload.key'* ]]
  [[ "$output" == *'--cert=${CREDENTIALS_DIRECTORY}/upload.crt'* ]]
  [[ "$output" == *'--trust=${CREDENTIALS_DIRECTORY}/ca.crt'* ]]
}

@test "relay --http strips cert lines and uses http scheme" {
  run "$SHIP" --receiver-host recv.example.net --http --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"URL=http://recv.example.net:19532"* ]]
  [[ "$output" != *"ServerKeyFile="* ]]
  [[ "$output" != *"TrustedCertificateFile="* ]]
  [[ "$output" != *"LoadCredential="* ]]
  [[ "$output" != *"CREDENTIALS_DIRECTORY"* ]]
}

@test "relay requires a receiver target" {
  run "$SHIP" --print
  [ "$status" -ne 0 ]
}

@test "relay rejects a non-numeric port" {
  run "$SHIP" --receiver-host recv.example.net --port abc --print
  [ "$status" -ne 0 ]
}

@test "relay writes the drop-ins under --root" {
  run "$SHIP" --root "$ROOT" --receiver-host recv.example.net
  [ "$status" -eq 0 ]
  [ -f "$ROOT/etc/systemd/journald.conf.d/10-onionwarden.conf" ]
  [ -f "$ROOT/etc/systemd/journal-upload.conf.d/10-onionwarden.conf" ]
  [ -f "$ROOT/etc/systemd/system/systemd-journal-upload.service.d/10-onionwarden.conf" ]
  grep -q "URL=https://recv.example.net:19532" \
    "$ROOT/etc/systemd/journal-upload.conf.d/10-onionwarden.conf"
}

@test "relay --enable restarts journal-upload so changed drop-ins take effect" {
  stub_systemctl
  run "$SHIP" --root "$ROOT" --receiver-host recv.example.net --enable
  [ "$status" -eq 0 ]
  calls=$(< "$SYSTEMCTL_LOG")
  expected=$'daemon-reload\nrestart systemd-journald\nenable systemd-journal-upload.service\nrestart systemd-journal-upload.service'
  [ "$calls" = "$expected" ]
}

# --- receiver: rendering ---------------------------------------------------

@test "receiver --print renders remote.conf + socket listen drop-in with port" {
  run "$REMOTE" --port 19532 --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"journal-remote.conf.d/10-onionwarden.conf"* ]]
  [[ "$output" == *"systemd-journal-remote.socket.d/10-onionwarden.conf"* ]]
  [[ "$output" == *"SplitMode=host"* ]]
  [[ "$output" == *"ListenStream=19532"* ]]
}

@test "receiver socket drop-in clears the package default before setting the port" {
  run "$REMOTE" --port 23456 --print
  [ "$status" -eq 0 ]
  # an empty ListenStream= must precede the real one (clears the vendor default)
  printf '%s\n' "$output" | grep -A2 '\[Socket\]' | grep -qx 'ListenStream='
  [[ "$output" == *"ListenStream=23456"* ]]
}

@test "receiver --http strips cert lines" {
  run "$REMOTE" --http --print
  [ "$status" -eq 0 ]
  [[ "$output" != *"ServerKeyFile="* ]]
}

@test "receiver --enable restarts the socket so changed ports take effect" {
  stub_systemctl
  run "$REMOTE" --root "$ROOT" --port 28000 --enable
  [ "$status" -eq 0 ]
  calls=$(< "$SYSTEMCTL_LOG")
  expected=$'daemon-reload\nenable systemd-journal-remote.socket\nis-active --quiet systemd-journal-remote.service\nrestart systemd-journal-remote.socket'
  [ "$calls" = "$expected" ]
}

@test "receiver --enable restarts an active remote service after rebinding the socket" {
  stub_systemctl
  export SYSTEMCTL_ACTIVE_UNITS="systemd-journal-remote.service"
  run "$REMOTE" --root "$ROOT" --port 28000 --enable
  [ "$status" -eq 0 ]
  calls=$(< "$SYSTEMCTL_LOG")
  expected=$'daemon-reload\nenable systemd-journal-remote.socket\nis-active --quiet systemd-journal-remote.service\nstop systemd-journal-remote.service\nrestart systemd-journal-remote.socket\nstart systemd-journal-remote.service'
  [ "$calls" = "$expected" ]
}

# --- receiver: idempotency -------------------------------------------------

@test "receiver setup is idempotent (byte-identical on re-run)" {
  run "$REMOTE" --root "$ROOT" --port 19532
  [ "$status" -eq 0 ]
  before=$(fp "$ROOT")
  run "$REMOTE" --root "$ROOT" --port 19532
  [ "$status" -eq 0 ]
  after=$(fp "$ROOT")
  [ "$before" = "$after" ]
}

@test "receiver setup creates the per-host journal store" {
  run "$REMOTE" --root "$ROOT" --port 19532
  [ "$status" -eq 0 ]
  [ -d "$ROOT/var/log/journal/remote" ]
}

@test "relay setup is idempotent (byte-identical on re-run)" {
  run "$SHIP" --root "$ROOT" --receiver-host recv.example.net
  [ "$status" -eq 0 ]
  before=$(fp "$ROOT")
  run "$SHIP" --root "$ROOT" --receiver-host recv.example.net
  [ "$status" -eq 0 ]
  after=$(fp "$ROOT")
  [ "$before" = "$after" ]
}

@test "changing the port re-renders the listen drop-in (not appended)" {
  "$REMOTE" --root "$ROOT" --port 19532 >/dev/null 2>&1
  "$REMOTE" --root "$ROOT" --port 28000 >/dev/null 2>&1
  f="$ROOT/etc/systemd/system/systemd-journal-remote.socket.d/10-onionwarden.conf"
  run grep -c 'ListenStream=28000' "$f"
  [ "$output" -eq 1 ]
  run grep -c 'ListenStream=19532' "$f"
  [ "$output" -eq 0 ]
}
