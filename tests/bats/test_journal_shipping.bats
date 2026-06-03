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

@test "relay --http strips cert lines and uses http scheme" {
  run "$SHIP" --receiver-host recv.example.net --http --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"URL=http://recv.example.net:19532"* ]]
  [[ "$output" != *"ServerKeyFile="* ]]
  [[ "$output" != *"TrustedCertificateFile="* ]]
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
  # The empty ListenStream= must appear strictly BEFORE the real one, otherwise
  # the vendor default isn't actually cleared. Compare line numbers.
  empty_ln=$(printf '%s\n' "$output" | grep -n '^ListenStream=$' | head -1 | cut -d: -f1)
  val_ln=$(printf '%s\n' "$output" | grep -n '^ListenStream=23456$' | head -1 | cut -d: -f1)
  [ -n "$empty_ln" ]
  [ -n "$val_ln" ]
  [ "$empty_ln" -lt "$val_ln" ]
}

@test "relay rejects newline-injected --receiver-url" {
  run "$SHIP" --receiver-url "$(printf 'https://r.invalid:5555\nURL=http://attacker:19532')" --print
  [ "$status" -ne 0 ]
}

@test "relay rejects a --cert-dir with shell/sed metacharacters" {
  run "$SHIP" --receiver-host recv.example.net --cert-dir '/etc/x|evil' --print
  [ "$status" -ne 0 ]
}

@test "relay rejects a --receiver-url embedding a render() placeholder" {
  # @CERT_DIR@/@PORT@ would otherwise be second-order substituted by later
  # sed passes in render(); the URL is the only @-bearing interpolated value.
  run "$SHIP" --receiver-url 'https://r.invalid:5555@CERT_DIR@' --print
  [ "$status" -ne 0 ]
  run "$SHIP" --receiver-url 'https://r.invalid@PORT@' --print
  [ "$status" -ne 0 ]
}

@test "receiver pins ExecStart --output only for a custom --journal-dir" {
  run "$REMOTE" --port 19532 --journal-dir /srv/journals --print
  [ "$status" -eq 0 ]
  [[ "$output" == *"systemd-journal-remote.service.d/10-onionwarden.conf"* ]]
  [[ "$output" == *"--output=/srv/journals/"* ]]
  # default path leaves the stock unit untouched (no service.d override)
  run "$REMOTE" --port 19532 --print
  [ "$status" -eq 0 ]
  [[ "$output" != *"systemd-journal-remote.service.d/10-onionwarden.conf"* ]]
}

@test "receiver --http strips cert lines" {
  run "$REMOTE" --http --print
  [ "$status" -eq 0 ]
  [[ "$output" != *"ServerKeyFile="* ]]
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
  run "$REMOTE" --root "$ROOT" --port 19532
  [ "$status" -eq 0 ]
  run "$REMOTE" --root "$ROOT" --port 28000
  [ "$status" -eq 0 ]
  f="$ROOT/etc/systemd/system/systemd-journal-remote.socket.d/10-onionwarden.conf"
  run grep -c 'ListenStream=28000' "$f"
  [ "$output" -eq 1 ]
  run grep -c 'ListenStream=19532' "$f"
  [ "$output" -eq 0 ]
}
