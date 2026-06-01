#!/usr/bin/env bats
# bin/onionwarden-fleet-diff — operator-side cross-fleet baseline diff (PLAN §6).
#
# Mirrors tests/test_fleet_diff.py at the shell level: empty / single-host /
# diverged / missing-baseline, plus the Markdown rendering and exit-code
# contract. Kept pure-fixture so it runs on the macOS bash-3.2 build host.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  BIN="$REPO/bin/onionwarden-fleet-diff"
  FLEET=$(mktemp -d "${TMPDIR:-/tmp}/owarden-fleet.XXXXXX")
}

teardown() {
  rm -rf "$FLEET"
}

# host NAME ROLE — make a host dir with a role file and an empty state/ tree.
host() {
  mkdir -p "$FLEET/$1/state"
  printf '%s\n' "$2" > "$FLEET/$1/role"
}

@test "empty fleet: exit 0, says no hosts" {
  run "$BIN" --fleet-dir "$FLEET"
  [ "$status" -eq 0 ]
  [[ "$output" == *"No hosts found"* ]]
}

@test "single-host fleet: inventory only, no cross-compare" {
  host solo tor-relay
  printf 'module ext4 -\nmodule tcp_bbr -\n' > "$FLEET/solo/state/modules.state"
  run "$BIN" --fleet-dir "$FLEET" --indicators modules
  [ "$status" -eq 0 ]
  [[ "$output" == *"Single host in this role"* ]]
  [[ "$output" == *"inventory: 2 line(s)"* ]]
}

@test "diverged fleet: minority module is flagged within role" {
  host relay-a tor-relay; host relay-b tor-relay; host relay-c tor-relay
  for h in relay-a relay-b relay-c; do
    printf 'module ext4 -\nmodule tcp_bbr -\n' > "$FLEET/$h/state/modules.state"
  done
  printf 'module nfsd PE\n' >> "$FLEET/relay-c/state/modules.state"
  run "$BIN" --fleet-dir "$FLEET" --indicators modules
  [ "$status" -eq 0 ]
  [[ "$output" == *"module nfsd PE"* ]]
  [[ "$output" == *"on 1/3: relay-c"* ]]
  [[ "$output" == *"absent on: relay-a relay-b"* ]]
}

@test "identical hosts produce zero divergences" {
  host relay-a tor-relay; host relay-b tor-relay
  for h in relay-a relay-b; do
    printf 'sshd permitrootlogin no\n' > "$FLEET/$h/state/ssh.state"
  done
  run "$BIN" --fleet-dir "$FLEET" --indicators ssh
  [ "$status" -eq 0 ]
  [[ "$output" == *"within-role divergences: 0"* ]]
}

@test "roles compared independently: eval-host port is not a relay divergence" {
  host relay-a tor-relay; host relay-b tor-relay; host evalbox eval-host
  printf 'listen tcp 0.0.0.0:9001\n' > "$FLEET/relay-a/state/ports.state"
  printf 'listen tcp 0.0.0.0:9001\n' > "$FLEET/relay-b/state/ports.state"
  printf 'listen tcp 0.0.0.0:8080\n' > "$FLEET/evalbox/state/ports.state"
  run "$BIN" --fleet-dir "$FLEET" --indicators ports
  [ "$status" -eq 0 ]
  [[ "$output" == *"fleet summary:** 0 within-role divergence"* ]]
}

@test "missing baseline: strict (default) is a hard error, exit 3" {
  host good tor-relay
  printf 'module ext4 -\n' > "$FLEET/good/state/modules.state"
  mkdir -p "$FLEET/bad"   # host dir, no state/
  run "$BIN" --fleet-dir "$FLEET"
  [ "$status" -eq 3 ]
  [[ "$output" == *"bad"* ]]
}

@test "missing baseline: --no-strict excludes the broken host, exit 0" {
  host good tor-relay
  printf 'module ext4 -\n' > "$FLEET/good/state/modules.state"
  mkdir -p "$FLEET/bad"
  run "$BIN" --fleet-dir "$FLEET" --no-strict --indicators modules
  [ "$status" -eq 0 ]
  [[ "$output" == *"hosts: 1"* ]]
}

@test "--fail-on-divergence returns exit 4 when a divergence exists" {
  host relay-a tor-relay; host relay-b tor-relay
  printf 'module ext4 -\n' > "$FLEET/relay-a/state/modules.state"
  printf 'module ext4 -\nmodule evil X\n' > "$FLEET/relay-b/state/modules.state"
  run "$BIN" --fleet-dir "$FLEET" --indicators modules --fail-on-divergence
  [ "$status" -eq 4 ]
}

@test "nonexistent fleet-dir is a usage-class failure" {
  run "$BIN" --fleet-dir "$FLEET/does-not-exist"
  [ "$status" -ne 0 ]
}

@test "friendly indicator aliases map to canonical state files" {
  host relay-a tor-relay; host relay-b tor-relay
  printf 'sshd permitrootlogin no\n' > "$FLEET/relay-a/state/ssh.state"
  printf 'sshd permitrootlogin yes\n' > "$FLEET/relay-b/state/ssh.state"
  run "$BIN" --fleet-dir "$FLEET" --indicators "sshd-config kernel-taint listeners"
  [ "$status" -eq 0 ]
  # sshd-config alias resolved to ssh.state and found the divergence
  [[ "$output" == *"permitrootlogin"* ]]
}
