#!/usr/bin/env bats
# bin/onionwarden-virt-inventory — per-host virt inventory (OPERATOR_DECISIONS §6).
# Shell-level mirror of tests/test_virt_inventory.py: fixture-driven verdicts,
# the self-contained `bash -s` streaming contract, and graceful degradation.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  BIN="$REPO/bin/onionwarden-virt-inventory"
  FIX=$(mktemp -d "${TMPDIR:-/tmp}/owarden-virt.XXXXXX")
}

teardown() {
  rm -rf "$FIX"
}

@test "kvm fixture -> verdict vm" {
  printf 'kvm' > "$FIX/detect_virt"
  printf 'none' > "$FIX/detect_virt_container"
  printf 'kvm' > "$FIX/detect_virt_vm"
  run "$BIN" --host relay-kvm --fixture-dir "$FIX"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"verdict":"vm"'* ]]
}

@test "lxc fixture -> verdict container" {
  printf 'lxc' > "$FIX/detect_virt"
  printf 'lxc' > "$FIX/detect_virt_container"
  printf 'none' > "$FIX/detect_virt_vm"
  run "$BIN" --host ct1 --fixture-dir "$FIX"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"verdict":"container"'* ]]
}

@test "none + real DMI -> verdict bare-metal" {
  printf 'none' > "$FIX/detect_virt"
  printf 'none' > "$FIX/detect_virt_container"
  printf 'none' > "$FIX/detect_virt_vm"
  printf 'Dell Inc.' > "$FIX/dmi_sys_vendor"
  printf 'PowerEdge R640' > "$FIX/dmi_product_name"
  run "$BIN" --host bm1 --fixture-dir "$FIX"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"verdict":"bare-metal"'* ]]
}

@test "cloud DMI vendor infers vm even when detect-virt=none" {
  printf 'none' > "$FIX/detect_virt"
  printf 'none' > "$FIX/detect_virt_container"
  printf 'none' > "$FIX/detect_virt_vm"
  printf 'Amazon EC2' > "$FIX/dmi_sys_vendor"
  run "$BIN" --host c1 --fixture-dir "$FIX"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"verdict":"vm"'* ]]
}

@test "host label is honoured" {
  printf 'none' > "$FIX/detect_virt"
  run "$BIN" --host gatedopen --fixture-dir "$FIX"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"host_id":"gatedopen"'* ]]
}

@test "captures no serial / uuid (no PII)" {
  printf 'kvm' > "$FIX/detect_virt"
  run "$BIN" --host h --fixture-dir "$FIX"
  [ "$status" -eq 0 ]
  [[ "$output" != *serial* ]]
  [[ "$output" != *uuid* ]]
}

@test "streams over bash -s with -u (no BASH_SOURCE unbound error)" {
  run bash -us -- --host streamed < "$BIN"
  [ "$status" -eq 0 ]
  [[ "$output" == *'"host_id":"streamed"'* ]]
  [[ "$output" != *"unbound variable"* ]]
}

@test "live run on a host without the probes lists degraded, exits 0" {
  ONIONWARDEN_DMI_DIR="$FIX/none" ONIONWARDEN_PROC="$FIX/noproc" run "$BIN" --host live
  [ "$status" -eq 0 ]
  [[ "$output" == *'"degraded":['* ]]
}

@test "unknown argument is a usage error" {
  run "$BIN" --bogus
  [ "$status" -ne 0 ]
}
