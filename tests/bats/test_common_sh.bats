#!/usr/bin/env bats
# Regression tests for helpers in lib/common.sh.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  # shellcheck source=/dev/null
  source "$REPO/lib/common.sh"
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/owarden-common.XXXXXX")
}

teardown() {
  rm -rf "$TMP"
}

# --- kv_read: values containing `=` must be preserved ---------------------

@test "kv_read: plain KEY=VALUE round-trip" {
  printf 'foo=bar\n' > "$TMP/f"
  run kv_read "$TMP/f" foo
  [ "$status" -eq 0 ]
  [ "$output" = "bar" ]
}

@test "kv_read: VALUE containing one '=' is preserved (KEY=a=b → a=b)" {
  printf 'KEY=a=b\n' > "$TMP/f"
  run kv_read "$TMP/f" KEY
  [ "$status" -eq 0 ]
  [ "$output" = "a=b" ]
}

@test "kv_read: VALUE of all '=' chars is preserved (KEY=== → ==)" {
  printf 'KEY===\n' > "$TMP/f"
  run kv_read "$TMP/f" KEY
  [ "$status" -eq 0 ]
  [ "$output" = "==" ]
}

@test "kv_read: empty VALUE is preserved (KEY= → empty string)" {
  printf 'KEY=\n' > "$TMP/f"
  run kv_read "$TMP/f" KEY
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
}

@test "kv_read: only first matching KEY is returned" {
  printf 'KEY=first\nKEY=second\n' > "$TMP/f"
  run kv_read "$TMP/f" KEY
  [ "$status" -eq 0 ]
  [ "$output" = "first" ]
}

@test "kv_read: non-matching KEY prefix is not matched (PREFIX vs KEY)" {
  printf 'OTHERKEY=x\nKEY=y\n' > "$TMP/f"
  run kv_read "$TMP/f" KEY
  [ "$status" -eq 0 ]
  [ "$output" = "y" ]
}

@test "kv_read: missing file produces empty output (errors swallowed)" {
  # Status may be non-zero (awk can't open the file), but stderr is suppressed
  # and stdout must be empty so the caller's `var=$(kv_read …)` form is safe.
  run kv_read "$TMP/does-not-exist" KEY
  [ "$output" = "" ]
}

@test "kv_read: missing KEY produces empty output" {
  printf 'A=1\nB=2\n' > "$TMP/f"
  run kv_read "$TMP/f" MISSING
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
}
