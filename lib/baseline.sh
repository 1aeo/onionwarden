# shellcheck shell=bash
# lib/baseline.sh — signed baseline manifest + per-check state files.
#
# A baseline directory contains:
#   manifest.json       flat JSON: identity + sha256 of every state file
#   manifest.json.sig   Ed25519 signature over manifest.json (signed off-box)
#   state/<check>.state line-oriented, sorted, deterministic per-check state
#
# Trust chain: verify manifest.json's signature, THEN confirm each state file's
# sha256 matches the manifest entry. The signature covers the hashes, so a
# tampered state file is caught even though the state files are not individually
# signed. Line-oriented state means diffs are plain `comm`/`diff` — no jq.

if [ -n "${_ONIONWARDEN_BASELINE_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_BASELINE_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# shellcheck source=lib/verify.sh
. "$(dirname "${BASH_SOURCE[0]}")/verify.sh"

BASELINE_SCHEMA="onionwarden-baseline-v1"

onionwarden_version() {
  local vf
  vf="$(onionwarden_root)/VERSION"
  if [ -f "$vf" ]; then tr -d ' \n\r\t' < "$vf"; else printf 'unknown'; fi
}

# manifest_get FILE KEY — read a scalar from our own flat-JSON manifest.
# Safe because the manifest format is author-controlled (we emit it below).
manifest_get() {
  awk -v k="$2" '
    {
      if (match($0, "\"" k "\"[ ]*:[ ]*")) {
        rest = substr($0, RSTART + RLENGTH)
        if (substr(rest, 1, 1) == "\"") {
          rest = substr(rest, 2)
          q = index(rest, "\"")
          print substr(rest, 1, q - 1)
        } else {
          sub(/[ ,}].*$/, "", rest)
          print rest
        }
        exit
      }
    }' "$1"
}

# manifest_state_checks FILE — list check names that have a state.<name> entry.
manifest_state_checks() {
  grep -oE '"state\.[a-z0-9_]+"' "$1" 2>/dev/null \
    | sed -E 's/"state\.([a-z0-9_]+)"/\1/' | sort -u
}

# baseline_state_file DIR CHECK — path to a check's state file ("" if absent).
baseline_state_file() {
  local f="$1/state/$2.state"
  if [ -f "$f" ]; then printf '%s' "$f"; fi
}

baseline_reject_symlinks() {
  local dir=$1 link status
  link=$(find "$dir" -type l -print -quit 2>/dev/null)
  status=$?
  if [ "$status" -ne 0 ]; then
    log_err "baseline: unable to scan for symlinks in $dir"
    return 1
  fi
  if [ -n "$link" ]; then
    log_err "baseline: symlink present in signed baseline tree: $link"
    return 1
  fi
  return 0
}

# baseline_verify DIR PUBKEY — verify signature, every state-file hash, that no
# UNLISTED state file is present (R1-4), and that the baseline is not an
# anti-rollback violation (R1-1). Returns 0 only if all hold.
baseline_verify() {
  local dir=$1 pubkey=$2 manifest="$1/manifest.json"
  baseline_reject_symlinks "$dir" || return 1
  [ -f "$manifest" ] || { log_err "baseline: manifest missing in $dir"; return 1; }
  if ! onionwarden_verify_artifact "$pubkey" "$manifest"; then
    log_err "baseline: manifest.json signature invalid"
    return 1
  fi

  local checks check expected actual sf
  checks=$(manifest_state_checks "$manifest")

  # Every state file named in the (signed) manifest must hash-match.
  while IFS= read -r check; do
    [ -n "$check" ] || continue
    expected=$(manifest_get "$manifest" "state.$check")
    sf="$dir/state/$check.state"
    actual=$(sha256_file "$sf")
    if [ "$expected" != "$actual" ]; then
      log_err "baseline: state file '$check' hash mismatch (manifest=$expected actual=$actual)"
      return 1
    fi
  done <<< "$checks"

  # R1-4: a state file on disk but ABSENT from the signed manifest is untrusted
  # input — refuse it rather than let its check diff against attacker state.
  if [ -d "$dir/state" ]; then
    for sf in "$dir"/state/*.state; do
      [ -f "$sf" ] || continue
      check=$(basename "$sf" .state)
      if ! printf '%s\n' "$checks" | grep -qx "$check"; then
        log_err "baseline: state file '$check.state' is present but not in the signed manifest — refusing"
        return 1
      fi
    done
  fi

  # R1-1: anti-rollback. captured_at is inside the signed manifest; refuse a
  # baseline older than the newest one this host has ever accepted.
  local captured rollback last
  captured=$(manifest_get "$manifest" captured_at)
  rollback="$(onionwarden_state_dir)/baseline_captured_at"
  last=$(cat "$rollback" 2>/dev/null || printf '')
  if [ -n "$last" ] && [ -n "$captured" ] && [[ "$captured" < "$last" ]]; then
    log_err "baseline: captured_at ($captured) older than last accepted ($last) — rollback refused (R1-1)"
    return 1
  fi
  if [ -n "$captured" ]; then
    mkdir -p "$(onionwarden_state_dir)" 2>/dev/null || true
    printf '%s' "$captured" > "$rollback" 2>/dev/null || true
  fi
  return 0
}

# baseline_write_manifest DIR HOST_ID — (re)build manifest.json from the state
# files present under DIR/state/. Called by onionwarden-baseline (off-box signing
# happens afterwards). Output is deterministic given identical state files.
baseline_write_manifest() {
  local dir=$1 host_id=$2 manifest="$1/manifest.json"
  local captured_at sf check first
  captured_at=$(now_iso)
  {
    printf '{\n'
    printf '  "schema": "%s",\n' "$BASELINE_SCHEMA"
    printf '  "host_id": "%s",\n' "$(json_escape "$host_id")"
    printf '  "captured_at": "%s",\n' "$captured_at"
    printf '  "onionwarden_version": "%s",\n' "$(onionwarden_version)"
    first=1
    for sf in "$dir"/state/*.state; do
      [ -f "$sf" ] || continue
      check=$(basename "$sf" .state)
      printf '  "state.%s": "%s",\n' "$check" "$(sha256_file "$sf")"
    done
    # trailing structural key keeps every state line comma-terminated.
    printf '  "manifest_built": "ok"\n'
    printf '}\n'
  } > "$manifest"
}
