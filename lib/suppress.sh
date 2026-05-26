# shellcheck shell=bash
# lib/suppress.sh — physical-access maintenance window (PLAN §3.7).
#
# Before an operator legitimately touches a host's console they open a
# time-boxed window that downgrades the physical-CONTACT fatal signals
# (#10 input-device, #11 console-login — never #9 PROMISC, never #1-#8).
#
# The window is an Ed25519-SIGNED token, not an unsigned state file: C5 forbids
# anything in state/ from suppressing a check. The signature is the authority
# (an attacker cannot mint a token without the fleet private key); time bounds
# auto-expire it; a monotonic opened_at guard rejects a replayed old token.

if [ -n "${_ONIONWARDEN_SUPPRESS_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_SUPPRESS_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# shellcheck source=lib/config.sh
. "$(dirname "${BASH_SOURCE[0]}")/config.sh"
# shellcheck source=lib/verify.sh
. "$(dirname "${BASH_SOURCE[0]}")/verify.sh"

suppress_token_path() {
  printf '%s' "${ONIONWARDEN_SUPPRESS_TOKEN:-$(onionwarden_conf_dir)/suppress.token}"
}

# suppress_physical_active -> 0 if a valid signed physical-access window is in
# effect right now. Emits nothing on the happy path; warns on a rejected token.
suppress_physical_active() {
  local tok sig pub host now opened expires nonce scope last
  tok=$(suppress_token_path); sig="$tok.sig"
  [ -f "$tok" ] && [ -f "$sig" ] || return 1

  pub="${ONIONWARDEN_PUBKEY:-$(cfg_get verify_pubkey_path "$(onionwarden_root)/onionwarden.pub")}"
  if ! onionwarden_verify_sig "$pub" "$tok" "$sig"; then
    log_warn "suppress: token signature invalid — window NOT honored"
    return 1
  fi

  host=$(json_field "$tok" host_id)
  scope=$(json_field "$tok" scope)
  opened=$(json_field "$tok" opened_at)
  expires=$(json_field "$tok" expires_at)
  nonce=$(json_field "$tok" nonce)

  [ "$host" = "$(cfg_get host_id)" ] || { log_warn "suppress: token host mismatch"; return 1; }
  [ "$scope" = "physical" ] || return 1

  now=$(now_iso)
  # ISO-8601 UTC timestamps sort lexicographically.
  if [[ "$now" > "$expires" ]] || [[ "$now" == "$expires" ]]; then
    return 1   # expired (no warning — expiry is the normal end of a window)
  fi
  if [[ "$opened" > "$now" ]]; then
    log_warn "suppress: token not yet active (opened_at in the future)"
    return 1
  fi

  # Anti-replay: a token strictly OLDER than the most recent one ever honored is
  # a replay. An equal opened_at is the same token being re-honored across runs
  # for the duration of its window — that is expected, not a replay.
  last=$(cat "$(onionwarden_state_dir)/suppress_last" 2>/dev/null || printf '')
  if [ -n "$last" ] && [[ "$opened" < "$last" ]]; then
    log_warn "suppress: token opened_at ($opened) older than last honored ($last) — replay rejected"
    return 1
  fi
  mkdir -p "$(onionwarden_state_dir)" 2>/dev/null || true
  printf '%s' "$opened" > "$(onionwarden_state_dir)/suppress_last"
  return 0
}

# suppress_describe — human-readable window status (used by `onionwarden suppress status`).
suppress_describe() {
  local tok
  tok=$(suppress_token_path)
  if [ ! -f "$tok" ]; then printf 'no suppression token installed\n'; return 0; fi
  if suppress_physical_active; then
    printf 'ACTIVE physical-access window: reason=%s operator=%s expires=%s\n' \
      "$(json_field "$tok" reason)" "$(json_field "$tok" operator)" \
      "$(json_field "$tok" expires_at)"
  else
    printf 'token present but NOT active (expired, replayed, or invalid signature)\n'
  fi
}
