# shellcheck shell=bash
# lib/fatal.sh — fatal-action kill-switch evaluator (PLAN §3.7).
#
# Ships DISARMED. fatal_evaluate() is called by the dispatcher after every run.
# It acts only when ALL of:
#   - host.conf:fatal_action_armed = true        (signed master veto)
#   - state/fatal_armed present                  (set by `onionwarden-fatal arm`)
#   - a finding carries "fatal_candidate":true    (already post-allowlist /
#     post-apt-correlation — C3: the checks demote allowlisted/correlated ones)
#   - the finding's signal is within the armed scope
#   - no cooldown is in effect
# Off-box-first: the event is shipped to events.log before any action so the
# record survives the host going down. ONIONWARDEN_FATAL_DRYRUN=1 logs the action
# instead of performing it (used by `onionwarden-fatal dry-run` and the tests).

if [ -n "${_ONIONWARDEN_FATAL_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_FATAL_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# shellcheck source=lib/config.sh
. "$(dirname "${BASH_SOURCE[0]}")/config.sh"
# shellcheck source=lib/alert.sh
. "$(dirname "${BASH_SOURCE[0]}")/alert.sh"

# High-confidence fatal signals — `poweroff` is armable for these from Phase 2
# (PLAN §3.7). The rest need Phase-4 `--scope all` arming.
_FATAL_HIGHCONF="ld_so_preload kernel_taint uid0 promiscuous_iface promisc_xcheck input_device console_login"

fatal_armed_file() { printf '%s' "$(onionwarden_state_dir)/fatal_armed"; }
fatal_cooldown_file() { printf '%s' "$(onionwarden_state_dir)/fatal_cooldown"; }

# fatal_is_armed -> 0 if the kill-switch is fully armed. Echoes "action scope".
fatal_is_armed() {
  cfg_bool fatal_action_armed false || return 1   # signed master veto
  local af; af=$(fatal_armed_file)
  [ -f "$af" ] || return 1
  return 0
}

_fatal_armed_action() { awk -F= '$1=="action"{print $2}' "$(fatal_armed_file)" 2>/dev/null | head -n1; }
_fatal_armed_scope()  { awk -F= '$1=="scope"{print $2}'  "$(fatal_armed_file)" 2>/dev/null | head -n1; }

# The deterministic freeze ruleset (C5): the §2.2 nft check regenerates this
# byte-for-byte to recognise a legitimate freeze. Drops NEW outbound, keeps
# established + inbound SSH.
fatal_freeze_ruleset() {
  cat <<'NFT'
table inet onionwarden_freeze {
	chain output {
		type filter hook output priority 0; policy drop;
		ct state established,related accept
		oifname "lo" accept
		tcp sport 22 accept
		ip daddr 127.0.0.0/8 accept
		ip6 daddr ::1 accept
	}
	chain input {
		type filter hook input priority 0; policy accept;
	}
}
NFT
}

_fatal_in_cooldown() {
  local cf hours last now
  cf=$(fatal_cooldown_file)
  [ -f "$cf" ] || return 1
  hours=$(cfg_get fatal_cooldown_hours 24)
  last=$(awk -F= '$1=="epoch"{print $2}' "$cf" 2>/dev/null | head -n1)
  [ -n "$last" ] || return 1
  now=$(now_epoch)
  [ $(( now - last )) -lt $(( hours * 3600 )) ]
}

_fatal_record_cooldown() {
  { printf 'epoch=%s\n' "$(now_epoch)"
    printf 'iso=%s\n' "$(now_iso)"
    printf 'signal=%s\n' "$1"
    printf 'action=%s\n' "$2"
  } > "$(fatal_cooldown_file)"
}

# _fatal_perform ACTION SIGNAL SUMMARY
_fatal_perform() {
  local action=$1 signal=$2 summary=$3
  if [ "${ONIONWARDEN_FATAL_DRYRUN:-0}" = "1" ]; then
    log_warn "fatal[dry-run]: WOULD perform '$action' for signal '$signal'"
    printf 'DRYRUN action=%s signal=%s\n' "$action" "$signal"
    return 0
  fi
  command -v wall >/dev/null 2>&1 && \
    printf 'onionwarden FATAL: %s — performing %s. (%s)\n' "$signal" "$action" "$summary" \
      | wall 2>/dev/null || true
  case "$action" in
    poweroff)
      log_err "fatal: powering off — $signal"
      if command -v systemctl >/dev/null 2>&1; then systemctl poweroff
      else poweroff; fi ;;
    freeze)
      if command -v nft >/dev/null 2>&1; then
        nft list ruleset > "$(onionwarden_state_dir)/pre_freeze_ruleset" 2>/dev/null || true
        fatal_freeze_ruleset | nft -f - && log_err "fatal: freeze ruleset installed — $signal"
      else
        log_err "fatal: freeze requested but nft absent — no containment applied"
        return 1
      fi ;;
    custom)
      local cs="$(onionwarden_conf_dir)/fatal-action.sh"
      if [ -x "$cs" ]; then "$cs" "$signal" "$summary" || log_err "fatal: custom action exited nonzero"
      else log_err "fatal: custom action $cs missing/not-executable"; return 1; fi ;;
  esac
}

# fatal_evaluate FINDINGS_FILE RUN_MAX_SEV
fatal_evaluate() {
  local findings=$1
  [ -f "$findings" ] || return 0

  # Gather fatal-candidate findings (already post-allowlist/post-correlation).
  local fatal_lines
  fatal_lines=$(grep '"fatal_candidate":true' "$findings" 2>/dev/null || true)
  [ -n "$fatal_lines" ] || return 0

  if ! fatal_is_armed; then
    log_warn "fatal: $(printf '%s\n' "$fatal_lines" | grep -c . ) fatal signal(s) observed — kill-switch DISARMED, no action taken"
    return 0
  fi

  local action scope
  action=$(_fatal_armed_action); scope=$(_fatal_armed_scope)
  [ -n "$action" ] || action=$(cfg_get fatal_action alert)

  # `alert` is report-only — the findings already went out via the normal path.
  if [ "$action" = "alert" ]; then
    log_info "fatal: action=alert (report-only) — $(printf '%s\n' "$fatal_lines" | grep -c .) fatal signal(s)"
    return 0
  fi

  if _fatal_in_cooldown; then
    log_warn "fatal: cooldown active — action '$action' suppressed (still logged/pushed)"
    events_append fatal_cooldown WARN "fatal signal during cooldown — action suppressed" || true
    return 0
  fi

  # Take the first in-scope fatal finding and act once.
  local line signal summary
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    signal=$(printf '%s' "$line" | sed -n 's/.*"signal":"\([a-z_]*\)".*/\1/p')
    summary=$(printf '%s' "$line" | sed -n 's/.*"summary":"\([^"]*\)".*/\1/p')

    # poweroff scope gate: highconf subset only unless armed --scope all.
    if [ "$action" = "poweroff" ] && [ "${scope:-highconf}" = "highconf" ]; then
      case " $_FATAL_HIGHCONF " in
        *" $signal "*) ;;
        *) log_warn "fatal: signal '$signal' outside high-confidence poweroff scope — needs Phase-4 '--scope all' arming"
           continue ;;
      esac
    fi

    # Off-box-first: ship the event before acting so the record survives.
    events_append fatal CRIT "fatal_action=$action triggered by $signal: $summary" \
      "$(printf '{"action":"%s","signal":"%s"}' "$action" "$signal")" || \
      log_warn "fatal: off-box send failed — proceeding with containment anyway"

    _fatal_record_cooldown "$signal" "$action"
    _fatal_perform "$action" "$signal" "$summary"
    return 0
  done <<< "$fatal_lines"
}
