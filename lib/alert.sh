# shellcheck shell=bash
# lib/alert.sh — off-box alerting (PLAN §4).
#
# Four channels, all endpoint-configurable in host.conf:
#   1. dead-man's switch  — heartbeat to a provider that alerts on ABSENCE
#   2. ntfy push          — rich WARN/CRIT findings
#   3. events.log         — append-only forensic log on the off-box receiver
#   4. email              — CRIT-only tertiary, survives a receiver outage
#
# Test seam: if ONIONWARDEN_ALERT_SINK names a directory, every channel writes
# what it WOULD send into that directory instead of hitting the network — so
# the dispatcher and alerting are exercised end-to-end with no real endpoints.

if [ -n "${_ONIONWARDEN_ALERT_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_ALERT_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# shellcheck source=lib/config.sh
. "$(dirname "${BASH_SOURCE[0]}")/config.sh"

_alert_sink() { [ -n "${ONIONWARDEN_ALERT_SINK:-}" ] && [ -d "${ONIONWARDEN_ALERT_SINK:-/nonexistent}" ]; }

# onionwarden_http_post URL DATA [HEADER ...] -> 0 on success.
onionwarden_http_post() {
  local url=$1 data=$2; shift 2
  local hdr args=()
  for hdr in "$@"; do args+=( -H "$hdr" ); done
  if command -v curl >/dev/null 2>&1; then
    # ${args[@]+...} guard: bash 3.2 errors on "${args[@]}" of an empty array.
    curl -fsS --max-time 15 --retry 1 ${args[@]+"${args[@]}"} -d "$data" "$url" >/dev/null 2>&1
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null --timeout=15 --post-data="$data" "$url" >/dev/null 2>&1
  else
    log_err "alert: no curl/wget — cannot POST to $url"
    return 1
  fi
}

# --- 1. dead-man's switch -------------------------------------------------
# deadman_ping ok|fail  (PRIMARY trust anchor — alerting-on-absence).
deadman_ping() {
  local status=$1
  local provider url
  provider=$(cfg_get deadman_provider "healthchecks-saas")
  url=$(cfg_get deadman_url "")
  [ -n "$url" ] || { log_warn "alert: deadman_url unset — skipping heartbeat"; return 0; }
  local target="$url"
  [ "$status" = "fail" ] && target="${url%/}/fail"
  if _alert_sink; then
    printf '%s %s %s\n' "$(now_iso)" "$provider" "$target" >> "$ONIONWARDEN_ALERT_SINK/deadman"
    return 0
  fi
  onionwarden_http_post "$target" "onionwarden heartbeat $(now_iso)" || \
    log_warn "alert: dead-man ping to $target failed"
}

# --- 2. ntfy push ---------------------------------------------------------
# ntfy_push SEVERITY TITLE BODY
ntfy_push() {
  local sev=$1 title=$2 body=$3
  local url token prio tags
  url=$(cfg_get ntfy_url "")
  token=$(cfg_get ntfy_token "")
  [ -n "$url" ] || { log_warn "alert: ntfy_url unset — skipping push"; return 0; }
  case "$sev" in
    CRIT) prio="max";     tags="rotating_light" ;;
    WARN) prio="default"; tags="warning" ;;
    *)    prio="low";     tags="information_source" ;;
  esac
  if _alert_sink; then
    printf '%s\t%s\t%s\t%s\n' "$sev" "$prio" "$title" "$body" >> "$ONIONWARDEN_ALERT_SINK/ntfy"
    return 0
  fi
  local hdrs=( "Title: $title" "Priority: $prio" "Tags: $tags" )
  [ -n "$token" ] && hdrs+=( "Authorization: Bearer $token" )
  onionwarden_http_post "$url" "$body" "${hdrs[@]}" || \
    log_warn "alert: ntfy push failed"
}

# --- events.log sequence numbers (M7) -------------------------------------
# Monotonic per-host counter; the receiver alerts on a gap (a dropped CRIT).
next_event_seq() {
  local sf seq
  sf="$(onionwarden_state_dir)/event_seq"
  mkdir -p "$(dirname "$sf")" 2>/dev/null || true
  if command -v flock >/dev/null 2>&1; then
    ( flock 9
      seq=$(cat "$sf" 2>/dev/null || printf 0)
      seq=$(( seq + 1 ))
      printf '%s\n' "$seq" > "$sf"
      printf '%s' "$seq"
    ) 9>"$sf.lock"
  else
    seq=$(cat "$sf" 2>/dev/null || printf 0)
    seq=$(( seq + 1 ))
    printf '%s\n' "$seq" > "$sf"
    printf '%s' "$seq"
  fi
}

# --- 3. events.log append (off-box, append-only) --------------------------
# events_append KIND SEVERITY SUMMARY [DETAIL_JSON]
# Builds one signed-transport JSON line and ships it to the receiver over SSH
# with the restricted append-only key. Carries a seq number for gap detection.
events_append() {
  local kind=$1 sev=$2 summary=$3 detail=${4:-{\}}
  local seq host_id run_id entry
  seq=$(next_event_seq)
  host_id=$(cfg_get host_id "unknown")
  run_id="${ONIONWARDEN_RUN_ID:-unknown}"
  entry=$(printf '{"seq":%s,"ts":"%s","host_id":"%s","run_id":"%s","kind":"%s","severity":"%s","summary":"%s","detail":%s}' \
    "$seq" "$(now_iso)" "$(json_escape "$host_id")" "$(json_escape "$run_id")" \
    "$(json_escape "$kind")" "$(json_escape "$sev")" "$(json_escape "$summary")" "$detail")

  if _alert_sink; then
    printf '%s\n' "$entry" >> "$ONIONWARDEN_ALERT_SINK/events.log"
    return 0
  fi

  local target key sshhost
  target=$(cfg_get offbox_log_target "")
  key=$(cfg_get offbox_ssh_key "$(onionwarden_conf_dir)/keys/offbox_ed25519")
  if [ -z "$target" ]; then
    log_warn "alert: offbox_log_target unset — events.log append skipped"
    return 0
  fi
  # target is host:path; the receiver's restricted key forces the append
  # command, so only the host part is used to connect.
  sshhost=${target%%:*}
  if ! printf '%s\n' "$entry" | \
       ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=15 "$sshhost" 2>/dev/null; then
    log_warn "alert: events.log append to $sshhost failed (buffering locally)"
    # Local buffer — replayed on the next successful run (PLAN §4 resilience).
    mkdir -p "$(onionwarden_state_dir)/event_buffer" 2>/dev/null || true
    printf '%s\n' "$entry" >> "$(onionwarden_state_dir)/event_buffer/pending.ndjson"
    return 1
  fi
}

# events_flush_buffer — replay locally-buffered events after an outage.
# R2-3: the buffer is RENAMED out of the way before sending, so a concurrent
# events_append (e.g. from onionwarden-fatal) writes to a fresh pending.ndjson and
# is never truncated away unsent.
events_flush_buffer() {
  local buf flushing target key sshhost
  buf="$(onionwarden_state_dir)/event_buffer/pending.ndjson"
  [ -s "$buf" ] || return 0
  flushing="$buf.flushing.$$"
  mv "$buf" "$flushing" 2>/dev/null || return 0   # another flush already took it
  if _alert_sink; then
    cat "$flushing" >> "$ONIONWARDEN_ALERT_SINK/events.log"
    rm -f "$flushing"
    return 0
  fi
  target=$(cfg_get offbox_log_target "")
  key=$(cfg_get offbox_ssh_key "$(onionwarden_conf_dir)/keys/offbox_ed25519")
  if [ -z "$target" ]; then
    cat "$flushing" >> "$buf"; rm -f "$flushing"; return 0
  fi
  sshhost=${target%%:*}
  if ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=15 "$sshhost" < "$flushing" 2>/dev/null; then
    rm -f "$flushing"
    log_info "alert: flushed buffered events.log entries"
  else
    # still unreachable — re-buffer (receiver re-orders by sequence number)
    cat "$flushing" >> "$buf"
    rm -f "$flushing"
  fi
}

# --- 4. email (CRIT only) -------------------------------------------------
onionwarden_email() {
  local subject=$1 body=$2 to
  to=$(cfg_get email_to "")
  [ -n "$to" ] || return 0
  if _alert_sink; then
    printf 'To: %s\nSubject: %s\n\n%s\n' "$to" "$subject" "$body" >> "$ONIONWARDEN_ALERT_SINK/email"
    return 0
  fi
  if command -v mail >/dev/null 2>&1; then
    printf '%s\n' "$body" | mail -s "$subject" "$to" 2>/dev/null || \
      log_warn "alert: email send failed"
  else
    log_warn "alert: 'mail' not installed — CRIT email to $to skipped"
  fi
}
