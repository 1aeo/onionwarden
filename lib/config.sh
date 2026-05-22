# shellcheck shell=bash
# lib/config.sh — host.conf + role-profile parsing (PLAN §0.6, §3.4).
#
# host.conf is a declarative key=value file. Arrays are [a, b, c].
# A role profile (roles/<role>.conf) is loaded FIRST; host.conf overrides it.
# Parsed config lands in a flat normalized store file so cfg_get/cfg_list need
# no JSON parser (Phase-1 ships without jq).

if [ -n "${_ONIONWARDEN_CONFIG_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_CONFIG_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Preserve an inherited value: the dispatcher loads config once and exports
# _CFG_STORE so check subprocesses reuse the parsed store without re-parsing.
_CFG_STORE="${_CFG_STORE:-}"

_cfg_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# Parse one config file's lines into the store. $1=file $2=store
_cfg_parse_file() {
  local file=$1 store=$2 line key val
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    case "$line" in *=*) ;; *) continue ;; esac
    key=$(_cfg_trim "${line%%=*}")
    [ -n "$key" ] || continue
    val=$(_cfg_trim "${line#*=}")
    case "$val" in
      \[*)
        # Array. Content is between the first [ and the last ].
        local body items item
        body=${val#*[}
        body=${body%%]*}
        # host.conf array fully replaces any role-profile array of same key.
        if [ -s "$store" ]; then
          grep -v "^${key}\[\]	" "$store" > "${store}.tmp" 2>/dev/null || true
          mv "${store}.tmp" "$store"
        fi
        printf '%s\t__ARRAY__\n' "$key" >> "$store"
        # Skip the split for an empty array [] — bash 3.2 errors on "${a[@]}"
        # of an empty array under `set -u`.
        if [ -n "$(_cfg_trim "$body")" ]; then
          items=()
          IFS=',' read -r -a items <<< "$body"
          for item in "${items[@]}"; do
            item=$(_cfg_trim "$item")
            item=${item#\"}; item=${item%\"}
            item=${item#\'}; item=${item%\'}
            [ -n "$item" ] || continue
            printf '%s[]\t%s\n' "$key" "$item" >> "$store"
          done
        fi
        ;;
      \"*)
        val=${val#\"}
        val=${val%%\"*}
        printf '%s\t%s\n' "$key" "$val" >> "$store"
        ;;
      *)
        # Bare scalar: strip a trailing inline comment.
        val=${val%%#*}
        val=$(_cfg_trim "$val")
        printf '%s\t%s\n' "$key" "$val" >> "$store"
        ;;
    esac
  done < "$file"
}

# cfg_load HOST_CONF [ROLES_DIR]
# Loads role profile (named by host.conf's `role`) then host.conf on top.
# Sets the globals _CFG_STORE and _CFG_ROLE. MUST NOT be called inside $(...)
# — a command-substitution subshell would discard the _CFG_STORE assignment.
_CFG_ROLE=""
cfg_load() {
  local host_conf=$1 roles_dir=${2:-}
  [ -f "$host_conf" ] || die "config: host.conf not found: $host_conf"
  _CFG_STORE=$(mktemp "${TMPDIR:-/tmp}/onionwarden-cfg.XXXXXX")
  : > "$_CFG_STORE"

  # First pass: discover the role from host.conf only.
  local role
  role=$(grep -E '^[[:space:]]*role[[:space:]]*=' "$host_conf" 2>/dev/null | head -n1 || true)
  role=${role#*=}
  role=$(_cfg_trim "$role")
  role=${role#\"}; role=${role%%\"*}
  [ -n "$role" ] || role="generic"
  _CFG_ROLE="$role"

  if [ -n "$roles_dir" ] && [ -f "$roles_dir/${role}.conf" ]; then
    _cfg_parse_file "$roles_dir/${role}.conf" "$_CFG_STORE"
  fi
  _cfg_parse_file "$host_conf" "$_CFG_STORE"
}

cfg_cleanup() {
  [ -n "$_CFG_STORE" ] && rm -f "$_CFG_STORE" "${_CFG_STORE}.tmp" 2>/dev/null || true
  _CFG_STORE=""
}

# cfg_get KEY [DEFAULT] — last scalar wins (host.conf overrides role).
cfg_get() {
  local key=$1 def=${2:-} val
  [ -n "$_CFG_STORE" ] || { printf '%s' "$def"; return 0; }
  val=$(grep -E "^${key}	" "$_CFG_STORE" 2>/dev/null | grep -v '	__ARRAY__$' | tail -n1 || true)
  if [ -z "$val" ]; then printf '%s' "$def"; return 0; fi
  printf '%s' "${val#*	}"
}

# cfg_list KEY — newline-delimited array elements (empty if unset).
cfg_list() {
  local key=$1
  [ -n "$_CFG_STORE" ] || return 0
  grep -E "^${key}\[\]	" "$_CFG_STORE" 2>/dev/null | sed 's/^[^	]*	//' || true
}

# cfg_is_set KEY — 0 if the key (scalar or array) was defined anywhere.
cfg_is_set() {
  local key=$1
  [ -n "$_CFG_STORE" ] || return 1
  grep -qE "^${key}(\[\])?	" "$_CFG_STORE" 2>/dev/null
}

# cfg_bool KEY [DEFAULT] — 0 (true) / 1 (false). Anything not exactly "true"
# (case-insensitive) is false, so a typo fails safe to the conservative side.
cfg_bool() {
  local v
  v=$(cfg_get "$1" "${2:-false}")
  case "$v" in
    [Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]) return 0 ;;
    *) return 1 ;;
  esac
}

# cfg_list_has KEY VALUE — 0 if VALUE is an element of array KEY.
cfg_list_has() {
  local key=$1 needle=$2 item
  while IFS= read -r item; do
    [ "$item" = "$needle" ] && return 0
  done <<< "$(cfg_list "$key")"
  return 1
}
