#!/usr/bin/env bash
# lib/checks/modules.sh — loaded kernel module diff (PLAN §2.1, §3.7 fatal #5).
#
# Module set is cross-read three ways (lsmod / /proc/modules / /sys/module) so a
# rootkit hiding a module from one view but not another is caught. A new module
# is CRIT; fatal only if it is unsigned/out-of-tree (per-module taint O/E) and
# not allowlisted — in-tree signed demand-loaded modules are normal.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="modules"
CHECK_CADENCE="fast"

modules_collect() {
  if prof_bool is_container; then
    printf 'na container\n'
    return 0
  fi
  if [ ! -r /proc/modules ]; then
    printf 'na no-proc-modules\n'
    return 0
  fi

  local lsmod_set procmod_set sysmod_set name taintf letters
  lsmod_set=$( { lsmod 2>/dev/null | awk 'NR>1{print $1}'; } | sort -u )
  procmod_set=$( awk '{print $1}' /proc/modules 2>/dev/null | sort -u )
  sysmod_set=$( ls /sys/module 2>/dev/null | sort -u )

  # Per-module taint letters (O = out-of-tree, E = unsigned).
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    letters="-"
    taintf="/sys/module/$name/taint"
    if [ -r "$taintf" ]; then
      letters=$(tr -d ' \n' < "$taintf" 2>/dev/null || printf '-')
      [ -n "$letters" ] || letters="-"
    fi
    printf 'module %s %s\n' "$name" "$letters"
  done <<< "$procmod_set"

  # Cross-check: lsmod and /proc/modules must agree exactly; /sys/module must
  # be a superset of the loaded set. Any divergence suggests active hiding.
  local diff_lp diff_ls
  diff_lp=$(comm -3 <(printf '%s\n' "$lsmod_set") <(printf '%s\n' "$procmod_set") | tr -d '\t' | tr '\n' ',' )
  diff_ls=$(comm -23 <(printf '%s\n' "$procmod_set") <(printf '%s\n' "$sysmod_set") | tr '\n' ',')
  if [ -n "$diff_lp" ] || [ -n "$diff_ls" ]; then
    printf 'xcheck disagree lsmod_vs_proc=%s proc_not_in_sys=%s\n' "${diff_lp:-none}" "${diff_ls:-none}"
  else
    printf 'xcheck ok\n'
  fi
}

modules_analyze() {
  local base_file=$1 cur_file=$2

  if grep -q '^na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" loaded_modules "$(awk '$1=="na"{print $2}' "$cur_file" | head -n1)"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" loaded_modules "no baseline module set"
    return 0
  fi

  # Cross-check disagreement -> hiding.
  if grep -q '^xcheck disagree' "$cur_file" 2>/dev/null; then
    emit_finding "$CHECK_NAME" module_xcheck CRIT \
      "module list cross-check disagreement — a module may be hidden from one view" \
      "consistent" "$(grep '^xcheck disagree' "$cur_file" | sed 's/^xcheck disagree //')" true
  fi

  local base_mods cur_mods name letters
  base_mods=$(awk '$1=="module"{print $2}' "$base_file" | sort -u)
  cur_mods=$(awk '$1=="module"{print $2}' "$cur_file" | sort -u)

  # New modules.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if cfg_list_has expected_extra_modules "$name"; then
      emit_finding "$CHECK_NAME" loaded_modules INFO \
        "module '$name' loaded since baseline — allowlisted in expected_extra_modules" \
        "absent" "$name" false
      continue
    fi
    letters=$(awk -v m="$name" '$1=="module"&&$2==m{print $3}' "$cur_file" | head -n1)
    case "$letters" in
      *O*|*E*)
        emit_finding "$CHECK_NAME" loaded_modules CRIT \
          "module '$name' loaded since baseline and is out-of-tree/unsigned (taint '$letters')" \
          "absent" "$name" true ;;
      *)
        emit_finding "$CHECK_NAME" loaded_modules CRIT \
          "module '$name' loaded since baseline (in-tree/signed — investigate, not auto-fatal)" \
          "absent" "$name" false ;;
    esac
  done <<< "$(comm -13 <(printf '%s\n' "$base_mods") <(printf '%s\n' "$cur_mods"))"

  # Removed modules.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    emit_finding "$CHECK_NAME" loaded_modules INFO \
      "module '$name' unloaded since baseline" "$name" "absent" false
  done <<< "$(comm -23 <(printf '%s\n' "$base_mods") <(printf '%s\n' "$cur_mods"))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
