#!/usr/bin/env bash
# lib/checks/packages.sh — package & filesystem integrity (PLAN §2.4).
#
# debsums/dpkg --verify, the dpkg DB, APT sources & keys, and (if installed)
# AIDE. A changed packaged file is CRIT unless apt-correlated (§5). A new APT
# repo or signing key is CRIT — that is supply-chain persistence.
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"
# shellcheck source=lib/apt_correlate.sh
. "$(dirname "${BASH_SOURCE[0]}")/../apt_correlate.sh"

CHECK_NAME="packages"
CHECK_CADENCE="daily"

packages_collect() {
  # Changed packaged files: debsums -c (preferred) or dpkg --verify (weaker).
  local path corr
  if command -v debsums >/dev/null 2>&1; then
    debsums -c 2>/dev/null | while IFS= read -r path; do
      [ -n "$path" ] || continue
      corr=$(apt_correlate_file "$path")
      printf 'pkgfile %s %s\n' "$path" "$corr"
    done
  elif command -v dpkg >/dev/null 2>&1; then
    dpkg --verify 2>/dev/null | awk '{print $NF}' | while IFS= read -r path; do
      [ -n "$path" ] || continue
      corr=$(apt_correlate_file "$path")
      printf 'pkgfile %s %s\n' "$path" "$corr"
    done
  else
    printf 'pkgfile na no-debsums-dpkg\n'
  fi

  # dpkg DB + installed-package set.
  [ -f /var/lib/dpkg/status ] && printf 'dpkgstatus %s\n' "$(sha256_file /var/lib/dpkg/status)"
  if command -v dpkg >/dev/null 2>&1; then
    printf 'selections %s\n' "$(dpkg --get-selections 2>/dev/null | sha256_string "$(cat)")"
  fi

  # APT sources & signing keys.
  local f
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/* \
           /etc/apt/trusted.gpg.d/* /etc/apt/keyrings/*; do
    [ -f "$f" ] || continue
    printf 'aptsource %s %s\n' "$f" "$(sha256_file "$f")"
  done

  # AIDE — detect-and-skip if absent.
  if command -v aide >/dev/null 2>&1; then
    if aide --check >/dev/null 2>&1; then printf 'aide clean\n'; else printf 'aide changes\n'; fi
  else
    printf 'aide na_not_installed\n'
  fi
}

packages_analyze() {
  local base_file=$1 cur_file=$2
  if grep -q '^pkgfile na ' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" package_integrity "no debsums/dpkg available"
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" package_integrity "no baseline package state"
    return 0
  fi

  # Changed packaged files (new vs baseline pkgfile entries).
  local line path corr
  while IFS= read -r line; do
    case "$line" in pkgfile\ /*) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    corr=$(printf '%s' "$line" | awk '{print $3}')
    grep -qE "^pkgfile $path " "$base_file" 2>/dev/null && continue   # already known-changed
    if [ "$corr" = "correlated" ]; then
      emit_finding "$CHECK_NAME" package_integrity INFO \
        "packaged file changed but apt-correlated: $path" "intact" "changed" false
    else
      emit_finding "$CHECK_NAME" package_integrity CRIT \
        "packaged file modified and NOT apt-correlated: $path" "intact" "changed" false
    fi
  done < "$cur_file"

  # APT sources & keys — a new repo/key is supply-chain persistence.
  while IFS= read -r line; do
    case "$line" in aptsource\ *) ;; *) continue ;; esac
    path=$(printf '%s' "$line" | awk '{print $2}')
    chash=$(printf '%s' "$line" | awk '{print $3}')
    bhash=$(grep -E "^aptsource $path " "$base_file" 2>/dev/null | awk '{print $3}' | head -n1 || true)
    if [ -z "$bhash" ]; then
      emit_finding "$CHECK_NAME" apt_sources CRIT "new APT source/key: $path" "absent" "$chash" false
    elif [ "$bhash" != "$chash" ]; then
      emit_finding "$CHECK_NAME" apt_sources CRIT "APT source/key changed: $path" "$bhash" "$chash" false
    fi
  done < "$cur_file"

  # dpkg DB + selection drift.
  local bds cds bsel csel
  bds=$(awk '$1=="dpkgstatus"{print $2}' "$base_file" | head -n1)
  cds=$(awk '$1=="dpkgstatus"{print $2}' "$cur_file" | head -n1)
  [ -n "$bds" ] && [ "$bds" != "$cds" ] && emit_finding "$CHECK_NAME" dpkg_db WARN \
    "dpkg status DB changed (expected after apt activity)" "$bds" "$cds" false
  bsel=$(awk '$1=="selections"{print $2}' "$base_file" | head -n1)
  csel=$(awk '$1=="selections"{print $2}' "$cur_file" | head -n1)
  [ -n "$bsel" ] && [ "$bsel" != "$csel" ] && emit_finding "$CHECK_NAME" package_set WARN \
    "installed-package set changed — confirm via apt history" "$bsel" "$csel" false

  # AIDE.
  if grep -q '^aide changes' "$cur_file" 2>/dev/null; then
    emit_finding "$CHECK_NAME" aide CRIT "AIDE reports filesystem changes since its DB" "clean" "changes" false
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
