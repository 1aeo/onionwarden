# shellcheck shell=bash
# lib/apt_correlate.sh — apt-correlation for packaged-file churn (PLAN §5, M5).
#
# apt/unattended-upgrades legitimately rewrite /boot, modules, and packaged
# files. A change is demoted WARN->INFO only if it is PROVABLY part of a real
# apt run. The anchor (M5) is the per-file hash match against the package DB —
# NOT mtime, which root can forge with `touch`. Used at COLLECT time by the
# boot_integrity and packages checks; the verdict is written into the state
# file so analyze() stays a pure function.

if [ -n "${_ONIONWARDEN_APT_CORRELATE_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_APT_CORRELATE_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

_APT_HISTORY="${ONIONWARDEN_APT_HISTORY:-/var/log/apt/history.log}"

# apt_history_packages — package names touched by apt (Install/Upgrade/Reinstall).
apt_history_packages() {
  local f
  for f in "$_APT_HISTORY" "${_APT_HISTORY}".*; do
    [ -f "$f" ] || continue
    case "$f" in *.gz) zcat "$f" 2>/dev/null ;; *) cat "$f" 2>/dev/null ;; esac
  done | awk -F: '/^(Install|Upgrade|Reinstall):/ {
      sub(/^[^:]*: */, "")
      n = split($0, parts, ", ")
      for (i = 1; i <= n; i++) { split(parts[i], p, " "); print p[1] }
    }' | sed 's/:.*//' | sort -u
}

# apt_correlate_file PATH -> "correlated" | "uncorrelated"
# correlated  = PATH is owned by a package, that package appears in apt history,
#               AND PATH currently matches the package DB (dpkg --verify passes).
# uncorrelated = anything else — including a file edited to content that matches
#               NO package (the case a blanket time-window rule would miss).
apt_correlate_file() {
  local path=$1 owner
  command -v dpkg >/dev/null 2>&1 || { printf 'uncorrelated'; return 0; }
  owner=$(dpkg -S "$path" 2>/dev/null | head -n1 | sed 's/:.*//' | tr -d ' ')
  if [ -z "$owner" ]; then printf 'uncorrelated'; return 0; fi
  if ! apt_history_packages | grep -qx "$owner"; then
    printf 'uncorrelated'; return 0
  fi
  # Hash anchor: if dpkg --verify lists PATH as failed, the file does NOT match
  # the package — it is an arbitrary edit, not the new package's file.
  if dpkg --verify "$owner" 2>/dev/null | awk '{print $NF}' | grep -qx "$path"; then
    printf 'uncorrelated'; return 0
  fi
  printf 'correlated'
}

# apt_correlate_kernel — coarse signal for /boot churn: was a linux-image /
# linux-headers / initramfs-tools package touched by apt at all? /boot's initrd
# is generated, not a packaged file, so the per-file hash anchor cannot apply;
# this is an honest weaker signal (documented in IMPLEMENTATION_NOTES).
apt_correlate_kernel() {
  if apt_history_packages | grep -qE '^(linux-image|linux-headers|linux-modules|initramfs-tools|grub)'; then
    printf 'correlated'
  else
    printf 'uncorrelated'
  fi
}
