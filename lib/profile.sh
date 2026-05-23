# shellcheck shell=bash
# lib/profile.sh — host capability detection (PLAN §0.2).
#
# detect-and-skip: every check consults the profile and either runs or no-ops
# with a logged "N/A: <reason>". The profile is captured into the signed
# baseline, so a *change* (EFI appears, virt_type flips, host becomes a
# hypervisor) is itself a signal — see lib/checks/profile.sh.
#
# profile_detect() is a collector (Linux-only, runs commands). prof_load/prof_get
# read a profile file and are pure — those are what checks and tests use.

if [ -n "${_ONIONWARDEN_PROFILE_SH:-}" ]; then return 0 2>/dev/null || true; fi
_ONIONWARDEN_PROFILE_SH=1

# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Preserve an inherited value (dispatcher exports _PROF_FILE to check children).
_PROF_FILE="${_PROF_FILE:-}"

prof_load() { _PROF_FILE=$1; }

prof_get() {
  local key=$1 def=${2:-} line
  [ -n "$_PROF_FILE" ] && [ -f "$_PROF_FILE" ] || { printf '%s' "$def"; return 0; }
  line=$(grep -E "^${key}=" "$_PROF_FILE" 2>/dev/null | tail -n1 || true)
  if [ -z "$line" ]; then printf '%s' "$def"; return 0; fi
  printf '%s' "${line#*=}"
}

prof_bool() {
  case "$(prof_get "$1" "${2:-false}")" in
    true|1|yes) return 0 ;;
    *) return 1 ;;
  esac
}

_b() { if "$@" >/dev/null 2>&1; then printf 'true'; else printf 'false'; fi; }

# profile_detect — emit key=value capability lines to stdout. Linux target only.
profile_detect() {
  local os_id="unknown" os_version="unknown"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-unknown}")
    os_version=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-unknown}")
  fi
  printf 'os_id=%s\n' "$os_id"
  printf 'os_version=%s\n' "$os_version"

  # Supported OS gate (PLAN §0.2): the tool refuses to run elsewhere.
  case "$os_id" in
    ubuntu|debian) printf 'os_supported=true\n' ;;
    *)             printf 'os_supported=false\n' ;;
  esac

  local virt="none" container="false"
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt=$(systemd-detect-virt 2>/dev/null || printf 'none')
    if systemd-detect-virt --container >/dev/null 2>&1; then container="true"; fi
  fi
  printf 'virt_type=%s\n' "$virt"
  printf 'is_container=%s\n' "$container"

  printf 'efi_present=%s\n' "$(_b test -d /sys/firmware/efi)"
  printf 'secureboot_tool=%s\n' "$(_b command -v mokutil)"
  printf 'lockdown_available=%s\n' "$(_b test -r /sys/kernel/security/lockdown)"

  # Hypervisor: running QEMU guests or an active libvirtd.
  local is_hyper="false"
  if pgrep -x libvirtd >/dev/null 2>&1 || pgrep -f 'qemu-system' >/dev/null 2>&1; then
    is_hyper="true"
  fi
  printf 'is_hypervisor=%s\n' "$is_hyper"

  # Cloud instance: cloud-init present AND not disabled, or a known cloud DMI
  # vendor. The Ubuntu live installer drops `/etc/cloud/cloud-init.disabled`
  # after first boot on bare-metal installs; cloud-init's systemd generator
  # then writes `/run/cloud-init/disabled` at boot and short-circuits all four
  # cloud-init units. Treating either marker as authoritative avoids flagging
  # is_cloud=true on bare-metal hosts that ship cloud-init purely as a
  # first-boot installer helper (relay-a et al). DMI vendor still wins:
  # AWS/GCP/Azure/etc. lie about being bare-metal sometimes.
  local is_cloud="false" vendor=""
  [ -r /sys/class/dmi/id/sys_vendor ] && vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
  if [ -d /run/cloud-init ] \
     && [ ! -e /run/cloud-init/disabled ] \
     && [ ! -e /etc/cloud/cloud-init.disabled ]; then
    is_cloud="true"
  fi
  case "$vendor" in
    *Amazon*|*Google*|*Microsoft*|*DigitalOcean*|*Hetzner*) is_cloud="true" ;;
  esac
  printf 'is_cloud=%s\n' "$is_cloud"

  printf 'have_auditd=%s\n'  "$(_b command -v auditctl)"
  printf 'have_debsums=%s\n' "$(_b command -v debsums)"
  printf 'have_aide=%s\n'    "$(_b command -v aide)"
  printf 'have_bpftool=%s\n' "$(_b command -v bpftool)"
  printf 'have_nft=%s\n'     "$(_b command -v nft)"
  printf 'have_getcap=%s\n'  "$(_b command -v getcap)"
  printf 'have_snap=%s\n'    "$(_b command -v snap)"
  printf 'have_curl=%s\n'    "$(_b command -v curl)"
  printf 'have_jq=%s\n'      "$(_b command -v jq)"

  # Immutable-attribute (chattr +i) support depends on the FS of the install
  # prefix, not the distro. ext*/btrfs/xfs support it; tmpfs/zfs/overlay do not.
  local prefix="${ONIONWARDEN_PREFIX:-/opt/onionwarden}" fs="unknown" imm="false"
  if command -v stat >/dev/null 2>&1; then
    fs=$(stat -f -c %T "$prefix" 2>/dev/null || stat -f -c %T / 2>/dev/null || printf 'unknown')
  fi
  case "$fs" in
    ext2/ext3|ext4|btrfs|xfs) imm="true" ;;
  esac
  printf 'install_fs=%s\n' "$fs"
  printf 'immutable_fs_supported=%s\n' "$imm"

  # Ed25519 verification backend (drives lib/verify.sh).
  local osl="false"
  if command -v openssl >/dev/null 2>&1; then
    if openssl genpkey -algorithm ED25519 -out /dev/null >/dev/null 2>&1; then osl="true"; fi
  fi
  printf 'openssl_ed25519=%s\n' "$osl"

  printf 'kernel_release=%s\n' "$(uname -r 2>/dev/null || printf unknown)"
  printf 'detected_at=%s\n' "$(now_iso)"
}
