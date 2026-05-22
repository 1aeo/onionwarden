#!/usr/bin/env bash
# lib/checks/input_devices.sh — local input-device hotplug (PLAN §2.8, fatal #10).
#
# A remote-managed host should gain no keyboard/mouse. A USB HID keyboard
# (class 03/subclass 01/protocol 01) or mouse (03/01/02), or a new PS/2 (serio)
# input device appearing after baseline is fatal #10. For a VM this also catches
# the hypervisor hot-plugging a virtual input device into the running guest.
# Downgraded per physical_access_mode (allowed -> INFO, suppress window -> WARN).
set -euo pipefail

# shellcheck source=lib/check_runtime.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check_runtime.sh"

CHECK_NAME="input_devices"
CHECK_CADENCE="fast"

input_devices_collect() {
  local d cls sub proto name
  # USB HID interfaces. Identity is class/subclass/protocol + product strings,
  # NOT the kernel bus path (which renumbers on replug — see critique R5).
  if [ -d /sys/bus/usb/devices ]; then
    for d in /sys/bus/usb/devices/*; do
      [ -f "$d/bInterfaceClass" ] || continue
      cls=$(cat "$d/bInterfaceClass" 2>/dev/null || printf '')
      sub=$(cat "$d/bInterfaceSubClass" 2>/dev/null || printf '')
      proto=$(cat "$d/bInterfaceProtocol" 2>/dev/null || printf '')
      [ "$cls" = "03" ] || continue   # 03 = HID
      # Identify by the parent device's vendor/product, stable across replug.
      local pdir vid pid prod
      pdir=$(dirname "$d")
      vid=$(cat "$pdir/idVendor" 2>/dev/null || printf '????')
      pid=$(cat "$pdir/idProduct" 2>/dev/null || printf '????')
      prod=$(cat "$pdir/product" 2>/dev/null || printf 'unknown')
      printf 'usbhid %s/%s/%s %s:%s %s\n' "$cls" "$sub" "$proto" "$vid" "$pid" "$prod"
    done
  fi
  # /sys/class/input event devices (keyboards/mice register here regardless of bus).
  if [ -d /sys/class/input ]; then
    for d in /sys/class/input/event*; do
      [ -e "$d" ] || continue
      name=$(cat "$d/device/name" 2>/dev/null || printf 'unknown')
      printf 'inputdev %s\n' "$name"
    done
  fi
  # PS/2 (serio) devices.
  if [ -d /sys/bus/serio/devices ]; then
    for d in /sys/bus/serio/devices/*; do
      [ -e "$d/description" ] || continue
      printf 'serio %s\n' "$(cat "$d/description" 2>/dev/null || printf 'unknown')"
    done
  fi
  # R5-2: kernel-log input-device registrations. These persist for the whole
  # boot, so they catch a plug-attack-unplug that the point-in-time sysfs
  # snapshot above would miss. The device name is stable across reboots.
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -k -q --no-pager 2>/dev/null \
      | sed -n 's/.* input: \(.*\) as \/devices.*/\1/p' \
      | sort -u | while IFS= read -r kn; do
          [ -n "$kn" ] && printf 'kmsg_input %s\n' "$kn"
        done
  fi
  printf 'collected ok\n'
}

# _input_allowlisted TOKEN -> 0 if TOKEN is in expected_input_devices.
_input_allowlisted() { cfg_list_has expected_input_devices "$1"; }

# _input_severity -> echoes "SEV FATAL" honoring physical_access_mode.
_input_severity() {
  case "$(physical_access_mode)" in
    allowed)    printf 'INFO false' ;;
    suppressed) printf 'WARN false' ;;
    *)          printf 'CRIT true'  ;;
  esac
}

input_devices_analyze() {
  local base_file=$1 cur_file=$2
  if ! grep -q '^collected ok' "$cur_file" 2>/dev/null; then
    emit_na "$CHECK_NAME" input_device "input-device sysfs not collected"
    return 0
  fi
  if [ ! -s "$base_file" ]; then
    emit_na "$CHECK_NAME" input_device "no baseline input-device set"
    return 0
  fi

  local sev fatal line cps desc token esev efatal
  read -r sev fatal <<< "$(_input_severity)"

  # _emit_input KIND-DESC LINE TOKEN — emit one finding, demoting to INFO if
  # the device's identity token is allowlisted in expected_input_devices (R5-1).
  _emit_input() {
    esev="$sev"; efatal="$fatal"
    if _input_allowlisted "$3"; then esev="INFO"; efatal="false"; fi
    emit_finding "$CHECK_NAME" input_device "$esev" "$1" "absent" "$2" "$efatal"
  }

  # New USB HID keyboards/mice (allowlist token = vid:pid).
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    cps=$(printf '%s' "$line" | awk '{print $2}')
    token=$(printf '%s' "$line" | awk '{print $3}')
    case "$cps" in
      03/01/01) desc="USB HID keyboard" ;;
      03/01/02) desc="USB HID mouse" ;;
      *)        desc="USB HID device ($cps)" ;;
    esac
    _emit_input "new $desc attached since baseline: $(printf '%s' "$line" | sed 's/^usbhid //')" \
      "$line" "$token"
  done <<< "$(comm -13 \
      <(grep '^usbhid ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^usbhid ' "$cur_file" 2>/dev/null | sort -u))"

  # New /sys/class/input event devices (allowlist token = device name).
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    token=$(printf '%s' "$line" | sed 's/^inputdev //')
    _emit_input "new input event device since baseline: $token" "$line" "$token"
  done <<< "$(comm -13 \
      <(grep '^inputdev ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^inputdev ' "$cur_file" 2>/dev/null | sort -u))"

  # New PS/2 serio input devices.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    token=$(printf '%s' "$line" | sed 's/^serio //')
    _emit_input "new PS/2 (serio) input device since baseline: $token" "$line" "$token"
  done <<< "$(comm -13 \
      <(grep '^serio ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^serio ' "$cur_file" 2>/dev/null | sort -u))"

  # New kernel-log input registrations (R5-2 — catches a plug-attack-unplug).
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    token=$(printf '%s' "$line" | sed 's/^kmsg_input //')
    _emit_input "kernel logged a new input device since baseline (may already be unplugged): $token" \
      "$line" "$token"
  done <<< "$(comm -13 \
      <(grep '^kmsg_input ' "$base_file" 2>/dev/null | sort -u) \
      <(grep '^kmsg_input ' "$cur_file" 2>/dev/null | sort -u))"
}

if [ "${BASH_SOURCE[0]}" = "${0:-}" ]; then
  check_run_cli "$@"
fi
