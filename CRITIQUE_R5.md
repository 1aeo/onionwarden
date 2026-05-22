# CRITIQUE R5 — Input-device + console-login detection

**Lens:** false positives (USB flapping, serial-console boot output mistaken
for a login) and false negatives (HID-class spoofing, BadUSB, transient
plug-attack-unplug). **Files read:** `lib/checks/input_devices.sh` (whole),
`lib/checks/console_login.sh` (whole), `lib/check_runtime.sh:physical_access_mode`.

## Findings

### R5-1 (MEDIUM) — No per-device allowlist for input devices
`input_devices` keys USB HID devices on class/subclass/protocol + vid:pid (not
the bus path — so a replug of the *same* device does not false-positive, good).
But the only knob for an *expected* device is the all-or-nothing
`physical_access_allowed`. A host that legitimately gains an input device
post-baseline — a uinput device from an accessibility tool or a KVM/synergy
agent, an IPMI dongle re-enumerated — has no middle ground: re-baseline, or
disable the whole signal. Every other check has an `expected_*` allowlist;
this one does not.

### R5-2 (MEDIUM) — Plug-attack-unplug within the fast interval is invisible
The check is a point-in-time sysfs snapshot on the ~1-min fast cadence. A
BadUSB keystroke-injection attack is a seconds-long plug → inject → unplug; by
the next tick the device is gone and the snapshot diff shows nothing. The
durable evidence is the kernel log (`input: <name> as /devices/...`,
`usb ...: new ... device`), which persists for the rest of the boot — but no
check looked at it. (Class-spoofing / composite BadUSB is *not* a gap: to act
as a keyboard a device must present an HID interface and register under
`/sys/class/input/event*`, which the `inputdev` rows already capture.)

### R5-3 (MEDIUM) — `console_login` only sees *current* sessions
`console_login` reads `who`, which shows sessions open *right now*. A console
login that opens and closes within the ~1-min interval leaves no `who` entry
and is missed. PLAN §2.8 explicitly calls for "`who` ... **+ new `last`/wtmp
tty entries since cursor**" — the wtmp half was not implemented, so a
short-lived console session is invisible.

## Non-findings (examined, no issue)

- Serial-console false positive: the `^tty[0-9]+$` filter excludes `ttyS*`
  (the `S` is not a digit), so serial-console boot output / sessions never trip
  #11 — matching PLAN §2.8's `tty[0-9]*` scope.
- USB replug false positive: device identity is vid:pid + HID class, not the
  renumbering bus path — a disconnect/reconnect of the same device is a no-op.

## Fixes applied

- **R5-1:** added an `expected_input_devices` host.conf allowlist; an
  allowlisted new device (matched by vid:pid for USB HID, by name for
  input/serio devices) demotes to INFO instead of CRIT.
- **R5-2:** `input_devices` now also collects `input:` device-registration
  lines from `journalctl -k`; a registration not seen at baseline is a finding
  even if the device has since been unplugged (durable for the boot).
- **R5-3:** `console_login` now also parses `last` (wtmp) for `tty[0-9]`
  logins; a closed console session by a new user/tty is caught. (Residual: a
  *repeat* login by an already-baselined user on a closed session is only
  caught while active via `who` — documented.)
