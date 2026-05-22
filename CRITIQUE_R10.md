# CRITIQUE R10 — Cross-distribution & kernel-version portability

**Lens:** Ubuntu 24.04 stock vs OEM kernels vs Debian 13; assumptions about
systemd version, `/proc` and `/sys` layout, and tool behaviour that would
silently break. **Files read:** all `lib/checks/*.sh` collectors,
`lib/profile.sh`, the `systemd/` units, `lib/checks/packages.sh`,
`lib/checks/boot_integrity.sh`, `lib/checks/kernel_state.sh`,
`lib/checks/network_deep.sh` (`/proc/<pid>/cgroup`).

## Findings

### R10-4 (HIGH) — `packages` collector aborts exactly when it finds changes
`packages_collect` runs `debsums -c | while ...` and `dpkg --verify | awk |
while ...`. **`dpkg --verify` exits 1 when it finds discrepancies** (and
`debsums -c` likewise reports a non-zero status on changed files). Under
`set -euo pipefail` that non-zero pipeline status aborts `packages_collect` —
so on any host that actually has a modified packaged file (precisely the case
worth reporting) the collector dies and the dispatcher records only a generic
"collect failed" WARN. The check silently fails when it matters most.

### R10-3 (MEDIUM) — Kernel/boot checks do not detect-and-skip in a container
PLAN §0.2: "container → kernel/boot group no-ops" — a container shares the host
kernel, which is out of scope for a guest (§1 trust boundaries). `modules`
honors this (`na container`), but `taint`, `kernel_state`, and `boot_integrity`
do not — in a container they read the host kernel's taint/kexec/lockdown/`/boot`
state and would alert on a host-side change the container neither owns nor can
act on.

### R10-2 (LOW) — `boot_integrity`'s GRUB-core block is not failure-guarded
The legacy-BIOS GRUB-core hash uses `lsblk`/`findmnt`/`dd`. The
`lsblk ... | head` pipeline is not wrapped — on a host missing util-linux, or
with an unusual root device, the non-zero status aborts `boot_integrity_collect`
under `set -e` instead of degrading to the intended `na_no_bootdev`.

## Non-findings (examined, no issue)

- `/proc/<pid>/cgroup` substring-matching in `network_deep` works on both
  cgroup v1 and v2 — the unit name appears in the path either way.
- systemd-version assumptions hold: `--no-legend`, `--value`, `MemoryMax`,
  `ProtectSystem=strict` are all well within Ubuntu 24.04 (systemd 255) and
  Debian 13 (systemd 257) baselines.
- Cross-flavor kernel comparison (`linux-image-*` of any flavor) is the
  *intended* behaviour per PLAN §0.5 — a WARN reboot-hint, not a defect.
- `/sys`/`/proc` reads in `taint`/`kernel_state`/`promisc`/`input_devices` are
  all `[ -r ]`/`[ -d ]`-guarded; an OEM kernel lacking `/sys/module/*/taint`
  degrades cleanly.
- Debian 13: `ID=debian` is in `os_supported`; apt/dpkg/debsums/aide/mokutil all
  behave identically; OEM-meta-package naming is Ubuntu-only and isolated.

## Fixes applied

- **R10-4:** the `debsums -c` / `dpkg --verify` producers are wrapped
  `{ ... || true; }` so a non-zero "found changes" status no longer aborts the
  collector; the changed-file lines are still parsed and reported.
- **R10-3:** `taint`, `kernel_state`, and `boot_integrity` collectors now emit
  `na container` when the host profile says `is_container`, and their
  analyzers detect-and-skip on it — matching `modules`.
- **R10-2:** the GRUB-core block guards `lsblk`/`findmnt` with `command -v` and
  tolerates their failure, degrading to `na_no_bootdev`.
