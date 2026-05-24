"""Regression tests for the widened kernel_state collector.

The pre-rename `secure-server` tree widened `_KS_SYSCTLS` from 5 to 25 keys
in commit b24fad7 to track the full CIS Debian 12 / STIG hardening surface
(rp_filter, accept_redirects, send_redirects, fs.protected_fifos, …). The
filter-repo extraction to `1aeo/onionwarden` silently reverted it to 5 keys.
These tests fence the widened list so the same silent revert can't happen
again — the bash collector behaviour is exercised against a stubbed `sysctl`,
and the script source is also grepped so a list-trim shows up even without
running the collector.
"""
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
KS_SCRIPT = ROOT / "lib" / "checks" / "kernel_state.sh"

# The 25 sysctls that MUST be in the collector list. Touching this set is a
# deliberate hardening decision — bump the count below and update the comment
# block in lib/checks/kernel_state.sh if you intentionally widen or trim.
REQUIRED_SYSCTLS = [
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.unprivileged_bpf_disabled",
    "kernel.kexec_load_disabled",
    "kernel.yama.ptrace_scope",
    "kernel.randomize_va_space",
    "fs.suid_dumpable",
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
    "fs.protected_fifos",
    "fs.protected_regular",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.default.accept_source_route",
]


def _run_collect():
    """Source kernel_state.sh, stub sysctl + prof_bool, run kernel_state_collect.

    Returns the collector's stdout. Works on macOS (no Linux /proc) because
    every external probe is either /proc-gated by `[ -r ... ]` or replaced by
    a shell function we inject before sourcing.
    """
    script = f"""
set -u
# Shim profile + sysctl + bpftool BEFORE sourcing the check so kernel_state
# uses our fakes instead of system binaries / runtime helpers.
prof_bool() {{ return 1; }}                 # not a container
sysctl() {{
  case "$1" in
    -n) printf '0\\n' ;;                    # any key returns 0 — value irrelevant
    *)  printf '0\\n' ;;
  esac
}}
export -f prof_bool sysctl 2>/dev/null || true
# Tell check_runtime.sh not to bail on missing common.sh helpers.
. {ROOT}/lib/check_runtime.sh
. {KS_SCRIPT}
kernel_state_collect
"""
    proc = subprocess.run(
        ["/bin/bash", "-c", script],
        capture_output=True, text=True,
        env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)},
    )
    assert proc.returncode == 0, (
        f"kernel_state_collect exited {proc.returncode}\nstderr:\n{proc.stderr}"
    )
    return proc.stdout


def test_collector_emits_every_required_sysctl():
    """Every key in REQUIRED_SYSCTLS appears as a `sysctl <key> <value>` line."""
    out = _run_collect()
    emitted = {
        line.split()[1] for line in out.splitlines()
        if line.startswith("sysctl ") and len(line.split()) >= 2
    }
    missing = [k for k in REQUIRED_SYSCTLS if k not in emitted]
    assert not missing, (
        f"kernel_state_collect dropped {len(missing)} required sysctl(s): {missing}\n"
        f"full output:\n{out}"
    )


def test_collector_emits_rp_filter_and_protected_fifos():
    """Spot-check: the two most-frequently-drifted-by-default keys.

    These are the smoke signals: rp_filter and protected_fifos are absent in
    Debian defaults and almost always show up as 'below recommended' on a
    fresh relay. If the collector ever silently drops them again, this test
    fires first.
    """
    out = _run_collect()
    assert "sysctl net.ipv4.conf.all.rp_filter" in out, out
    assert "sysctl fs.protected_fifos" in out, out


def test_source_script_lists_every_required_sysctl():
    """Source-level fence: the script text itself names every required key.

    This catches a regression even if the collector function isn't run (e.g.
    a future refactor that moves the list into a generated config file or
    drops a key from the literal). Pure string match — no bash needed.
    """
    src = KS_SCRIPT.read_text()
    missing = [k for k in REQUIRED_SYSCTLS if k not in src]
    assert not missing, (
        f"kernel_state.sh source is missing required sysctl(s): {missing}"
    )


def test_required_sysctl_count_is_25():
    """If you intentionally widen or trim REQUIRED_SYSCTLS, also bump this
    count — a one-line guard against accidental list edits."""
    assert len(REQUIRED_SYSCTLS) == 25, (
        f"REQUIRED_SYSCTLS now has {len(REQUIRED_SYSCTLS)} entries; "
        f"update this assertion deliberately when widening/trimming."
    )
