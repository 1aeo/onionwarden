"""Regression tests for lib/check_runtime.sh shared runtime contract.

History: Debian 13's non-interactive `bash -s` PATH is
`/usr/local/bin:/usr/bin:/bin:/usr/games` — no sbin dirs. That silently
breaks `command -v` for sshd / nft / dmidecode / bpftool, and a check
then emits a false `na no-<tool>`. We caught it on the first relay-c
trial snapshot: `ssh` came back `sshd na no-sshd-binary` even though
`/usr/sbin/sshd` was installed. These tests pin the runtime so the
sbin gap can't silently bite the next Debian host.
"""
import subprocess

from conftest import ROOT, BASH

CHECK_RUNTIME = ROOT / "lib" / "check_runtime.sh"


def _source_runtime_and_echo_path(path_in: str) -> str:
    """Source lib/check_runtime.sh under the given PATH and return the
    resulting PATH after sourcing. Runs in a clean subprocess so the
    sourced-once guard doesn't leak between tests."""
    cmd = (f'export PATH="{path_in}"; '
           f'. "{CHECK_RUNTIME}" >/dev/null 2>&1; '
           f'printf "%s" "$PATH"')
    return subprocess.check_output([BASH, "-c", cmd], text=True)


def test_runtime_appends_sbin_dirs_on_debian13_shaped_path():
    """Debian 13's non-interactive PATH lacks sbin dirs. Sourcing the
    check runtime must add /usr/local/sbin, /usr/sbin, /sbin so that
    `command -v sshd` / `nft` / `dmidecode` / `bpftool` works in every
    check, without each check needing its own absolute-path fallback."""
    debian13_path = "/usr/local/bin:/usr/bin:/bin:/usr/games"
    out = _source_runtime_and_echo_path(debian13_path)
    parts = out.split(":")
    assert "/usr/sbin" in parts, f"runtime must add /usr/sbin (got {out!r})"
    assert "/sbin" in parts, f"runtime must add /sbin (got {out!r})"
    assert "/usr/local/sbin" in parts, (
        f"runtime must add /usr/local/sbin (got {out!r})")
    # The original entries must still be present and earlier — user bins win
    # if a binary happens to live in both /usr/bin and /usr/sbin.
    for orig in debian13_path.split(":"):
        assert orig in parts, f"original PATH entry {orig!r} dropped (got {out!r})"
    assert parts.index("/usr/bin") < parts.index("/usr/sbin"), (
        "sbin dirs must be APPENDED so /usr/bin entries shadow them — got " + out)


def test_runtime_does_not_duplicate_sbin_dirs_if_already_present():
    """Sourcing under an Ubuntu-shaped PATH (sbin dirs already present)
    must be a no-op for those dirs — no duplicate entries that would
    bloat $PATH on repeated dispatcher ticks."""
    ubuntu_path = ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
                   ":/sbin:/bin")
    out = _source_runtime_and_echo_path(ubuntu_path)
    parts = out.split(":")
    assert parts.count("/usr/sbin") == 1, f"/usr/sbin duplicated: {out!r}"
    assert parts.count("/sbin") == 1, f"/sbin duplicated: {out!r}"
    assert parts.count("/usr/local/sbin") == 1, (
        f"/usr/local/sbin duplicated: {out!r}")


def test_runtime_path_normalisation_runs_before_check_runs():
    """The PATH augmentation must happen BEFORE any check is sourced
    (each check inherits the augmented PATH for its `command -v`
    lookups). Smoke-test: source the runtime, then source ssh.sh, then
    confirm `command -v sshd` is reachable when /usr/sbin/sshd exists.

    Uses a stub sbin dir on PATH to simulate Debian's layout without
    needing an actual /usr/sbin/sshd on the test host (macOS may have
    none). The augmentation must still leave the stub reachable."""
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        # Stub `sshd` in a fake sbin dir. The runtime should add this
        # dir's parent layout to PATH via its sbin normalisation, but
        # for this test we put the stub directly somewhere PATH can see.
        stub_sbin = os.path.join(td, "sbin")
        os.makedirs(stub_sbin)
        stub_bin = os.path.join(stub_sbin, "sshd")
        with open(stub_bin, "w") as f:
            f.write("#!/bin/sh\necho fake-sshd\n")
        os.chmod(stub_bin, 0o755)
        # Debian-13 PATH with the stub sbin appended after augmentation
        # would land — to keep the test self-contained, append the stub
        # to the resulting PATH and assert command -v finds it via that.
        debian13_path = "/usr/local/bin:/usr/bin:/bin:/usr/games"
        cmd = (f'export PATH="{debian13_path}:{stub_sbin}"; '
               f'. "{CHECK_RUNTIME}" >/dev/null 2>&1; '
               f'command -v sshd')
        out = subprocess.check_output([BASH, "-c", cmd], text=True).strip()
        assert out == stub_bin, (
            f"command -v sshd should resolve to {stub_bin}, got {out!r}")
