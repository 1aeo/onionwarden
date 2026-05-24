"""Regression tests for the /proc/mounts-based install_fs detector.

The pre-rename `secure-server` tree fixed `install_fs` in commit b24fad7 so
that `stat -f -c %T` 's "ext2/ext3" family-name collapse doesn't mis-report
ext4 hosts. The filter-repo extraction to `1aeo/onionwarden` silently reverted
the fix. These tests use a fixture /proc/mounts via ONIONWARDEN_PROC_MOUNTS
to drive the detector deterministically on macOS too.
"""
import os
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROFILE_SH = ROOT / "lib" / "profile.sh"


def _run_profile_detect(env_overrides):
    """Source profile.sh and run profile_detect(); return its stdout.

    profile_detect runs many probes (os-release, dmi, command -v); on macOS
    those gracefully degrade to default values and don't crash. We only care
    about the install_fs= line in stdout for these tests.
    """
    script = f". {PROFILE_SH}; profile_detect"
    env = {**os.environ, **env_overrides}
    proc = subprocess.run(
        ["/bin/bash", "-c", script], capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, (
        f"profile_detect exited {proc.returncode}\nstderr:\n{proc.stderr}"
    )
    return proc.stdout


def _install_fs(out):
    m = re.search(r"^install_fs=(.+)$", out, re.MULTILINE)
    assert m, f"profile_detect output had no install_fs= line:\n{out}"
    return m.group(1).strip()


def _immutable_supported(out):
    m = re.search(r"^immutable_fs_supported=(.+)$", out, re.MULTILINE)
    assert m, f"profile_detect output had no immutable_fs_supported= line:\n{out}"
    return m.group(1).strip()


def test_ext4_install_path_reported_as_ext4_not_ext2_ext3(tmp_path):
    """The bug we're fencing: ext4 must not be collapsed to 'ext2/ext3'."""
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "/dev/sda2 /opt ext4 rw,relatime 0 0\n"
        "tmpfs /run tmpfs rw,nosuid,nodev,size=1638160k 0 0\n"
    )
    out = _run_profile_detect({
        "ONIONWARDEN_PROC_MOUNTS": str(mounts),
        "ONIONWARDEN_PREFIX": "/opt/onionwarden",
    })
    assert _install_fs(out) == "ext4", out
    assert _immutable_supported(out) == "true", out


def test_longest_prefix_match_wins(tmp_path):
    """A mount at /opt must beat the root mount when prefix is /opt/onionwarden."""
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "/dev/sda1 / btrfs rw,relatime 0 0\n"
        "/dev/sda2 /opt ext4 rw,relatime 0 0\n"
    )
    out = _run_profile_detect({
        "ONIONWARDEN_PROC_MOUNTS": str(mounts),
        "ONIONWARDEN_PREFIX": "/opt/onionwarden",
    })
    assert _install_fs(out) == "ext4", out


def test_falls_back_to_root_when_prefix_not_mounted(tmp_path):
    """No mount covers the prefix → return the root mount's fs type."""
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "/dev/sda1 / xfs rw,relatime 0 0\n"
    )
    out = _run_profile_detect({
        "ONIONWARDEN_PROC_MOUNTS": str(mounts),
        "ONIONWARDEN_PREFIX": "/opt/onionwarden",
    })
    assert _install_fs(out) == "xfs", out
    assert _immutable_supported(out) == "true", out


def test_btrfs_and_xfs_still_supported(tmp_path):
    """Sanity: the immutable-supported set still recognises btrfs and xfs."""
    for fs in ("btrfs", "xfs", "ext2", "ext3", "ext4"):
        mounts = tmp_path / f"mounts_{fs}"
        mounts.write_text(f"/dev/sda1 / {fs} rw,relatime 0 0\n")
        out = _run_profile_detect({
            "ONIONWARDEN_PROC_MOUNTS": str(mounts),
            "ONIONWARDEN_PREFIX": "/opt/onionwarden",
        })
        assert _install_fs(out) == fs, f"{fs}: {out}"
        assert _immutable_supported(out) == "true", f"{fs}: {out}"


def test_tmpfs_marks_immutable_unsupported(tmp_path):
    """tmpfs (and other non-ext/btrfs/xfs) must NOT claim chattr +i support."""
    mounts = tmp_path / "mounts"
    mounts.write_text("tmpfs / tmpfs rw,nosuid 0 0\n")
    out = _run_profile_detect({
        "ONIONWARDEN_PROC_MOUNTS": str(mounts),
        "ONIONWARDEN_PREFIX": "/opt/onionwarden",
    })
    assert _install_fs(out) == "tmpfs", out
    assert _immutable_supported(out) == "false", out
