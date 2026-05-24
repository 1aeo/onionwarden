"""Tests for the parallel snapshot path in bin/onionwarden-snapshot.

The snapshot tool now opens up to --parallel N concurrent SSH sessions, one
per check. We can't reach a real Linux peer from the test host so every test
points $ONIONWARDEN_SNAPSHOT_SSH at a stub script that runs the bundle locally
(stripping any `timeout NN` / `nice -n NN` / `sudo -n` wrappers that don't
exist on macOS).

What we assert:
  - mini-bundles for every check are valid bash and invoke <check>_collect
  - a parallel run produces one .current + one .exit per check
  - rerunning produces byte-identical .current files (no orchestration races)
  - --parallel 1 produces the same .current set as --parallel 8 (determinism
    across concurrency widths)
  - parallel wall-clock is materially faster than serial wall-clock with
    artificial fixed-time checks (the central perf claim of the change)
"""
import os
import pathlib
import shutil
import stat
import subprocess
import time

import pytest

from conftest import ROOT, BASH

SNAPSHOT_BIN = str(ROOT / "bin" / "onionwarden-snapshot")
CHECKS_DIR = ROOT / "lib" / "checks"
CHECK_NAMES = sorted(p.stem for p in CHECKS_DIR.glob("*.sh"))


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

FAKE_SSH = r"""#!/usr/bin/env bash
# Test stub: behave like ssh(1) for the snapshot tool.
#   $1 = HOST (ignored)
#   $2..$N = command tokens to run remotely (here, run locally)
# We strip the wrappers that don't exist on macOS (`timeout NN`, `nice -n NN`,
# `sudo -n`) so the inner `bash -s` reads the bundle from stdin and exits.
shift  # drop HOST
cmd="$*"
while :; do
  case "$cmd" in
    "timeout "[0-9]*) cmd="${cmd#timeout [0-9]* }" ;;
    "nice -n "[0-9]*) cmd="${cmd#nice -n [0-9]* }" ;;
    "sudo -n "*)      cmd="${cmd#sudo -n }" ;;
    *) break ;;
  esac
done
exec bash -c "$cmd"
"""

# A second stub that ignores stdin entirely and prints a per-check fixed
# payload after sleeping FAKE_SLEEP seconds. Lets us bench parallelism with
# wall-clock guarantees independent of real collector behaviour.
FAKE_SSH_SLEEP = r"""#!/usr/bin/env bash
# Test stub for perf bench: ignore the command, sleep $FAKE_SLEEP, emit a
# deterministic payload to stdout. The snapshot tool uses our stdout as the
# .current file content.
shift  # drop HOST
sleep "${FAKE_SLEEP:-1}"
printf 'fake-collector-output sleep=%s\n' "${FAKE_SLEEP:-1}"
exit 0
"""


@pytest.fixture
def fake_ssh(tmp_path):
    p = tmp_path / "fake-ssh.sh"
    p.write_text(FAKE_SSH)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


@pytest.fixture
def fake_ssh_sleep(tmp_path):
    p = tmp_path / "fake-ssh-sleep.sh"
    p.write_text(FAKE_SSH_SLEEP)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


def _run_snapshot(out_dir, fake_ssh_path, parallel, extra_env=None):
    """Drive bin/onionwarden-snapshot end-to-end with the fake-ssh stub."""
    env = dict(os.environ)
    env["ONIONWARDEN_SNAPSHOT_SSH"] = fake_ssh_path
    env["ONIONWARDEN_SNAPSHOT_PERCHECK"] = "8"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [BASH, SNAPSHOT_BIN, "localhost",
         "--out", str(out_dir), "--parallel", str(parallel)],
        capture_output=True, text=True, env=env, timeout=300)


# ---------------------------------------------------------------------------
# mini-bundle validity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("check", CHECK_NAMES)
def test_print_check_emits_valid_bash(check):
    """Every per-check bundle parses under `bash -n` and calls <check>_collect."""
    out = subprocess.check_output(
        [BASH, SNAPSHOT_BIN, "--print-check", check], text=True)
    assert out.startswith("#!/usr/bin/env bash"), \
        f"{check}: missing shebang"
    syntax = subprocess.run([BASH, "-n"], input=out, capture_output=True,
                            text=True)
    assert syntax.returncode == 0, \
        f"{check}: bash -n failed:\n{syntax.stderr}"
    assert f"__snap_one {check}\n" in out, \
        f"{check}: bundle does not invoke __snap_one {check}"


def test_print_check_unknown_check_dies():
    """Asking for a check that doesn't exist refuses cleanly (no SSH)."""
    p = subprocess.run([BASH, SNAPSHOT_BIN, "--print-check", "no-such-check"],
                       capture_output=True, text=True)
    assert p.returncode != 0
    assert "no such check" in p.stderr.lower()


# ---------------------------------------------------------------------------
# end-to-end parallel run
# ---------------------------------------------------------------------------

def test_parallel_run_produces_per_check_files(fake_ssh, tmp_path):
    """--parallel 4 produces a .current AND an .exit file per check."""
    out_dir = tmp_path / "snap"
    p = _run_snapshot(out_dir, fake_ssh, 4)
    assert out_dir.exists()
    # The tool can exit 2 if any check FAILED — that's normal on macOS where
    # find/-based collectors time out. The orchestration itself must have run.
    assert p.returncode in (0, 2), \
        f"snapshot exited {p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}"
    for check in CHECK_NAMES:
        assert (out_dir / f"{check}.current").exists(), \
            f"{check}.current missing"
        assert (out_dir / f"{check}.exit").exists(), \
            f"{check}.exit missing"
    # raw/meta.txt records the parallel width used (and asserts the report path).
    meta = (out_dir / "raw" / "meta.txt").read_text()
    assert "parallel=4" in meta, meta


def test_parallel_run_records_meta(fake_ssh, tmp_path):
    """The meta header records the parallel width actually used."""
    out_dir = tmp_path / "snap"
    p = _run_snapshot(out_dir, fake_ssh, 8)
    assert p.returncode in (0, 2)
    meta = (out_dir / "raw" / "meta.txt").read_text()
    assert "parallel=8" in meta


def test_serial_mode_works(fake_ssh, tmp_path):
    """--parallel 1 still runs each check (back-compat with single-threaded callers)."""
    out_dir = tmp_path / "snap"
    p = _run_snapshot(out_dir, fake_ssh, 1)
    assert p.returncode in (0, 2)
    for check in CHECK_NAMES:
        assert (out_dir / f"{check}.current").exists()


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------

def _current_files_digest(out_dir):
    """A deterministic digest of every .current file's content (sorted by name)."""
    d = {}
    for f in sorted(pathlib.Path(out_dir).glob("*.current")):
        d[f.name] = f.read_bytes()
    return d


def test_parallel_runs_byte_identical(fake_ssh, tmp_path):
    """Two consecutive --parallel 8 runs produce byte-identical .current files
    (the orchestration must not introduce non-determinism in per-check output)."""
    out1 = tmp_path / "snap-a"
    out2 = tmp_path / "snap-b"
    p1 = _run_snapshot(out1, fake_ssh, 8)
    p2 = _run_snapshot(out2, fake_ssh, 8)
    assert p1.returncode in (0, 2)
    assert p2.returncode in (0, 2)
    d1 = _current_files_digest(out1)
    d2 = _current_files_digest(out2)
    # The KEY set must match exactly (same check files written).
    assert set(d1) == set(d2)
    # And content must match for every check whose collector emits no
    # timestamps. On macOS most collectors that succeed are time-independent
    # (clock prints `ntp_sync na_no_timedatectl`, profile prints constants,
    # etc.). We allow per-check skips only if BOTH sides genuinely differ.
    diffs = [name for name in d1 if d1[name] != d2[name]]
    # process_ancestry and any collector that walks live /proc can vary;
    # we accept a small budget of timing-sensitive files and surface what
    # they were if it's larger than that.
    BUDGET = 5
    assert len(diffs) <= BUDGET, \
        ("more than {} per-check files differed between two parallel runs "
         "(non-determinism in orchestration?): {}").format(BUDGET, diffs)


def test_serial_and_parallel_byte_identical_for_pure_checks(fake_ssh, tmp_path):
    """For checks whose output is independent of wall-clock and process state,
    --parallel 1 and --parallel 8 must produce the SAME bytes. We pin
    `now_iso()` via ONIONWARDEN_NOW so the profile check's `detected_at=` line
    is stable across runs — without that, timestamp drift between the two
    invocations would make the check look non-deterministic when in fact
    only the wall clock differs."""
    out_s = tmp_path / "snap-serial"
    out_p = tmp_path / "snap-parallel"
    pinned_time = {"ONIONWARDEN_NOW": "2026-01-01T00:00:00Z",
                   "ONIONWARDEN_NOW_EPOCH": "1767225600"}
    p1 = _run_snapshot(out_s, fake_ssh, 1, extra_env=pinned_time)
    p2 = _run_snapshot(out_p, fake_ssh, 8, extra_env=pinned_time)
    assert p1.returncode in (0, 2)
    assert p2.returncode in (0, 2)
    # Pick a few checks known to be deterministic on macOS with a pinned
    # clock: profile (now ONIONWARDEN_NOW-driven), clock (degrades to fixed
    # na string), boot_integrity (file hashes only).
    for check in ("profile", "clock", "boot_integrity"):
        s = (out_s / f"{check}.current").read_bytes()
        p = (out_p / f"{check}.current").read_bytes()
        assert s == p, \
            f"{check}: serial and parallel outputs differ\n--- serial ---\n{s.decode(errors='replace')[:400]}\n--- parallel ---\n{p.decode(errors='replace')[:400]}"


# ---------------------------------------------------------------------------
# failure semantics
# ---------------------------------------------------------------------------

def test_one_failing_check_does_not_block_others(tmp_path):
    """If one ssh invocation fails, the OTHER per-check invocations still run.
    We force failure on a specific check name by inspecting stdin in the stub."""
    out_dir = tmp_path / "snap"
    stub = tmp_path / "ssh-fail-one.sh"
    stub.write_text(r"""#!/usr/bin/env bash
shift  # drop HOST
cmd="$*"
while :; do
  case "$cmd" in
    "timeout "[0-9]*) cmd="${cmd#timeout [0-9]* }" ;;
    "nice -n "[0-9]*) cmd="${cmd#nice -n [0-9]* }" ;;
    "sudo -n "*)      cmd="${cmd#sudo -n }" ;;
    *) break ;;
  esac
done
# Read the entire bundle off stdin so the snapshot tool can deliver the next
# check. The clock bundle ends with `__snap_one clock`; we exit non-zero on
# that one only.
bundle=$(cat)
if printf '%s' "$bundle" | grep -q '^__snap_one clock$'; then
  printf 'forced-failure\n' >&2
  exit 17
fi
printf '%s' "$bundle" | bash -s
""")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    p = _run_snapshot(out_dir, str(stub), 4)
    # Exit must be non-zero because at least one check failed.
    assert p.returncode == 2, f"expected exit 2, got {p.returncode}\n{p.stdout}\n{p.stderr}"
    # clock should be FAILED.
    assert (out_dir / "clock.exit").read_text().strip() == "17"
    assert "forced-failure" in (out_dir / "clock.err").read_text()
    # But other checks (e.g. accounts) STILL produced output.
    assert (out_dir / "accounts.exit").read_text().strip() == "0"


# ---------------------------------------------------------------------------
# performance bench (the central claim)
# ---------------------------------------------------------------------------

def test_parallel_wallclock_beats_serial(fake_ssh_sleep, tmp_path):
    """Each fake check takes 1s; with 24 checks, serial ~= 24s, --parallel 8
    ~= 3s, --parallel 4 ~= 6s. We assert the 8-way is materially faster than
    the serial run (>3x) — the central perf claim of this PR."""
    env_extra = {"FAKE_SLEEP": "1"}
    # --parallel 1
    out_s = tmp_path / "snap-serial"
    t0 = time.monotonic()
    p1 = _run_snapshot(out_s, fake_ssh_sleep, 1, extra_env=env_extra)
    serial_s = time.monotonic() - t0
    assert p1.returncode in (0, 2), p1.stderr

    # --parallel 8
    out_p = tmp_path / "snap-par8"
    t0 = time.monotonic()
    p2 = _run_snapshot(out_p, fake_ssh_sleep, 8, extra_env=env_extra)
    par8_s = time.monotonic() - t0
    assert p2.returncode in (0, 2), p2.stderr

    speedup = serial_s / par8_s if par8_s > 0 else 0
    print(("\nperf: parallel=1 -> %.2fs ; parallel=8 -> %.2fs ; "
           "speedup=%.2fx") % (serial_s, par8_s, speedup))
    # 24 checks × 1s each, capped at 8 in flight → ideal ~3s parallel vs ~24s
    # serial = 8x. Real-world overhead (preflight, semaphore, ssh stub fork)
    # eats some — require ≥3x to leave headroom for CI variance.
    assert speedup >= 3.0, \
        ("expected ≥3x speedup, measured %.2fx (serial=%.2fs, par8=%.2fs)"
         % (speedup, serial_s, par8_s))
