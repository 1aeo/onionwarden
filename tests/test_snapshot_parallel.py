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
import sys
import time

import pytest

from conftest import ROOT, BASH

SNAPSHOT_BIN = str(ROOT / "bin" / "onionwarden-snapshot")
CHECKS_DIR = ROOT / "lib" / "checks"
CHECK_NAMES = sorted(p.stem for p in CHECKS_DIR.glob("*.sh"))
# Fail loudly if the glob discovered nothing — otherwise the parametrize'd and
# loop-over-CHECK_NAMES tests below silently degrade to no-ops and pass.
assert CHECK_NAMES, f"no checks discovered in {CHECKS_DIR} — glob 'lib/checks/*.sh' matched nothing"


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


# ---------------------------------------------------------------------------
# pinned host state (de-flakes the byte-identity test — see PR "de-flake
# test_parallel_runs_byte_identical")
# ---------------------------------------------------------------------------
#
# The byte-identity test asserts the *orchestration* introduces no
# non-determinism in per-check output. To isolate orchestration from genuine
# host churn it must feed the collectors a FIXED snapshot of host state — the
# same idea as the sibling serial/parallel test pinning now_iso() via
# ONIONWARDEN_NOW.
#
# network_deep is the collector that flaked CI ~30-50% of runs (worse on
# 24.04 than 22.04). It reads live /proc/net/tcp* (outbound sockets) and
# `ip neigh` (ARP). On a busy Linux runner BOTH churn between two back-to-back
# snapshots: a background process opens a connection to a NEW peer, or an ARP
# entry ages REACHABLE->STALE. The per-row normaliser in network_deep
# (canonicalise to `outbound <comm> <dst:port>`, dropping ephemeral src_port
# and transient TCP fine-state) correctly collapses *within-connection* churn,
# but it cannot collapse a brand-new peer or neighbour appearing mid-snapshot
# — so network_deep.current diverged between runs and the test failed.
#
# Fix: pin network_deep's inputs for this test. ONIONWARDEN_PROC redirects the
# socket/fd/comm reads at a synthetic /proc fixture; stub `ip`/`nft` on PATH
# fix the route/iface/arp/nft lines. Production is UNCHANGED — collectors still
# read live state on real relays, so tamper detection is intact. The collector
# still runs end-to-end here (normalise + sort + RAW: relocation), so an
# orchestration race that reordered, duplicated, or truncated rows would STILL
# fail this test — network_deep stays a *compared* file, not an allowlisted one.
# /etc/resolv.conf (the `dns` lines) is read by absolute path and is static for
# the lifetime of a CI job, so it needs no pinning.

# A synthetic /proc/net/tcp: 3 outbound sockets (tor x2, sshd) + 1 LISTEN
# (no remote — skipped by the collector). Fields mirror the kernel layout:
#   idx local_address rem_address st tx:rx tr:tm->when retrnsmt uid timeout inode ...
_FAKE_PROC_NET_TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    "   0: 0100007F:1F90 5B1F8A0A:2329 01 00000000:00000000 00:00000000 00000000  1000        0 5001 1 ffff 100\n"
    "   1: 0100007F:9C40 4E0C2D0B:0050 06 00000000:00000000 00:00000000 00000000  1000        0 5002 1 ffff 100\n"
    "   2: 0100007F:0016 0A00020F:E1B2 01 00000000:00000000 00:00000000 00000000     0        0 5003 1 ffff 100\n"
    "   3: 0100007F:24C2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 9999 1 ffff 100\n"
)

# Per-PID /proc data the network_deep + process_ancestry collectors read.
#   (pid, comm, cgroup, stat, [(fd, inode), ...])
_FAKE_PROC_PIDS = [
    (1000, "tor",        "0::/system.slice/system-tor.slice/tor@0.service\n",
     "1000 (tor) S 1 1000 1000 0 -1 4194304 0 0 0 0 0 0\n",
     [(10, 5001), (11, 5002)]),
    (1001, "sshd",       "0::/system.slice/ssh.service\n",
     "1001 (sshd) S 1 1001 1001 0 -1 4194304 0 0 0 0 0 0\n",
     [(4, 5003)]),
    (1002, "prometheus", "0::/system.slice/prometheus.service\n",
     "1002 (prometheus) S 1 1002 1002 0 -1 4194304 0 0 0 0 0 0\n",
     [(7, 5004)]),
]

# `ip`/`nft` stubs: deterministic output for exactly the subcommands the
# collectors invoke (network_deep: route/link/neigh + nft; promisc: link).
# `*)` arms emit nothing and exit 0 so any other invocation stays harmless.
_FAKE_IP_STUB = r"""#!/usr/bin/env bash
case "$*" in
  "route show")    printf 'default via 10.0.2.2 dev eth0\n10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15\n' ;;
  "-br link show") printf 'lo               UNKNOWN        00:00:00:00:00:00\neth0             UP             52:54:00:12:34:56\n' ;;
  "neigh show")    printf '10.0.2.2 dev eth0 lladdr 52:54:00:12:35:02 router REACHABLE\n' ;;
  *)               : ;;
esac
"""

_FAKE_NFT_STUB = r"""#!/usr/bin/env bash
case "$*" in
  "list ruleset") printf 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0;\n\t}\n}\n' ;;
  *)              : ;;
esac
"""


@pytest.fixture
def pinned_host_state(tmp_path):
    """Build a fixed /proc tree + `ip`/`nft` stubs and return the env that
    pins every volatile input network_deep reads. Passed to BOTH parallel runs
    so any divergence is the orchestration's fault, not the host's."""
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    (proc / "net" / "tcp").write_text(_FAKE_PROC_NET_TCP)
    # tcp6/udp/udp6 exist but are empty (header-less is fine: the collector
    # skips short lines). Their presence exercises the multi-file read loop.
    for f in ("tcp6", "udp", "udp6"):
        (proc / "net" / f).write_text("")
    for pid, comm, cgroup, stat_line, fds in _FAKE_PROC_PIDS:
        d = proc / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "cgroup").write_text(cgroup)
        (d / "stat").write_text(stat_line)
        for fd, inode in fds:
            os.symlink(f"socket:[{inode}]", d / "fd" / str(fd))

    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("ip", _FAKE_IP_STUB), ("nft", _FAKE_NFT_STUB)):
        b = bindir / name
        b.write_text(body)
        b.chmod(b.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    return {
        "ONIONWARDEN_PROC": str(proc),
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
    }


def _run_snapshot(out_dir, fake_ssh_path, parallel, extra_env=None,
                  single_bundle=False):
    """Drive bin/onionwarden-snapshot end-to-end with the fake-ssh stub."""
    env = dict(os.environ)
    env["ONIONWARDEN_SNAPSHOT_SSH"] = fake_ssh_path
    env["ONIONWARDEN_SNAPSHOT_PERCHECK"] = "8"
    if extra_env:
        env.update(extra_env)
    argv = [BASH, SNAPSHOT_BIN, "localhost", "--out", str(out_dir)]
    if single_bundle:
        argv.append("--single-bundle")
    else:
        argv.extend(["--parallel", str(parallel)])
    return subprocess.run(argv, capture_output=True, text=True, env=env,
                          timeout=300)


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


def _exit_ok(out_dir, current_name):
    """True iff the check behind `<name>.current` exited 0 (collector succeeded).

    A collector killed by the per-check watchdog (e.g. `find / -xdev` in `suid`
    blowing past the test's short per-check timeout on a slow build host) exits
    non-zero AND leaves a *partially written* .current — whatever it managed to
    emit before SIGTERM. That partial content is inherently nondeterministic
    (the kill lands at a different byte each run), so it must NOT be treated as
    an orchestration-determinism signal: the non-zero .exit already flags it."""
    ef = pathlib.Path(out_dir) / (current_name[: -len(".current")] + ".exit")
    try:
        return ef.read_text().strip() == "0"
    except FileNotFoundError:
        return False


def test_parallel_runs_byte_identical(fake_ssh, pinned_host_state, tmp_path):
    """Two consecutive --parallel 8 runs produce byte-identical .current files
    (the orchestration must not introduce non-determinism in per-check output).

    `pinned_host_state` redirects network_deep's live-kernel reads (/proc/net
    sockets, `ip neigh` ARP, nft ruleset) at a FIXED fixture so the test
    measures orchestration determinism, not host-network quiescence — see the
    fixture docstring. Production collectors are unchanged."""
    out1 = tmp_path / "snap-a"
    out2 = tmp_path / "snap-b"
    p1 = _run_snapshot(out1, fake_ssh, 8, extra_env=pinned_host_state)
    p2 = _run_snapshot(out2, fake_ssh, 8, extra_env=pinned_host_state)
    assert p1.returncode in (0, 2)
    assert p2.returncode in (0, 2)
    d1 = _current_files_digest(out1)
    d2 = _current_files_digest(out2)
    # The KEY set must match exactly (same check files written).
    assert set(d1) == set(d2)
    # network_deep MUST have taken the real collection path (not the macOS
    # `na no-procnet` short-circuit) — otherwise the pinning is a no-op and the
    # byte-identity guarantee below is vacuous. Assert the fixture's outbound
    # peers are present so a regression that breaks ONIONWARDEN_PROC plumbing
    # is caught here rather than re-surfacing as a CI flake.
    nd1 = (out1 / "network_deep.current").read_text()
    assert "outbound tor 10.138.31.91:9001" in nd1, \
        f"network_deep did not collect from the pinned /proc fixture:\n{nd1}"
    assert "na no-procnet" not in nd1, nd1
    # And content must match for every check whose collector emits no
    # timestamps. On macOS most collectors that succeed are time-independent
    # (clock prints `ntp_sync na_no_timedatectl`, profile prints constants,
    # etc.). We allow per-check skips only if BOTH sides genuinely differ.
    diffs = sorted(name for name in d1 if d1[name] != d2[name])
    # Drop checks that FAILED (collector killed by the per-check watchdog) on
    # either run: their .current is a truncated fragment, not a determinism
    # signal. On the macOS build host `suid`/`filesystem` run `find /...` walks
    # that exceed the test's short per-check timeout and are SIGTERM'd (rc=143),
    # leaving a partial file that differs byte-for-byte between runs. On Linux CI
    # these complete fast (rc=0) and stay compared. This is orthogonal to the
    # ALLOWED_VARIABLE allowlist below, which covers checks that SUCCEED but
    # legitimately vary (wall-clock timestamps, sliding journal windows).
    diffs = [n for n in diffs if _exit_ok(out1, n) and _exit_ok(out2, n)]
    # Explicit allowlist of collectors whose .current output legitimately
    # varies between back-to-back runs. Each entry names the underlying source
    # of nondeterminism — it must be a property of the *collector's input*,
    # not of the orchestration. Anything else differing means the orchestration
    # introduced non-determinism — fail loudly with the unexpected file names.
    #
    # Cross-platform entries:
    #   profile.current         — records detected_at= wall-clock timestamp.
    #   process_ancestry.current — its `tmpexec` rows come from a live
    #                             `find /tmp /var/tmp /dev/shm`; temp files
    #                             churn between runs even with /proc pinned, so
    #                             this stays variable on Linux. On macOS the
    #                             /proc walk short-circuits, so it's harmless.
    # network_deep.current is DELIBERATELY NOT in this set: the `pinned_host_state`
    # fixture freezes its live inputs (/proc/net sockets, `ip neigh`, nft) so it
    # is byte-identical by construction AND stays a *compared* file — an
    # orchestration race that reordered/duplicated/truncated its rows still
    # fails this test. The per-row normaliser alone is NOT enough: it collapses
    # src_port/TCP-state churn but not a brand-new outbound peer appearing
    # mid-snapshot, which is exactly what flaked CI before the fixture existed.
    # Forensic 5-tuple detail lives in raw/network_deep.raw (NOT compared).
    ALLOWED_VARIABLE = {"profile.current", "process_ancestry.current"}
    # Linux-only entries: these collectors short-circuit on macOS
    # (`na no-systemctl` / `na no-journalctl` / no live /usr,/etc walks),
    # so the names never appear in the macOS diff comparison. Adding them
    # only on Linux makes the platform-dependency explicit:
    #   filesystem.current      — `find /usr /etc /bin /sbin` walks live
    #                             system dirs; on busy Linux CI runners,
    #                             transient files (apt/dpkg locks, ld.so.cache
    #                             rebuilds, tmp under /etc) appear/disappear
    #                             between back-to-back runs.
    #   scheduled.current       — `systemctl list-timers --all` output
    #                             includes wall-clock "next"/"left"/"last"
    #                             columns that re-render every invocation.
    #   auth_log.current        — `journalctl -u ssh --since "-1h"` is a
    #                             sliding wall-clock window; lines drop off
    #                             the back as seconds tick, and new sshd
    #                             noise can appear on a real Linux host.
    if sys.platform.startswith("linux"):
        ALLOWED_VARIABLE |= {
            "filesystem.current",
            "scheduled.current",
            "auth_log.current",
        }
    unexpected = [n for n in diffs if n not in ALLOWED_VARIABLE]
    assert not unexpected, (
        f"unexpected nondeterministic .current files between parallel runs "
        f"(orchestration race?): {unexpected}"
    )


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
# single-bundle mode parity (regression — see CodeRabbit feedback on PR #3)
# ---------------------------------------------------------------------------

def test_single_bundle_writes_per_check_exit_files(fake_ssh, tmp_path):
    """--single-bundle must write one .exit file per check, same as --parallel.

    Before this fix, the legacy single-bundle path emitted only the per-check
    .current files; the report loop that reads `<check>.exit` to compute
    failed=N therefore always read 0 and any per-check collector failure was
    invisible to operators and CI gates. The bundle now embeds the rc in the
    END delimiter and the dispatcher's awk pass writes the .exit file."""
    out_dir = tmp_path / "snap"
    p = _run_snapshot(out_dir, fake_ssh, parallel=1, single_bundle=True)
    assert p.returncode in (0, 2), \
        f"single-bundle exited {p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}"
    missing_exit = [c for c in CHECK_NAMES
                    if not (out_dir / f"{c}.exit").exists()]
    assert not missing_exit, \
        f"single-bundle did not write .exit files for: {missing_exit}"
    # meta.txt records the mode so operators can tell the modes apart.
    meta = (out_dir / "raw" / "meta.txt").read_text()
    assert "parallel=single-bundle" in meta, meta


def test_single_bundle_propagates_collector_failure(tmp_path):
    """If a collector inside the single-bundle stream exits non-zero, the END
    marker carries that rc and the resulting .exit file reflects it (so the
    failure-count loop counts it and the script exits 2)."""
    out_dir = tmp_path / "snap"
    stub = tmp_path / "ssh-clock-fail.sh"
    stub.write_text(r"""#!/usr/bin/env bash
shift
cmd="$*"
while :; do
  case "$cmd" in
    "timeout "[0-9]*) cmd="${cmd#timeout [0-9]* }" ;;
    "nice -n "[0-9]*) cmd="${cmd#nice -n [0-9]* }" ;;
    "sudo -n "*)      cmd="${cmd#sudo -n }" ;;
    *) break ;;
  esac
done
# Inject a clock_collect override AFTER all inlined check files (which define
# the real clock_collect) but BEFORE the driver loop runs. The bundle ends
# with `for __c in ...; do __snap "$__c"; done` — inserting the override on
# the line above forces clock_collect to exit 42.
bundle=$(cat | sed -e 's|^for __c in|clock_collect() { return 42; }\
&|')
printf '%s' "$bundle" | bash -c "$cmd"
""")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    p = _run_snapshot(out_dir, str(stub), parallel=1, single_bundle=True)
    # The script must surface partial-failure via exit 2 (same contract as
    # the parallel path) — before this fix it would have exited 0.
    assert p.returncode == 2, \
        f"expected exit 2 from single-bundle clock failure, got {p.returncode}\n{p.stdout}\n{p.stderr}"
    assert (out_dir / "clock.exit").read_text().strip() == "42"
    # Other checks must still be marked rc=0.
    assert (out_dir / "accounts.exit").read_text().strip() == "0"


# ---------------------------------------------------------------------------
# --help completeness (regression — sed range used to truncate new flags)
# ---------------------------------------------------------------------------

def test_help_lists_all_cli_flags():
    """--help must mention every flag the parser accepts. A `sed -n '2,Np'`
    range previously silently dropped new flags whenever the file header
    grew; the heredoc fix means a future flag added without updating help
    will be caught by this test."""
    out = subprocess.check_output(
        [BASH, SNAPSHOT_BIN, "--help"], text=True)
    for flag in ("--out", "--with-sudo", "--ssh-opt", "--parallel",
                 "--single-bundle", "--print-bundle", "--print-check",
                 "--help"):
        assert flag in out, f"--help output missing {flag}\n--- output ---\n{out}"


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
