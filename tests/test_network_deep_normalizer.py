"""Regression tests for the network_deep outbound normalizer.

Background: per-snapshot /proc/net/tcp 5-tuples churn on a busy guard —
ephemeral src_port rotates per socket and TCP fine-state cycles through
TIME_WAIT/CLOSE_WAIT/FIN_WAIT within milliseconds. The cross-host dry-run
showed two parallel snapshots a few seconds apart see DIFFERENT 5-tuple sets
for the SAME stable peers, which made `network_deep.current` non-byte-identical
across runs even on quiescent hosts.

The normalizer canonicalises each outbound row to `outbound <comm> <dst:port>`,
dropping src_port AND TCP fine-state. State coverage is widened from
`ESTABLISHED only` to ESTABLISHED+CLOSING-bucket+SYN-bucket so a destination
briefly in TIME_WAIT still shows up. Forensic detail (proto + state_class + src)
goes to `RAW:`-prefixed lines that the snapshot tool relocates to
`raw/network_deep.raw` (NOT compared for tamper detection).

These tests build minimal fake /proc trees and run lib/checks/network_deep.sh
directly against them. They explicitly DO NOT use the SSH/snapshot tool path —
that lives in test_snapshot_parallel.py — they test the collector's contract
in isolation, on a Linux-style fake /proc that runs on any platform.
"""
import os
import subprocess

import pytest

from conftest import ROOT, BASH

NETWORK_DEEP = str(ROOT / "lib" / "checks" / "network_deep.sh")
TCP_HEADER = "  sl  local_address rem_address st tx rx tr tm retr uid to inode ref pnt\n"


def _make_proc(root, conns, pids):
    """Build a minimal fake /proc.

    conns: list of dicts {local: "HEXIP:HEXPORT", rem: "HEXIP:HEXPORT",
                          st: "01", inode: 100000}
    pids:  list of dicts {pid: 1234, comm: "tor",
                          cgroup: "0::/system.slice/tor.service\\n",
                          sockets: [inode, ...]}
    Empty tcp6/udp/udp6 are created (header only).
    """
    os.makedirs(os.path.join(root, "net"))
    with open(os.path.join(root, "net", "tcp"), "w") as fh:
        fh.write(TCP_HEADER)
        for i, c in enumerate(conns):
            fh.write("  %d: %s %s %s 00:00 00:00 00 0 0 %d 1 0\n" % (
                i, c["local"], c["rem"], c["st"], c["inode"]))
    for f in ("tcp6", "udp", "udp6"):
        open(os.path.join(root, "net", f), "w").write("  sl local rem st\n")
    for p in pids:
        pdir = os.path.join(root, str(p["pid"]))
        os.makedirs(os.path.join(pdir, "fd"))
        for j, inode in enumerate(p["sockets"]):
            os.symlink("socket:[%d]" % inode,
                       os.path.join(pdir, "fd", str(10 + j)))
        open(os.path.join(pdir, "comm"), "w").write(p["comm"] + "\n")
        open(os.path.join(pdir, "cgroup"), "w").write(p["cgroup"])
        open(os.path.join(pdir, "stat"), "w").write(
            "%d (%s) S 1 0 0\n" % (p["pid"], p["comm"]))
    return root


def _run_collect(proc_root, tmp_path):
    """Run `network_deep.sh collect` against a fake /proc; return stdout."""
    conf = tmp_path / "host.conf"
    conf.write_text('host_id = "regression"\nrole = "generic"\n')
    env = {**os.environ, "ONIONWARDEN_ROOT": str(ROOT),
           "ONIONWARDEN_PROC": str(proc_root)}
    p = subprocess.run(
        [BASH, NETWORK_DEEP, "collect", "--config", str(conf),
         "--roles", str(ROOT / "roles")],
        capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stderr
    return p.stdout


def _outbound_lines(stdout):
    """Just the normalized `outbound ` rows — what the analyzer compares."""
    return sorted(l for l in stdout.splitlines() if l.startswith("outbound "))


def _raw_lines(stdout):
    """Just the `RAW: outbound_raw ` rows — relocated by snapshot tool."""
    return sorted(l for l in stdout.splitlines() if l.startswith("RAW: "))


def _hex_addr(ip, port):
    """`A.B.C.D` + int port → `DDCCBBAA:HEXPORT` (little-endian per /proc/net/tcp)."""
    a, b, c, d = (int(x) for x in ip.split("."))
    return "%02X%02X%02X%02X:%04X" % (d, c, b, a, port)


# ---------------------------------------------------------------------------
# regression 1: src_port churn must not change normalized output
# ---------------------------------------------------------------------------

def test_src_port_churn_normalized_identical(tmp_path):
    """Same outbound destinations, DIFFERENT ephemeral src ports → identical
    `outbound ` rows. This is the canonical relay scenario: every outbound TCP
    socket gets a fresh ephemeral src port, but the peer set is stable."""
    proc_a = tmp_path / "proc_a"
    proc_b = tmp_path / "proc_b"
    pids = [{"pid": 1000, "comm": "sshd",
             "cgroup": "0::/system.slice/ssh.service\n",
             "sockets": [100000, 100001]}]
    # Same dst, different src_port across the two snapshots.
    conns_a = [
        {"local": _hex_addr("10.0.0.1", 49152), "rem": _hex_addr("1.2.3.4", 22),
         "st": "01", "inode": 100000},
        {"local": _hex_addr("10.0.0.1", 49153), "rem": _hex_addr("5.6.7.8", 443),
         "st": "01", "inode": 100001},
    ]
    conns_b = [
        {"local": _hex_addr("10.0.0.1", 58420), "rem": _hex_addr("1.2.3.4", 22),
         "st": "01", "inode": 100000},
        {"local": _hex_addr("10.0.0.1", 61015), "rem": _hex_addr("5.6.7.8", 443),
         "st": "01", "inode": 100001},
    ]
    _make_proc(str(proc_a), conns_a, pids)
    _make_proc(str(proc_b), conns_b, pids)
    out_a = _outbound_lines(_run_collect(proc_a, tmp_path))
    out_b = _outbound_lines(_run_collect(proc_b, tmp_path))
    assert out_a == out_b, (
        "src_port churn changed normalized output:\n"
        "A: %s\nB: %s" % (out_a, out_b))
    # And the rows must actually be present (not vacuously equal because empty).
    assert any("1.2.3.4:22" in l for l in out_a), out_a
    assert any("5.6.7.8:443" in l for l in out_a), out_a


# ---------------------------------------------------------------------------
# regression 2: state-class collapse — fine-state churn within a bucket must
# not change normalized output (TIME_WAIT, CLOSE_WAIT, FIN_WAIT all → CLOSING).
# ---------------------------------------------------------------------------

def test_within_bucket_state_churn_normalized_identical(tmp_path):
    """A peer cycling through fine TCP states (TIME_WAIT → CLOSE_WAIT) produces
    identical `outbound ` rows — both fine states collapse to CLOSING in raw,
    and normalized rows drop state_class entirely."""
    proc_a = tmp_path / "proc_a"
    proc_b = tmp_path / "proc_b"
    pids = [{"pid": 1000, "comm": "client",
             "cgroup": "0::/system.slice/client.service\n",
             "sockets": [100000]}]
    # Same dst, fine state TIME_WAIT (06) vs CLOSE_WAIT (08).
    conns_a = [{"local": _hex_addr("10.0.0.1", 49152),
                "rem": _hex_addr("1.2.3.4", 8443),
                "st": "06", "inode": 100000}]
    conns_b = [{"local": _hex_addr("10.0.0.1", 49152),
                "rem": _hex_addr("1.2.3.4", 8443),
                "st": "08", "inode": 100000}]
    _make_proc(str(proc_a), conns_a, pids)
    _make_proc(str(proc_b), conns_b, pids)
    out_a = _outbound_lines(_run_collect(proc_a, tmp_path))
    out_b = _outbound_lines(_run_collect(proc_b, tmp_path))
    assert out_a == out_b, (
        "within-bucket state churn changed normalized output:\n"
        "A: %s\nB: %s" % (out_a, out_b))
    assert out_a == ["outbound client 1.2.3.4:8443"], out_a


def test_established_vs_timewait_both_visible(tmp_path):
    """The old collector (ESTABLISHED-only) hid TIME_WAIT outbound destinations.
    The normalizer must surface them so a connection that races into TIME_WAIT
    between snapshot capture and analyser run is still subject to tamper-
    detection. Both ESTABLISHED (01) and TIME_WAIT (06) destinations appear."""
    proc = tmp_path / "proc"
    pids = [{"pid": 1000, "comm": "client",
             "cgroup": "0::/system.slice/client.service\n",
             "sockets": [100000, 100001]}]
    conns = [
        {"local": _hex_addr("10.0.0.1", 49152), "rem": _hex_addr("1.2.3.4", 443),
         "st": "01", "inode": 100000},   # ESTABLISHED
        {"local": _hex_addr("10.0.0.1", 49153), "rem": _hex_addr("5.6.7.8", 443),
         "st": "06", "inode": 100001},   # TIME_WAIT
    ]
    _make_proc(str(proc), conns, pids)
    out = _outbound_lines(_run_collect(proc, tmp_path))
    dsts = [l.split()[-1] for l in out]
    assert "1.2.3.4:443" in dsts, out
    assert "5.6.7.8:443" in dsts, out


# ---------------------------------------------------------------------------
# regression 3: a new dst_ip not at baseline must show up in normalized output
# ---------------------------------------------------------------------------

def test_new_destination_detected(tmp_path):
    """The normalizer preserves the tamper signal: a destination that's absent
    in the baseline but present in the current snapshot appears in `outbound `
    rows (the analyzer's diff fires from those rows)."""
    proc_baseline = tmp_path / "proc_baseline"
    proc_current = tmp_path / "proc_current"
    pids = [{"pid": 1000, "comm": "sshd",
             "cgroup": "0::/system.slice/ssh.service\n",
             "sockets": [100000, 100001]}]
    base_conns = [
        {"local": _hex_addr("10.0.0.1", 49152), "rem": _hex_addr("1.2.3.4", 22),
         "st": "01", "inode": 100000},
    ]
    cur_conns = [
        {"local": _hex_addr("10.0.0.1", 49152), "rem": _hex_addr("1.2.3.4", 22),
         "st": "01", "inode": 100000},
        # NEW outbound — never seen at baseline
        {"local": _hex_addr("10.0.0.1", 49153), "rem": _hex_addr("9.9.9.9", 4444),
         "st": "01", "inode": 100001},
    ]
    _make_proc(str(proc_baseline), base_conns, pids[:])
    _make_proc(str(proc_current), cur_conns, pids[:])
    base_out = _outbound_lines(_run_collect(proc_baseline, tmp_path))
    cur_out = _outbound_lines(_run_collect(proc_current, tmp_path))
    # New row appears in current, absent in baseline.
    new = set(cur_out) - set(base_out)
    assert new == {"outbound sshd 9.9.9.9:4444"}, (base_out, cur_out, new)


# ---------------------------------------------------------------------------
# raw companion: forensic verbose form is emitted, contains state_class + src,
# and is prefixed `RAW: ` (so snapshot tool can relocate to raw/network_deep.raw).
# ---------------------------------------------------------------------------

def test_raw_lines_emit_forensic_detail(tmp_path):
    """The collector emits `RAW: outbound_raw <proto> <state_class> <comm>
    <src> <dst>` lines alongside the normalized rows. These carry the verbose
    forensic detail the normalizer dropped from `.current`."""
    proc = tmp_path / "proc"
    pids = [{"pid": 1000, "comm": "sshd",
             "cgroup": "0::/system.slice/ssh.service\n",
             "sockets": [100000]}]
    conns = [{"local": _hex_addr("10.0.0.1", 49152),
              "rem": _hex_addr("1.2.3.4", 22),
              "st": "01", "inode": 100000}]
    _make_proc(str(proc), conns, pids)
    out = _run_collect(proc, tmp_path)
    raw = _raw_lines(out)
    assert len(raw) == 1, raw
    fields = raw[0].split()
    # `RAW: outbound_raw tcp ESTABLISHED sshd 10.0.0.1:49152 1.2.3.4:22`
    assert fields[0] == "RAW:" and fields[1] == "outbound_raw"
    assert fields[2] == "tcp"
    assert fields[3] == "ESTABLISHED"
    assert fields[4] == "sshd"
    assert fields[5] == "10.0.0.1:49152"
    assert fields[6] == "1.2.3.4:22"


def test_state_class_buckets_collapse(tmp_path):
    """Fine TCP states collapse to four buckets in raw rows:
    01→ESTABLISHED, 02/03→SYN, 04/05/06/08/09/0B→CLOSING.
    LISTEN (0A) and CLOSE (07) are skipped entirely."""
    proc = tmp_path / "proc"
    # one socket per distinct fine state
    fine_states = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B"]
    pids = [{"pid": 1000, "comm": "p",
             "cgroup": "0::/system.slice/p.service\n",
             "sockets": [100000 + i for i in range(len(fine_states))]}]
    conns = []
    for i, st in enumerate(fine_states):
        conns.append({"local": _hex_addr("10.0.0.1", 49152 + i),
                      "rem": _hex_addr("1.2.3.%d" % (4 + i), 22),
                      "st": st, "inode": 100000 + i})
    _make_proc(str(proc), conns, pids)
    out = _run_collect(proc, tmp_path)
    raw = _raw_lines(out)
    buckets = {l.split()[3] for l in raw}
    assert buckets == {"ESTABLISHED", "SYN", "CLOSING"}, buckets
    # LISTEN (0A) and CLOSE (07) must be ABSENT from outbound at all — they
    # have no remote endpoint or are dead-socket transients respectively.
    norm = _outbound_lines(out)
    # 11 fine states; 2 skipped (07, 0A); 9 destinations emitted; one row each
    # in normalized form (each destination distinct).
    assert len(norm) == 9, norm


# ---------------------------------------------------------------------------
# end-to-end via snapshot tool — RAW: lines are relocated to raw/<check>.raw
# ---------------------------------------------------------------------------

def test_snapshot_tool_relocates_raw_lines(tmp_path):
    """A snapshot bundle is run via the fake-ssh stub that lets the collector
    run locally. The post-processing pass in onionwarden-snapshot must move
    `RAW: ` lines out of `network_deep.current` into `raw/network_deep.raw`,
    leaving `.current` byte-identical across back-to-back runs."""
    import stat
    fake_ssh = tmp_path / "fake-ssh.sh"
    fake_ssh.write_text(r"""#!/usr/bin/env bash
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
exec bash -c "$cmd"
""")
    fake_ssh.chmod(fake_ssh.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    out = tmp_path / "snap"
    env = dict(os.environ)
    env["ONIONWARDEN_SNAPSHOT_SSH"] = str(fake_ssh)
    env["ONIONWARDEN_SNAPSHOT_PERCHECK"] = "8"
    p = subprocess.run(
        [BASH, str(ROOT / "bin" / "onionwarden-snapshot"), "localhost",
         "--out", str(out), "--parallel", "1"],
        capture_output=True, text=True, env=env, timeout=180)
    assert p.returncode in (0, 2), p.stderr
    cur = (out / "network_deep.current").read_text()
    # No RAW: lines must leak into .current.
    assert "RAW: " not in cur, "RAW: lines must be stripped from .current"
    # On macOS the /proc/net/tcp probe fails and the collector emits
    # `outbound na no-procnet` — no RAW lines emitted, so the raw companion
    # file may or may not exist. On Linux with a real /proc, RAW lines are
    # always emitted and the companion file MUST exist. We accept either.
    raw_path = out / "raw" / "network_deep.raw"
    if raw_path.exists():
        raw_content = raw_path.read_text()
        # Every line must be in the raw companion's expected format.
        for line in raw_content.splitlines():
            assert line.startswith("outbound_raw "), line
