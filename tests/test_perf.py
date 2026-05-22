"""Relay-scale performance tests for the two collectors that must handle a real
tor relay (~200 tor instances, thousands of connections). A simulated
relay-scale /proc tree is built once; each collector is run against it and
timed. Budgets are generous (fail at 2x) to avoid CI flake — the point is to
catch an O(N^2) regression, not to benchmark."""
import os
import subprocess
import time

import pytest

from conftest import ROOT, BASH

N_PIDS = 500          # processes in the fake /proc (process_ancestry: 500+)
N_CONNS = 5000        # established connections (network_deep: 5000+)
N_SOCKET_PIDS = 200   # pids that actually own sockets (~200 tor instances)


def make_relay_proc(root):
    """Build a fake /proc simulating a busy tor relay under `root`."""
    os.makedirs(os.path.join(root, "net"))
    # /proc/net/tcp — header + N_CONNS established (st=01) connections.
    with open(os.path.join(root, "net", "tcp"), "w") as fh:
        fh.write("  sl  local_address rem_address st tx rx tr tm retr uid to inode ref pnt\n")
        for i in range(N_CONNS):
            rem = "%08X:01BB" % ((0x08080808 + i) & 0xFFFFFFFF)
            fh.write("  %d: 0100007F:1F90 %s 01 00:00 00:00 00 0 0 %d 1 0\n"
                     % (i, rem, 100000 + i))
    for f in ("tcp6", "udp", "udp6"):
        open(os.path.join(root, "net", f), "w").write("  sl local rem st\n")

    base = 1000
    conns_per = N_CONNS // N_SOCKET_PIDS
    inode = 100000
    for k in range(N_PIDS):
        pid = base + k
        pdir = os.path.join(root, str(pid))
        os.makedirs(os.path.join(pdir, "fd"))
        if k < N_SOCKET_PIDS:
            if k % 20 == 0:                       # ~10 non-tor socket owners
                comm, cg = "miner", "0::/system.slice/miner.service\n"
            else:                                 # the rest are tor instances
                comm = "tor"
                cg = "0::/system.slice/system-tor.slice/tor@%d.service\n" % k
            for j in range(conns_per):
                if inode >= 100000 + N_CONNS:
                    break
                os.symlink("socket:[%d]" % inode,
                           os.path.join(pdir, "fd", str(10 + j)))
                inode += 1
        else:
            comm, cg = "worker", "0::/system.slice/worker.service\n"
        open(os.path.join(pdir, "comm"), "w").write(comm + "\n")
        open(os.path.join(pdir, "cgroup"), "w").write(cg)
        open(os.path.join(pdir, "stat"), "w").write(
            "%d (%s) S 1 0 0\n" % (pid, comm))

    # one daemon->shell pair so svcshell is exercised at scale: a bash whose
    # parent (pid base+1) is a tor instance.
    sp = base + N_PIDS
    os.makedirs(os.path.join(root, str(sp), "fd"))
    open(os.path.join(root, str(sp), "comm"), "w").write("bash\n")
    open(os.path.join(root, str(sp), "cgroup"), "w").write("0::/x\n")
    open(os.path.join(root, str(sp), "stat"), "w").write(
        "%d (bash) S %d 0 0\n" % (sp, base + 1))
    return root


@pytest.fixture(scope="module")
def relay_proc(tmp_path_factory):
    return make_relay_proc(str(tmp_path_factory.mktemp("relayproc") / "proc"))


def test_network_deep_relay_scale(relay_proc, tmp_path):
    """network_deep collects 5000 connections / 200 tor instances within
    budget (30 s; test fails >60 s) and is O(conns+pids), not O(N^2)."""
    conf = tmp_path / "host.conf"
    conf.write_text('host_id = "relay-a"\nrole = "tor-relay"\n')
    env = {**os.environ, "ONIONWARDEN_ROOT": str(ROOT), "ONIONWARDEN_PROC": relay_proc}
    t0 = time.monotonic()
    p = subprocess.run(
        [BASH, str(ROOT / "lib" / "checks" / "network_deep.sh"), "collect",
         "--config", str(conf), "--roles", str(ROOT / "roles")],
        capture_output=True, text=True, env=env)
    elapsed = time.monotonic() - t0
    assert p.returncode == 0, p.stderr
    out = [l for l in p.stdout.splitlines() if l.startswith("outbound ")]
    print("\nnetwork_deep: %d outbound lines, %.2fs (budget 30s)" % (len(out), elapsed))
    # ~10 non-tor socket owners x 25 conns each ~= 250 emitted; tor excluded.
    assert 100 < len(out) < 1500, "expected non-tor conns shown, tor excluded; got %d" % len(out)
    assert all(l.split()[1] != "tor" for l in out), "a tor-owned connection leaked the exclusion"
    assert elapsed < 60, "network_deep took %.1fs — over 2x the 30s budget" % elapsed


def test_process_ancestry_relay_scale(relay_proc):
    """process_ancestry walks 500+ processes within budget (10 s; fails >20 s)."""
    env = {**os.environ, "ONIONWARDEN_ROOT": str(ROOT), "ONIONWARDEN_PROC": relay_proc}
    t0 = time.monotonic()
    p = subprocess.run(
        [BASH, str(ROOT / "lib" / "checks" / "process_ancestry.sh"), "collect"],
        capture_output=True, text=True, env=env)
    elapsed = time.monotonic() - t0
    assert p.returncode == 0, p.stderr
    print("\nprocess_ancestry: %.2fs (budget 10s)" % elapsed)
    assert "svcshell tor bash" in p.stdout, "daemon-spawned shell not detected at scale"
    assert elapsed < 20, "process_ancestry took %.1fs — over 2x the 10s budget" % elapsed
