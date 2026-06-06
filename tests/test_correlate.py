"""Receiver-side cross-host correlation (`receiver/bin/onionwarden-correlate`, M6).

correlate answers "is the FLEET under coordinated attack?" — the detection a
per-host view structurally cannot make. These tests build fixture events.log
trees (each event carries a receiver-stamped recv_ts) and pin `now` via
ONIONWARDEN_NOW_EPOCH so every window/threshold assertion is deterministic.

Three patterns (PLAN §4 M6): fan-out (same finding across N hosts), ip-spray
(same source IP across N hosts), blackout (N hosts silent simultaneously). The
load-bearing false-positive guard is DISTINCT-host counting: a single host, or
one host repeating a finding, must never form a cluster.
"""
import calendar
import json
import os
import subprocess
import time

from conftest import ROOT

CORRELATE = ROOT / "receiver" / "bin" / "onionwarden-correlate"


def _epoch(iso):
    return int(calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")))


def _ev(root, host, *, seq=1, kind="finding", sev="CRIT", recv_ts,
        check="modules", signal="new-module", observed="module nfsd PE",
        summary="x"):
    hd = root / host
    hd.mkdir(parents=True, exist_ok=True)
    detail = {"check": check, "signal": signal, "observed": observed}
    line = json.dumps(
        {"seq": seq, "ts": recv_ts, "host_id": host, "kind": kind,
         "severity": sev, "summary": summary, "detail": detail,
         "recv_ts": recv_ts}, separators=(",", ":"))
    with open(hd / "events.log", "a") as fh:
        fh.write(line + "\n")


def _silent_host(root, host, recv_ts):
    """A host whose only/last event is a selfreport at recv_ts."""
    _ev(root, host, kind="selfreport", sev="INFO", recv_ts=recv_ts,
        check="", signal="", observed="")


def _run(root, now_iso, *args):
    env = {**os.environ,
           "ONIONWARDEN_RECEIVER_ROOT": str(root),
           "ONIONWARDEN_NOW_EPOCH": str(_epoch(now_iso))}
    return subprocess.run(["python3", str(CORRELATE), *args],
                          capture_output=True, text=True, env=env)


def _json(root, now_iso, *args):
    r = _run(root, now_iso, "--format", "json", *args)
    assert r.returncode in (0, 2), f"rc={r.returncode}\n{r.stderr}"
    return json.loads(r.stdout)


# --- fan-out ---------------------------------------------------------------

def test_fanout_same_module_three_hosts(tmp_path):
    for h, t in (("relay-a", "10:00:00"), ("relay-b", "10:05:00"),
                 ("relay-c", "10:12:00")):
        _ev(tmp_path, h, recv_ts="2026-05-29T%sZ" % t)
    r = _run(tmp_path, "2026-05-29T10:30:00Z")
    assert r.returncode == 2
    assert "fan-out" in r.stdout and "module nfsd PE" in r.stdout
    doc = _json(tmp_path, "2026-05-29T10:30:00Z")
    fan = [c for c in doc["clusters"] if c["kind"] == "fan-out"]
    assert len(fan) == 1
    assert fan[0]["host_count"] == 3
    assert set(fan[0]["hosts"]) == {"relay-a", "relay-b", "relay-c"}


def test_single_host_finding_is_not_a_cluster(tmp_path):
    """FP isolation: one host's anomaly is single-host noise, never a cluster."""
    _ev(tmp_path, "relay-a", recv_ts="2026-05-29T10:00:00Z")
    r = _run(tmp_path, "2026-05-29T10:30:00Z", "--min-hosts", "2")
    assert r.returncode == 0


def test_one_host_repeating_does_not_inflate_count(tmp_path):
    """FP guard: the same host reporting a finding 5x is ONE distinct host."""
    for s in range(1, 6):
        _ev(tmp_path, "relay-a", seq=s,
            recv_ts="2026-05-29T10:0%d:00Z" % s)
    r = _run(tmp_path, "2026-05-29T10:30:00Z", "--min-hosts", "2")
    assert r.returncode == 0  # only 1 distinct host -> no cluster


def test_fanout_counts_later_repeat_inside_window(tmp_path):
    """An earlier repeat by one host must not mask a later fleet-wide fan-out."""
    _ev(tmp_path, "relay-a", seq=1, recv_ts="2026-05-29T00:00:00Z")
    _ev(tmp_path, "relay-a", seq=2, recv_ts="2026-05-29T10:00:00Z")
    _ev(tmp_path, "relay-b", recv_ts="2026-05-29T10:05:00Z")
    _ev(tmp_path, "relay-c", recv_ts="2026-05-29T10:10:00Z")
    doc = _json(tmp_path, "2026-05-29T10:30:00Z")
    fan = [c for c in doc["clusters"] if c["kind"] == "fan-out"]
    assert len(fan) == 1
    assert fan[0]["host_count"] == 3
    assert set(fan[0]["hosts"]) == {"relay-a", "relay-b", "relay-c"}
    assert fan[0]["spread_min"] == 10.0


def test_distinct_observed_does_not_cluster_by_default(tmp_path):
    """Different module names on different hosts are NOT a fan-out by default —
    the key includes `observed`. (Coarse mode relaxes this; see below.)"""
    _ev(tmp_path, "relay-a", observed="module aaa A", recv_ts="2026-05-29T10:00:00Z")
    _ev(tmp_path, "relay-b", observed="module bbb B", recv_ts="2026-05-29T10:01:00Z")
    _ev(tmp_path, "relay-c", observed="module ccc C", recv_ts="2026-05-29T10:02:00Z")
    assert _run(tmp_path, "2026-05-29T10:30:00Z").returncode == 0


def test_coarse_mode_clusters_differing_observed(tmp_path):
    """--coarse drops `observed`: 'every host got A new module within the hour'
    clusters even when the module names differ (higher recall)."""
    _ev(tmp_path, "relay-a", observed="module aaa A", recv_ts="2026-05-29T10:00:00Z")
    _ev(tmp_path, "relay-b", observed="module bbb B", recv_ts="2026-05-29T10:01:00Z")
    _ev(tmp_path, "relay-c", observed="module ccc C", recv_ts="2026-05-29T10:02:00Z")
    r = _run(tmp_path, "2026-05-29T10:30:00Z", "--coarse")
    assert r.returncode == 2
    doc = _json(tmp_path, "2026-05-29T10:30:00Z", "--coarse")
    assert any(c["kind"] == "fan-out" and c["host_count"] == 3
               for c in doc["clusters"])


def test_fanout_later_window_is_larger_and_more_severe(tmp_path):
    """An earlier qualifying WARN window (2 hosts) must not mask a later,
    larger CRIT window (3 hosts) for the same key. We keep the WORST window."""
    # earlier WARN cluster: relay-a + relay-b, both WARN, near 00:00
    _ev(tmp_path, "relay-a", seq=1, sev="WARN", recv_ts="2026-05-29T00:00:00Z")
    _ev(tmp_path, "relay-b", seq=1, sev="WARN", recv_ts="2026-05-29T00:03:00Z")
    # later, worse cluster: 3 distinct hosts, one CRIT, near 10:00
    _ev(tmp_path, "relay-a", seq=2, sev="WARN", recv_ts="2026-05-29T10:00:00Z")
    _ev(tmp_path, "relay-b", seq=2, sev="WARN", recv_ts="2026-05-29T10:02:00Z")
    _ev(tmp_path, "relay-c", seq=1, sev="CRIT", recv_ts="2026-05-29T10:05:00Z")
    doc = _json(tmp_path, "2026-05-29T10:30:00Z", "--min-hosts", "2",
                "--window-min", "10")
    fan = [c for c in doc["clusters"] if c["kind"] == "fan-out"]
    assert len(fan) == 1
    assert fan[0]["severity"] == "CRIT"
    assert fan[0]["host_count"] == 3
    assert set(fan[0]["hosts"]) == {"relay-a", "relay-b", "relay-c"}


# --- threshold + window tuning ---------------------------------------------

def test_min_hosts_threshold(tmp_path):
    for h, t in (("relay-a", "10:00:00"), ("relay-b", "10:05:00"),
                 ("relay-c", "10:12:00")):
        _ev(tmp_path, h, recv_ts="2026-05-29T%sZ" % t)
    assert _run(tmp_path, "2026-05-29T10:30:00Z", "--min-hosts", "3").returncode == 2
    assert _run(tmp_path, "2026-05-29T10:30:00Z", "--min-hosts", "4").returncode == 0


def test_window_excludes_spread_out_findings(tmp_path):
    # three hosts, but spread over 40 min — not "near-simultaneous" at window=5
    for h, t in (("relay-a", "10:00:00"), ("relay-b", "10:20:00"),
                 ("relay-c", "10:40:00")):
        _ev(tmp_path, h, recv_ts="2026-05-29T%sZ" % t)
    assert _run(tmp_path, "2026-05-29T11:00:00Z", "--window-min", "5").returncode == 0
    assert _run(tmp_path, "2026-05-29T11:00:00Z", "--window-min", "60").returncode == 2


def test_since_min_excludes_old_findings_from_fanout(tmp_path):
    # 9-day-old fan-out, lookback 24h: must NOT produce a fan-out cluster.
    for h, t in (("relay-a", "10:00:00"), ("relay-b", "10:05:00"),
                 ("relay-c", "10:06:00")):
        _ev(tmp_path, h, recv_ts="2026-05-20T%sZ" % t)
    doc = _json(tmp_path, "2026-05-29T11:30:00Z", "--since-min", "1440")
    assert not any(c["kind"] == "fan-out" for c in doc["clusters"])


# --- ip-spray --------------------------------------------------------------

def test_ip_spray_same_source_across_hosts(tmp_path):
    for h, t in (("relay-a", "11:00:00"), ("relay-b", "11:02:00"),
                 ("relay-c", "11:09:00")):
        _ev(tmp_path, h, sev="WARN", check="auth_log", signal="new-src",
            observed="203.0.113.7 failed-auth burst", recv_ts="2026-05-29T%sZ" % t)
    doc = _json(tmp_path, "2026-05-29T11:30:00Z")
    spray = [c for c in doc["clusters"] if c["kind"] == "ip-spray"]
    assert len(spray) == 1
    assert "203.0.113.7" in spray[0]["key"]
    assert spray[0]["host_count"] == 3


def test_ip_spray_counts_later_repeat_inside_window(tmp_path):
    """A prior hit from the same IP on one host must not hide a later spray."""
    _ev(tmp_path, "relay-a", seq=1, sev="WARN", check="auth_log",
        signal="new-src", observed="203.0.113.7 failed-auth burst",
        recv_ts="2026-05-29T00:00:00Z")
    _ev(tmp_path, "relay-a", seq=2, sev="WARN", check="auth_log",
        signal="new-src", observed="203.0.113.7 failed-auth burst",
        recv_ts="2026-05-29T11:00:00Z")
    for h, t in (("relay-b", "11:02:00"), ("relay-c", "11:09:00")):
        _ev(tmp_path, h, sev="WARN", check="auth_log", signal="new-src",
            observed="203.0.113.7 failed-auth burst", recv_ts="2026-05-29T%sZ" % t)
    doc = _json(tmp_path, "2026-05-29T11:30:00Z")
    spray = [c for c in doc["clusters"] if c["kind"] == "ip-spray"]
    assert len(spray) == 1
    assert spray[0]["host_count"] == 3
    assert spray[0]["spread_min"] == 9.0


def test_ip_spray_ignores_bind_all_address(tmp_path):
    """0.0.0.0 is a bind-all, not a peer — must not become an ip-spray key."""
    for h, t in (("relay-a", "11:00:00"), ("relay-b", "11:02:00"),
                 ("relay-c", "11:03:00")):
        _ev(tmp_path, h, sev="WARN", check="ports", signal="listener",
            observed="listen tcp 0.0.0.0:9001", recv_ts="2026-05-29T%sZ" % t)
    doc = _json(tmp_path, "2026-05-29T11:30:00Z")
    assert not any(c["kind"] == "ip-spray" for c in doc["clusters"])


# --- blackout --------------------------------------------------------------

def test_blackout_simultaneous_silence(tmp_path):
    for h, t in (("relay-a", "10:00:00"), ("relay-b", "10:02:00"),
                 ("relay-c", "10:05:00")):
        _silent_host(tmp_path, h, "2026-05-29T%sZ" % t)
    # a 4th host still fresh -> not part of the blackout
    _silent_host(tmp_path, "relay-d", "2026-05-29T11:25:00Z")
    r = _run(tmp_path, "2026-05-29T11:30:00Z", "--min-hosts", "3",
             "--stale-min", "30")
    assert r.returncode == 2
    doc = _json(tmp_path, "2026-05-29T11:30:00Z", "--min-hosts", "3",
                "--stale-min", "30")
    black = [c for c in doc["clusters"] if c["kind"] == "blackout"]
    assert len(black) == 1
    assert set(black[0]["hosts"]) == {"relay-a", "relay-b", "relay-c"}
    assert "relay-d" not in black[0]["hosts"]


def test_blackout_not_fired_when_silences_spread_out(tmp_path):
    """One relay flapping at a time != a coordinated takedown. Silences 4h apart
    must not cluster even though all three are individually stale."""
    _silent_host(tmp_path, "relay-a", "2026-05-29T01:00:00Z")
    _silent_host(tmp_path, "relay-b", "2026-05-29T05:00:00Z")
    _silent_host(tmp_path, "relay-c", "2026-05-29T09:00:00Z")
    r = _run(tmp_path, "2026-05-29T11:30:00Z", "--min-hosts", "3",
             "--stale-min", "30", "--window-min", "60")
    assert r.returncode == 0


def test_fresh_hosts_are_not_silent(tmp_path):
    for h in ("relay-a", "relay-b", "relay-c"):
        _silent_host(tmp_path, h, "2026-05-29T11:29:00Z")  # 1 min ago
    r = _run(tmp_path, "2026-05-29T11:30:00Z", "--min-hosts", "3",
             "--stale-min", "30")
    assert r.returncode == 0


# --- CLI contract ----------------------------------------------------------

def test_quiet_suppresses_clean_line(tmp_path):
    _ev(tmp_path, "relay-a", recv_ts="2026-05-29T10:00:00Z")
    r = _run(tmp_path, "2026-05-29T10:30:00Z", "--quiet")
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_min_hosts_below_two_rejected(tmp_path):
    r = _run(tmp_path, "2026-05-29T10:30:00Z", "--min-hosts", "1")
    assert r.returncode == 1


def test_nonpositive_tuning_values_rejected(tmp_path):
    """--window-min/--since-min/--stale-min must fail fast on <= 0, like
    --min-hosts: a zero/negative window or lookback is nonsensical."""
    for flag in ("--window-min", "--since-min", "--stale-min"):
        for bad in ("0", "-1"):
            r = _run(tmp_path, "2026-05-29T10:30:00Z", flag, bad)
            assert r.returncode == 1, "%s %s should be rejected" % (flag, bad)
            assert flag in r.stderr


def test_correlate_subcommand_accepted(tmp_path):
    _ev(tmp_path, "relay-a", recv_ts="2026-05-29T10:00:00Z")
    r = _run(tmp_path, "2026-05-29T10:30:00Z", "correlate", "--quiet")
    assert r.returncode == 0


def test_empty_root_is_clean(tmp_path):
    r = _run(tmp_path, "2026-05-29T10:30:00Z")
    assert r.returncode == 0


# --- deployment wiring -----------------------------------------------------

def test_receiver_setup_installs_correlate(tmp_path):
    """receiver-setup.sh must deploy onionwarden-correlate into .bin alongside
    the append handler + receiver, executable, so the */10 cron line resolves."""
    from conftest import BASH
    root = tmp_path / "data"
    subprocess.run(
        [BASH, str(ROOT / "receiver" / "receiver-setup.sh"),
         "--root", str(root), "--hosts", "relay-a relay-b"],
        capture_output=True, text=True,
        env={**os.environ, "ONIONWARDEN_RECEIVER_ROOT": str(root)})
    # Note: receiver-setup.sh may exit nonzero on a host without chattr (the
    # macOS build host); the binary `cp`s happen before the chattr step, so the
    # wiring assertion holds either way. On Linux CI the script returns 0.
    tool = root / ".bin" / "onionwarden-correlate"
    assert tool.exists() and os.access(tool, os.X_OK)


def test_receiver_md_schedules_correlate():
    text = (ROOT / "receiver" / "RECEIVER.md").read_text()
    assert "onionwarden-correlate" in text
    # the cron line must carry --quiet so a clean fleet doesn't mail noise
    assert "onionwarden-correlate --quiet" in text


def test_receiver_md_cron_has_no_empty_env_var_after_edit():
    """The Vixie-cron empty-value trap (IMPLEMENTATION_NOTES) — re-assert it
    still holds after adding the correlate cron line."""
    import re
    text = (ROOT / "receiver" / "RECEIVER.md").read_text()
    m = re.search(r"cat <<'EOF' > /etc/cron\.d/onionwarden-receiver\n(.*?)\nEOF",
                  text, re.DOTALL)
    assert m
    offending = [ln for ln in m.group(1).splitlines()
                 if re.match(r"^ONIONWARDEN_[A-Z0-9_]+=\s*$", ln)]
    assert not offending, offending
