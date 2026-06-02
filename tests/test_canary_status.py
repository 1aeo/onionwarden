"""Phase-4 canary rollout health (`bin/onionwarden-canary-status`).

Turns "has the canary been quiet for long enough?" into a PASS/HOLD verdict
against the signoff gate (docs/PHASE4_CANARY_PLAYBOOK.md): >= require-days of
observation, zero UNEXPLAINED WARN/CRIT, and the canary not stale. Events are
fixture-built with recv_ts and `now` pinned via --now-epoch for determinism.
"""
import calendar
import json
import os
import subprocess
import time

from conftest import ROOT

CANARY = ROOT / "bin" / "onionwarden-canary-status"
DISPATCH = ROOT / "bin" / "onionwarden"


def _epoch(iso):
    return int(calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")))


def _events(path, rows):
    """rows: list of (seq, iso_ts, kind, sev, check, signal, summary)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        for seq, ts, kind, sev, check, signal, summary in rows:
            detail = {"check": check, "signal": signal, "observed": summary}
            fh.write(json.dumps(
                {"seq": seq, "ts": ts, "host_id": "relay-a",
                 "run_id": ts, "kind": kind, "severity": sev,
                 "summary": summary, "detail": detail, "recv_ts": ts},
                separators=(",", ":")) + "\n")


def _run(events, now_iso, *args):
    return subprocess.run(
        ["python3", str(CANARY), "--events", str(events),
         "--now-epoch", str(_epoch(now_iso)), *args],
        capture_output=True, text=True)


def _json(events, now_iso, *args):
    r = _run(events, now_iso, "--format", "json", *args)
    return json.loads(r.stdout), r.returncode


# baseline fixture: 8 days of life, one WARN early on.
def _clean8(path):
    _events(path, [
        (1, "2026-05-20T10:00:00Z", "selfreport", "INFO", "", "", "boot"),
        (2, "2026-05-21T10:00:00Z", "finding", "WARN", "clock", "unsynced",
         "NTP not settled"),
        (3, "2026-05-28T11:00:00Z", "selfreport", "INFO", "", "", "alive"),
    ])


def test_hold_when_unexplained_warn(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _clean8(ev)
    doc, rc = _json(ev, "2026-05-28T11:10:00Z")
    assert rc == 1
    assert doc["verdict"] == "HOLD"
    assert doc["unexplained_count"] == 1
    assert doc["observed_days"] >= 7  # time is fine; the WARN is the blocker


def test_pass_when_warn_acked(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _clean8(ev)
    ack = tmp_path / "acks"; ack.write_text("clock/unsynced  # benign\n")
    doc, rc = _json(ev, "2026-05-28T11:10:00Z", "--ack-file", str(ack))
    assert rc == 0
    assert doc["verdict"] == "PASS"
    assert doc["unexplained_count"] == 0
    assert doc["acks_loaded"] == 1


def test_hold_when_too_few_days(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _events(ev, [
        (1, "2026-05-27T10:00:00Z", "selfreport", "INFO", "", "", "boot"),
        (2, "2026-05-28T10:00:00Z", "selfreport", "INFO", "", "", "alive"),
    ])
    doc, rc = _json(ev, "2026-05-28T10:05:00Z")  # ~1 day
    assert rc == 1 and doc["verdict"] == "HOLD"
    assert any("clean days" in r for r in doc["reasons"])


def test_hold_when_crit_even_if_acked_warn(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _events(ev, [
        (1, "2026-05-20T10:00:00Z", "selfreport", "INFO", "", "", "boot"),
        (2, "2026-05-25T10:00:00Z", "finding", "CRIT", "modules", "new-module",
         "module nfsd"),
        (3, "2026-05-28T10:00:00Z", "selfreport", "INFO", "", "", "alive"),
    ])
    doc, rc = _json(ev, "2026-05-28T10:05:00Z")
    assert rc == 1 and doc["verdict"] == "HOLD"
    assert doc["counts"]["CRIT"] == 1
    assert doc["unexplained_count"] == 1


def test_hold_when_stale(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _clean8(ev)
    ack = tmp_path / "acks"; ack.write_text("clock/unsynced\n")
    # now is 2 days after the last event -> stale
    doc, rc = _json(ev, "2026-05-30T11:00:00Z", "--ack-file", str(ack))
    assert rc == 1 and doc["verdict"] == "HOLD" and doc["stale"] is True
    assert any("STALE" in r for r in doc["reasons"])


def test_no_events_holds(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    ev.parent.mkdir(parents=True)
    ev.write_text("")
    doc, rc = _json(ev, "2026-05-28T10:00:00Z")
    assert rc == 1 and doc["verdict"] == "HOLD"
    assert any("no events" in r for r in doc["reasons"])


def test_ack_pattern_matches_signal_substring(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _events(ev, [
        (1, "2026-05-20T10:00:00Z", "selfreport", "INFO", "", "", "boot"),
        (2, "2026-05-22T10:00:00Z", "finding", "WARN", "snap", "revision",
         "snap core revision changed"),
        (3, "2026-05-28T10:00:00Z", "selfreport", "INFO", "", "", "alive"),
    ])
    ack = tmp_path / "acks"; ack.write_text("snap\n")  # coarse substring
    doc, rc = _json(ev, "2026-05-28T10:05:00Z", "--ack-file", str(ack))
    assert rc == 0 and doc["unexplained_count"] == 0


def test_since_days_window_excludes_old_warn(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _events(ev, [
        (1, "2026-05-01T10:00:00Z", "finding", "WARN", "clock", "unsynced", "old"),
        (2, "2026-05-26T10:00:00Z", "selfreport", "INFO", "", "", "boot"),
        (3, "2026-05-28T10:00:00Z", "selfreport", "INFO", "", "", "alive"),
    ])
    # require only 2 days, window 3 days -> old WARN excluded -> PASS
    doc, rc = _json(ev, "2026-05-28T10:05:00Z",
                    "--require-days", "2", "--since-days", "3")
    assert rc == 0 and doc["verdict"] == "PASS"


def test_receiver_root_resolution(tmp_path):
    root = tmp_path / "recvroot"
    _clean8(root / "relay-a" / "events.log")
    ack = tmp_path / "acks"; ack.write_text("clock/unsynced\n")
    r = subprocess.run(
        ["python3", str(CANARY), "--receiver-root", str(root),
         "--host", "relay-a", "--now-epoch", str(_epoch("2026-05-28T11:10:00Z")),
         "--ack-file", str(ack), "--format", "json"],
        capture_output=True, text=True)
    assert r.returncode == 0
    assert json.loads(r.stdout)["verdict"] == "PASS"


def test_missing_source_is_usage_error(tmp_path):
    r = subprocess.run(["python3", str(CANARY)], capture_output=True, text=True,
                       env={k: v for k, v in os.environ.items()
                            if k != "ONIONWARDEN_RECEIVER_ROOT"})
    assert r.returncode == 2


def test_missing_ack_file_is_usage_error(tmp_path):
    # An unreadable/missing --ack-file must be a clean usage error (exit 2),
    # not an uncaught OSError traceback.
    ev = tmp_path / "events.log"
    _clean8(ev)
    r = _run(ev, "2026-05-28T11:10:00Z", "--ack-file", str(tmp_path / "nope.acks"))
    assert r.returncode == 2
    assert "ack-file" in r.stderr
    assert "Traceback" not in r.stderr


def test_dispatched_via_onionwarden_cli(tmp_path):
    ev = tmp_path / "relay-a" / "events.log"
    _clean8(ev)
    ack = tmp_path / "acks"; ack.write_text("clock/unsynced\n")
    r = subprocess.run(
        ["bash", str(DISPATCH), "canary-status", "--events", str(ev),
         "--now-epoch", str(_epoch("2026-05-28T11:10:00Z")),
         "--ack-file", str(ack)],
        capture_output=True, text=True,
        env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    assert r.returncode == 0 and "PASS" in r.stdout
