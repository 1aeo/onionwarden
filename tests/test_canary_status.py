"""Phase-4 canary rollout health (`bin/onionwarden-canary-status`).

Turns "has the canary been quiet for long enough?" into a three-state verdict
(Option D) against the signoff gate (docs/PHASE4_CANARY_PLAYBOOK.md):
  * PASS — >= require-days observed, zero unexplained WARN, not stale, zero CRIT.
  * HOLD — any of the above unmet, OR a CRIT that is not validly acknowledged.
  * WARN — would PASS but for a CRIT the operator acknowledged with a documented,
           non-expired, non-self-signed ack ("eyes open"); never promotes to PASS.
Events are fixture-built with recv_ts and `now` pinned via --now-epoch for
determinism. CRIT acks are recorded via the audited `ack` subcommand.
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


def _ack(now_iso, store, finding_id, reason="benign", signer="operator",
         *extra):
    """Drive the `ack` subcommand; returns the CompletedProcess."""
    cmd = ["python3", str(CANARY), "ack",
           "--finding-id", finding_id, "--ack-store", str(store),
           "--now-epoch", str(_epoch(now_iso)), "--signer", signer]
    if reason is not None:
        cmd += ["--reason", reason]
    return subprocess.run(cmd + list(extra), capture_output=True, text=True)


# fixture: 8 days of life with a single CRIT early on, otherwise clean. Absent
# the CRIT this PASSes — so the CRIT alone decides PASS/HOLD/WARN.
def _crit8(path):
    _events(path, [
        (1, "2026-05-20T10:00:00Z", "selfreport", "INFO", "", "", "boot"),
        (2, "2026-05-23T10:00:00Z", "finding", "CRIT", "modules", "new-module",
         "module nfsd"),
        (3, "2026-05-28T11:00:00Z", "selfreport", "INFO", "", "", "alive"),
    ])


def _crit_finding_id(ev, now_iso="2026-05-28T11:10:00Z"):
    doc, _ = _json(ev, now_iso)
    crits = [u for u in doc["unexplained"] if u["severity"] == "CRIT"]
    assert crits, "fixture should surface a blocking CRIT"
    return crits[0]["finding_id"]


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


# --- Option D: three-state CRIT verdict (PASS / HOLD / WARN) ---

def test_pass_when_no_crit(tmp_path):
    # Green path: clean window, no CRIT -> PASS (exit 0).
    ev = tmp_path / "relay-a" / "events.log"
    _clean8(ev)
    ack = tmp_path / "acks"; ack.write_text("clock/unsynced  # benign\n")
    doc, rc = _json(ev, "2026-05-28T11:10:00Z", "--ack-file", str(ack))
    assert rc == 0 and doc["verdict"] == "PASS"
    assert doc["counts"]["CRIT"] == 0
    assert doc["acked_crit_count"] == 0


def test_hold_when_crit_unacked(tmp_path):
    # A CRIT with no ack blocks the gate -> HOLD (exit 1), never PASS.
    ev = tmp_path / "relay-a" / "events.log"
    _crit8(ev)
    store = tmp_path / "acks.jsonl"  # exists-but-empty / absent: no acks
    doc, rc = _json(ev, "2026-05-28T11:10:00Z", "--ack-store", str(store))
    assert rc == 1 and doc["verdict"] == "HOLD"
    assert doc["counts"]["CRIT"] == 1
    assert doc["acked_crit_count"] == 0
    crit = [u for u in doc["unexplained"] if u["severity"] == "CRIT"]
    assert crit and crit[0]["ack_state"] == "none"


def test_warn_when_crit_acked(tmp_path):
    # A CRIT acked with a documented, valid, non-self-signed ack downgrades
    # HOLD -> WARN (exit 3) -- "rolling forward with eyes open", NOT PASS.
    ev = tmp_path / "relay-a" / "events.log"
    _crit8(ev)
    store = tmp_path / "acks.jsonl"
    fid = _crit_finding_id(ev)
    r = _ack("2026-05-28T11:00:00Z", store, fid,
             reason="nfsd is expected on this NFS-backed canary", signer="op")
    assert r.returncode == 0, r.stderr
    doc, rc = _json(ev, "2026-05-28T11:10:00Z", "--ack-store", str(store))
    assert rc == 3 and doc["verdict"] == "WARN"
    assert doc["counts"]["CRIT"] == 1
    assert doc["acked_crit_count"] == 1
    assert doc["unexplained_count"] == 0
    assert doc["acked_crits"][0]["ack_signer"] == "op"
    assert "nfsd" in doc["acked_crits"][0]["ack_reason"]
    # default fleet gate is conservative (pass-only) -> WARN does not roll fwd.
    assert doc["gate_pass"] is False
    # a pass-warn wave may roll forward on WARN.
    doc2, _ = _json(ev, "2026-05-28T11:10:00Z", "--ack-store", str(store),
                    "--rollout-gate", "pass-warn")
    assert doc2["verdict"] == "WARN" and doc2["gate_pass"] is True


def test_hold_when_ack_expired(tmp_path):
    # An ack older than its TTL is no longer valid -> back to HOLD.
    ev = tmp_path / "relay-a" / "events.log"
    _crit8(ev)
    store = tmp_path / "acks.jsonl"
    fid = _crit_finding_id(ev)
    # ack 5 days before "now" with the default 72h TTL -> expired.
    r = _ack("2026-05-23T11:00:00Z", store, fid, reason="looked benign",
             signer="op")
    assert r.returncode == 0, r.stderr
    doc, rc = _json(ev, "2026-05-28T11:10:00Z", "--ack-store", str(store))
    assert rc == 1 and doc["verdict"] == "HOLD"
    assert doc["acked_crit_count"] == 0
    crit = [u for u in doc["unexplained"] if u["severity"] == "CRIT"]
    assert crit and crit[0]["ack_state"] == "expired"


def test_hold_when_ack_self_signed(tmp_path):
    # An ack signed by the same identity that triggered the alert (the finding's
    # host_id) is auditable but never gate-valid -> HOLD.
    ev = tmp_path / "relay-a" / "events.log"  # host_id == "relay-a"
    _crit8(ev)
    store = tmp_path / "acks.jsonl"
    fid = _crit_finding_id(ev)
    r = _ack("2026-05-28T11:00:00Z", store, fid, reason="trust me",
             signer="relay-a")  # == triggering host_id -> self-signed
    assert r.returncode == 0, r.stderr
    doc, rc = _json(ev, "2026-05-28T11:10:00Z", "--ack-store", str(store))
    assert rc == 1 and doc["verdict"] == "HOLD"
    assert doc["acked_crit_count"] == 0
    crit = [u for u in doc["unexplained"] if u["severity"] == "CRIT"]
    assert crit and crit[0]["ack_state"] == "self"


def test_reason_required_for_ack(tmp_path):
    # The ack subcommand rejects a missing --reason at parse time (exit 2).
    store = tmp_path / "acks.jsonl"
    r = _ack("2026-05-28T11:00:00Z", store, "deadbeefdeadbeef", reason=None)
    assert r.returncode == 2
    assert "reason" in r.stderr
    assert not store.exists()  # nothing written on a rejected ack


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
