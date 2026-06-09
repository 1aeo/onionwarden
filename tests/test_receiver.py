"""Off-box receiver: append handler hardening + active verification."""
import json
import os
import re
import subprocess

from conftest import ROOT, BASH

APPEND = ROOT / "receiver" / "receiver-append.sh"
RECEIVER = ROOT / "receiver" / "onionwarden-receiver"


def _append(root, lines, env_extra=None, expected_host=None):
    env = {**os.environ, "ONIONWARDEN_RECEIVER_ROOT": str(root)}
    if env_extra:
        env.update(env_extra)
    cmd = [BASH, str(APPEND)] + ([expected_host] if expected_host else [])
    subprocess.run(cmd, input="\n".join(lines) + "\n",
                   text=True, env=env, check=True)


def _receiver(root, *args):
    env = {**os.environ, "ONIONWARDEN_RECEIVER_ROOT": str(root)}
    return subprocess.run(["python3", str(RECEIVER), *args],
                          capture_output=True, text=True, env=env)


def test_deadman_pending_fail_forces_fail_ping(tmp_path):  # R8-2
    """A pending-fail marker forces /fail even on a clean `ok` ping, so a clean
    run cannot reset the provider timer and mask an undelivered CRIT."""
    state = tmp_path / "state"; state.mkdir()
    (state / "deadman_pending_fail").touch()
    sink = tmp_path / "sink"; sink.mkdir()
    conf = tmp_path / "host.conf"
    conf.write_text('host_id="t"\nrole="generic"\n'
                    'deadman_url = "https://x.invalid/dm"\n')
    env = {**os.environ, "ONIONWARDEN_ROOT": str(ROOT),
           "ONIONWARDEN_STATE_DIR": str(state), "ONIONWARDEN_ALERT_SINK": str(sink)}
    script = (f'. "{ROOT}/lib/alert.sh"; '
              f'cfg_load "{conf}" "{ROOT}/roles"; deadman_ping ok')
    subprocess.run([BASH, "-c", script], env=env, check=True,
                   capture_output=True, text=True)
    assert "/fail" in (sink / "deadman").read_text()
    assert not (state / "deadman_pending_fail").exists()  # cleared on success


def _ev(seq, host, kind="finding", sev="INFO", detail=None):
    o = {"seq": seq, "ts": "2026-05-21T10:00:00Z", "host_id": host,
         "kind": kind, "severity": sev}
    if detail is not None:
        o["detail"] = detail
    # Compact — mirrors what lib/alert.sh:events_append ships.
    return json.dumps(o, separators=(",", ":"))


def test_append_routes_by_host(tmp_path):
    _append(tmp_path, [_ev(1, "relay_a"), _ev(1, "relay_b")])
    assert (tmp_path / "relay_a" / "events.log").exists()
    assert (tmp_path / "relay_b" / "events.log").exists()


def test_append_sanitises_malicious_host_id(tmp_path):
    # A path-traversal host_id must not escape the receiver root.
    _append(tmp_path, ['{"host_id":"../../etc","kind":"finding","severity":"WARN"}'])
    assert not (tmp_path / ".." / ".." / "etc" / "events.log").exists()
    landed = list(tmp_path.glob("*/events.log"))
    assert landed and all(p.parent.name.startswith("_") for p in landed)


def test_append_rate_limit(tmp_path):
    lines = [_ev(i, "relay_a") for i in range(1, 21)]
    _append(tmp_path, lines, env_extra={"ONIONWARDEN_APPEND_RATE_MAX": "5"})
    kept = open(tmp_path / "relay_a" / "events.log").read().splitlines()
    assert len(kept) == 5  # only RATE_MAX lines kept


def test_append_rejects_non_json(tmp_path):
    _append(tmp_path, ["this is not json", _ev(1, "relay_a")])
    kept = open(tmp_path / "relay_a" / "events.log").read().splitlines()
    assert len(kept) == 1


def test_verify_record_and_check_ok(tmp_path):
    _append(tmp_path, [_ev(1, "relay_a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "ppp"})])
    assert _receiver(tmp_path, "verify-record").returncode == 0
    r = _receiver(tmp_path, "verify-check")
    assert r.returncode == 0 and "ok" in r.stdout


def test_verify_check_detects_pubkey_swap(tmp_path):
    _append(tmp_path, [_ev(1, "relay_a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "ppp"})])
    _receiver(tmp_path, "verify-record")
    _append(tmp_path, [_ev(2, "relay_a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "EVIL"})])
    r = _receiver(tmp_path, "verify-check")
    assert r.returncode == 2 and "MISMATCH" in r.stdout


def test_seqcheck_detects_gap(tmp_path):
    _append(tmp_path, [_ev(1, "relay_a"), _ev(2, "relay_a"),
                       _ev(4, "relay_a")])  # seq 3 missing
    r = _receiver(tmp_path, "seqcheck")
    assert r.returncode == 2 and "gap" in r.stdout.lower()


def test_seqcheck_clean(tmp_path):
    _append(tmp_path, [_ev(1, "relay_a"), _ev(2, "relay_a"),
                       _ev(3, "relay_a")])
    r = _receiver(tmp_path, "seqcheck")
    assert r.returncode == 0


def test_digest_rolls_up(tmp_path):
    _append(tmp_path, [_ev(1, "relay_a", "finding", "CRIT")])
    r = _receiver(tmp_path, "digest")
    assert r.returncode == 0 and "relay_a" in r.stdout


def test_verify_check_uses_highest_seq_not_file_order(tmp_path):  # R8-1
    """A replayed lower-seq good selfreport appended AFTER a bad one must not
    mask the mismatch — latest is selected by seq, not file order."""
    _append(tmp_path, [_ev(1, "relay_a", "selfreport", "INFO",
                           {"selfhash": "good", "pubkeyhash": "good"})])
    _receiver(tmp_path, "verify-record")
    _append(tmp_path, [
        _ev(3, "relay_a", "selfreport", "INFO",
            {"selfhash": "BAD", "pubkeyhash": "good"}),
        _ev(1, "relay_a", "selfreport", "INFO",      # replay, lower seq, last
            {"selfhash": "good", "pubkeyhash": "good"}),
    ])
    r = _receiver(tmp_path, "verify-check")
    assert r.returncode == 2 and "MISMATCH" in r.stdout


def test_append_rejects_underscore_host_id(tmp_path):  # R8-3
    """A host cannot file itself under a receiver-reserved `_`-prefixed dir
    (which verify-check/seqcheck/digest exclude) to escape verification."""
    _append(tmp_path, ['{"host_id":"_evil","kind":"finding","severity":"WARN"}'])
    assert not (tmp_path / "_evil" / "events.log").exists()
    assert (tmp_path / "_invalid" / "events.log").exists()


def test_append_host_pin_rewrites_mismatched_host_id(tmp_path):  # R1-F1
    """A key bound to relay_a (forced-command first arg) cannot file events
    under relay_b — the event is rewritten to relay_a and a warning is
    logged. Contains stolen-key blast radius to one host_id."""
    _append(tmp_path, [_ev(1, "relay_b")], expected_host="relay_a")
    assert (tmp_path / "relay_a" / "events.log").exists()
    assert not (tmp_path / "relay_b").exists()
    log = (tmp_path / "receiver.log").read_text()
    assert "host-pin MISMATCH" in log and "relay_a" in log and "relay_b" in log


def test_append_host_pin_passes_matching_host_id(tmp_path):  # R1-F1
    _append(tmp_path, [_ev(1, "relay_a")], expected_host="relay_a")
    assert (tmp_path / "relay_a" / "events.log").exists()
    log_path = tmp_path / "receiver.log"
    if log_path.exists():
        assert "host-pin MISMATCH" not in log_path.read_text()


def test_appender_stamps_recv_ts(tmp_path):  # R2-F2
    """Every accepted event line carries a receiver-stamped recv_ts."""
    _append(tmp_path, [_ev(1, "relay_a")])
    line = (tmp_path / "relay_a" / "events.log").read_text().strip()
    ev = json.loads(line)
    assert "recv_ts" in ev and ev["recv_ts"].endswith("Z")
    # original fields preserved
    assert ev["host_id"] == "relay_a" and ev["seq"] == 1


def test_installed_receiver_helpers_derive_shared_root_without_env(tmp_path):
    """SSH ForceCommand does not propagate cron env; .bin helpers must agree."""
    import shutil

    root = tmp_path / "receiver-root"
    bindir = root / ".bin"
    bindir.mkdir(parents=True)
    appender = bindir / "receiver-append.sh"
    receiver = bindir / "onionwarden-receiver"
    shutil.copy(APPEND, appender)
    shutil.copy(RECEIVER, receiver)
    appender.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items()
           if k != "ONIONWARDEN_RECEIVER_ROOT"}
    env["HOME"] = str(home)

    subprocess.run([BASH, str(appender)],
                   input=_ev(1, "relay_a", "selfreport", "INFO",
                             {"selfhash": "aaa", "pubkeyhash": "ppp"}) + "\n",
                   text=True, env=env, check=True)
    assert (root / "relay_a" / "events.log").exists()
    assert not (home / "onionwarden" / "relay_a" / "events.log").exists()

    r = subprocess.run(["python3", str(receiver), "verify-record"],
                       capture_output=True, text=True, env=env, check=False)
    assert r.returncode == 0, r.stderr
    assert (root / "relay_a" / "known_good.json").exists()


def test_events_log_age_uses_recv_ts_over_mtime(tmp_path):  # R2-F2
    """A bare `touch` cannot mask staleness — recv_ts of the latest event
    is the authoritative freshness signal."""
    import time as _t
    _append(tmp_path, [_ev(1, "relay_a")])
    log = tmp_path / "relay_a" / "events.log"
    # Backdate the recv_ts inside the file (simulating a host that hasn't
    # appended for >1 hour) and bump mtime to "now" via touch.
    line = log.read_text().strip()
    ev = json.loads(line)
    ev["recv_ts"] = "2020-01-01T00:00:00Z"
    log.write_text(json.dumps(ev, separators=(",", ":")) + "\n")
    _t.sleep(0.05)  # ensure mtime is fresh
    os.utime(log, None)
    r = _receiver(tmp_path, "verify-check", env_extra=None) if False else \
        subprocess.run(["python3", str(RECEIVER), "verify-check"],
                       capture_output=True, text=True,
                       env={**os.environ,
                            "ONIONWARDEN_RECEIVER_ROOT": str(tmp_path),
                            "ONIONWARDEN_STALE_MINUTES": "30"})
    assert "silent" in r.stdout  # staleness fires despite the touch


def test_seqcheck_resumes_from_state_file(tmp_path):  # R3-F3
    """Second seqcheck only sees the NEW slice; state file persists offset."""
    _append(tmp_path, [_ev(1, "relay_a"), _ev(2, "relay_a")])
    r1 = _receiver(tmp_path, "seqcheck")
    assert r1.returncode == 0
    assert (tmp_path / "relay_a" / ".seqcheck.state.json").exists()
    state = json.loads((tmp_path / "relay_a" / ".seqcheck.state.json").read_text())
    assert state["last_seq"] == 2 and state["last_offset"] > 0

    _append(tmp_path, [_ev(3, "relay_a")])
    r2 = _receiver(tmp_path, "seqcheck")
    assert r2.returncode == 0 and "1 new events" in r2.stdout


def test_seqcheck_reset_acks_after_one_warning(tmp_path):  # R3-F4
    """A legitimate appender restart (seq drops to 1) WARNs once, then
    subsequent runs treat the new sequence as authoritative."""
    _append(tmp_path, [_ev(1, "relay_a"), _ev(2, "relay_a"), _ev(3, "relay_a")])
    _receiver(tmp_path, "seqcheck")
    # Now appender restarts: seq 1 again.
    _append(tmp_path, [_ev(1, "relay_a"), _ev(2, "relay_a")])
    r1 = _receiver(tmp_path, "seqcheck")
    assert "reset" in r1.stdout.lower()
    # Next event after reset should NOT re-warn.
    _append(tmp_path, [_ev(3, "relay_a")])
    r2 = _receiver(tmp_path, "seqcheck")
    assert "reset" not in r2.stdout.lower()


def test_verify_check_per_host_stale_override(tmp_path):  # R3-F2
    """A per-host .stale_minutes file overrides the global env-var default.

    Use an event age between the default (30 min) and the override (1 day);
    default would fire, override should not."""
    import time as _t
    (tmp_path / "relay_a").mkdir()
    (tmp_path / "relay_a" / ".stale_minutes").write_text("1440")  # 24h
    sixty_min_ago = _t.strftime("%Y-%m-%dT%H:%M:%SZ",
                                _t.gmtime(_t.time() - 60 * 60))
    line = ('{"seq":1,"ts":"%s","host_id":"relay_a","kind":"sr",'
            '"severity":"INFO","recv_ts":"%s"}' % (sixty_min_ago, sixty_min_ago))
    (tmp_path / "relay_a" / "events.log").write_text(line + "\n")

    # Sanity: default would fire (60 > 30) ...
    r0 = subprocess.run(["python3", str(RECEIVER), "verify-check"],
                        capture_output=True, text=True,
                        env={**os.environ,
                             "ONIONWARDEN_RECEIVER_ROOT": str(tmp_path),
                             "ONIONWARDEN_STALE_MINUTES": "30"})
    # ... but the per-host override (1440) suppresses since 60 < 1440.
    # The .stale_minutes file is read on every cmd_verify_check invocation,
    # so the same run that sees both env-default-fire and per-host-suppress
    # produces only the latter result for relay_a.
    assert "silent" not in r0.stdout


def test_verify_record_writes_audit_event(tmp_path):  # R2-F1
    """verify-record appends a +a-protected audit event with the known-good
    payload, so a forged known_good.json can be cross-checked against the
    audit trail."""
    _append(tmp_path, [_ev(1, "relay_a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "ppp"})])
    r = _receiver(tmp_path, "verify-record")
    assert r.returncode == 0
    events = (tmp_path / "relay_a" / "events.log").read_text().splitlines()
    audit = [json.loads(l) for l in events if json.loads(l).get("kind") == "verify_record"]
    assert len(audit) == 1
    kg = audit[0]["detail"]["recorded_known_good"]
    assert kg["selfhash"] == "aaa" and kg["pubkeyhash"] == "ppp"


def test_receiver_md_cron_heredoc_has_no_empty_env_var():
    """Regression: the cron-file heredoc in RECEIVER.md must not emit any
    `ONIONWARDEN_*=` line with an empty value. Vixie cron 3.0pl1 on Ubuntu
    24.04 rejects such lines as "bad minute" — the parser falls through to
    cron-entry parsing and treats the var name as the minute field, silently
    invalidating the entire crontab file. The heredoc must ship every such
    env var either with a non-empty value or commented out.
    Diagnosed on 192.0.2.41 deploy 2026-05-24."""
    text = (ROOT / "receiver" / "RECEIVER.md").read_text()
    m = re.search(
        r"cat <<'EOF' > /etc/cron\.d/onionwarden-receiver\n(.*?)\nEOF",
        text, re.DOTALL)
    assert m, "RECEIVER.md no longer contains the expected cron-file heredoc"
    body = m.group(1)
    offending = [ln for ln in body.splitlines()
                 if re.match(r"^ONIONWARDEN_[A-Z0-9_]+=\s*$", ln)]
    assert not offending, (
        "RECEIVER.md cron heredoc has empty-value env-var lines that Vixie "
        "cron will reject ('bad minute'). Ship commented out instead. "
        "Offenders: %r" % offending)
