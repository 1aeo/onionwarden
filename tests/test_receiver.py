"""Off-box receiver: append handler hardening + active verification."""
import json
import os
import subprocess

from conftest import ROOT, BASH

APPEND = ROOT / "receiver" / "receiver-append.sh"
RECEIVER = ROOT / "receiver" / "onionwarden-receiver"


def _append(root, lines, env_extra=None):
    env = {**os.environ, "ONIONWARDEN_RECEIVER_ROOT": str(root)}
    if env_extra:
        env.update(env_extra)
    subprocess.run([BASH, str(APPEND)], input="\n".join(lines) + "\n",
                   text=True, env=env, check=True)


def _receiver(root, *args):
    env = {**os.environ, "ONIONWARDEN_RECEIVER_ROOT": str(root)}
    return subprocess.run(["python3", str(RECEIVER), *args],
                          capture_output=True, text=True, env=env)


def _ev(seq, host, kind="finding", sev="INFO", detail=None):
    o = {"seq": seq, "ts": "2026-05-21T10:00:00Z", "host_id": host,
         "kind": kind, "severity": sev}
    if detail is not None:
        o["detail"] = detail
    # Compact — mirrors what lib/alert.sh:events_append ships.
    return json.dumps(o, separators=(",", ":"))


def test_append_routes_by_host(tmp_path):
    _append(tmp_path, [_ev(1, "relay-a"), _ev(1, "eval-host")])
    assert (tmp_path / "relay-a" / "events.log").exists()
    assert (tmp_path / "eval-host" / "events.log").exists()


def test_append_sanitises_malicious_host_id(tmp_path):
    # A path-traversal host_id must not escape the receiver root.
    _append(tmp_path, ['{"host_id":"../../etc","kind":"finding","severity":"WARN"}'])
    assert not (tmp_path / ".." / ".." / "etc" / "events.log").exists()
    landed = list(tmp_path.glob("*/events.log"))
    assert landed and all(p.parent.name.startswith("_") for p in landed)


def test_append_rate_limit(tmp_path):
    lines = [_ev(i, "relay-a") for i in range(1, 21)]
    _append(tmp_path, lines, env_extra={"ONIONWARDEN_APPEND_RATE_MAX": "5"})
    kept = open(tmp_path / "relay-a" / "events.log").read().splitlines()
    assert len(kept) == 5  # only RATE_MAX lines kept


def test_append_rejects_non_json(tmp_path):
    _append(tmp_path, ["this is not json", _ev(1, "relay-a")])
    kept = open(tmp_path / "relay-a" / "events.log").read().splitlines()
    assert len(kept) == 1


def test_verify_record_and_check_ok(tmp_path):
    _append(tmp_path, [_ev(1, "relay-a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "ppp"})])
    assert _receiver(tmp_path, "verify-record").returncode == 0
    r = _receiver(tmp_path, "verify-check")
    assert r.returncode == 0 and "ok" in r.stdout


def test_verify_check_detects_pubkey_swap(tmp_path):
    _append(tmp_path, [_ev(1, "relay-a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "ppp"})])
    _receiver(tmp_path, "verify-record")
    _append(tmp_path, [_ev(2, "relay-a", "selfreport", "INFO",
                           {"selfhash": "aaa", "pubkeyhash": "EVIL"})])
    r = _receiver(tmp_path, "verify-check")
    assert r.returncode == 2 and "MISMATCH" in r.stdout


def test_seqcheck_detects_gap(tmp_path):
    _append(tmp_path, [_ev(1, "relay-a"), _ev(2, "relay-a"),
                       _ev(4, "relay-a")])  # seq 3 missing
    r = _receiver(tmp_path, "seqcheck")
    assert r.returncode == 2 and "gap" in r.stdout.lower()


def test_seqcheck_clean(tmp_path):
    _append(tmp_path, [_ev(1, "relay-a"), _ev(2, "relay-a"),
                       _ev(3, "relay-a")])
    r = _receiver(tmp_path, "seqcheck")
    assert r.returncode == 0


def test_digest_rolls_up(tmp_path):
    _append(tmp_path, [_ev(1, "relay-a", "finding", "CRIT")])
    r = _receiver(tmp_path, "digest")
    assert r.returncode == 0 and "relay-a" in r.stdout
