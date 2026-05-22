"""End-to-end dispatcher tests (bin/onionwarden-run): trust states, finding
routing, heartbeat, and the bootstrapping -> trusted transition."""
import json
import os
import subprocess

import pytest

from conftest import ROOT, ED25519, BASH, sign_file


def _run(env, cadence="fast"):
    proc = subprocess.run([BASH, str(ROOT / "bin" / "onionwarden-run"), cadence],
                          capture_output=True, text=True, env=env)
    return proc


def _summary(logdir):
    line = None
    for ln in open(os.path.join(logdir, "runs.ndjson")):
        if '"type":"run_summary"' in ln:
            line = ln
    return json.loads(line) if line else None


@pytest.fixture
def tree(tmp_path):
    """A full scratch install tree with a signed baseline + host.conf."""
    conf = tmp_path / "conf"; conf.mkdir()
    var = tmp_path / "var"
    (var / "baseline" / "state").mkdir(parents=True)
    (var / "state").mkdir(parents=True)
    log = tmp_path / "log"; log.mkdir()
    sink = tmp_path / "sink"; sink.mkdir()
    priv = tmp_path / "priv.pem"; pub = tmp_path / "onionwarden.pub"
    subprocess.run(["python3", str(ED25519), "keygen", str(priv), str(pub)],
                   check=True)

    host_conf = conf / "host.conf"
    host_conf.write_text(
        'host_id = "testhost"\nrole = "generic"\n'
        'deadman_url = "https://example.invalid/dm"\n'
        'ntfy_url = "https://example.invalid/ntfy"\n'
        'alert_push_level = "warn"\n')
    sign_file(str(priv), str(host_conf))

    # baseline: a controlled taint state file
    (var / "baseline" / "state" / "taint.state").write_text("tainted 0\n")
    subprocess.run(
        [BASH, "-c", f'. "{ROOT}/lib/baseline.sh"; '
         f'baseline_write_manifest "{var}/baseline" testhost'],
        check=True, env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    sign_file(str(priv), str(var / "baseline" / "manifest.json"))

    profile = tmp_path / "profile.state"
    profile.write_text("os_id=ubuntu\nos_supported=true\nvirt_type=kvm\n"
                        "is_container=false\n")

    env = {**os.environ,
           "ONIONWARDEN_ROOT": str(ROOT),
           "ONIONWARDEN_CONF_DIR": str(conf),
           "ONIONWARDEN_VAR_DIR": str(var),
           "ONIONWARDEN_LOG_DIR": str(log),
           "ONIONWARDEN_ALERT_SINK": str(sink),
           "ONIONWARDEN_VERIFY_BACKEND": "python",
           "ONIONWARDEN_PUBKEY": str(pub),
           "ONIONWARDEN_PROFILE_FILE": str(profile)}
    return {"dir": tmp_path, "env": env, "var": var, "log": log,
            "sink": sink, "priv": str(priv), "conf": conf}


def test_bootstrapping_collect_only(tree):
    """No verified baseline + bootstrapping marker -> collect-only, no CRIT."""
    (tree["var"] / "state" / "bootstrapping").touch()
    # remove the baseline so it is genuinely 'nobaseline'
    os.remove(tree["var"] / "baseline" / "manifest.json")
    env = {**tree["env"], "ONIONWARDEN_RUN_ID": "boot1"}
    proc = _run(env)
    assert proc.returncode == 0
    s = _summary(tree["log"])
    assert s["trust"] == "nobaseline"
    # bootstrapping must not raise a signature CRIT
    assert s["severity"] != "CRIT"


def test_trusted_clean_run(tree):
    env = {**tree["env"], "ONIONWARDEN_RUN_ID": "r1"}
    proc = _run(env)
    assert proc.returncode == 0
    s = _summary(tree["log"])
    assert s["trust"] == "trusted"
    # heartbeat OK ping recorded
    assert "/fail" not in open(tree["sink"] / "deadman").read()


def test_trusted_deviation_routes_alerts(tree):
    """A fake-state taint deviation -> CRIT, ntfy push, events.log, /fail."""
    fake = tree["dir"] / "fake"; fake.mkdir()
    (fake / "taint.current").write_text("tainted 4096\n")
    env = {**tree["env"], "ONIONWARDEN_RUN_ID": "r2",
           "ONIONWARDEN_FAKE_STATE_DIR": str(fake)}
    proc = _run(env)
    assert proc.returncode == 0
    s = _summary(tree["log"])
    assert s["trust"] == "trusted" and s["severity"] == "CRIT"
    assert "/fail" in open(tree["sink"] / "deadman").read()
    assert os.path.exists(tree["sink"] / "ntfy")
    events = open(tree["sink"] / "events.log").read()
    assert '"severity":"CRIT"' in events


def test_bad_baseline_signature_is_crit(tree):
    """A tampered baseline (no bootstrapping) -> CRIT, analysis skipped."""
    # tamper a state file after signing -> hash mismatch
    (tree["var"] / "baseline" / "state" / "taint.state").write_text("tainted 99\n")
    env = {**tree["env"], "ONIONWARDEN_RUN_ID": "r3"}
    proc = _run(env)
    assert proc.returncode == 0
    s = _summary(tree["log"])
    assert s["trust"] == "badbaseline" and s["severity"] == "CRIT"
    log = open(tree["log"] / "runs.ndjson").read()
    assert "baseline_signature" in log


def test_bootstrapping_transition_clears_marker(tree):
    """A first fully-verified run ends the bootstrapping state (M2)."""
    (tree["var"] / "state" / "bootstrapping").touch()
    env = {**tree["env"], "ONIONWARDEN_RUN_ID": "r4"}
    proc = _run(env)
    assert proc.returncode == 0
    assert not os.path.exists(tree["var"] / "state" / "bootstrapping")
    assert _summary(tree["log"])["trust"] == "trusted"
