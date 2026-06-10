"""Fatal-action kill-switch (lib/fatal.sh, onionwarden-fatal) and the suppression
workflow (lib/suppress.sh, onionwarden-suppress)."""
import json
import os
import subprocess
import time

import pytest

from conftest import ROOT, ED25519, BASH, sign_file


@pytest.fixture
def kstree(tmp_path):
    """Minimal tree for fatal/suppress tests: conf + var + keypair."""
    conf = tmp_path / "conf"; conf.mkdir()
    (conf / "keys").mkdir()
    var = tmp_path / "var"
    (var / "state").mkdir(parents=True)
    (var / "baseline").mkdir(parents=True)
    log = tmp_path / "log"; log.mkdir()
    priv = tmp_path / "priv.pem"; pub = tmp_path / "onionwarden.pub"
    subprocess.run(["python3", str(ED25519), "keygen", str(priv), str(pub)],
                   check=True)
    env = {**os.environ,
           "ONIONWARDEN_ROOT": str(ROOT),
           "ONIONWARDEN_CONF_DIR": str(conf),
           "ONIONWARDEN_VAR_DIR": str(var),
           "ONIONWARDEN_LOG_DIR": str(log),
           "ONIONWARDEN_VERIFY_BACKEND": "python",
           "ONIONWARDEN_PUBKEY": str(pub)}
    return {"dir": tmp_path, "conf": conf, "var": var, "env": env,
            "priv": str(priv), "pub": str(pub)}


def _write_conf(kstree, extra=""):
    (kstree["conf"] / "host.conf").write_text(
        'host_id = "testhost"\nrole = "generic"\n' + extra)


# Compact JSON — mirrors exactly what lib/common.sh:emit_finding produces.
FATAL_FINDING = json.dumps({
    "check": "taint", "signal": "kernel_taint", "severity": "CRIT",
    "summary": "taint bit O", "baseline": "0", "observed": "4096",
    "fatal_candidate": True}, separators=(",", ":"))


def _eval(kstree, findings_text):
    ff = kstree["dir"] / "findings.ndjson"
    ff.write_text(findings_text + "\n")
    script = (f'. "{ROOT}/lib/fatal.sh"; '
              f'cfg_load "{kstree["conf"]}/host.conf" "{ROOT}/roles"; '
              f'fatal_evaluate "{ff}" CRIT')
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          env=kstree["env"])


def test_fatal_disarmed_takes_no_action(kstree):
    _write_conf(kstree)  # fatal_action_armed unset -> false
    r = _eval(kstree, FATAL_FINDING)
    assert "DISARMED" in r.stderr and "no action" in r.stderr


def test_fatal_armed_dryrun_would_act(kstree):
    _write_conf(kstree, 'fatal_action = "poweroff"\nfatal_action_armed = true\n')
    (kstree["var"] / "state" / "fatal_armed").write_text(
        "action=poweroff\nscope=highconf\n")
    env = {**kstree["env"], "ONIONWARDEN_FATAL_DRYRUN": "1"}
    ff = kstree["dir"] / "findings.ndjson"
    ff.write_text(FATAL_FINDING + "\n")
    script = (f'. "{ROOT}/lib/fatal.sh"; '
              f'cfg_load "{kstree["conf"]}/host.conf" "{ROOT}/roles"; '
              f'fatal_evaluate "{ff}" CRIT')
    r = subprocess.run([BASH, "-c", script], capture_output=True, text=True, env=env)
    assert "WOULD perform" in (r.stdout + r.stderr)


def test_fatal_master_veto_blocks_even_with_armed_file(kstree):
    """host.conf fatal_action_armed=false vetoes even if state/fatal_armed exists."""
    _write_conf(kstree, 'fatal_action = "poweroff"\nfatal_action_armed = false\n')
    (kstree["var"] / "state" / "fatal_armed").write_text(
        "action=poweroff\nscope=all\n")
    r = _eval(kstree, FATAL_FINDING)
    assert "DISARMED" in r.stderr


def test_fatal_arm_refuses_poweroff_without_oob(kstree):
    """poweroff arming hard-refuses without --attest-oob (§3.7 item 6)."""
    _write_conf(kstree, 'fatal_action = "poweroff"\nfatal_action_armed = true\n')
    r = subprocess.run([BASH, str(ROOT / "bin" / "onionwarden-fatal"), "arm",
                        "--action", "poweroff"],
                       capture_output=True, text=True, env=kstree["env"])
    assert r.returncode != 0
    assert "attest-oob" in (r.stdout + r.stderr).lower()


def test_fatal_arm_refuses_on_failed_checklist(kstree):
    """With attestations supplied, the checklist still refuses on an immature
    baseline (no signed baseline / no apt-correlation evidence)."""
    _write_conf(kstree, 'fatal_action = "poweroff"\nfatal_action_armed = true\n')
    r = subprocess.run([BASH, str(ROOT / "bin" / "onionwarden-fatal"), "arm",
                        "--action", "poweroff", "--attest-oob",
                        "--attest-phase2", "--attest-offbox"],
                       capture_output=True, text=True, env=kstree["env"])
    assert r.returncode != 0
    out = (r.stdout + r.stderr).lower()
    assert "checklist failed" in out and "item1" in out


def test_fatal_status_reports_disarmed(kstree):
    _write_conf(kstree)
    r = subprocess.run([BASH, str(ROOT / "bin" / "onionwarden-fatal"), "status"],
                       capture_output=True, text=True, env=kstree["env"])
    assert "DISARMED" in r.stdout


# --- suppression workflow -------------------------------------------------
def _suppress(kstree, *args, **kw):
    return subprocess.run([BASH, str(ROOT / "bin" / "onionwarden-suppress"), *args],
                          capture_output=True, text=True, env=kstree["env"], **kw)


def test_suppress_request_install_activates(kstree):
    _write_conf(kstree)
    tok = kstree["dir"] / "tok"
    r = _suppress(kstree, "request", "--reason", "crash cart",
                  "--duration", "30m", "--out", str(tok))
    assert r.returncode == 0 and tok.exists()
    sign_file(kstree["priv"], str(tok))
    r = _suppress(kstree, "install", "--token", str(tok))
    assert r.returncode == 0 and "ACTIVE" in r.stdout


def test_suppress_rejects_unsigned_token(kstree):
    _write_conf(kstree)
    tok = kstree["dir"] / "tok"
    _suppress(kstree, "request", "--reason", "x", "--duration", "10m",
              "--out", str(tok))
    # forge a .sig with garbage
    (kstree["dir"] / "tok.sig").write_bytes(b"\x00" * 64)
    r = _suppress(kstree, "install", "--token", str(tok))
    assert r.returncode != 0 and "INVALID" in (r.stdout + r.stderr)


def test_suppress_rejects_expired_token(kstree):
    _write_conf(kstree)
    tok = kstree["dir"] / "tok"
    tok.write_text('{"host_id":"testhost","scope":"physical","reason":"old",'
                   '"operator":"x","opened_at":"2020-01-01T00:00:00Z",'
                   '"expires_at":"2020-01-01T00:30:00Z","nonce":"n1"}')
    sign_file(kstree["priv"], str(tok))
    r = _suppress(kstree, "install", "--token", str(tok))
    assert r.returncode != 0  # expired -> not active


def test_suppress_clear_revokes_token(kstree):
    """R4-2: after `clear`, re-installing the same captured token is refused."""
    _write_conf(kstree)
    kstree["env"]["ONIONWARDEN_NOW"] = "2026-06-10T02:00:00Z"
    tok = kstree["dir"] / "tok"
    _suppress(kstree, "request", "--reason", "visit", "--duration", "60m",
              "--out", str(tok))
    sign_file(kstree["priv"], str(tok))
    assert _suppress(kstree, "install", "--token", str(tok)).returncode == 0
    assert _suppress(kstree, "clear").returncode == 0
    # the token file is still valid + unexpired, but clear revoked it
    r = _suppress(kstree, "install", "--token", str(tok))
    assert r.returncode != 0


def test_suppress_rejects_replayed_old_token(kstree):
    _write_conf(kstree)
    # Install a current token, then try to install an OLDER one.
    new = kstree["dir"] / "new"
    _suppress(kstree, "request", "--reason", "now", "--duration", "30m",
              "--out", str(new))
    sign_file(kstree["priv"], str(new))
    assert _suppress(kstree, "install", "--token", str(new)).returncode == 0

    old = kstree["dir"] / "old"
    old.write_text('{"host_id":"testhost","scope":"physical","reason":"replay",'
                   '"operator":"x","opened_at":"2021-01-01T00:00:00Z",'
                   '"expires_at":"2099-01-01T00:00:00Z","nonce":"old"}')
    sign_file(kstree["priv"], str(old))
    r = _suppress(kstree, "install", "--token", str(old))
    assert r.returncode != 0  # opened_at older than last honored -> replay
