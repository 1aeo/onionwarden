"""Shared pytest fixtures and helpers for the onionwarden test suite.

The watchdog targets Linux but the checks are designed so analyze() is a PURE
function of (baseline state, current state, config) — so every check is tested
from fixtures on any host, no Linux required. Tests drive the bash checks via
their `analyze` CLI and assert on the structured JSON findings; Python tooling
(ed25519, receiver) is exercised directly. The system /bin/bash on the macOS
build host is 3.2, so a passing run also proves bash-3.2 compatibility.
"""
import json
import os
import pathlib
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKS = ROOT / "lib" / "checks"
ED25519 = ROOT / "lib" / "ed25519.py"
BASH = "/bin/bash"


def _write(path, content):
    if isinstance(content, (list, tuple)):
        content = "\n".join(content) + ("\n" if content else "")
    pathlib.Path(path).write_text(content)
    return str(path)


def run_analyze(check, baseline, current, config=None, env=None, profile=None):
    """Run lib/checks/<check>.sh analyze on fixture state; return finding dicts.

    baseline/current are lists of state-file lines (or strings). config is
    host.conf text (or None). Returns a list of parsed JSON finding objects.
    """
    tmp = tempfile.mkdtemp(prefix="onionwarden-test-")
    base_f = _write(os.path.join(tmp, "baseline.state"), baseline)
    cur_f = _write(os.path.join(tmp, "current.state"), current)
    cmd = [BASH, str(CHECKS / f"{check}.sh"), "analyze",
           "--baseline", base_f, "--current", cur_f]
    if config is not None:
        conf_f = _write(os.path.join(tmp, "host.conf"), config)
        cmd += ["--config", conf_f, "--roles", str(ROOT / "roles")]
    if profile is not None:
        prof_f = _write(os.path.join(tmp, "profile.state"), profile)
        cmd += ["--profile", prof_f]
    full_env = dict(os.environ)
    full_env["ONIONWARDEN_ROOT"] = str(ROOT)
    if env:
        full_env.update(env)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=full_env)
    assert proc.returncode == 0, (
        f"{check} analyze exited {proc.returncode}\nstderr:\n{proc.stderr}")
    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            findings.append(json.loads(line))
    return findings


def severities(findings):
    return [f["severity"] for f in findings]


def fatal_findings(findings):
    return [f for f in findings if f.get("fatal_candidate") is True]


@pytest.fixture
def keypair(tmp_path):
    """A throwaway Ed25519 keypair (PEM): returns (priv_path, pub_path)."""
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "onionwarden.pub"
    subprocess.run(["python3", str(ED25519), "keygen", str(priv), str(pub)],
                   check=True)
    return str(priv), str(pub)


def sign_file(priv, path):
    subprocess.run(["python3", str(ED25519), "sign", priv, path, path + ".sig"],
                   check=True)


@pytest.fixture
def minimal_config():
    """A minimal valid host.conf body."""
    return 'host_id = "testhost"\nrole = "generic"\n'
