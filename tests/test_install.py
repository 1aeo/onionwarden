"""install.sh — verifies it lays a correct, installable tree into a scratch
prefix WITHOUT touching the real system (no systemd, no chattr, no real host)."""
import hashlib
import os
import subprocess

from conftest import ROOT, ED25519, BASH


def test_install_into_scratch_tree(tmp_path):
    pub = tmp_path / "onionwarden.pub"
    priv = tmp_path / "priv.pem"
    subprocess.run(["python3", str(ED25519), "keygen", str(priv), str(pub)],
                   check=True)
    prefix = tmp_path / "opt" / "onionwarden"
    confdir = tmp_path / "etc" / "onionwarden"
    var = tmp_path / "var" / "lib" / "onionwarden"
    log = tmp_path / "var" / "log" / "onionwarden"
    sysd = tmp_path / "etc" / "systemd"

    r = subprocess.run(
        [BASH, str(ROOT / "install.sh"),
         "--answers", str(ROOT / "examples" / "answers-canary.example"),
         "--pubkey", str(pub),
         "--prefix", str(prefix), "--conf-dir", str(confdir),
         "--var-dir", str(var), "--log-dir", str(log),
         "--systemd-dir", str(sysd),
         "--no-systemd", "--no-immutable"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

    # code tree laid down
    assert (prefix / "bin" / "onionwarden-run").exists()
    assert (prefix / "lib" / "checks" / "taint.sh").exists()
    assert (prefix / "roles" / "tor-relay.conf").exists()
    assert (prefix / "onionwarden.pub").exists()

    # host.conf generated from the answers file
    host_conf = (confdir / "host.conf").read_text()
    assert 'host_id            = "relay_a"' in host_conf

    # C2: the pubkey-hash pin is embedded into the installed verify.sh
    want = hashlib.sha256(pub.read_bytes()).hexdigest()
    verify = (prefix / "lib" / "verify.sh").read_text()
    assert f'ONIONWARDEN_PUBKEY_SHA256_PIN="{want}"' in verify
    assert "@PUBKEY_SHA256@" not in verify

    # M2: the host is left in the bootstrapping state
    assert (var / "state" / "bootstrapping").exists()

    # systemd units staged
    assert (sysd / "onionwarden-fast.timer").exists()


def test_install_requires_answers_and_pubkey(tmp_path):
    r = subprocess.run([BASH, str(ROOT / "install.sh")],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "answers" in r.stderr


def test_install_dry_run_changes_nothing(tmp_path):
    pub = tmp_path / "onionwarden.pub"
    priv = tmp_path / "priv.pem"
    subprocess.run(["python3", str(ED25519), "keygen", str(priv), str(pub)],
                   check=True)
    prefix = tmp_path / "opt" / "onionwarden"
    r = subprocess.run(
        [BASH, str(ROOT / "install.sh"),
         "--answers", str(ROOT / "examples" / "answers-evalhost.example"),
         "--pubkey", str(pub), "--prefix", str(prefix),
         "--conf-dir", str(tmp_path / "etc"),
         "--var-dir", str(tmp_path / "var"),
         "--log-dir", str(tmp_path / "log"),
         "--no-systemd", "--no-immutable", "--dry-run"],
        capture_output=True, text=True)
    assert r.returncode == 0
    assert not prefix.exists()  # dry-run created nothing
