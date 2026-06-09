"""Cross-fleet baseline diff (`bin/onionwarden-fleet-diff`, PLAN §6 Phase 3).

fleet-diff is an OPERATOR-SIDE tool: it reads each host's per-host baseline
(`state/<check>.state`), set-diffs the key integrity indicators across hosts,
groups by role, and surfaces within-role divergences. These tests drive it from
fixture baseline trees — no Linux, no real fleet — and assert on the structured
(JSON) report and the exit-code contract.
"""
import json
import os
import subprocess

import pytest

from conftest import ROOT, BASH, sign_file

FLEET_DIFF = ROOT / "bin" / "onionwarden-fleet-diff"


def _host(fleet, name, role="tor-relay", states=None, *, make_state=True):
    """Lay a host baseline dir under `fleet`. `states` maps check->list-of-lines."""
    hd = fleet / name
    if role is not None:
        hd.mkdir(parents=True, exist_ok=True)
        (hd / "role").write_text(role + "\n")
    if make_state:
        sd = hd / "state"
        sd.mkdir(parents=True, exist_ok=True)
        for check, lines in (states or {}).items():
            (sd / f"{check}.state").write_text(
                "".join(l + "\n" for l in lines))
    return hd


def _run(fleet, *args):
    cmd = [BASH, str(FLEET_DIFF), "--fleet-dir", str(fleet), *args]
    return subprocess.run(cmd, capture_output=True, text=True,
                          env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})


def _json(fleet, *args):
    r = _run(fleet, "--format", "json", *args)
    assert r.returncode in (0, 4), f"unexpected rc {r.returncode}\n{r.stderr}"
    return json.loads(r.stdout), r.returncode


# --- empty fleet -----------------------------------------------------------

def test_empty_fleet_succeeds(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    r = _run(fleet)
    assert r.returncode == 0
    assert "No hosts found" in r.stdout
    doc, _ = _json(fleet)
    assert doc["host_count"] == 0 and doc["roles"] == []


def test_empty_fleet_reserved_dirs_ignored(tmp_path):
    """A live receiver tree has dotfiles and _-reserved dirs; they are not hosts."""
    fleet = tmp_path / "fleet"; fleet.mkdir()
    (fleet / "_unknown").mkdir()
    (fleet / ".git").mkdir()
    doc, _ = _json(fleet)
    assert doc["host_count"] == 0


# --- single-host fleet -----------------------------------------------------

def test_single_host_inventory_only(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _host(fleet, "solo", states={"modules": ["module ext4 -", "module tcp_bbr -"]})
    r = _run(fleet, "--indicators", "modules")
    assert r.returncode == 0
    assert "Single host in this role" in r.stdout
    assert "inventory: 2 line(s)" in r.stdout
    doc, _ = _json(fleet, "--indicators", "modules")
    # A single-host role can have no within-role divergence by definition.
    assert doc["divergence_total"] == 0
    role = doc["roles"][0]
    assert role["host_count"] == 1
    assert role["indicators"]["modules"]["divergences"] == []


# --- diverged-hosts fleet --------------------------------------------------

def _diverged_fleet(fleet):
    common = {
        "modules": ["module ext4 -", "module tcp_bbr -"],
        "ssh": ["sshd permitrootlogin no", "sshd passwordauthentication no"],
        "ports": ["listen tcp 0.0.0.0:22", "listen tcp 0.0.0.0:9001"],
        "suid": ["suid /usr/bin/sudo deadbeef"],
        "taint": [],
    }
    for h in ("relay-a", "relay-b", "relay-c"):
        _host(fleet, h, states={k: list(v) for k, v in common.items()})
    # relay-c: a module the others lack + a rogue listener
    (fleet / "relay-c" / "state" / "modules.state").write_text(
        "module ext4 -\nmodule tcp_bbr -\nmodule nfsd PE\n")
    (fleet / "relay-c" / "state" / "ports.state").write_text(
        "listen tcp 0.0.0.0:22\nlisten tcp 0.0.0.0:9001\nlisten tcp 0.0.0.0:31337\n")


def test_diverged_fleet_flags_minority_module(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _diverged_fleet(fleet)
    doc, rc = _json(fleet)
    assert rc == 0
    role = next(r for r in doc["roles"] if r["role"] == "tor-relay")
    mod = role["indicators"]["modules"]["divergences"]
    assert len(mod) == 1
    d = mod[0]
    assert d["line"] == "module nfsd PE"
    assert d["present"] == "relay-c"
    assert set(d["absent"].split()) == {"relay-a", "relay-b"}
    assert d["present_count"] == 1


def test_diverged_fleet_flags_rogue_listener(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _diverged_fleet(fleet)
    doc, _ = _json(fleet)
    role = next(r for r in doc["roles"] if r["role"] == "tor-relay")
    ports = role["indicators"]["ports"]["divergences"]
    assert [p["line"] for p in ports] == ["listen tcp 0.0.0.0:31337"]


def test_identical_hosts_have_no_divergence(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    for h in ("relay-a", "relay-b"):
        _host(fleet, h, states={"ssh": ["sshd permitrootlogin no"]})
    doc, _ = _json(fleet, "--indicators", "ssh")
    assert doc["divergence_total"] == 0


def test_roles_are_compared_independently(tmp_path):
    """An eval-host listening on a port no relay has is NOT a relay divergence —
    role grouping is the whole point (a relay and an eval-host SHOULD differ)."""
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _host(fleet, "relay-a", role="tor-relay",
          states={"ports": ["listen tcp 0.0.0.0:9001"]})
    _host(fleet, "relay-b", role="tor-relay",
          states={"ports": ["listen tcp 0.0.0.0:9001"]})
    _host(fleet, "evalbox", role="eval-host",
          states={"ports": ["listen tcp 0.0.0.0:8080"]})
    doc, _ = _json(fleet, "--indicators", "ports")
    # No within-role divergence: both relays match; eval-host is alone in its role.
    assert doc["divergence_total"] == 0


def test_fail_on_divergence_exit_code(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _diverged_fleet(fleet)
    r = _run(fleet, "--fail-on-divergence")
    assert r.returncode == 4
    # without the flag, a divergence is reported but not an error
    assert _run(fleet).returncode == 0


def test_roles_map_overrides_role_file(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _host(fleet, "h1", role="generic", states={"ssh": ["sshd x 1"]})
    _host(fleet, "h2", role="generic", states={"ssh": ["sshd x 2"]})
    rmap = tmp_path / "roles.map"
    rmap.write_text("h1 tor-relay\nh2 tor-relay\n")
    doc, _ = _json(fleet, "--indicators", "ssh", "--roles-map", str(rmap))
    roles = {r["role"] for r in doc["roles"]}
    assert roles == {"tor-relay"}  # roles-map wins over per-host role file


# --- missing-baseline error path -------------------------------------------

def test_missing_baseline_is_strict_error(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _host(fleet, "good", states={"modules": ["module ext4 -"]})
    (fleet / "bad").mkdir()  # host dir with no state/ baseline at all
    r = _run(fleet)
    assert r.returncode == 3
    assert "bad" in r.stderr


def test_missing_baseline_no_strict_excludes_host(tmp_path):
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _host(fleet, "good", states={"modules": ["module ext4 -"]})
    (fleet / "bad").mkdir()
    doc, rc = _json(fleet, "--no-strict", "--indicators", "modules")
    assert rc == 0
    assert doc["host_count"] == 1  # bad host dropped


def test_receiver_layout_baseline_subdir(tmp_path):
    """Receiver stores baselines at <host>/baseline/state/ — fleet-diff must
    transparently resolve that nesting (RECEIVER.md / PLAN §5)."""
    fleet = tmp_path / "fleet"; fleet.mkdir()
    hd = fleet / "relay-a"
    (hd / "baseline" / "state").mkdir(parents=True)
    (hd / "role").write_text("tor-relay\n")
    (hd / "baseline" / "state" / "modules.state").write_text("module ext4 -\n")
    hd2 = fleet / "relay-b"
    (hd2 / "baseline" / "state").mkdir(parents=True)
    (hd2 / "role").write_text("tor-relay\n")
    (hd2 / "baseline" / "state" / "modules.state").write_text(
        "module ext4 -\nmodule weird -\n")
    doc, _ = _json(fleet, "--indicators", "modules")
    role = doc["roles"][0]
    divs = role["indicators"]["modules"]["divergences"]
    assert [d["line"] for d in divs] == ["module weird -"]


# --- signature verification (--pubkey) integration -------------------------

def _signed_host(fleet, name, states, priv):
    """Build a signed baseline (manifest.json + .sig) the way onionwarden-baseline
    + onionwarden-sign would, so the --pubkey path exercises baseline_verify."""
    hd = _host(fleet, name, states=states)
    # build manifest.json via lib/baseline.sh:baseline_write_manifest
    script = (
        f'. "{ROOT}/lib/common.sh"; . "{ROOT}/lib/baseline.sh"; '
        f'baseline_write_manifest "{hd}" "{name}"')
    subprocess.run([BASH, "-c", script], check=True,
                   env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)},
                   capture_output=True, text=True)
    sign_file(priv, str(hd / "manifest.json"))
    return hd


def test_pubkey_verified_fleet_diffs_clean(tmp_path, keypair):
    priv, pub = keypair
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _signed_host(fleet, "relay-a", {"modules": ["module ext4 -"]}, priv)
    _signed_host(fleet, "relay-b",
                 {"modules": ["module ext4 -", "module rogue -"]}, priv)
    r = _run(fleet, "--pubkey", pub, "--indicators", "modules",
             "--format", "json")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["verified"] is True
    # both baselines verified independently — no false rollback across hosts
    assert doc["host_count"] == 2
    role = doc["roles"][0]
    assert [d["line"] for d in role["indicators"]["modules"]["divergences"]] \
        == ["module rogue -"]


def test_pubkey_rejects_tampered_state(tmp_path, keypair):
    priv, pub = keypair
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _signed_host(fleet, "relay-a", {"modules": ["module ext4 -"]}, priv)
    hd = _signed_host(fleet, "relay-b", {"modules": ["module ext4 -"]}, priv)
    # tamper a state file AFTER signing — manifest hash no longer matches
    (hd / "state" / "modules.state").write_text("module BACKDOOR -\n")
    r = _run(fleet, "--pubkey", pub, "--indicators", "modules")
    assert r.returncode == 3  # strict: an unverifiable baseline is an error
    assert "relay-b" in r.stderr


def test_pubkey_ignores_unsigned_role_file_that_would_hide_divergence(tmp_path, keypair):
    priv, pub = keypair
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _signed_host(fleet, "relay-a", {"modules": ["module ext4 -"]}, priv)
    hd = _signed_host(fleet, "relay-b",
                      {"modules": ["module ext4 -", "module rogue -"]}, priv)
    # This file is outside the signed baseline. In verified mode it must not be
    # able to move relay-b into a singleton role and suppress the rogue module.
    (hd / "role").write_text("singleton\n")

    r = _run(fleet, "--pubkey", pub, "--indicators", "modules",
             "--fail-on-divergence", "--format", "json")
    assert r.returncode == 4, r.stderr
    doc = json.loads(r.stdout)
    role = next(r for r in doc["roles"] if r["role"] == "unknown")
    assert [d["line"] for d in role["indicators"]["modules"]["divergences"]] \
        == ["module rogue -"]


def test_pubkey_reads_verified_copy_not_mutated_original(tmp_path, keypair):
    priv, pub = keypair
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _signed_host(fleet, "relay-a", {"modules": ["module ext4 -"]}, priv)
    hd = _signed_host(fleet, "relay-b",
                      {"modules": ["module ext4 -", "module rogue -"]}, priv)

    fakebin = tmp_path / "fakebin"; fakebin.mkdir()
    wrapper = fakebin / "sha256sum"
    wrapper.write_text("""#!/usr/bin/env python3
import hashlib
import os
import pathlib
import sys

for name in sys.argv[1:]:
    data = pathlib.Path(name).read_bytes()
    print(f"{hashlib.sha256(data).hexdigest()}  {name}")
    parts = pathlib.Path(name).parts
    if "relay-b" in parts and name.endswith("/state/modules.state"):
        pathlib.Path(os.environ["OW_MUTATE_AFTER_HASH"]).write_text("module ext4 -\\n")
""")
    wrapper.chmod(0o755)

    env_path = f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}"
    cmd = [BASH, str(FLEET_DIFF), "--fleet-dir", str(fleet), "--pubkey", pub,
           "--indicators", "modules", "--fail-on-divergence", "--format", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT),
                            "PATH": env_path,
                            "OW_MUTATE_AFTER_HASH": str(hd / "state" / "modules.state")})
    assert r.returncode == 4, r.stderr
    doc = json.loads(r.stdout)
    role = doc["roles"][0]
    assert [d["line"] for d in role["indicators"]["modules"]["divergences"]] \
        == ["module rogue -"]
    assert (hd / "state" / "modules.state").read_text() == "module ext4 -\n"


def test_pubkey_rejects_symlinked_state_to_prevent_post_verify_mutation(tmp_path, keypair):
    priv, pub = keypair
    fleet = tmp_path / "fleet"; fleet.mkdir()
    _signed_host(fleet, "relay-a", {"modules": ["module ext4 -"]}, priv)
    hd = _signed_host(fleet, "relay-b",
                      {"modules": ["module ext4 -", "module rogue -"]}, priv)

    mutable_target = tmp_path / "mutable_modules.state"
    mutable_target.write_text("module ext4 -\nmodule rogue -\n")
    (hd / "state" / "modules.state").unlink()
    os.symlink(mutable_target, hd / "state" / "modules.state")

    fakebin = tmp_path / "fakebin"; fakebin.mkdir()
    wrapper = fakebin / "sha256sum"
    wrapper.write_text("""#!/usr/bin/env python3
import hashlib
import os
import pathlib
import sys

for name in sys.argv[1:]:
    data = pathlib.Path(name).read_bytes()
    print(f"{hashlib.sha256(data).hexdigest()}  {name}")
    parts = pathlib.Path(name).parts
    if "relay-b" in parts and name.endswith("/state/modules.state"):
        pathlib.Path(os.environ["OW_SYMLINK_TARGET"]).write_text("module ext4 -\\n")
""")
    wrapper.chmod(0o755)

    env_path = f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}"
    cmd = [BASH, str(FLEET_DIFF), "--fleet-dir", str(fleet), "--pubkey", pub,
           "--indicators", "modules", "--fail-on-divergence", "--format", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT),
                            "PATH": env_path,
                            "OW_SYMLINK_TARGET": str(mutable_target)})
    assert r.returncode == 3
    assert "relay-b" in r.stderr
    assert "missing/unverified baseline" in r.stderr
    assert mutable_target.read_text() == "module ext4 -\nmodule rogue -\n"
