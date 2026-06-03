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
                "".join(line + "\n" for line in lines))
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
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    r = _run(fleet)
    assert r.returncode == 0
    assert "No hosts found" in r.stdout
    doc, _ = _json(fleet)
    assert doc["host_count"] == 0 and doc["roles"] == []


def test_empty_fleet_reserved_dirs_ignored(tmp_path):
    """A live receiver tree has dotfiles and _-reserved dirs; they are not hosts."""
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    (fleet / "_unknown").mkdir()
    (fleet / ".git").mkdir()
    doc, _ = _json(fleet)
    assert doc["host_count"] == 0


# --- single-host fleet -----------------------------------------------------

def test_single_host_inventory_only(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
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
    fleet = tmp_path / "fleet"
    fleet.mkdir()
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
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _diverged_fleet(fleet)
    doc, _ = _json(fleet)
    role = next(r for r in doc["roles"] if r["role"] == "tor-relay")
    ports = role["indicators"]["ports"]["divergences"]
    assert [p["line"] for p in ports] == ["listen tcp 0.0.0.0:31337"]


def test_identical_hosts_have_no_divergence(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    for h in ("relay-a", "relay-b"):
        _host(fleet, h, states={"ssh": ["sshd permitrootlogin no"]})
    doc, _ = _json(fleet, "--indicators", "ssh")
    assert doc["divergence_total"] == 0


def test_roles_are_compared_independently(tmp_path):
    """An eval-host listening on a port no relay has is NOT a relay divergence —
    role grouping is the whole point (a relay and an eval-host SHOULD differ)."""
    fleet = tmp_path / "fleet"
    fleet.mkdir()
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
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _diverged_fleet(fleet)
    r = _run(fleet, "--fail-on-divergence")
    assert r.returncode == 4
    # without the flag, a divergence is reported but not an error
    assert _run(fleet).returncode == 0


def test_roles_map_overrides_role_file(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "h1", role="generic", states={"ssh": ["sshd x 1"]})
    _host(fleet, "h2", role="generic", states={"ssh": ["sshd x 2"]})
    rmap = tmp_path / "roles.map"
    rmap.write_text("h1 tor-relay\nh2 tor-relay\n")
    doc, _ = _json(fleet, "--indicators", "ssh", "--roles-map", str(rmap))
    roles = {r["role"] for r in doc["roles"]}
    assert roles == {"tor-relay"}  # roles-map wins over per-host role file


def test_unusable_roles_map_fails_fast(tmp_path):
    """A --roles-map that is missing, symlinked, or unreadable must abort with a
    clear error rather than silently falling back to per-host metadata (which
    would change the role inventory with no signal)."""
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "h1", role="generic", states={"ssh": ["sshd x 1"]})

    # missing
    r = _run(fleet, "--indicators", "ssh", "--roles-map",
             str(tmp_path / "nope.map"))
    assert r.returncode != 0 and "roles-map does not exist" in r.stderr

    # symlink
    secret = tmp_path / "secret.map"
    secret.write_text("h1 SECRETROLE\n")
    link = tmp_path / "link.map"
    link.symlink_to(secret)
    r = _run(fleet, "--indicators", "ssh", "--roles-map", str(link))
    assert r.returncode != 0 and "must not be a symlink" in r.stderr
    assert "SECRETROLE" not in r.stdout


# --- missing-baseline error path -------------------------------------------

def test_missing_baseline_is_strict_error(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "good", states={"modules": ["module ext4 -"]})
    (fleet / "bad").mkdir()  # host dir with no state/ baseline at all
    r = _run(fleet)
    assert r.returncode == 3
    assert "bad" in r.stderr


def test_missing_baseline_no_strict_excludes_host(tmp_path):
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "good", states={"modules": ["module ext4 -"]})
    (fleet / "bad").mkdir()
    doc, rc = _json(fleet, "--no-strict", "--indicators", "modules")
    assert rc == 0
    assert doc["host_count"] == 1  # bad host dropped


def test_receiver_layout_baseline_subdir(tmp_path):
    """Receiver stores baselines at <host>/baseline/state/ — fleet-diff must
    transparently resolve that nesting (RECEIVER.md / PLAN §5)."""
    fleet = tmp_path / "fleet"
    fleet.mkdir()
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
    fleet = tmp_path / "fleet"
    fleet.mkdir()
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
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _signed_host(fleet, "relay-a", {"modules": ["module ext4 -"]}, priv)
    hd = _signed_host(fleet, "relay-b", {"modules": ["module ext4 -"]}, priv)
    # tamper a state file AFTER signing — manifest hash no longer matches
    (hd / "state" / "modules.state").write_text("module BACKDOOR -\n")
    r = _run(fleet, "--pubkey", pub, "--indicators", "modules")
    assert r.returncode == 3  # strict: an unverifiable baseline is an error
    assert "relay-b" in r.stderr


def test_symlinked_state_file_is_not_followed(tmp_path):
    """Security: a malicious fleet/receiver tree must not exfiltrate
    operator-local files. A state file symlinked at an out-of-tree secret is
    skipped, not read into the report."""
    secret = tmp_path / "secret.txt"
    secret.write_text("listen tcp 0.0.0.0:31337 SECRETLEAK\n")
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "relay-a", states={"ports": ["listen tcp 0.0.0.0:9001"]})
    # relay-b: same role, but its ports.state is a symlink to the secret.
    hb = _host(fleet, "relay-b", states={})
    (hb / "state" / "ports.state").symlink_to(secret)
    r = _run(fleet, "--indicators", "ports")
    assert "SECRETLEAK" not in r.stdout
    assert "SECRETLEAK" not in r.stderr
    # relay-b's only *.state is a symlink, so it has no *real* state file and is
    # treated as a broken baseline — strict mode (default) refuses to report.
    assert r.returncode == 3
    assert "relay-b" in r.stderr
    # With --no-strict the broken host is dropped and the rest is reported; the
    # symlinked secret never reaches the JSON.
    doc, _ = _json(fleet, "--no-strict", "--indicators", "ports")
    role = next(x for x in doc["roles"] if x["role"] == "tor-relay")
    lines = [d["line"] for d in role["indicators"]["ports"]["divergences"]]
    assert all("SECRETLEAK" not in ln for ln in lines)


def test_symlinked_host_root_is_not_followed(tmp_path):
    """The <host> directory itself being a symlink is refused, so a tree cannot
    redirect a whole host root at an out-of-tree directory holding real state."""
    secret_host = tmp_path / "outside_host"
    (secret_host / "state").mkdir(parents=True)
    (secret_host / "state" / "ports.state").write_text(
        "listen tcp 0.0.0.0:31337 SECRETLEAK\n")
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "relay-a", states={"ports": ["listen tcp 0.0.0.0:9001"]})
    # relay-b is a symlink to a directory that contains a perfectly real state/.
    (fleet / "relay-b").symlink_to(secret_host, target_is_directory=True)
    # A symlinked host root is treated as a missing baseline (rejected), so its
    # contents never reach the report. --no-strict so we still get JSON to assert.
    r = _run(fleet, "--indicators", "ports")
    assert "SECRETLEAK" not in r.stdout
    assert "SECRETLEAK" not in r.stderr
    doc, _ = _json(fleet, "--no-strict", "--indicators", "ports")
    role = next(x for x in doc["roles"] if x["role"] == "tor-relay")
    lines = [d["line"] for d in role["indicators"]["ports"]["divergences"]]
    assert all("SECRETLEAK" not in ln for ln in lines)


def test_symlinked_role_file_is_not_followed(tmp_path):
    """A symlinked `role` metadata file must not leak an operator-local file's
    contents into the report as a role name (parity with state-file handling)."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRETROLELEAK\n")
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "relay-a", states={"ports": ["listen tcp 0.0.0.0:9001"]})
    # relay-b: role file points at an out-of-tree secret.
    hb = _host(fleet, "relay-b", role=None,
               states={"ports": ["listen tcp 0.0.0.0:9001"]})
    (hb / "role").symlink_to(secret)
    r = _run(fleet, "--indicators", "ports")
    assert "SECRETROLELEAK" not in r.stdout
    assert "SECRETROLELEAK" not in r.stderr
    doc, _ = _json(fleet, "--indicators", "ports")
    assert all(x["role"] != "SECRETROLELEAK" for x in doc["roles"])


def test_symlinked_state_dir_is_not_followed(tmp_path):
    """The 'state' parent dir being a symlink is likewise refused, so a tree
    cannot redirect a whole host's state at an operator-local directory."""
    secret_dir = tmp_path / "outside"
    secret_dir.mkdir()
    (secret_dir / "ports.state").write_text(
        "listen tcp 0.0.0.0:31337 SECRETLEAK\n")
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    _host(fleet, "relay-a", states={"ports": ["listen tcp 0.0.0.0:9001"]})
    hb = fleet / "relay-b"
    hb.mkdir(parents=True)
    (hb / "role").write_text("tor-relay\n")
    (hb / "state").symlink_to(secret_dir, target_is_directory=True)
    r = _run(fleet, "--indicators", "ports")
    assert "SECRETLEAK" not in r.stdout
    assert "SECRETLEAK" not in r.stderr
