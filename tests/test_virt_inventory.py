"""Per-host virtualization inventory (`bin/onionwarden-virt-inventory`, §6).

OPERATOR_DECISIONS §6 inventoried relay-b only; this tool inventories any host.
It's a SELF-CONTAINED collector (sources nothing from lib/) so it can stream over
`ssh HOST 'bash -s'`. The detection commands are Linux-only, so — like every
other collector in this repo — the LIVE path runs only on a real host; here we
drive the verdict/JSON-assembly logic through the tool's --fixture-dir replay
mode, which is the security-relevant half.
"""
import json
import os
import subprocess

from conftest import ROOT, BASH

VIRT = ROOT / "bin" / "onionwarden-virt-inventory"


def _fixture(tmp_path, files):
    d = tmp_path / "fix"
    d.mkdir()
    for name, content in files.items():
        (d / name).write_text(content)
    return d


def _run(host, fixture_dir=None, env=None, stdin_stream=False):
    args = [BASH, str(VIRT), "--host", host]
    if fixture_dir is not None:
        args += ["--fixture-dir", str(fixture_dir)]
    full_env = {**os.environ}
    if env:
        full_env.update(env)
    r = subprocess.run(args, capture_output=True, text=True, env=full_env)
    return r


def _json(host, fixture_dir=None, env=None):
    r = _run(host, fixture_dir, env)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _mock_detect_virt(tmp_path, script):
    mockbin = tmp_path / "mockbin"
    mockbin.mkdir()
    detect_virt = mockbin / "systemd-detect-virt"
    detect_virt.write_text(script)
    detect_virt.chmod(0o755)
    return mockbin


# --- verdicts --------------------------------------------------------------

def test_kvm_vm_verdict(tmp_path):
    fix = _fixture(tmp_path, {
        "detect_virt": "kvm", "detect_virt_container": "none",
        "detect_virt_vm": "kvm",
        "dmi_sys_vendor": "QEMU", "dmi_product_name": "Standard PC (Q35)",
        "dmi_bios_version": "1.16.0", "dmi_system_manufacturer": "QEMU",
        "cgroup_version": "v2", "proc_1_cgroup": "0::/",
        "ns_types": "cgroup ipc mnt net pid user uts ", "userns_active": "false",
    })
    d = _json("relay-kvm", fix)
    assert d["verdict"] == "vm"
    assert "kvm" in d["verdict_basis"]
    assert d["dmi"]["sys_vendor"] == "QEMU"
    assert d["cgroup"]["version"] == "v2"
    assert "user" in d["namespaces"]["types"]
    assert d["degraded"] == []  # fixture mode degrades nothing


def test_lxc_container_verdict(tmp_path):
    fix = _fixture(tmp_path, {
        "detect_virt": "lxc", "detect_virt_container": "lxc",
        "detect_virt_vm": "none", "userns_active": "true",
    })
    d = _json("ct1", fix)
    assert d["verdict"] == "container"
    assert "lxc" in d["verdict_basis"]
    assert d["namespaces"]["userns_active"] == "true"


def test_bare_metal_verdict(tmp_path):
    fix = _fixture(tmp_path, {
        "detect_virt": "none", "detect_virt_container": "none",
        "detect_virt_vm": "none",
        "dmi_sys_vendor": "Dell Inc.", "dmi_product_name": "PowerEdge R640",
        "dmi_bios_version": "2.10.2", "dmi_system_manufacturer": "Dell Inc.",
    })
    d = _json("bm1", fix)
    assert d["verdict"] == "bare-metal"


def test_dmi_vendor_infers_vm_when_detect_virt_says_none(tmp_path):
    """Some clouds report systemd-detect-virt=none but a telltale DMI vendor —
    the DMI fallback must still classify it a VM, not bare-metal."""
    fix = _fixture(tmp_path, {
        "detect_virt": "none", "detect_virt_container": "none",
        "detect_virt_vm": "none",
        "dmi_sys_vendor": "Amazon EC2", "dmi_product_name": "m5.large",
        "dmi_bios_version": "1.0", "dmi_system_manufacturer": "Amazon EC2",
    })
    d = _json("cloud1", fix)
    assert d["verdict"] == "vm"
    assert "dmi-vendor" in d["verdict_basis"]


def test_unknown_when_nothing_detectable(tmp_path):
    fix = _fixture(tmp_path, {
        "detect_virt": "unknown", "detect_virt_container": "unknown",
        "detect_virt_vm": "unknown",
    })
    d = _json("mystery", fix)
    assert d["verdict"] == "unknown"


def test_live_detect_virt_none_stdout_is_not_duplicated(tmp_path):
    """systemd-detect-virt prints 'none' but exits 1 on non-virtualized probes.
    The live path must capture that stdout once, not append a fallback 'none'."""
    mockbin = _mock_detect_virt(tmp_path, """#!/usr/bin/env bash
printf 'none\\n'
exit 1
""")
    dmi = _fixture(tmp_path, {
        "sys_vendor": "Dell Inc.",
        "product_name": "PowerEdge R640",
        "bios_version": "2.10.2",
    })

    d = _json("bm-live", env={
        "PATH": f"{mockbin}:{os.environ['PATH']}",
        "ONIONWARDEN_DMI_DIR": str(dmi),
        "ONIONWARDEN_PROC": str(tmp_path / "noproc"),
    })

    assert d["systemd_detect_virt"] == {
        "overall": "none",
        "container": "none",
        "vm": "none",
    }
    assert d["verdict"] == "bare-metal"


def test_live_vm_not_masked_by_container_none_probe(tmp_path):
    mockbin = _mock_detect_virt(tmp_path, """#!/usr/bin/env bash
case "${1:-}" in
  --container) printf 'none\\n'; exit 1 ;;
  --vm) printf 'kvm\\n'; exit 0 ;;
  *) printf 'kvm\\n'; exit 0 ;;
esac
""")
    dmi = _fixture(tmp_path, {
        "sys_vendor": "Dell Inc.",
        "product_name": "PowerEdge R640",
        "bios_version": "2.10.2",
    })

    d = _json("vm-live", env={
        "PATH": f"{mockbin}:{os.environ['PATH']}",
        "ONIONWARDEN_DMI_DIR": str(dmi),
        "ONIONWARDEN_PROC": str(tmp_path / "noproc"),
    })

    assert d["systemd_detect_virt"]["container"] == "none"
    assert d["systemd_detect_virt"]["vm"] == "kvm"
    assert d["verdict"] == "vm"


# --- JSON contract ---------------------------------------------------------

def test_schema_and_required_fields(tmp_path):
    fix = _fixture(tmp_path, {"detect_virt": "none",
                              "detect_virt_container": "none",
                              "detect_virt_vm": "none",
                              "dmi_sys_vendor": "QEMU"})
    d = _json("h", fix)
    assert d["schema"] == "onionwarden-virt-inventory-v1"
    for k in ("host_id", "collected_at", "verdict", "verdict_basis",
              "systemd_detect_virt", "dmi", "cgroup", "namespaces", "degraded"):
        assert k in d, k
    assert d["host_id"] == "h"
    assert set(d["systemd_detect_virt"]) == {"overall", "container", "vm"}
    assert set(d["dmi"]) == {"sys_vendor", "product_name", "bios_version",
                             "system_manufacturer"}


def test_collected_at_is_pinnable(tmp_path):
    fix = _fixture(tmp_path, {"detect_virt": "none",
                              "detect_virt_container": "none",
                              "detect_virt_vm": "none"})
    d = _json("h", fix, env={"ONIONWARDEN_NOW": "2026-05-29T00:00:00Z"})
    assert d["collected_at"] == "2026-05-29T00:00:00Z"


def test_no_serial_or_uuid_fields(tmp_path):
    """No PII: the inventory must not collect serials/UUIDs, only vendor/product/
    BIOS-version strings."""
    fix = _fixture(tmp_path, {"detect_virt": "kvm",
                              "detect_virt_container": "none",
                              "detect_virt_vm": "kvm"})
    text = _run("h", fix).stdout.lower()
    assert "serial" not in text
    assert "uuid" not in text
    assert "product_serial" not in text


def test_values_are_json_escaped(tmp_path):
    """A DMI string with a quote/backslash must not break the JSON."""
    fix = _fixture(tmp_path, {
        "detect_virt": "none", "detect_virt_container": "none",
        "detect_virt_vm": "none",
        "dmi_product_name": 'Weird "Quoted" \\ Model',
    })
    d = _json("h", fix)  # would raise if JSON were malformed
    assert d["dmi"]["product_name"] == 'Weird "Quoted" \\ Model'


# --- streaming + degraded --------------------------------------------------

def test_streams_over_bash_s_without_unbound_error(tmp_path):
    """The canonical fleet invocation is `ssh HOST 'bash -s' < this`. Under bash 5
    with -u that would trip BASH_SOURCE[0] if the script enabled -u; assert it
    runs clean (same regression class as test_snapshot_bundle)."""
    src = VIRT.read_text()
    p = subprocess.run([BASH, "-us", "--", "--host", "streamed"],
                       input=src, capture_output=True, text=True)
    assert "unbound variable" not in p.stderr, p.stderr
    d = json.loads(p.stdout)
    assert d["host_id"] == "streamed"


def test_live_mode_records_degraded_probes(tmp_path):
    """On the macOS build host none of the Linux probes exist, so a LIVE run
    (no --fixture-dir) must list them under degraded — and still emit valid JSON
    with verdict 'unknown'. This is the detect-and-degrade contract."""
    d = _json("livehost", fixture_dir=None,
              env={"ONIONWARDEN_DMI_DIR": str(tmp_path / "nope"),
                   "ONIONWARDEN_PROC": str(tmp_path / "noproc")})
    # at least the dmi-sysfs degradation should be present on a host w/o sysfs
    assert any("dmi sysfs" in x or "dmidecode" in x or "systemd-detect-virt" in x
               for x in d["degraded"])
