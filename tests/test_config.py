"""host.conf + role-profile parsing (lib/config.sh)."""
import os
import subprocess
import tempfile

from conftest import ROOT, BASH


def cfg(conf_text, snippet):
    """Source config.sh, cfg_load conf_text, run snippet; return stdout."""
    tmp = tempfile.mkdtemp(prefix="onionwarden-cfg-")
    conf = os.path.join(tmp, "host.conf")
    open(conf, "w").write(conf_text)
    script = (
        f'. "{ROOT}/lib/config.sh"; '
        f'cfg_load "{conf}" "{ROOT}/roles"; {snippet}'
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_scalar_quoted():
    assert cfg('host_id = "eval-host"\nrole="generic"\n', 'cfg_get host_id') == "eval-host"


def test_scalar_bare_with_comment():
    assert cfg('role="generic"\ncanary = false  # Q1\n', 'cfg_get canary') == "false"


def test_array_parsing():
    out = cfg('role="generic"\nexpected_lan_ports = [22, 3000, 18789]\n',
              'cfg_list expected_lan_ports | tr "\\n" ","')
    assert out == "22,3000,18789,"


def test_empty_array_ok():
    # An empty [] must not error under set -u (bash 3.2 empty-array trap).
    out = cfg('role="generic"\ndisable_checks = []\n',
              'cfg_list disable_checks | wc -l | tr -d " "')
    assert out == "0"


def test_list_has():
    conf = 'role="generic"\nexpected_admins = ["operator", "ops"]\n'
    assert cfg(conf, 'cfg_list_has expected_admins operator && echo Y || echo N') == "Y"
    assert cfg(conf, 'cfg_list_has expected_admins mallory && echo Y || echo N') == "N"


def test_bool():
    assert cfg('role="generic"\nx = true\n', 'cfg_bool x && echo Y || echo N') == "Y"
    assert cfg('role="generic"\nx = false\n', 'cfg_bool x && echo Y || echo N') == "N"
    # A typo fails safe to false.
    assert cfg('role="generic"\nx = ture\n', 'cfg_bool x && echo Y || echo N') == "N"


def test_role_profile_loaded_then_overridden():
    # tor-relay role sets outbound_mode=exclude-process; host.conf can override.
    assert cfg('role = "tor-relay"\n', 'cfg_get outbound_mode') == "exclude-process"
    assert cfg('role = "tor-relay"\noutbound_mode = "allowlist"\n',
               'cfg_get outbound_mode') == "allowlist"


def test_host_array_replaces_role_array():
    # A host.conf array fully replaces the role-profile array of the same key.
    out = cfg('role = "tor-relay"\nextra_integrity_paths = ["/only/this"]\n',
              'cfg_list extra_integrity_paths | tr "\\n" ","')
    assert out == "/only/this,"


def test_default_when_unset():
    assert cfg('role="generic"\n', 'cfg_get nonesuch DEFLT') == "DEFLT"
