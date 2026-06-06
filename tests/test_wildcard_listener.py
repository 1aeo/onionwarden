"""Wildcard-listener check (`lib/checks/wildcard_listener.sh`).

Premise: nothing on these hosts should listen on a wildcard address
(0.0.0.0 / * / [::]); every wildcard bind is CRIT unless the operator has
explicitly allowlisted it in <comm>:<port>:<proto> form. Motivated by the BGP
audit, which found FRR bgpd on 0.0.0.0:179 across three hosts that onionwarden
did not flag (ports.sh's bind-IP expectation check is opt-in).

analyze() is a pure function of (current state, allowlist file). The allowlist
path is injected via $ONIONWARDEN_WILDCARD_ALLOW so these run on any OS.
"""
import os

from conftest import run_analyze

GENERIC = 'host_id="t"\nrole="generic"\n'

# collect() emits one line per wildcard listener:
#   wildcard <proto> <port> <comm> <pid> <user> <bind> <exe>
BGPD = "wildcard tcp 179 bgpd 1234 frr 0.0.0.0 /usr/lib/frr/bgpd"
BGPD6 = "wildcard tcp 179 bgpd 1234 frr [::] /usr/lib/frr/bgpd"
SSHD_TCP = "wildcard tcp 22 sshd 700 root 0.0.0.0 /usr/sbin/sshd"
SSHD_UDP = "wildcard udp 22 sshd 700 root 0.0.0.0 /usr/sbin/sshd"
NC = "wildcard tcp 4444 nc 5150 mallory 0.0.0.0 /usr/bin/nc"


def _run(current, allow_lines=None, allow_path=None, tmp_path=None):
    """Run analyze with an injected allowlist file (or a missing path)."""
    env = {}
    if allow_path is not None:                       # explicit (maybe missing) path
        env["ONIONWARDEN_WILDCARD_ALLOW"] = str(allow_path)
    elif allow_lines is not None:
        f = tmp_path / "wildcard-listener.allow"
        f.write_text("\n".join(allow_lines) + "\n")
        env["ONIONWARDEN_WILDCARD_ALLOW"] = str(f)
    else:                                            # no allowlist at all
        env["ONIONWARDEN_WILDCARD_ALLOW"] = str(
            (tmp_path or "/nonexistent") and (tmp_path / "missing.allow"))
    return run_analyze("wildcard_listener", [], current, GENERIC, env=env)


def _binds(findings):
    return [f for f in findings if f.get("signal") == "wildcard_bind"]


def test_wildcard_unallowlisted_is_crit(tmp_path):
    f = _binds(_run([BGPD], tmp_path=tmp_path))
    assert len(f) == 1
    assert f[0]["severity"] == "CRIT"
    assert "comm=bgpd" in f[0]["observed"] and "port=179" in f[0]["observed"]
    assert "user=frr" in f[0]["observed"] and "pid=1234" in f[0]["observed"]
    assert "exe=/usr/lib/frr/bgpd" in f[0]["observed"]
    assert "bind only a specific" in f[0]["summary"]   # remediation hint present


def test_allowlist_entry_suppresses(tmp_path):
    f = _binds(_run([BGPD], allow_lines=["bgpd:179:tcp"], tmp_path=tmp_path))
    assert f == []


def test_specific_ip_bind_no_finding(tmp_path):
    # A specific-IP bind is never a wildcard line; analyze re-checks and skips.
    specific = "wildcard tcp 179 bgpd 1234 frr 1.2.3.4 /usr/lib/frr/bgpd"
    assert _binds(_run([specific], tmp_path=tmp_path)) == []


def test_ipv6_wildcard_is_crit(tmp_path):
    f = _binds(_run([BGPD6], tmp_path=tmp_path))
    assert len(f) == 1 and f[0]["severity"] == "CRIT"
    assert "bind=[::]" in f[0]["observed"]


def test_missing_allowlist_flags_everything(tmp_path):
    # allowlist file absent -> nothing is permitted -> every wildcard fires.
    f = _binds(_run([BGPD, NC], allow_path=tmp_path / "does-not-exist.allow"))
    assert len(f) == 2
    assert all(x["severity"] == "CRIT" for x in f)


def test_malformed_allowlist_lines_ignored(tmp_path):
    # Comments / blanks / wrong-arity lines are skipped without aborting the
    # parse; the one valid entry still suppresses, and a junk line like
    # "garbage" must NOT accidentally allowlist an unrelated listener.
    allow = [
        "# SECURITY: bgpd peers reach us over the mgmt VRF only",
        "",
        "garbage",
        "a:b",            # 2 fields
        "a:b:c:d",        # 4 fields
        "bgpd:179:tcp",   # the one valid entry
    ]
    f = _binds(_run([BGPD, NC], allow_lines=allow, tmp_path=tmp_path))
    # bgpd suppressed by the valid entry; nc still CRIT (junk didn't allow it).
    assert len(f) == 1
    assert "comm=nc" in f[0]["observed"]


def test_proto_specificity(tmp_path):
    # allowlist grants sshd:22:tcp; the actual bind is UDP -> proto differs ->
    # still CRIT (all three fields must match).
    f = _binds(_run([SSHD_UDP], allow_lines=["sshd:22:tcp"], tmp_path=tmp_path))
    assert len(f) == 1 and f[0]["severity"] == "CRIT"
    # the tcp form with the same allowlist IS suppressed.
    assert _binds(_run([SSHD_TCP], allow_lines=["sshd:22:tcp"],
                       tmp_path=tmp_path)) == []


def test_each_offender_is_its_own_event(tmp_path):
    f = _binds(_run([BGPD, NC, SSHD_TCP], tmp_path=tmp_path))
    assert len(f) == 3
    comms = sorted(x["observed"].split("comm=")[1].split()[0] for x in f)
    assert comms == ["bgpd", "nc", "sshd"]


def test_inline_comment_on_allowlist_entry(tmp_path):
    # A SECURITY justification may sit inline after the entry.
    allow = ["bgpd:179:tcp   # SECURITY: reviewed 2026-06-06, mgmt VRF only"]
    assert _binds(_run([BGPD], allow_lines=allow, tmp_path=tmp_path)) == []
