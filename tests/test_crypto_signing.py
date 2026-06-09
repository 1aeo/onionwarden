"""Signing chain: ed25519, verify.sh, and the baseline trust chain."""
import os
import subprocess
import tempfile

from conftest import ROOT, ED25519, BASH, sign_file


def _verify_sh(pub, f, sig, backend="python"):
    """Call lib/verify.sh:onionwarden_verify_sig; return True/False."""
    script = (
        f'export ONIONWARDEN_VERIFY_BACKEND={backend}; '
        f'. "{ROOT}/lib/verify.sh"; '
        f'onionwarden_verify_sig "{pub}" "{f}" "{sig}" && echo OK || echo FAIL'
    )
    out = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                         env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    return out.stdout.strip() == "OK"


def test_ed25519_roundtrip(keypair):
    priv, pub = keypair
    tmp = tempfile.mkdtemp()
    msg = os.path.join(tmp, "m")
    open(msg, "w").write("onionwarden baseline manifest")
    sign_file(priv, msg)
    assert _verify_sh(pub, msg, msg + ".sig")


def test_verify_rejects_tampered_payload(keypair):
    priv, pub = keypair
    tmp = tempfile.mkdtemp()
    msg = os.path.join(tmp, "m")
    open(msg, "w").write("original")
    sign_file(priv, msg)
    open(msg, "w").write("tampered")          # change payload after signing
    assert not _verify_sh(pub, msg, msg + ".sig")


def test_verify_rejects_wrong_key(keypair, tmp_path):
    priv, pub = keypair
    other_priv = tmp_path / "other.pem"
    other_pub = tmp_path / "other.pub"
    subprocess.run(["python3", str(ED25519), "keygen",
                    str(other_priv), str(other_pub)], check=True)
    tmp = tempfile.mkdtemp()
    msg = os.path.join(tmp, "m")
    open(msg, "w").write("payload")
    sign_file(str(other_priv), msg)            # signed by a DIFFERENT key
    assert not _verify_sh(pub, msg, msg + ".sig")


def test_verify_rejects_corrupt_signature(keypair):
    priv, pub = keypair
    tmp = tempfile.mkdtemp()
    msg = os.path.join(tmp, "m")
    open(msg, "w").write("payload")
    sign_file(priv, msg)
    with open(msg + ".sig", "r+b") as fh:     # flip a byte of the signature
        fh.seek(0)
        b = fh.read(1)
        fh.seek(0)
        fh.write(bytes([b[0] ^ 0xFF]))
    assert not _verify_sh(pub, msg, msg + ".sig")


def test_baseline_verify_detects_tampered_state(keypair):
    """A state file edited after the manifest was signed must fail the chain."""
    priv, pub = keypair
    bdir = tempfile.mkdtemp()
    os.makedirs(os.path.join(bdir, "state"))
    sf = os.path.join(bdir, "state", "taint.state")
    open(sf, "w").write("tainted 0\n")
    # build + sign the manifest over the honest state
    subprocess.run(
        [BASH, "-c",
         f'. "{ROOT}/lib/baseline.sh"; baseline_write_manifest "{bdir}" testhost'],
        check=True, env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    sign_file(priv, os.path.join(bdir, "manifest.json"))

    def verify():
        out = subprocess.run(
            [BASH, "-c",
             f'export ONIONWARDEN_VERIFY_BACKEND=python; . "{ROOT}/lib/baseline.sh"; '
             f'baseline_verify "{bdir}" "{pub}" && echo OK || echo FAIL'],
            capture_output=True, text=True,
            env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
        return out.stdout.strip()

    assert verify() == "OK"
    open(sf, "w").write("tainted 4096\n")     # tamper the state file
    assert verify() == "FAIL"                  # signature covers its hash


def test_baseline_verify_rejects_symlinked_state_even_when_hash_matches(keypair, tmp_path):
    """Signed baselines must be self-contained regular files, not live links."""
    priv, pub = keypair
    bdir = tmp_path / "baseline"
    state_dir = bdir / "state"
    state_dir.mkdir(parents=True)
    target = tmp_path / "mutable_taint.state"
    target.write_text("tainted 0\n")
    os.symlink(target, state_dir / "taint.state")

    subprocess.run(
        [BASH, "-c",
         f'. "{ROOT}/lib/baseline.sh"; baseline_write_manifest "{bdir}" testhost'],
        check=True, env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    sign_file(priv, str(bdir / "manifest.json"))

    out = subprocess.run(
        [BASH, "-c",
         f'export ONIONWARDEN_VERIFY_BACKEND=python; . "{ROOT}/lib/baseline.sh"; '
         f'baseline_verify "{bdir}" "{pub}" && echo OK || echo FAIL'],
        capture_output=True, text=True,
        env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    assert out.stdout.strip() == "FAIL"
    assert "symlink present" in out.stderr


def test_pubkey_pin_mismatch_refused(keypair, tmp_path):
    """verify.sh refuses a pubkey whose hash != the embedded C2 pin."""
    priv, pub = keypair
    tmp = tempfile.mkdtemp()
    msg = os.path.join(tmp, "m")
    open(msg, "w").write("payload")
    sign_file(priv, msg)
    # A pin that does not match the pubkey must make verification refuse.
    script = (
        f'export ONIONWARDEN_VERIFY_BACKEND=python; . "{ROOT}/lib/verify.sh"; '
        f'ONIONWARDEN_PUBKEY_SHA256_PIN=deadbeefdeadbeef; '
        f'onionwarden_verify_sig "{pub}" "{msg}" "{msg}.sig" && echo OK || echo FAIL'
    )
    out = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                         env={**os.environ, "ONIONWARDEN_ROOT": str(ROOT)})
    assert out.stdout.strip() == "FAIL"
