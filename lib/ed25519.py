#!/usr/bin/env python3
"""Pure-Python Ed25519 (RFC 8032) — dependency-free sign/verify for onionwarden.

On Ubuntu 24.04 / Debian 13 the watchdog verifies signatures with `openssl
pkeyutl` (fast, no extra package — PLAN §3.5). This module is the FALLBACK
verifier for hosts whose openssl predates Ed25519 support, and it is what the
off-box signing tool and the test suite use. It needs only the Python 3
standard library (hashlib, base64) — no `cryptography` package — so it runs
unchanged on a minimal image and on the macOS build host.

Keys are stored as PEM (openssl-native, so the production openssl path and
this fallback consume the identical files). Signatures are raw 64 bytes,
exactly what `openssl pkeyutl -sign` emits for Ed25519.

CLI:
  ed25519.py keygen PRIV.pem PUB.pem
  ed25519.py pubkey PRIV.pem PUB.pem
  ed25519.py sign   PRIV.pem FILE SIG
  ed25519.py verify PUB.pem  FILE SIG     (exit 0 = valid, 1 = invalid)
"""
import base64
import hashlib
import os
import sys

# --- field / curve constants (RFC 8032, Curve25519 / Edwards) --------------
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _hint(m):
    return int.from_bytes(_H(m), "little")


def _inv(x):
    return pow(x, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY) % _Q
_B = (_BX, _BY)


def _edwards_add(p, p2):
    x1, y1 = p
    x2, y2 = p2
    denom = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom)
    return (x3 % _Q, y3 % _Q)


def _scalarmult(p, e):
    # Iterative double-and-add (avoids deep recursion).
    result = (0, 1)
    addend = p
    while e > 0:
        if e & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        e >>= 1
    return result


def _encodepoint(p):
    x, y = p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _Q - x
    p = (x, y)
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        raise ValueError("point not on curve")
    return p


def _clamp(h):
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def _public_from_seed(seed):
    h = _H(seed)
    a = _clamp(h)
    return _encodepoint(_scalarmult(_B, a))


def _sign(seed, msg):
    h = _H(seed)
    a = _clamp(h)
    pub = _encodepoint(_scalarmult(_B, a))
    r = _hint(h[32:64] + msg)
    rr = _encodepoint(_scalarmult(_B, r))
    s = (r + _hint(rr + pub + msg) * a) % _L
    return rr + s.to_bytes(32, "little")


def _verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        rr = _decodepoint(sig[:32])
        aa = _decodepoint(pub)
    except (ValueError, IndexError):
        return False
    s = int.from_bytes(sig[32:64], "little")
    if s >= _L:  # non-canonical S — reject (malleability guard)
        return False
    h = _hint(sig[:32] + pub + msg)
    lhs = _scalarmult(_B, s)
    rhs = _edwards_add(rr, _scalarmult(aa, h))
    return lhs == rhs


# --- PEM <-> raw -----------------------------------------------------------
_PUB_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
_PRIV_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def _pem_body(text, label):
    lines = []
    grab = False
    for line in text.splitlines():
        line = line.strip()
        if line == "-----BEGIN %s-----" % label:
            grab = True
            continue
        if line == "-----END %s-----" % label:
            break
        if grab and line:
            lines.append(line)
    if not lines:
        raise ValueError("no %s PEM block found" % label)
    return base64.b64decode("".join(lines))


def _pem_wrap(der, label):
    b64 = base64.b64encode(der).decode("ascii")
    chunks = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (
        label, "\n".join(chunks), label)


def load_public_pem(path):
    der = _pem_body(open(path).read(), "PUBLIC KEY")
    if not der.startswith(_PUB_DER_PREFIX) or len(der) != len(_PUB_DER_PREFIX) + 32:
        raise ValueError("malformed Ed25519 public key DER")
    return der[len(_PUB_DER_PREFIX):]


def load_private_pem(path):
    der = _pem_body(open(path).read(), "PRIVATE KEY")
    if not der.startswith(_PRIV_DER_PREFIX) or len(der) != len(_PRIV_DER_PREFIX) + 32:
        raise ValueError("malformed Ed25519 private key DER")
    return der[len(_PRIV_DER_PREFIX):]


def write_public_pem(path, raw):
    open(path, "w").write(_pem_wrap(_PUB_DER_PREFIX + raw, "PUBLIC KEY"))


def write_private_pem(path, seed):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(_pem_wrap(_PRIV_DER_PREFIX + seed, "PRIVATE KEY"))


def _main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    cmd = argv[1]
    try:
        if cmd == "keygen":
            seed = os.urandom(32)
            write_private_pem(argv[2], seed)
            write_public_pem(argv[3], _public_from_seed(seed))
            return 0
        if cmd == "pubkey":
            seed = load_private_pem(argv[2])
            write_public_pem(argv[3], _public_from_seed(seed))
            return 0
        if cmd == "sign":
            seed = load_private_pem(argv[2])
            msg = open(argv[3], "rb").read()
            open(argv[4], "wb").write(_sign(seed, msg))
            return 0
        if cmd == "verify":
            pub = load_public_pem(argv[2])
            msg = open(argv[3], "rb").read()
            sig = open(argv[4], "rb").read()
            return 0 if _verify(pub, msg, sig) else 1
    except Exception as exc:  # noqa: BLE001 — CLI: any failure is a hard error
        sys.stderr.write("ed25519: %s\n" % exc)
        return 3
    sys.stderr.write("ed25519: unknown command %r\n" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
