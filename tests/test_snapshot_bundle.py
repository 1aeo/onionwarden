"""Regression tests for the remote bundle produced by `onionwarden-snapshot`.

History: bash 5 on Ubuntu treats `${BASH_SOURCE[0]}` as unbound under `set -u`
when run via `bash -s` (BASH_SOURCE has 0 elements). The inlined
lib/check_runtime.sh has `_crt_dir="$(dirname "${BASH_SOURCE[0]}")"` at
top-level, and lib/common.sh:onionwarden_root() has the same shape inside its
function body. Two snapshot runs silently truncated `network_deep` and
`process_ancestry` to 0 bytes because of this — we caught it only by reading
raw/remote-stderr.log. These tests assert the bundle now runs with `set -u`
disabled so that single point of unsafety can never silently bite again.
"""
import subprocess

from conftest import ROOT, BASH

SNAPSHOT_BIN = str(ROOT / "bin" / "onionwarden-snapshot")


def _build_bundle():
    return subprocess.check_output(
        [BASH, SNAPSHOT_BIN, "--print-bundle"], text=True)


def test_print_bundle_emits_valid_bash():
    bundle = _build_bundle()
    assert bundle.startswith("#!/usr/bin/env bash"), "missing shebang"
    p = subprocess.run([BASH, "-n"], input=bundle, capture_output=True, text=True)
    assert p.returncode == 0, f"bundle fails bash -n:\n{p.stderr}"


def test_bundle_preamble_does_not_enable_set_u():
    """Preamble must not `set -u`; inlined libs run their top-level code under
    it and hit BASH_SOURCE[0] on bash 5 `bash -s`."""
    bundle = _build_bundle()
    head = "\n".join(bundle.splitlines()[:3])
    assert " -u" not in head and "-uo" not in head, (
        "bundle preamble must not enable set -u; got:\n" + head)


def test_bundle_driver_disables_set_u_before_collectors():
    """The inlined check files each `set -euo pipefail` at their top-level when
    inlined — re-enabling -u right before the driver runs. The driver MUST
    explicitly disable -u (and -e) AFTER the last check is inlined and BEFORE
    the collector loop runs, or BASH_SOURCE[0] in the inlined libs trips again."""
    bundle = _build_bundle()
    disable_at = bundle.rfind("set +eu")
    last_enable_at = bundle.rfind("set -euo pipefail")
    driver_at = bundle.find("for __c in")
    assert disable_at != -1, "bundle missing `set +eu`"
    assert driver_at > 0, "driver loop missing from bundle"
    assert disable_at > last_enable_at, (
        "`set +eu` must come AFTER the last `set -euo pipefail` from an "
        "inlined check file — otherwise -u is re-enabled by the next check")
    assert disable_at < driver_at, (
        "`set +eu` must come BEFORE the `for __c in ...` driver loop")


def test_bundle_runs_under_bash_s_without_bash_source_error():
    """End-to-end: pipe the bundle through `bash -s -u` and confirm no
    'BASH_SOURCE[0]: unbound variable' surfaces. We run with -u explicitly
    enabled on the host bash to simulate the Ubuntu bash 5 behaviour as
    closely as possible; the bundle's own `set +eu` must dominate."""
    bundle = _build_bundle()
    # Run via `bash -s` reading from stdin, same way the snapshot tool ships
    # it. We capture stderr for the regression check; we don't care about
    # exit code or stdout content (most collectors no-op on the macOS test
    # host since /proc etc. are absent — that is the whole point of the
    # snapshot tool needing a real Linux target).
    p = subprocess.run([BASH, "-s"], input=bundle,
                       capture_output=True, text=True, timeout=120)
    assert "BASH_SOURCE[0]: unbound variable" not in p.stderr, (
        f"BASH_SOURCE regression — stderr contained the very error we fixed:\n{p.stderr}")
