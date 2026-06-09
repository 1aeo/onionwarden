"""onionwarden-quickstart wrapper behavior."""
import os
import shutil
import subprocess
import textwrap

from conftest import ROOT, BASH


def test_quickstart_fails_when_offline_analysis_fails(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    quickstart = bindir / "onionwarden-quickstart"
    shutil.copy(ROOT / "bin" / "onionwarden-quickstart", quickstart)
    quickstart.chmod(0o755)
    stub = bindir / "onionwarden"
    stub.write_text(textwrap.dedent("""\
        #!/usr/bin/env bash
        set -euo pipefail
        case "$1" in
          snapshot)
            shift
            out=""
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --out) out=$2; shift 2 ;;
                *) shift ;;
              esac
            done
            mkdir -p "$out"
            printf 'tainted 4096\\n' > "$out/taint.current"
            ;;
          run)
            printf 'analysis exploded\\n' >&2
            exit 42
            ;;
        esac
        """))
    stub.chmod(0o755)

    r = subprocess.run([BASH, str(quickstart), "relay-a"],
                       capture_output=True, text=True,
                       env={**os.environ, "TMPDIR": str(tmp_path)}, check=False)
    assert r.returncode == 1
    assert "analysis exploded" in r.stderr
    assert "analysis failed" in r.stderr
    assert "0 CRIT - 0 WARN - 0 INFO" not in r.stdout
