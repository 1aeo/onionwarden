# CRITIQUE R9 — Resource and reliability

**Lens:** timeouts, memory limits, dispatcher hangs, a wedged check subprocess,
log rotation, and dependence on jq/bpftrace/shellcheck. **Files read:**
`bin/onionwarden-run` (`run_sandboxed`, the check loop, logging), the `systemd/`
units, `lib/common.sh`, the checks' tool-availability guards.

## Findings

### R9-4 (HIGH) — No log rotation; `runs.ndjson` grows unbounded
The dispatcher appends ~25 NDJSON lines per run to `$LOG_DIR/runs.ndjson` every
fast tick — roughly 5 MB/day, ~1.8 GB/year. PLAN §5 specifies "logrotate 30
days, total size-capped (~200 MB)"; nothing implemented it. On a
space-constrained host (Appendix A: `eval-host` is 88% full) this fills the disk.

### R9-3 (MEDIUM) — `timeout` is called without `--kill-after`
`run_sandboxed` runs `timeout "$CHECK_TIMEOUT" ...`. Plain `timeout` sends only
SIGTERM. A check subprocess that ignores SIGTERM leaves `timeout` itself
waiting forever — the per-check bound is defeated and the whole run wedges
until systemd's coarse `TimeoutStartSec` kills it.

### R9-2 (MEDIUM) — The 512 MB `ulimit -v` cap can strangle `aide --check`
`run_sandboxed` set `ulimit -v 512M`. `ulimit -v` caps *virtual address
space* — a poor proxy for real usage — and `aide --check` over a full
filesystem routinely maps well past 512 MB. The packages (daily) check would
spuriously fail under the cap.

### R9-5 (LOW) — No output-size bound on a check subprocess
`run_sandboxed` bounds CPU time and memory but not output. A check emitting
pathologically large output (a host with millions of temp files, etc.) could
fill the disk with the captured `.current` file.

### R9-1 (LOW) — Loss of the per-check timeout is silent
If `timeout` is unavailable, `run_sandboxed` runs the check directly with no
time bound and says nothing — the operator has no signal that the per-check
guard is off.

## Non-findings (examined, no issue)

- **jq is genuinely not a runtime dependency** — the watchdog emits JSON with
  `printf` and reads only its own flat manifests; `bpftrace` is never used;
  `shellcheck` is dev-only. The real runtime deps (openssl|python3, curl|wget,
  coreutils, flock) all degrade or are detect-and-skipped.
- A wedged check no longer hangs the dispatcher indefinitely: systemd
  `TimeoutStartSec` (120/600/1800 s) is the backstop, and `-xdev` on every
  `find` avoids descending into a stuck NFS mount.

## Fixes applied

- **R9-4:** the dispatcher rotates `runs.ndjson` to `runs.ndjson.1` when it
  exceeds `ONIONWARDEN_LOG_MAX_BYTES` (default 100 MB) — total on-disk is bounded
  to ~200 MB with no logrotate dependency.
- **R9-3:** `run_sandboxed` now uses `timeout -k 10 "$CHECK_TIMEOUT"` — SIGKILL
  follows 10 s after SIGTERM.
- **R9-2:** the per-check `ulimit -v` cap is raised to 1.5 GB (it is a coarse
  runaway-catcher, not a tight bound; the systemd unit `MemoryMax` is the
  run-level cgroup cap).
- **R9-5:** `run_sandboxed` adds a `ulimit -f` output-size cap.
- **R9-1:** the dispatcher emits an INFO finding once if `timeout` is absent.
