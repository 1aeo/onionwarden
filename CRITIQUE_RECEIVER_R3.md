# Critique R3 — Cron-based dead-man / verify-check / seqcheck

**Scope:** races, false negatives, and stale-detection accuracy in
`verify-check`, `seqcheck`, `digest`, and the staleness signal.
**Files:** `receiver/onionwarden-receiver`.

## Findings

### F1 — Staleness signal is now strong (R2-F2 fix carries here)

Pre-R2, `events_log_age_seconds` used mtime. Anyone with shell as
`onionwarden` could `touch events.log` to mask staleness. R2 made it
prefer the receiver-stamped `recv_ts` of the highest-seq event, which
is in-band inside the `+a` log. ✓ — but two follow-ups remain.

### F2 — Staleness threshold is the only knob; no host-level override (real)

`ONIONWARDEN_STALE_MINUTES` is a single global value (default 30). A
fleet with one chatty host (5-min cadence) and one quiet (daily ping)
needs different thresholds per host, or the daily host trips every
cycle.

**Fix:** look up `stale_minutes` from a per-host `host.conf`-equivalent
on the receiver (e.g. `$RECVROOT/<host>/.stale_minutes`) before falling
back to the env-var default. Round 3 implements this.

### F3 — `seqcheck` loads every event into memory per host (DoS-grade scaling)

```python
seqs = [ev["seq"] for ev in read_events(hd) if isinstance(ev.get("seq"), int)]
```

For a host with 5M cumulative events, this is a 5M-int list AND the
underlying JSON parse of the full log on every cron run. Combined with
`*/5` cron, the receiver thrashes long before reaching the 365d retention
target. Same shape in `cmd_digest` (full file scan per host) — fine for
24h windows but only because nobody noticed yet.

**Fix:** seek-based streaming. Maintain a per-host
`.seqcheck.state.json` recording `last_seq_seen` + `last_offset`; on
each run, `seek(last_offset)`, iterate forward, update state. Gaps
become a constant-memory check. Round 3 implements this for seqcheck;
digest is left full-scan with a TODO since its 24h window naturally
bounds work — but a future fix is to maintain a 24h-rolling tally.

### F4 — `seqcheck` flags `reset` for legitimate appender restarts (false positive)

`resets = sum(1 for a, b in zip(seqs, seqs[1:]) if b <= a)` — a host that
legitimately reboots (and its watchdog restarts seq from 1) trips a
WARN, every cron run, until the gap closes (which it never does). The
receiver has no way to mark a reset as ack'd.

**Fix:** persist `last_seq_seen` (per F3); on a reset, log it ONCE and
then ratchet `last_seq_seen` down so subsequent runs treat the new
sequence as authoritative.

### F5 — `verify-check` ntfy posts up to 2 per host per run (noise)

The verify-check loop pushes ntfy for both staleness AND each
field-mismatch. With a 100-host fleet and a global outage, that's
200+ ntfy pushes in one cron cycle.

**Fix:** dedupe per host — at most one ntfy per host per run; the
message lists all triggered conditions. Round 3 implements this.

### F6 — Concurrent `verify-check` from two cron starts can race on stdout (cosmetic)

`*/5` cron means every 5 minutes; if a prior verify-check ran >5min
(possible with 1000 hosts), two are running. Both write to the same
ntfy URL; race-condition output is interleaved but not corrupted.
Acceptable.

### F7 — `read_events` swallows JSONDecodeError silently (low impact)

Corrupted bytes mid-line produce a silent skip. Acceptable, but a
counter exposed via `digest` ("3 lines unparseable for relay_a") would
help an operator catch in-progress corruption.

**Fix:** track per-host parse-failure count in `digest`. Round 3
implements.

## Fix application

R3 applies F2 (per-host stale override), F3 (seek-based seqcheck), F4
(reset ack via state file), F5 (dedup ntfy), F7 (parse-failure counter).

New tests:
- `test_seqcheck_resumes_from_state_file`
- `test_seqcheck_reset_acks_after_one_warning`
- `test_verify_check_per_host_stale_override`
- `test_verify_check_ntfy_dedup_per_host`
