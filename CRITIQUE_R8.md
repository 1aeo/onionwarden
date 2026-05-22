# CRITIQUE R8 — Off-box transport

**Lens:** receiver auth, replay protection, alert-path resilience when the
receiver is unreachable, what happens to events buffered during an outage.
**Files read:** `lib/alert.sh` (whole), `receiver/receiver-append.sh` (whole),
`receiver/onionwarden-receiver` (whole), `bin/onionwarden-run` alerting section.

## Findings

### R8-1 (HIGH) — `verify-check` takes the last entry by file order, not by seq
`onionwarden-receiver`'s `latest_of_kind` returned the *last matching line in the
file*. A compromised host can append a **replayed old** `selfreport` (with its
honest old self-hash) *after* its real, mismatching one — and `verify-check`
would read the replayed-good entry as "latest" and report `ok`, missing the
swap. The append handler does not dedupe, so nothing stops the replay.

### R8-2 (HIGH) — A failed `/fail` ping is masked by the next clean `ok` ping
On a WARN/CRIT run the dispatcher pings the dead-man `/fail` endpoint. If that
ping fails to deliver (network blip, provider hiccup), nothing retried it — and
the *next* clean run pings `ok`, which resets the provider's staleness timer.
Net result: a CRIT whose `/fail` did not land, followed by one clean run, is
**never alerted on the dead-man channel at all**. If the network was down for
exactly the CRIT run, the dead-man — the PRIMARY trust anchor — silently misses
it.

### R8-3 (HIGH) — A host can vanish from receiver verification via `host_id`
The append handler sanitises `host_id` to `[A-Za-z0-9_-]` — which **includes
`_`**. But `onionwarden-receiver`'s `host_dirs()` *excludes* `_`-prefixed
directories (they are the quarantine for malformed IDs). So a compromised host
that simply reports `host_id="_x"` has every event filed under `_x/`, which is
excluded from `verify-check`, `seqcheck`, AND the digest. Its real `relay-a/`
directory just goes quiet — and nothing flags a host that has *stopped*
appending (the dead-man is a separate channel the compromised host keeps
pinging). The host effectively goes dark on every receiver-side check while
still looking alive.

## Non-findings (examined, no issue)

- A compromised host forging "all-clear" appends is an accepted, documented
  residual (§4) — the dead-man and the off-box scan are the anchors, not the
  host's word.
- The per-host per-minute append rate limit is self-policing: a flood gets
  dropped, the drops create a `seq` gap, and `seqcheck` raises a CRIT.
- The local event buffer + `events_flush_buffer` replay path correctly
  preserves events across a receiver outage (and R2-3 already fixed its race).

## Fixes applied

- **R8-1:** `latest_of_kind` now selects the entry with the highest `seq`, so a
  replayed lower-seq entry cannot become "latest"; `seqcheck` independently
  flags the duplicate as a reset.
- **R8-2:** a failed `/fail` ping sets `state/deadman_pending_fail`; while that
  marker exists every run pings `/fail` (even on a clean run) until one
  succeeds — the CRIT's fail signal always eventually reaches the provider.
- **R8-3:** the append handler now routes any `_`/`.`-leading `host_id` to
  `_invalid`; and `onionwarden-receiver verify-check` flags any host whose
  `events.log` file mtime is stale (the host has stopped appending).
