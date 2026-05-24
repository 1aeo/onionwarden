# onionwarden — receiver

The off-box receiver. Runs on a single, off-fleet host. Collects per-host
event lines over a forced-command SSH key, runs the cron-driven
verification, and pushes to ntfy on CRIT.

## Files

| File | Role |
|------|------|
| [`onionwarden-receiver`](onionwarden-receiver) | The verifier. Four subcommands: `verify-record`, `verify-check`, `seqcheck`, `digest`. |
| [`receiver-append.sh`](receiver-append.sh) | The forced command behind every per-host SSH key. Sanitises host_id, rate-limits, stamps `recv_ts`, appends to `<host>/events.log`. |
| [`receiver-setup.sh`](receiver-setup.sh) | One-shot installer. Creates the per-host tree, applies `chattr +a`, installs scripts under `$ROOT/.bin`, prints the authorized_keys template. |
| [`RECEIVER.md`](RECEIVER.md) | Full operator runbook: install, config knobs, key rotation, log rotation, host migration. |
| [`receiver.pub.example`](receiver.pub.example) | Placeholder — generate your own with `../scripts/generate-receiver-key.sh`. |

## Subcommands at a glance

| Subcommand | Cadence | What it does |
|------------|---------|--------------|
| `verify-record [HOST...]` | once, at bootstrap | Snapshot each host's current `selfhash` + `pubkeyhash` as the known-good baseline. Also appends an audit-trail event to `events.log` (R2-F1). |
| `verify-check` | `*/5 *` (cron) | Compare every host's latest `selfhash` + `pubkeyhash` against the known-good; check staleness (per-host override via `<host>/.stale_minutes`); single ntfy push per host per run. |
| `seqcheck` | `*/5 *` (cron) | Per-host sequence-gap + reset detection. Stateful + seek-based; one WARN per reset (acked). |
| `digest` | `0 7 * * *` (cron) | One fleet-rollup line per host for the last 24h. CRIT count flagged; parse-failure count surfaced for in-progress corruption. |

See [`RECEIVER.md`](RECEIVER.md) for cron-line templates + the authorized_keys
template (`command="…/receiver-append.sh <host>",restrict <pubkey>`) that pins
each per-host SSH key to one host_id (R1-F1).

## Helpers in `../scripts/`

| Script | Purpose |
|--------|---------|
| `generate-receiver-key.sh` | Initial Ed25519 keypair for receiver signing. |
| `rotate-receiver-key.sh`   | Safe rotation — atomic swap + sha256 fingerprints. |
| `rotate-receiver-logs.sh`  | Weekly root cron: lifts `+a`, rotates, gzips, re-arms `+a`. |
