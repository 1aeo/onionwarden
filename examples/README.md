# examples

Runnable, synthetic fixtures for trying onionwarden. None of these contain real
host names, IPs, or endpoints — fill in your own before any real install.

## First watch

[`first-watch-output.txt`](first-watch-output.txt) is a sample of what
`onionwarden-quickstart <host>` (or `onionwarden snapshot` +
`onionwarden run --from-snapshot`) prints: a read-only inventory of one host
with no baseline yet, so every observation shows as `INFO … new`. Your output
will differ — it reflects the actual host. See the
[README Quick Start](../README.md#quick-start-5-minutes).

## Per-host answers files

`install.sh --answers FILE` turns a reviewable answers file into
`/etc/onionwarden/host.conf`. These are annotated templates — copy one, fill
every `CHANGE-ME`, and sign it off-box:

| File | For |
|------|-----|
| [`answers-canary.example`](answers-canary.example) | A Tor-relay rollout canary (`alert_push_level=warn`). Fully annotated — start here. |
| [`answers-evalhost.example`](answers-evalhost.example) | An eval host running nested VMs (`allow_virt_churn=true`, `workload_integrity_check=none`). |

Field-by-field meaning is in the canary file's comments and the
[host.conf schema in ONBOARDING.md](../docs/ONBOARDING.md#per-host-hostconf-template-the-shape)
(full schema: PLAN §3.4).

## Fatal-action hook

[`fatal-action.sh.example`](fatal-action.sh.example) is the template for a
custom `fatal_action` handler. The kill-switch ships disarmed; see
[ARCHITECTURE.md → Kill-switch](../docs/ARCHITECTURE.md#kill-switch-optional-ships-disarmed)
before wiring one up.
