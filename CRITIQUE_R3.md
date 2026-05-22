# CRITIQUE R3 — Fatal-action arming logic

**Lens:** can the checklist enforcement, cooldown, or disarmed-default be
bypassed or tricked? **Files read:** `lib/fatal.sh` (whole), `bin/onionwarden-fatal`
(whole), `bin/onionwarden-run` fatal hook, `host.conf` arming fields (§3.4).

## Findings

### R3-1 (HIGH) — Checklist auto-items read on-box logs (violates M3)
PLAN §3.7 M3 is explicit: checklist items 1-3/5 must be auto-verified **from
the off-box `events.log`, never from on-box logs, which a compromised host
controls and could forge into "7 quiet days".** `_chk_quiet_baseline` did
exactly the forbidden thing — it read the on-box `runs.ndjson` for the CRIT
count and `stat`'d the on-box `manifest.json` for age (an attacker can `touch`
it and truncate the log). A compromised host could sail through item 1.

### R3-2 (HIGH) — Cooldown is not signal-scoped and is attacker-forgeable
`_fatal_in_cooldown` suppressed **every** fatal action during the window,
regardless of which signal recurred — but §3.7 defines the cooldown as flap
protection for *the same finding* recurring. As written, one cooldowned signal
muted the kill-switch for *all* signals. Worse, `state/fatal_cooldown` is an
unsigned, attacker-writable file: writing a fresh one neutered the action
entirely (it would only ever log/push, never act).

### R3-3 (MEDIUM) — Fatal action taken from the unsigned armed-state file
`fatal_evaluate` derived the action from `_fatal_armed_action()` reading
`state/fatal_armed` — an unsigned, attacker-writable file. On a host the
operator armed for `freeze`, an attacker who can write `state/` could rewrite
it to `action=poweroff scope=all` and escalate a containment into a host-kill.
(Disarming via that file is an accepted root-attacker residual; *escalation*
of the action is not.)

### R3-4 (MEDIUM) — A failed dry-run reads as "clean"
`_chk_dry_run_clean` did `dry-run | grep -c WOULD-TRIGGER` and passed item 3 on
a count of 0. If `onionwarden-fatal dry-run` itself errors and prints nothing, the
count is 0 — so a crashed dry-run satisfied the "baseline does not self-trip"
check. The checklist would green-light arming without ever confirming the
baseline is safe.

## Non-findings (examined, no issue)

- The disarmed default holds: `fatal_is_armed` requires BOTH the signed
  `host.conf:fatal_action_armed=true` master veto AND the `state/fatal_armed`
  file; `install.sh` ships `fatal_action_armed=false`.
- Mis-attestation of the manual items (4/6/7) is an accepted, documented
  residual (§8) — the attestation is recorded with operator identity off-box.

## Fixes applied

- **R3-1:** `onionwarden-fatal arm` now requires `--events-log` (a fresh off-box
  `events.log` copy); item 1 counts CRIT events in *that* file. Item 2 became
  operator-attested (`--attest-apt`) — a fully-auto check needs a richer event
  schema (the demoted finding is INFO and never reaches `events.log`); this is
  documented as a deferred refinement.
- **R3-2:** the cooldown is now per-signal — `_fatal_in_cooldown <signal>` only
  suppresses a recurrence of the *same* signal; a different fatal signal always
  fires. Every cooldown suppression still emits a loud off-box WARN, so a
  forged `state/fatal_cooldown` is visible on the receiver.
- **R3-3:** `fatal_evaluate` now reads the action from the signed
  `host.conf:fatal_action`; `state/fatal_armed` carries only scope/metadata.
  `onionwarden-fatal arm --action` must match the signed `fatal_action` or it is
  refused. An attacker rewriting the armed file cannot escalate the action.
- **R3-4:** item 3 now requires the dry-run to positively emit its `dry-run:
  clean` result line — a crashed/empty dry-run fails the item.
