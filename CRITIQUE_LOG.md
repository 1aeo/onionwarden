# CRITIQUE_LOG.md

One paragraph per critique round — what the lens found and what changed.
Full findings are in `CRITIQUE_R<N>.md`.

## Round 1 — Signing chain
Looked at whether the pubkey, a signature, or a signed bundle could be swapped,
forged, or replayed. The Ed25519 primitive itself held up (non-canonical-S and
on-curve checks present, cross-checked against `pyca/cryptography`), but the
*freshness* of signed artifacts was unguarded: a validly-signed but **old**
baseline, `host.conf`, or upgrade bundle could simply be replayed, rolling the
host back to weaker trust state or known-buggy code. Two structural gaps too —
`baseline_verify` only hash-checked state files *named in the manifest*, so an
attacker could drop an extra unlisted `state/<check>.state` and have a check
diff against attacker-chosen "known-good"; and a failed pin substitution left
C2 silently inactive. Fixes: `baseline_verify` now enforces anti-rollback via
the signed `captured_at` and refuses any unlisted state file; the dispatcher
enforces a `config_epoch` anti-rollback on `host.conf` and surfaces an unset
pubkey pin; `onionwarden-upgrade` refuses a bundle older than the installed
version unless `--allow-downgrade`. All 115 tests pass.

## Round 2 — TOCTOU + race conditions
Traced every read-state-then-act-later window. The serious one: the dispatcher
hash-verified the on-disk baseline and *then later* let each check read those
same files — and the baseline directory is deliberately not immutable, so an
attacker who can write it could pass verification on honest files and swap a
`state/<check>.state` before the check read it (verified bytes ≠ used bytes).
Fixed by copying the baseline into the run's private 0700 tmpdir and
verifying + using the copy. Two smaller races: `onionwarden-upgrade` had no lock,
so two overlapping upgrades could interleave their `chattr -i`/apply/`chattr +i`
windows into a corrupt tree (now `flock`-guarded); and `events_flush_buffer`
emptied the local buffer with a send-then-truncate that could destroy an event
appended concurrently by `onionwarden-fatal` (now renames the buffer aside first).
All 115 tests pass.

## Round 3 — Fatal-action arming logic
Audited the first-arm checklist, cooldown, and disarmed default. The checklist
auto-items read the *on-box* `runs.ndjson` and `stat`'d the on-box manifest — a
direct violation of M3 ("never from on-box logs, which a compromised host
controls"); a compromised host could forge "7 quiet days". The cooldown was not
signal-scoped, so one cooldowned signal muted the kill-switch for *every*
signal, and `state/fatal_cooldown` is an unsigned attacker-writable file. The
fatal action was read from the unsigned `state/fatal_armed` file, letting an
attacker on an operator-`freeze`-armed host escalate to `poweroff scope=all`.
And a crashed dry-run (zero output) passed the "baseline does not self-trip"
item. Fixes: `arm` requires an off-box `--events-log` and verifies item 1
against it; the cooldown is per-signal and every suppression is loudly logged
off-box; the action is read from the signed `host.conf` (the armed file carries
only scope); item 3 requires the dry-run's positive `clean` result line. All
115 tests pass.

## Round 4 — Suppression workflow
Probed whether `onionwarden suppress` can silence real alerts and whether a stale
token can be replayed. Scope held up — only `input_devices`/`console_login`
consult `physical_access_mode`, so PROMISC and the root signals genuinely
cannot be muted, and suppression downgrades to WARN rather than silencing. But
`onionwarden-suppress clear` turned out to be cosmetic: it only `rm`d the local
token file, so a captured copy could be re-installed and honored until its
natural expiry — an operator who "closed" a window early had not. Fixed by
stamping `suppress_last` to now on `clear`, so the monotonic anti-replay guard
rejects the cleared token on re-install (covered by a new test). Also fixed a
literal-string bug in the nonce fallback (`"$$RANDOM"`). The remaining residual
— a root clock-rollback can resurrect an expired token — is documented; the
honest fix is receiver-side (trusted clock) and the on-box `clock` check's
unsynced-clock WARN is the partial detection. 116 tests pass.

## Round 5 — Input-device + console-login detection
Examined false positives and false negatives in the physical-access checks.
The replug FP and serial-console FP were already handled (vid:pid identity,
`^tty[0-9]+$` excludes `ttyS*`). Three real gaps: input_devices had no
per-device allowlist, so a legitimate post-baseline device (uinput/KVM/synergy)
forced the all-or-nothing `physical_access_allowed`; the sysfs snapshot is
point-in-time, so a seconds-long BadUSB plug-attack-unplug vanishes before the
next ~1-min tick; and console_login only read `who` (current sessions), missing
a console login that closed within the interval — PLAN §2.8 explicitly asked
for the `last`/wtmp half too. Fixes: added an `expected_input_devices`
allowlist; input_devices now also diffs `journalctl -k` input-registration
lines (durable for the boot, so a since-unplugged device is still caught);
console_login now also parses `last` for closed `tty[0-9]` sessions. Three new
tests; 119 pass.

## Round 6 — PROMISC detection
Stress-tested the promiscuous-interface check against virtualization edge
cases. The virtual-kind classification was sound (veth/tap/vnet/bridge/
wireguard/ifb/macvtap/vlan all excluded from fatal #9). But three real defects:
a physical NIC carrying a macvtap/macvlan child legitimately goes promiscuous,
and the check flagged that parent as fatal #9 — `allow_virt_churn` only
excluded the `virtual:*` branch, never a physical NIC promiscuous for a virtual
reason. The ip-vs-sysfs cross-check fired CRIT+fatal for every interface,
including a flapping veth where a transient disagreement is churn not hiding.
And virt-churn tolerance keyed only on the `allow_virt_churn` config flag, not
the `is_hypervisor` profile bit that PLAN §0.2 says should imply it. Fixes:
a physical NIC promiscuous on a virt-churn-tolerant host is WARN not fatal; the
cross-check is CRIT+fatal only for physical interfaces; tolerance is now
`allow_virt_churn OR is_hypervisor`. Four new tests; 122 pass.

## Round 7 — Kernel-taint bit interpretation
Checked the bit→severity mapping, the carve-outs, and unknown-bit handling.
The severity table matched PLAN §2.1 and the fatal set matched §3.7 #4, and
unknown bits were handled gracefully — but the livepatch carve-out was
inverted: a newly-set `K` (kernel live-patched) bit was *unconditionally*
downgraded to WARN, so an attacker live-patching the running kernel — a real
rootkit technique — would raise only a digest-level WARN. Fixed so K is CRIT +
fatal unless the operator opts out via `expected_taint_bits`, symmetric with
the OEM `O` carve-out. Two lower-grade issues: post-reboot bit clears emitted
one INFO per bit forever (now one consolidated INFO with reboot-aware wording),
and bits 8 (`A`) and 17 (`T`) — real kernel taint bits — were missing from the
decoder table (now added). Two updated tests; 123 pass.

## Round 8 — Off-box transport
Examined receiver auth, replay protection, and alert-path resilience during an
outage. Three real holes. `verify-check` took the *last line by file order* as
the latest self-report — so a compromised host could append a replayed old
good self-hash after its real bad one and the receiver would read "ok". A
`/fail` dead-man ping that failed to deliver was never retried, and the next
clean `ok` ping reset the provider's staleness timer — a CRIT during a network
blip could be missed entirely on the PRIMARY trust anchor. And the append
handler allowed `_`-leading host_ids while the receiver tooling excludes
`_`-prefixed directories — a host reporting `host_id="_x"` vanished from
verify-check, seqcheck, and the digest while still looking alive. Fixes:
`latest_of_kind` selects by highest `seq`; a failed `/fail` sets a pending
marker that forces `/fail` every run until one lands; the append handler routes
`_`/`.`-leading IDs to `_invalid`, and `verify-check` now flags a host whose
events.log has gone stale (stopped appending). Three new tests; 126 pass.

## Round 9 — Resource and reliability
Audited timeouts, memory limits, dispatcher hangs, log growth, and tool
dependencies. jq turned out genuinely unused (the watchdog emits JSON with
printf and reads only its own flat manifests) — but five real reliability
defects. The biggest: no log rotation at all — `runs.ndjson` grows ~1.8 GB/year
and would fill a space-constrained host (Appendix A notes eval-host at 88%). The
per-check `timeout` was called without `-k`, so a check ignoring SIGTERM hangs
`timeout` itself; the 512 MB `ulimit -v` cap could strangle `aide --check`;
there was no output-size bound; and a missing `timeout` binary silently dropped
the per-check time guard. Fixes: dispatcher-side size-capped rotation of
`runs.ndjson` (no logrotate dependency); `timeout -k 10`; the memory cap raised
to a coarse 1.5 GB runaway-catcher (the systemd `MemoryMax` is the real
run-level cgroup bound); a `ulimit -f` output cap; and an INFO finding when
`timeout` is absent. 126 tests pass.
