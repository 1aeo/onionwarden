# CRITIQUE R7 — Kernel-taint bit interpretation

**Lens:** which bits map to which severity; do the "ignore livepatch" and
"ignore OEM modules" carve-outs actually work; are new bit numbers handled
gracefully. **File read:** `lib/checks/taint.sh` (whole), against the PLAN §2.1
taint table and §3.7 #4 fatal list.

## Findings

### R7-1 (HIGH) — The livepatch (K) carve-out is INVERTED
`taint_analyze` had a special branch: any newly-set `K` (bit 15, kernel
live-patched) was unconditionally downgraded to **WARN, fatal=false**. That is
backwards. Kernel live-patching is a real rootkit/persistence technique — an
attacker who live-patches the running kernel would raise only a WARN that rides
the daily digest. PLAN §2.1 says K → "**CRIT** (unless you applied it)" and
§3.7 #4 lists K in the fatal set "unless K is an operator-applied livepatch".
The carve-out must be *opt-in*: K is CRIT + fatal **unless** the operator
declares the livepatch by putting `K` in `expected_taint_bits` — exactly how
the OEM-out-of-tree (`O`) carve-out already works.

### R7-2 (LOW) — Reboot-normal bit clears emit one finding per bit, forever
Taint bits are sticky until reboot; after a reboot the kernel's taint resets,
so every bit that was set at baseline reads as "cleared". The check emitted a
separate INFO finding *per cleared bit, every run*, until the host is
re-baselined — turning routine post-reboot churn into a stream of digest noise.

### R7-3 (LOW) — Bits 8 (A) and 17 (T) missing from the decoder table
`taint_bit_info` mirrors the PLAN §2.1 table, which omits bit 8
(`TAINT_OVERRIDDEN_ACPI_TABLE`, `A`) and bit 17 (`TAINT_RANDSTRUCT`, `T`). Both
are real, long-standing kernel taint bits — when set they fell through to the
"unknown bit — kernel newer than the table" path, which mis-describes a known
bit as a decoder gap.

## Non-findings (examined, no issue)

- The OEM out-of-tree carve-out works correctly: an OEM kernel sets `O` at boot,
  the baseline captures it, so it is not "newly set"; an OEM module loading
  *after* baseline is covered by putting `O` in `expected_taint_bits`.
- Severity mapping for bits 0-7, 9-16, 18 matches the PLAN §2.1 table; the
  fatal set (CRIT bits 0,1,3,12,13,15) matches §3.7 #4, and the hardware bits
  M(4)/B(5) are correctly WARN, not fatal.
- New/unknown bit numbers (0-31 scanned) are handled gracefully — emitted as a
  WARN rather than crashing or being silently dropped.

## Fixes applied

- **R7-1:** removed the K→WARN special case. K is now CRIT + fatal unless `K`
  is in `expected_taint_bits` (then INFO) — symmetric with the `O` carve-out
  and matching PLAN §2.1 / §3.7 #4.
- **R7-2:** cleared bits are now reported as a single INFO finding listing all
  cleared letters, with reboot-aware wording.
- **R7-3:** added bit 8 (`A`, WARN) and bit 17 (`T`, WARN) to the decoder table.
