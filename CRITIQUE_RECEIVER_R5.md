# Critique R5 — Public-repo readiness

**Scope:** anything in the receiver code or docs that leaks
fleet-specifics (post-scrub) or that an outside operator would
struggle with.
**Files:** `receiver/MIGRATION_TO_PROXMOX.md`, `receiver/*.sh`,
`receiver/onionwarden-receiver`, `README.md`.

## Findings

### F1 — `MIGRATION_TO_PROXMOX.md` is private-fleet-shaped (real, fixable)

The migration runbook is written as a one-shot ops doc for moving
the deployed receiver from a staging VM to a Proxmox host. References
to "staging", "the new Proxmox host", "exact apt packages on staging",
specific Ubuntu kernel/package versions captured at one moment in time
— none of that helps a public-template operator. Worse: it implies
this repo is tied to one specific deployment story (proxmox), which is
misleading.

Also: line 40 still references `secure-server/receiver/` (the
pre-rename path), missed by the rename pass because it was inside a
prose sentence about "the upstream receiver in …".

**Fix:** rewrite the doc as `receiver/RECEIVER.md` — generic operator
setup + migration guide that covers:
- the SSH-forced-command + cron architecture
- which packages to install (just package names, no pinned versions)
- the four config knobs (listen address, ufw allow, ntfy URL, per-host
  authorized_keys entries) that an operator must fill in
- the 4-step key-rotation protocol (R4)
- the rotation runbook for `events.log` (R2-F4)
- a generic "moving the receiver between hosts" section (the actual
  rsync bits, but agnostic to Proxmox)

Keep `MIGRATION_TO_PROXMOX.md` as a small wrapper that points at the
generic doc + adds Proxmox-only commentary, OR drop it entirely. R5
goes with the wrapper-redirect since the original is referenced from
the root README.

### F2 — No `receiver/README.md` for someone landing in that directory

Public users browsing the repo will look at `receiver/` and see four
files (`onionwarden-receiver`, `receiver-append.sh`,
`receiver-setup.sh`, `MIGRATION_TO_PROXMOX.md`) with no orientation.
A short `receiver/README.md` would help them know which file does
what, and which subcommands `onionwarden-receiver` provides.

**Fix:** add a one-page `receiver/README.md`.

### F3 — `verify-check` error messages aren't operator-actionable

When verify-check WARNs ("no known-good recorded (run verify-record)"),
the message tells the operator the WHAT but not the HOW. A new operator
needs to know which path to ssh into and which command to run.

**Fix:** include the canonical "run as: …" hint in the WARN/CRIT
messages where applicable. R5 patches the strings.

### F4 — `onionwarden-receiver` usage string is minimal

`if len(argv) < 2: sys.stderr.write(__doc__); return 2` — that prints
the module docstring, which is good. But the docstring lists
subcommands without examples. A new operator would benefit from a
concrete "first-time setup" example.

**Fix:** append a "Examples:" block to the docstring.

### F5 — Root README quickstart references nonexistent shell prompt details

The README quickstart says:
```
bash onionwarden/scripts/generate-receiver-key.sh
bash onionwarden/receiver/receiver-setup.sh --hosts "relay_a relay_b ..."
```

But `generate-receiver-key.sh` writes to `/var/lib/onionwarden/` by
default — which means the script needs sudo to mkdir. The quickstart
doesn't mention sudo, so a literal copy-paste fails on permission.

**Fix:** README quickstart shows `sudo bash …` for both receiver
scripts (already true for the collector install), plus a callout that
the bundle key + signing key files written there need the
`onionwarden` user to read them.

## Fix application

R5 applies F1–F5: rewrites the migration doc into a generic
`receiver/RECEIVER.md`, adds `receiver/README.md`, sharpens
`verify-check` messages, expands the receiver script docstring, and
fixes the root README quickstart.

No code-behaviour changes besides the verify-check message strings.
Existing tests are unaffected.
