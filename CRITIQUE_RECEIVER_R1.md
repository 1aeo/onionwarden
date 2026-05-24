# Critique R1 — Forced-command SSH lockdown

**Scope:** can the restricted SSH key escape the forced command?
**Files:** `receiver/receiver-setup.sh`, `receiver/receiver-append.sh`,
`receiver/MIGRATION_TO_PROXMOX.md`.

## What's already strong

- `restrict` in the `authorized_keys` line disables port-forwarding,
  X11, agent forwarding, PTY, and `~/.ssh/rc` — minimal escape surface.
- `command="…/receiver-append.sh"` forces the entry point regardless of
  `SSH_ORIGINAL_COMMAND` (and the script never inspects it).
- `host_id` is sanitised by a tight `[A-Za-z0-9_-]{1,64}` regex and a
  separate `[._]*` quarantine rule for receiver-reserved namespace
  (`_invalid`, `_unknown`).
- Over-long lines are truncated; per-host per-minute rate-limit caps
  flood damage; non-JSON-shaped lines are rejected.
- The shell user has `/bin/bash` (required for ForceCommand), but the
  authorized-keys entry pins the command; `bash -c "$ForceCommand"` does
  not source `~/.bashrc`, so a malicious `.bashrc` is not a vector.
- `PermitUserEnvironment` defaults to `no` in Ubuntu/Debian sshd, so
  `environment=` directives in `authorized_keys` are dormant — a host
  cannot smuggle env vars via the key entry.

## Findings

### F1 — Stolen-key cross-host impersonation (real, fixable)

`host_id` is read from the JSON body of each event, NOT from the SSH key
identity. A key stolen from `relay_a` can submit events claiming
`host_id: relay_b`, polluting `relay_b`'s `events.log`, masking real
findings, or filling `relay_b`'s known-good comparison with junk
selfreports. The key comment `onionwarden-<host>` is purely
documentation; nothing on the receiver enforces it.

**Fix:** pass the host expected on this key as the first arg to
`receiver-append.sh` via the forced command:

```
command="…/receiver-append.sh relay_a",restrict ssh-ed25519 … onionwarden-relay_a
```

then `receiver-append.sh` rejects any line whose JSON `host_id` ≠ `$1`
(or substitutes `$1` and warns to `receiver.log`). This binds each key
to exactly one host_id and contains the blast radius of a key compromise.

### F2 — World-readable events under default umask (minor)

`receiver-append.sh` does not set `umask`. With a typical user umask of
`0022`, new files (`events.log`, `.rate.*`, `known_good.json`) are
mode `0644` — readable to anyone with a shell on the receiver. The
receiver is intended to be a single-purpose host so the local-user
surface is small, but on a Proxmox host that may grow other tenants,
tighter perms are cheap.

**Fix:** `umask 077` at the top of `receiver-append.sh` and
`onionwarden-receiver`.

### F3 — Forced command path with whitespace breaks the authorized_keys line (operator footgun)

`receiver-setup.sh` prints `command="$BINDIR/receiver-append.sh",restrict
…` where `$BINDIR=$ROOT/.bin`. If the operator passes `--root /var/lib/
onionwarden plus spaces/`, the printed line is syntactically broken; SSH
will reject the key without a clear error.

**Fix:** the printed line already quotes the path with `"..."` which
handles spaces inside the command string fine — but the operator-pasted
authorized_keys file must preserve the quoting. Add a defensive check in
`receiver-setup.sh` to reject `--root` containing whitespace.

### F4 — `set -e` + `mkdir -p $hd` failure aborts the whole connection (minor DoS)

If `$RECVROOT/$host` is a regular file (e.g. someone shelled in and
touched `relay_a`), `mkdir -p` fails and `set -e` aborts the loop — all
subsequent events from that SSH session are dropped silently. This is
recoverable (the next session re-tries) but lets a local-write-capable
attacker drop the next event from any host.

**Fix:** continue past mkdir failure with a `receiver.log` warning
rather than aborting the loop.

### F5 — `chattr +a` runs with the wrong user in setup (operator hazard)

`receiver-setup.sh` calls `chattr +a "$hd/events.log"`. `chattr +a`
requires CAP_LINUX_IMMUTABLE — root, or a process with the cap. The
script is designed to run as the `onionwarden` user (its install dir
already needs to be writable by that user), so `chattr +a` silently
fails ("Operation not permitted"). The fallback message blames the FS;
the real cause is permission.

**Fix:** detect the perm-denied case explicitly and recommend
`sudo onionwarden-receiver harden` (or just `sudo` the setup) before
falling through.

## Fix application

Applying F1, F2, F4, F5 in this round (small, behaviour-preserving).
F3 is paper-only (defensive validation) — also applied.

A new test exercises F1: a key bound to `relay_a` submitting events
with `host_id: relay_b` lands under `relay_a` (or is rejected),
never under `relay_b`.
