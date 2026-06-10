# Troubleshooting

The failures a new operator is most likely to hit, and the fastest fix for each.
Per-host onboarding problems (signature INVALID, dead-man's switch not firing,
`chattr +i` surprises) are covered in the
[onboarding runbook](ONBOARDING.md#troubleshooting).

## First watch (`onionwarden-quickstart` / `onionwarden snapshot`)

### "snapshot failed" — cannot SSH to the target

`onionwarden-quickstart` and `onionwarden snapshot` connect non-interactively
(`BatchMode`). If the host needs a passphrase prompt or your key is not loaded,
the connection fails fast. Confirm plain SSH works first:

```sh
ssh <host> true        # must return with no prompt
ssh-add               # load your key into the agent if it does prompt
```

Use an alias or `user@host` form if your `~/.ssh/config` needs it.

### Some checks show `N/A`

Expected. A check whose tool is missing on the target degrades to `N/A` rather
than failing (detect-and-skip, PLAN §0.2). For a richer first watch, install the
optional tools on the target or re-run with `--with-sudo` so root-only collectors
(e.g. deep network state, package integrity) can run read-only.

### Empty or tiny inventory

Most collectors need root for full visibility. Re-run with `--with-sudo` (uses
`sudo -n` on the target — still no writes). If the host has almost nothing
listening, a short inventory is simply the truth.

## Install (`install.sh` on a monitored host)

### Missing package

The collector wants standard Ubuntu/Debian tools. Install the common set up front:

```sh
sudo apt-get update && sudo apt-get install -y \
  python3 jq curl file bsdmainutils iproute2 debsums
```

`tcpdump`, `bpftool`, and `aide` are optional — without them the matching checks
report `N/A` instead of running.

### "FS … — falling back to detection-only"

Your install prefix is on a filesystem that does not support `chattr +i`
(tmpfs, ZFS, overlayfs, NFS). The watchdog runs fine; it just loses the
script-immutability layer (PLAN §3.6). Acceptable for a canary; for steady-state
hosts move `/opt/onionwarden` to ext4/xfs/btrfs, or pass `--no-immutable`
deliberately for a test box.

## Receiver

### First heartbeat never lands in `events.log`

Almost always the receiver's `authorized_keys` line. It must pin the host with
a forced command, or the append is rejected:

```
command="…/receiver-append.sh <host_id>",restrict ssh-ed25519 <PUBKEY> onionwarden-<host_id>
```

Walk the four checks in
[ONBOARDING.md → "First heartbeat does not appear"](ONBOARDING.md#troubleshooting),
then check `journalctl -u ssh` on the receiver for forced-command errors.

### ntfy notifications never arrive

In `/etc/cron.d/onionwarden-receiver`, the `ONIONWARDEN_RECEIVER_NTFY=` line
ships commented out on purpose: Vixie cron (Ubuntu's `cron 3.0pl1`) treats an
env-var line with an *empty* value as a bad cron entry and silently invalidates
the whole file. Uncomment it **and assign a value** in one edit, never leave it
uncommented-but-empty. Details in [RECEIVER.md](../receiver/RECEIVER.md).

### Suppression / `chattr +a` permission errors

`events.log` is append-only (`chattr +a`); rotating or editing it needs
`CAP_LINUX_IMMUTABLE`. Run the rotation as root (`scripts/rotate-receiver-logs.sh`
already does), and re-run `receiver-setup.sh` under `sudo` if `chattr +a` was
skipped at setup time on ext4.

## Tests / CI

### `pytest` can't import `cryptography`

The suite needs `pytest` and `cryptography` in the Python environment:

```sh
python3 -m pip install pytest cryptography
python3 -m pytest tests/ -q
```

### `bats: command not found`

The onboarding tests use [bats](https://github.com/bats-core/bats-core). Either
install it (`sudo apt-get install -y bats`) or skip that suite — the Python
tests run independently:

```sh
python3 -m pytest tests/ -q --ignore=tests/bats
```

CI runs the same suite on Ubuntu 24.04 and 22.04 (`.github/workflows/test.yml`).
If a run is green in CI but red locally, compare your Python version and the
installed system tools against that workflow before assuming a real failure.
