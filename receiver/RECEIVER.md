# RECEIVER.md — operator runbook

Generic, deployment-agnostic install + operate guide for the off-box
receiver.

## Architecture (one screen)

```
monitored host
  └─ ssh -i host_key -p <PORT> onionwarden@<receiver> <<< '<json event>'
        │     (publickey-only, restricted-command authorized_keys entry)
        ▼
receiver
  ├─ sshd (ListenStream=<PORT> only)
  ├─ /opt/onionwarden/receiver/receiver-append.sh  ← forced command
  │     └─ appends line → /var/lib/onionwarden/data/<host>/events.log
  └─ cron (as onionwarden):
       */5  verify-check    → CRIT on selfhash/pubkeyhash mismatch + stale
       */5  seqcheck        → CRIT on per-host seq gaps + WARN once on reset
       07:00 UTC digest     → daily fleet rollup
       weekly rotate logs   → roots-only, lifts +a → mv → gz → re-arms +a
```

The receiver is **not a daemon**. The "always-on" piece is cron; the
"ingest" piece is `receiver-append.sh` invoked by SSH ForceCommand.
There is no listening application beyond sshd.

## User accounts (two)

| User | Shell | Purpose |
|------|-------|---------|
| `<admin-user>` | `/bin/bash`, sudo | Interactive admin. Key-only SSH; no password auth. |
| `onionwarden` | `/bin/bash` *(required)* | Ingest + cron. Forced-command-only SSH; never an interactive shell. Owns `/var/lib/onionwarden`. |

`onionwarden` needs `/bin/bash` because SSH `ForceCommand` invokes the
user's login shell to exec the command — `nologin` rejects SSH entirely.
The lockdown is at the `authorized_keys` level (`restrict` +
`command="…"` — see R1).

## Packages

Standard Ubuntu/Debian. Names identical on both:

```
python3 openssh-server cron ufw util-linux passwd coreutils
```

No PPAs. No pip. The receiver code uses only the Python 3 standard
library.

## First-time install

```sh
# 1. create the system users (as root):
useradd -m -s /bin/bash -G sudo <admin-user>
useradd -r -m -d /var/lib/onionwarden -s /bin/bash onionwarden

# 2. fetch this repo onto the receiver:
sudo -u onionwarden git clone https://github.com/<you>/onionwarden \
    /opt/onionwarden
sudo chown -R root:root /opt/onionwarden
sudo chmod -R 0755 /opt/onionwarden

# 3. generate the receiver signing keypair (one-shot):
sudo /opt/onionwarden/scripts/generate-receiver-key.sh
# prints sha256 — verify against the laptop copy you commit to the fork

# 4. lay out per-host event trees + apply chattr +a:
sudo -u onionwarden ONIONWARDEN_RECEIVER_ROOT=/var/lib/onionwarden/data \
    /opt/onionwarden/receiver/receiver-setup.sh \
    --hosts "relay_a relay_b relay_c"
# (re-run as sudo if chattr +a needs CAP_LINUX_IMMUTABLE — common on
#  ext4 with default privileges)

# 5. install the cron schedule (as root):
cat <<'EOF' > /etc/cron.d/onionwarden-receiver
ONIONWARDEN_RECEIVER_ROOT=/var/lib/onionwarden/data
# NOTE: Vixie cron (Ubuntu's 3.0pl1) rejects env-var lines with empty values
# as "bad minute" — the parser falls through to cron-entry parsing and treats
# the var name as the minute field, silently invalidating the whole file.
# Emit commented out; uncomment + assign when ntfy is configured.
# ONIONWARDEN_RECEIVER_NTFY=  # set to your ntfy URL when ntfy is configured
*/5 * * * *  onionwarden  /var/lib/onionwarden/data/.bin/onionwarden-receiver verify-check
*/5 * * * *  onionwarden  /var/lib/onionwarden/data/.bin/onionwarden-receiver seqcheck
0 7 * * *    onionwarden  /var/lib/onionwarden/data/.bin/onionwarden-receiver digest
0 4 * * 0    root         /opt/onionwarden/scripts/rotate-receiver-logs.sh
EOF
```

## Config knobs (the four you must edit)

1. **SSH listen address** — narrow from `0.0.0.0:<PORT>` to a specific
   IP. On Ubuntu 24.04 / Debian 13 sshd is often socket-activated; the
   real listen address is in `/etc/systemd/system/ssh.socket.d/listen.conf`
   (NOT `sshd_config Port`).
2. **ufw allow** — `ufw allow <PORT>/tcp`; or tighter,
   `ufw allow from <monitored-host-ip> to any port <PORT>` if your
   monitored hosts have known source IPs.
3. **ntfy endpoint** — uncomment `# ONIONWARDEN_RECEIVER_NTFY=` in
   `/etc/cron.d/onionwarden-receiver` and assign your ntfy URL. Left
   commented = no notification push; verify-check / seqcheck findings
   still print to cron's mail. Do NOT leave it uncommented-but-empty —
   Vixie cron rejects empty env-var values; the heredoc above ships
   commented out for exactly this reason.
4. **Per-host authorized_keys entries** — append ONE line per monitored
   host to `/var/lib/onionwarden/.ssh/authorized_keys`. Each line MUST
   pin the host_id as the forced-command first arg so a stolen key
   cannot impersonate another host (R1-F1):

   ```
   command="/var/lib/onionwarden/data/.bin/receiver-append.sh <host_id>",restrict ssh-ed25519 <PUBKEY> onionwarden-<host_id>
   ```

## Capturing the known-good baseline

ONCE, after the first round of events have arrived and the operator
has independently verified each host is in a known-good state:

```sh
sudo -u onionwarden /var/lib/onionwarden/data/.bin/onionwarden-receiver verify-record
```

That snapshots the current `selfhash` + `pubkeyhash` per host into
`<host>/known_good.json`. It also appends an audit-trail event to the
+a `events.log` (R2-F1) — keep both.

## Operating procedures

### Rotating the signing key (4-step dual-pin protocol)

The receiver signing key is currently inert (no live consumer), so
rotation today is zero-risk for verification. The procedure below is
the contract that future signing-of-digests code MUST honour, so
rotation never opens a verification gap. Do NOT compress these four
steps — skipping the overlap window makes every in-flight signed
message unverifiable for the duration of the gap.

1. **Generate the new keypair** on the receiver:
   ```sh
   sudo /opt/onionwarden/scripts/rotate-receiver-key.sh
   ```
   This atomically swaps the live keypair to the new one and keeps the
   old as `receiver.{priv,pub}.YYYYMMDD-HHMMSS.bak`. The script prints
   the sha256 fingerprint of both the new and old pubkeys.

2. **Publish BOTH pubkeys** to the repo fork:
   ```sh
   # on the laptop, after scp'ing the new pubkey back:
   cp receiver/receiver.pub receiver/receiver.pub.prev   # the OLD one
   cp <new-pubkey-from-receiver> receiver/receiver.pub   # the NEW one
   git add receiver/receiver.pub receiver/receiver.pub.prev
   git commit -m "rotate receiver signing key — overlap window opens"
   ```
   Verify the sha256 of `receiver.pub` matches what the script printed
   on the receiver: `openssl dgst -sha256 receiver/receiver.pub`.

3. **Roll collectors to pin BOTH pubkeys.** Once signing-of-digests is
   live, collectors will consult `verify_pubkey_paths = ["receiver.pub",
   "receiver.pub.prev"]` and accept a signed message verified by EITHER.
   Confirm the rollout reached every collector before step 4.

4. **After the overlap window** (≥ the longest in-flight signed-message
   TTL; 24h is ample for the current digest cadence), remove the
   previous pubkey:
   ```sh
   git rm receiver/receiver.pub.prev
   git commit -m "close receiver-key rotation overlap window"
   # then on the receiver:
   sudo rm /var/lib/onionwarden/receiver.{priv,pub}.YYYYMMDD-HHMMSS.bak
   ```

### Rotating the append-only events.log

`scripts/rotate-receiver-logs.sh` runs as root from the weekly cron
above. It lifts `chattr -a`, `mv`s to `events.log.YYYYMMDD-HHMMSS`,
gzips, recreates an empty events.log, and re-arms `chattr +a`.

### Per-host stale override

A daily-cadence host should not trip the default 30-minute staleness
warning. Override per host:

```sh
echo 1440 > /var/lib/onionwarden/data/<host>/.stale_minutes   # 24 h
```

### Migrating the receiver to a new host

1. Snapshot the current receiver (provider-specific — e.g. `vzdump` on
   Proxmox, EBS snapshot on AWS).
2. Provision the new host; install packages; create users.
3. rsync `/opt/onionwarden/` and `/var/lib/onionwarden/` to the new host.
4. Re-apply `chattr +a` on `events.log` files on the new FS.
5. Cut over per-monitored-host SSH config — update `receiver_host` /
   the SSH known-hosts pin to the new host's SSH key.
6. Decommission the old receiver (stop cron + power off).

## Verification checklist (post-install)

- [ ] `ss -tln` shows only `<configured-IP>:<PORT>`
- [ ] `ufw status` shows only `<PORT>/tcp ALLOW`
- [ ] `ssh -o PreferredAuthentications=password <admin>@<host>` → rejected
- [ ] `systemctl is-active cron ssh.socket` → both active
- [ ] one synthetic event lands at `/var/lib/onionwarden/data/<smoketest>/events.log`
- [ ] `verify-record` snapshots the smoketest host
- [ ] `verify-check` returns `ok smoketest`
- [ ] `seqcheck` returns `ok smoketest`
- [ ] `digest` lists the smoketest host with non-zero INFO count
- [ ] stop pushing for >`.stale_minutes` and confirm staleness CRIT fires
