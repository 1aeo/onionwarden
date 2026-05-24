# MIGRATION_TO_PROXMOX.md

Migrate the onionwarden off-box receiver from the staging VM (LAN <RECEIVER_IP>) to
the eventual public-IP Proxmox host with a clean rsync + recreate sequence.

This document describes the receiver **as actually deployed** — an SSH-forced-
command + cron architecture, NOT a long-running TCP daemon. There is no
listening receiver port beyond SSH, no `receiver.conf` JSON, and no in-band
HTTP/HTTPS API. The receiver's "always-on" piece is cron; the "ingest" piece
is `receiver-append.sh` invoked by SSH ForceCommand.

## Architecture summary (one screen)

```
monitored host
  └─ ssh -i host_key -p 49876 onionwarden@<receiver> <<< '<json event>'
        │     (publickey-only, restricted-command authorized_keys entry)
        ▼
receiver
  ├─ sshd (socket-activated; ListenStream=49876 only)
  ├─ /opt/onionwarden-receiver/append-shim.sh   ← forced command, sets env
  │      └─ exec /opt/onionwarden-receiver/receiver-append.sh
  │           └─ append line → /var/lib/onionwarden/data/<host>/events.log
  └─ cron (as onionwarden):
       */5 verify-check    → CRIT on selfhash/pubkeyhash mismatch + stale events.log
       */5 seqcheck        → CRIT on per-host seq gaps + resets
       07:00 UTC digest    → daily fleet rollup
```

Two user accounts on the receiver:
- `aeo1` — interactive admin (sudo). Key-only SSH. No password-auth.
- `onionwarden` — system user (UID < 1000), `/bin/bash` shell, `/var/lib/onionwarden`
  home. Receives events over SSH via forced-command-only keys; never an
  interactive shell. Runs the cron jobs.

### Deviations from the original brief (and why)

The brief assumed a daemon model (Python HTTPS listener, `receiver.conf`,
`systemctl enable onionwarden-receiver`). The upstream receiver in
`secure-server/receiver/` is SSH-only — there is no daemon to enable.
Concretely:

| Original brief | Actually deployed | Reason |
|---|---|---|
| `useradd -s /usr/sbin/nologin` for `onionwarden` | `useradd -s /bin/bash` | SSH `ForceCommand` invokes the user's login shell to exec the command; `nologin` rejects SSH entirely. Lockdown is at the `authorized_keys` level (`restrict` + `command="..."`). |
| `onionwarden-receiver.service` systemd unit | `/etc/cron.d/onionwarden-receiver` | No daemon in upstream — only the three cron-driven scripts (`verify-check`, `seqcheck`, `digest`). |
| `receiver.conf` JSON with `listen_port`/`listen_address`/etc. | Env vars (`ONIONWARDEN_RECEIVER_ROOT`, `ONIONWARDEN_RECEIVER_NTFY`) | The codebase reads two env vars; there is no JSON config. Settings live in `/etc/cron.d/onionwarden-receiver` and `/opt/onionwarden-receiver/append-shim.sh`. |
| Receiver signing keypair signs every outgoing payload | Keypair generated at `/var/lib/onionwarden/receiver.{priv,pub}` (PEM) but no current code path consumes it | Upgrade path: kept ready so a future signing-of-digests change is drop-in (matches the `lib/ed25519.py` PEM format). |
| `Port 49876` in `sshd_config` controls listening | Ubuntu 24.04 socket-activates sshd; the real listen port is in `/etc/systemd/system/ssh.socket.d/listen.conf` | sshd_config `Port` is ignored when `ssh.socket` is active. Both files are written to keep `sshd_config` self-documenting *and* the socket override correct. |
| `ONIONWARDEN_RECEIVER_ROOT=/var/lib/onionwarden` | `ONIONWARDEN_RECEIVER_ROOT=/var/lib/onionwarden/data` | The home dir gets polluted by snap-confined tools (`/var/lib/onionwarden/snap`, `.cache`, `.local`) which `host_dirs()` would otherwise treat as fake "hosts." `data/` is an isolated subdirectory. |
| `chattr +a` on `events.log` for append-only defence in depth | Skipped — staging FS rejects it | `receiver-setup.sh` falls back silently. The primary append-only guarantee is the SSH forced command (it can `>>` but cannot `truncate` or `rm`). On a Proxmox host with ext4 + `user_xattr` it should succeed; re-run `receiver-setup.sh` post-migration and confirm. |

## Exact apt packages installed on staging (Ubuntu 24.04.2 LTS, kernel 6.17.0-29-generic)

Pinned versions as captured during the staging build:

```
python3                3.12.3-0ubuntu2.1
openssh-server         1:9.6p1-3ubuntu13.16
openssh-client         1:9.6p1-3ubuntu13.16
cron                   3.0pl1-184ubuntu2
ufw                    0.36.2-6
util-linux             2.39.3-9ubuntu6.5
passwd                 1:4.13+dfsg1-4ubuntu3.2
coreutils              9.4-3ubuntu6
libpam-modules         1.5.3-5ubuntu5.5
```

All come from the Ubuntu 24.04 main archive. No third-party PPA needed. No pip
packages installed — the receiver code uses only the Python 3.12 standard
library (`hashlib`, `json`, `os`, `sys`, `time`, `urllib.request`).

If the Proxmox host uses Debian 13 instead of Ubuntu 24.04, the package names
are the same but versions differ; the receiver code works on either.

## Files to rsync to the new host

| Source on staging | Dest on new host | Notes |
|---|---|---|
| `/opt/onionwarden-receiver/` | same | Source-of-truth: `receiver-append.sh`, `receiver-setup.sh`, `onionwarden-receiver`, `append-shim.sh`. Owned `root:root`, mode 0755. |
| `/var/lib/onionwarden/data/` | same | Per-host events.log + known_good.json + receiver.log. The growing audit trail. Owned `onionwarden:onionwarden`. |
| `/var/lib/onionwarden/.ssh/authorized_keys` | same | Restricted per-host forced-command entries. Owned `onionwarden:onionwarden`, mode 0600. |
| `/var/lib/onionwarden/receiver.priv` | same OR regenerate | Future-use signing key. See "Rotate or keep" below. |
| `/var/lib/onionwarden/receiver.pub` | same OR regenerate | Public counterpart (also in this repo at `receiver/receiver.pub`). |
| `/etc/cron.d/onionwarden-receiver` | same | Cron schedule. Edit the `ONIONWARDEN_RECEIVER_NTFY=` line if/when ntfy goes in. |
| `/etc/ssh/sshd_config.d/99-onionwarden-hardening.conf` | same | Keys-only, AllowUsers, MaxAuthTries, etc. |
| `/etc/systemd/system/ssh.socket.d/listen.conf` | EDIT then copy | This is the **real** listen-port file. See "Config knobs" below. |
| `/etc/ufw/user.rules`, `/etc/ufw/user6.rules` | re-create with `ufw allow` | rsyncing ufw state is brittle; cleaner to `ufw --force reset` then re-apply the rules. |
| **NOT** rsynced | `/etc/passwd`, `/etc/shadow`, `/etc/group` | Recreate users on the destination (see runbook). Carrying shadow across hosts leaks the staging password hashes. |

## User-creation steps (cannot rsync — recreate on the new host)

```sh
# aeo1 — interactive admin
useradd -m -s /bin/bash -G sudo aeo1
NEW_PASS=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits+'-_.'; print(''.join(secrets.choice(a) for _ in range(40)))")
echo "aeo1:${NEW_PASS}" | chpasswd
echo "CAPTURE NEW AEO1 PASSWORD INTO PWMGR: ${NEW_PASS}"
# (Don't carry the staging password — generate fresh.)

# onionwarden — ingest/cron, /bin/bash REQUIRED for SSH ForceCommand
useradd -r -m -d /var/lib/onionwarden -s /bin/bash onionwarden
```

Then install your laptop SSH pubkey to `aeo1`:
```sh
ssh-copy-id -i ~/.ssh/onionwarden_receiver.pub -p 22 operator@<new-host>
# (port 22 until you copy the ssh.socket override and reload)
```

## Config knobs that change for production

1. **`/etc/systemd/system/ssh.socket.d/listen.conf` — `ListenStream`**
   On staging this is `0.0.0.0:49876` (LAN). On the public Proxmox host, narrow
   to the specific public IP:
   ```
   [Socket]
   ListenStream=
   ListenStream=<public-ip>:49876
   ```
   Then `systemctl daemon-reload && systemctl restart ssh.socket`.

2. **`ufw allow 49876/tcp`** — same, but `ufw allow from <monitored-host-ip> to any port 49876` is tighter if the monitored fleet has known source IPs.

3. **`/etc/cron.d/onionwarden-receiver` — `ONIONWARDEN_RECEIVER_NTFY=`**
   On staging this is blank (no notification endpoint yet). In production fill
   in the real ntfy URL, e.g. `https://ntfy.example.com/onionwarden-fleet-CRIT`.
   The receiver only emits a notification on `verify-check` CRIT (mismatch or
   stale events.log).

4. **Per-host SSH ForceCommand entries in `/var/lib/onionwarden/.ssh/authorized_keys`**
   The staging file has one entry for the `smoketest` synthetic host. In
   production, append one line per real monitored host, format:
   ```
   command="/opt/onionwarden-receiver/append-shim.sh",restrict ssh-ed25519 <PUBKEY> onionwarden-<host>
   ```

5. **`ONIONWARDEN_RECEIVER_ROOT`** — only change if the storage layout differs
   (e.g. the public host mounts `/var/lib/onionwarden` from a different volume).
   The shim, the cron file, and any operator one-shot invocations must agree.

### Rotate or keep `receiver.priv` (the signing keypair)?

| Option | Pro | Con |
|---|---|---|
| **Keep** (rsync as-is) | No coordination with operators — the public key in `receiver/receiver.pub` stays valid. | Staging private key was generated in a less-trusted environment (the bootstrap VM); if the staging host was ever compromised, the key is compromised too. Today nothing on the receiver uses this key, so the practical risk is zero, but a future signing change inherits any prior leak. |
| **Rotate** | Clean cryptographic provenance — the public key is "born" on the production host. | One coordination step: regenerate, copy the new `receiver.pub` to the laptop, commit it to the repo, update any monitored host that pins the key. |

Recommendation: **rotate during the migration cutover**. It costs one commit
and is the right hygienic default for a key that will eventually go live.

```sh
# on the new host, as onionwarden:
openssl genpkey -algorithm ed25519 -out /var/lib/onionwarden/receiver.priv
openssl pkey -in /var/lib/onionwarden/receiver.priv -pubout -out /var/lib/onionwarden/receiver.pub
chmod 600 /var/lib/onionwarden/receiver.priv
# then copy receiver.pub back to the laptop and commit
```

## Migration runbook

```
0. Pre-flight
   - Snapshot the staging VM (Proxmox UI or `vzdump`).
   - Verify the staging receiver is healthy:
       ssh receiver 'cat /var/lib/onionwarden/data/smoketest/events.log | wc -l'
       systemctl status cron ssh.socket
       /opt/onionwarden-receiver/onionwarden-receiver verify-check
   - Confirm the laptop has a clean clone of secure-server/ with the latest
     receiver.pub committed.

1. Provision the new Proxmox VM (Ubuntu 24.04 LTS or Debian 13).

2. Install packages:
       apt update
       apt install -y python3 openssh-server cron ufw

3. Recreate users (see "User-creation steps" above). PRINT the new aeo1
   password ONCE; do not log it.

4. Install your laptop key on aeo1 (still on port 22 — bootstrap):
       ssh-copy-id -i ~/.ssh/onionwarden_receiver.pub operator@<new-host>

5. rsync the deployment trees from staging (or from a clean source clone):
       rsync -aHx /opt/onionwarden-receiver/  root@<new>:/opt/onionwarden-receiver/
       rsync -aHx /var/lib/onionwarden/       onionwarden@<new>:/var/lib/onionwarden/
       # then on <new>:
       chown -R onionwarden:onionwarden /var/lib/onionwarden
       chown -R root:root /opt/onionwarden-receiver

6. Install the SSH and cron config files (edit `listen.conf` to use the
   specific public IP — see "Config knobs"):
       cp /etc/ssh/sshd_config.d/99-onionwarden-hardening.conf  /etc/ssh/sshd_config.d/
       cp /etc/systemd/system/ssh.socket.d/listen.conf        /etc/systemd/system/ssh.socket.d/
       cp /etc/cron.d/onionwarden-receiver                       /etc/cron.d/
       systemctl daemon-reload
       sshd -t  &&  systemctl restart ssh.socket

7. Verify key-only login on the new port from a SECOND shell BEFORE closing 22.
   (Mirror the staging two-phase pattern from the original setup.)

8. Set up ufw:
       ufw default deny incoming; ufw default allow outgoing
       ufw allow 49876/tcp comment 'ssh (onionwarden)'
       ufw --force enable

9. Optional: rotate receiver signing key (see "Rotate or keep"); commit the
   new receiver.pub to the repo.

10. Smoke-test (mirror the staging smoke test) — push a synthetic heartbeat +
    selfreport via the smoketest key; run verify-record, verify-check,
    seqcheck, digest; confirm stale fires after >1min with
    `ONIONWARDEN_STALE_MINUTES=1`.

11. Cutover: on each monitored host, update `/etc/onionwarden/host.conf` to point
    at the new receiver hostname/IP and the new public key fingerprint
    (StrictHostKeyChecking on the host side; if you pinned the staging SSH
    host key, you'll need to either re-pin to the new key or delete the old
    pinning). Push one event per host and verify it lands.

12. Decommission staging:
    - Verify all 9 hosts now appear in the new host's `digest` output.
    - Stop cron on staging:  systemctl disable --now cron
    - Power off the staging VM; keep the snapshot for ~30 days as rollback.
    - Remove the staging IP from any DNS / monitored-host configs / runbooks.
```

## Verify-after-migration checklist

After step 11, on the new host:

- [ ] `ss -tln` shows only `<public-ip>:49876` (or 0.0.0.0:49876 if not narrowed)
- [ ] `ufw status` shows only 49876/tcp ALLOW
- [ ] `ssh -o PreferredAuthentications=password operator@<new-host>` → rejected
- [ ] `systemctl is-active cron ssh.socket` → both active
- [ ] `/opt/onionwarden-receiver/onionwarden-receiver verify-check` returns `ok` for every monitored host
- [ ] `/opt/onionwarden-receiver/onionwarden-receiver digest` lists every monitored host with non-zero INFO count in the 24h window
- [ ] Synthetic stale test (`ONIONWARDEN_STALE_MINUTES=1`, stop pushing for 60+s) fires the CRIT push to ntfy

## Things this document does NOT cover (out of scope for the receiver)

- Per-host `onionwarden` watchdog install on monitored hosts (separate runbook in
  the repo — see `install.sh` and `PLAN.md`).
- Operator signing-key custody for fleet baselines (see `OPERATOR_DECISIONS.md`).
- ntfy / Healthchecks.io endpoint provisioning.
- DNS / certificate pinning for the public-IP cutover.
