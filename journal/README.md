# Off-box journal shipping (L6)

Closes the **log-vacuum gap** flagged in PLAN §2.7 / §6 (L6): the on-box
`journalctl --verify` daily check catches journal *corruption*, but a root
attacker can run `journalctl --vacuum-time=1s` for a clean, verify-passing wipe.
Streaming each host's journal off-box makes that wipe detectable — the receiver
already holds the copy.

```
 monitored host                                   off-box receiver
 ┌───────────────────────────┐                    ┌──────────────────────────────┐
 │ systemd-journald           │                    │ systemd-journal-remote.socket │
 │   Storage=persistent       │  mTLS https        │   ListenStream=19532          │
 │ systemd-journal-upload  ───┼───────────────────>│   SplitMode=host              │
 │   URL=https://recv:19532   │                    │ /var/log/journal/remote/      │
 └───────────────────────────┘                    │   remote-<host>.journal       │
                                                   └──────────────────────────────┘
```

This is a **separate channel** from onionwarden's signed `events.log` SSH push:
events.log carries structured findings; journal shipping carries the raw system
journal so a post-incident investigator (and the receiver) has the logs the host
might delete.

## Packages

- monitored host: `systemd-journal-remote` (ships `systemd-journal-upload`)
- receiver: `systemd-journal-remote`

```sh
apt-get install -y systemd-journal-remote
```

## mTLS material (do this first)

Journals must not cross the network in cleartext, and the receiver must accept
streams only from real fleet hosts. Both ends use mutual TLS. Provision a small
internal CA out-of-band (the same offline/trusted machine that holds the fleet
signing key is a fine home for it):

```
ca.crt          # the fleet journal CA (public)  -> every host + receiver
upload.key/crt  # per-monitored-host client cert -> that host's --cert-dir
remote.key/crt  # the receiver's server cert      -> receiver's --cert-dir
```

Default `--cert-dir` is `/etc/onionwarden/journal` on both ends. Keep the `.key`
files mode 0600, owned by the service user.

> Lab / pre-prod only: `--http` skips all of this and ships in cleartext with no
> peer auth. Never use it on a real relay.

## Receiver setup

```sh
sudo /opt/onionwarden/scripts/journal-remote-setup.sh \
    --port 19532 --cert-dir /etc/onionwarden/journal --enable
# then open the port to fleet source IPs only:
sudo ufw allow from <relay-ip> to any port 19532 proto tcp
```

Renders `/etc/systemd/journal-remote.conf.d/10-onionwarden.conf` (SplitMode=host,
mTLS) + the socket listen drop-in, creates `/var/log/journal/remote`, and enables
`systemd-journal-remote.socket`. Idempotent — safe to re-run.

## Monitored-host setup

Run from the onionwarden **repo checkout** on the host (the same checkout you ran
`install.sh` from — `install.sh` deliberately does not copy `scripts/`/`journal/`
into `/opt/onionwarden`, to keep them out of the Phase-1/2 self-hash set):

```sh
cd /path/to/onionwarden            # the cloned repo on the host
sudo ./scripts/journal-ship-setup.sh \
    --receiver-host recv.example.net --port 19532 \
    --cert-dir /etc/onionwarden/journal --enable
```

Renders the persistent-journald drop-in, the `journal-upload.conf.d` drop-in
(URL + mTLS), and a hardening drop-in for `systemd-journal-upload.service`, then
enables the uploader. Idempotent.

## Verify

```sh
# on the receiver, after a host has uploaded:
ls -l /var/log/journal/remote/remote-<host>.journal
journalctl --file=/var/log/journal/remote/remote-<host>.journal -n 20
# on the host:
systemctl status systemd-journal-upload     # active, cursor advancing
```

A persistent gap in `remote-<host>.journal` while the host is up is itself a
signal — pair it with the receiver's staleness checks.
