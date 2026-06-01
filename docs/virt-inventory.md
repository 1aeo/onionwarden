# Relay virtualization inventory (OPERATOR_DECISIONS §6, ⚠ HIGH-RISK)

`OPERATOR_DECISIONS.md` §6 inventoried the VM-vs-bare-metal status of **`relay-b`
only**. That status drives two Phase-0 decisions for *every* host:

- **(a) the offline trust-establishment method** — a VM is scanned via a
  disk-snapshot mount; bare metal needs IPMI / a live-USB boot;
- **(b) whether `chattr +i` works** — FS-dependent, and the install probe only
  tells you per host after the fact.

So the whole fleet must be inventoried before Phase 0. `bin/onionwarden-virt-inventory`
does that, one JSON object per host.

## What it captures (no PII)

`systemd-detect-virt` (overall / `--container` / `--vm`), DMI `sys_vendor` /
`product_name` / `bios_version` (sysfs) + `dmidecode -s system-manufacturer`,
cgroup version + pid-1 cgroup line, and the namespace set + user-namespace
status. It derives a `verdict` of **bare-metal / vm / container / unknown** with
the `verdict_basis` that produced it. It captures **no serial numbers or UUIDs**
— only vendor/product/BIOS strings.

It's read-only and degrades gracefully: a probe that needs root (`dmidecode`) or
is absent is listed under `degraded`, never fatal.

## Run it per host (paste-block pattern)

The tool is **self-contained** (sources nothing), so stream it over SSH —
nothing is installed on the target, exactly like `onionwarden snapshot`:

```sh
# from your admin box, with the onionwarden repo checked out:
mkdir -p inventory
for h in gatedopen microopen almostopen vipopen kindaopen closedopen; do
  ssh "$h" 'bash -s' < bin/onionwarden-virt-inventory > "inventory/$h.json"
done
```

…or, on a single host you're already logged into, one line:

```sh
ssh <host> 'bash -s' < bin/onionwarden-virt-inventory
```

`dmidecode` needs root — if your SSH user isn't root, prefix the remote command
with `sudo`:

```sh
ssh "$h" 'sudo bash -s' < bin/onionwarden-virt-inventory > "inventory/$h.json"
```

Add any other hosts you run to the list above (these six are the known fleet;
substitute/extend as needed — `relay-a`/`relay-b` are PLAN doc names, not real
hosts).

## Roll the results up

Once you have `inventory/*.json`, a quick fleet table:

```sh
for f in inventory/*.json; do
  python3 - "$f" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print("%-14s %-11s %-28s %s" % (
    d["host_id"], d["verdict"],
    d["dmi"]["sys_vendor"]+"/"+d["dmi"]["product_name"],
    ("degraded:"+",".join(d["degraded"])) if d["degraded"] else ""))
PY
done
```

Then record each host's verdict back into `OPERATOR_DECISIONS.md` §6 / the
Appendix-A inventory and plan the offline scan per the (a)/(b) split above. If
`onionwarden fleet-diff` (PR: fleet-diff) is in use, the inventory JSON can sit
alongside each host's baseline for cross-checking.
