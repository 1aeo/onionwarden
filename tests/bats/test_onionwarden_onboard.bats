#!/usr/bin/env bats
# Tests for bin/onionwarden-onboard — flag parsing + dry-run output.
#
# These are pure-local: --dry-run never touches SSH/scp/rsync, so the suite
# runs on any machine with bats + bash. Real SSH integration is out of scope
# (it would need a fleet) — covered by the runbook in docs/ONBOARDING.md.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  SCRIPT="$REPO/bin/onionwarden-onboard"
  FIXTURES="$BATS_TEST_DIRNAME/fixtures"

  # Scratch hosts/ dir with a fake signed host.conf so --check passes the
  # "exists" branch without us needing a real signature.
  HOSTS=$(mktemp -d "${TMPDIR:-/tmp}/onbard-hosts.XXXXXX")
  printf 'host_id = "fakehost"\nrole = "tor-relay"\n' > "$HOSTS/fakehost.conf"
  printf 'fakesig\n' > "$HOSTS/fakehost.conf.sig"
  PUB=$(mktemp "${TMPDIR:-/tmp}/onbard-pub.XXXXXX")
  printf -- '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n' > "$PUB"
}

teardown() {
  rm -rf "$HOSTS"
  rm -f "$PUB"
}

# --- usage / flag-parsing -------------------------------------------------

@test "--help prints usage and exits 0" {
  run "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"formal-onboarding wrapper"* ]]
  [[ "$output" == *"--check"* ]]
  [[ "$output" == *"--draft-host-conf"* ]]
  [[ "$output" == *"--install"* ]]
  [[ "$output" == *"--verify"* ]]
  [[ "$output" == *"--rollback"* ]]
}

@test "--version prints the version tag" {
  run "$SCRIPT" --version
  [ "$status" -eq 0 ]
  [[ "$output" == "onionwarden-onboard/"* ]]
}

@test "no mode = exit 2 usage error" {
  run "$SCRIPT" relay_a
  [ "$status" -eq 2 ]
  [[ "$output" == *"exactly one mode required"* ]]
}

@test "no host = exit 2 usage error" {
  run "$SCRIPT" --check
  [ "$status" -eq 2 ]
  [[ "$output" == *"missing HOST"* ]]
}

@test "two modes = exit 2 (mutually exclusive)" {
  run "$SCRIPT" --check --install relay_a
  [ "$status" -eq 2 ]
  [[ "$output" == *"mutually exclusive"* ]]
}

@test "two hosts = exit 2 (only one positional)" {
  run "$SCRIPT" --check relay_a relay_b
  [ "$status" -eq 2 ]
  [[ "$output" == *"only one HOST"* ]]
}

@test "unknown flag = exit 2" {
  run "$SCRIPT" --check --bogus-flag relay_a
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown option"* ]]
}

# --- require_arg: long-options need a non-flag value (CodeRabbit PR #2) ----

@test "--ssh-target with no following value = exit 2" {
  run "$SCRIPT" --check fakehost --ssh-target
  [ "$status" -eq 2 ]
  [[ "$output" == *"--ssh-target requires a value"* ]]
}

@test "--receiver consuming a following flag = exit 2" {
  run "$SCRIPT" --check --receiver --verify fakehost
  [ "$status" -eq 2 ]
  [[ "$output" == *"--receiver requires a value"* ]]
}

@test "--stale-window with empty value = exit 2" {
  run "$SCRIPT" --verify --stale-window "" fakehost
  [ "$status" -eq 2 ]
  [[ "$output" == *"--stale-window requires a value"* ]]
}

# --- dry-run output matches expected patterns -----------------------------

@test "--check --dry-run prints all five pre-flight steps" {
  run "$SCRIPT" --check --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"Pre-flight on fakehost"* ]]
  [[ "$output" == *"non-interactive SSH"* ]]
  [[ "$output" == *"OS family"* ]]
  [[ "$output" == *"passwordless sudo"* ]]
  [[ "$output" == *"cron python3 tcpdump bpftool"* ]]
  [[ "$output" == *"hosts/fakehost.conf"* ]]
  [[ "$output" == *"SSH path target->receiver"* ]]
  [[ "$output" == *"pre-flight clean"* ]]
}

@test "--install --dry-run runs preflight then install + receiver wiring" {
  run "$SCRIPT" --install --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    fakehost
  [ "$status" -eq 0 ]
  # preflight comes first
  [[ "$output" == *"Pre-flight on fakehost"* ]]
  # then install
  [[ "$output" == *"Install onionwarden on fakehost"* ]]
  [[ "$output" == *"rsync"* ]]
  [[ "$output" == *"scp"* ]]
  [[ "$output" == *"install.sh"* ]]
  [[ "$output" == *"--answers /tmp/onionwarden-host.conf"* ]]
  [[ "$output" == *"--pubkey /tmp/onionwarden.pub"* ]]
  [[ "$output" == *"crontab"* ]]
  # then receiver wiring
  [[ "$output" == *"Receiver wiring"* ]]
  [[ "$output" == *"offbox_ed25519.pub"* ]]
  # then dispatch_at_install
  [[ "$output" == *"dispatch_at_install"* ]]
  [[ "$output" == *"onionwarden run fast"* ]]
  # and next-steps
  [[ "$output" == *"baseline collect"* ]]
}

@test "--install --dry-run --no-chattr passes --no-immutable to install.sh" {
  run "$SCRIPT" --install --dry-run --no-chattr \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"--no-immutable"* ]]
}

@test "--install --dry-run WITHOUT --no-chattr does NOT pass --no-immutable" {
  run "$SCRIPT" --install --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" != *"--no-immutable"* ]]
}

@test "--verify --dry-run prints dead-man's switch round-trip + first-arm checklist" {
  run "$SCRIPT" --verify --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"Post-install verification for fakehost"* ]]
  [[ "$output" == *"is-enabled --quiet onionwarden-fast.timer"* ]]
  [[ "$output" == *"force a heartbeat"* ]]
  [[ "$output" == *"events.log"* ]]
  [[ "$output" == *"Dead-man's switch round-trip"* ]]
  [[ "$output" == *"sleep 240"* ]]
  [[ "$output" == *"First-arm checklist"* ]]
  [[ "$output" == *"Quiet baseline"* ]]
  [[ "$output" == *"OOB recovery"* ]]
  [[ "$output" == *"past Phase 2"* ]]
}

@test "--verify without --receiver and no fallback = exit 4 (fail-fast)" {
  # No .env, no offbox_log_target in fakehost.conf → must fail loudly
  # rather than silently skip the receiver round-trip (CodeRabbit PR #3).
  run "$SCRIPT" --verify --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    fakehost
  [ "$status" -eq 4 ]
  [[ "$output" == *"could not derive"* ]]
  [[ "$output" == *"offbox_log_target"* ]]
}

@test "--verify --receiver derived from hosts/<HOST>.conf offbox_log_target" {
  # Add an offbox_log_target line so _resolve_receiver picks it up.
  printf 'offbox_log_target = "onionwarden@receiver.example.net:~/data/fakehost/events.log"\n' \
    >> "$HOSTS/fakehost.conf"
  run "$SCRIPT" --verify --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"onionwarden@receiver.example.net"* ]]
  [[ "$output" == *"events.log"* ]]
  [[ "$output" == *"Dead-man's switch round-trip"* ]]
}

@test "--install fail-fast when no --receiver and no fallback" {
  run "$SCRIPT" --install --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    fakehost
  [ "$status" -eq 4 ]
  [[ "$output" == *"could not derive"* ]]
}

@test "--verify --dry-run --stale-window overrides the default" {
  run "$SCRIPT" --verify --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    --stale-window 660 \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"sleep 660"* ]]
  [[ "$output" != *"sleep 240"* ]]
}

@test "--rollback --dry-run disables timers + removes /opt/onionwarden" {
  run "$SCRIPT" --rollback --dry-run fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"Rollback onionwarden on fakehost"* ]]
  [[ "$output" == *"systemctl disable --now onionwarden-fast.timer"* ]]
  [[ "$output" == *"crontab"* ]]
  [[ "$output" == *"chattr -R -i /opt/onionwarden"* ]]
  [[ "$output" == *"rm -rf /opt/onionwarden /etc/onionwarden"* ]]
  [[ "$output" == *"daemon-reload"* ]]
  [[ "$output" == *"retained for forensics"* ]]
}

@test "--draft-host-conf --dry-run calls onionwarden snapshot" {
  run "$SCRIPT" --draft-host-conf --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --with-sudo \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"Draft host.conf for fakehost"* ]]
  [[ "$output" == *"onionwarden snapshot fakehost"* ]]
  [[ "$output" == *"--with-sudo"* ]]
  [[ "$output" == *"write draft host.conf"* ]]
}

@test "--ssh-target overrides HOST for SSH" {
  run "$SCRIPT" --check --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --ssh-target operator@fakehost.internal:36128 \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"Pre-flight on operator@fakehost.internal:36128"* ]]
  [[ "$output" == *"host_id=fakehost"* ]]
}

@test "--ssh-opt is repeatable and forwarded to ssh" {
  run "$SCRIPT" --install --dry-run \
    --hosts-dir "$HOSTS" --pubkey "$PUB" \
    --receiver onionwarden@receiver.example.net:22922 \
    --ssh-opt "ProxyJump=bastion" \
    --ssh-opt "User=ops" \
    fakehost
  [ "$status" -eq 0 ]
  [[ "$output" == *"-o ProxyJump=bastion"* ]]
  [[ "$output" == *"-o User=ops"* ]]
}

# --- fixture-based diff: catch silent dry-run output drift ----------------

@test "--rollback --dry-run output matches fixture" {
  run "$SCRIPT" --rollback --dry-run fakehost
  [ "$status" -eq 0 ]
  # Normalise the repo-root path that appears in the [dry-run] lines (a
  # caller running from a worktree will see a different absolute path).
  normalised=$(printf '%s\n' "$output" | sed "s|$REPO|<REPO>|g")
  expected=$(cat "$FIXTURES/rollback-dryrun.expected")
  if [ "$normalised" != "$expected" ]; then
    printf 'GOT:\n%s\n\nEXPECTED:\n%s\n' "$normalised" "$expected" >&3
    return 1
  fi
}
