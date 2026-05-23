"""Per-check unit tests — every check gets a positive, a negative, and (where
it has one) an allowlist / suppression path. analyze() is a pure function of
fixture state, so these run on any OS."""
from conftest import run_analyze, severities, fatal_findings

GENERIC = 'host_id="t"\nrole="generic"\n'


# --- taint ----------------------------------------------------------------
def test_taint_positive_fatal():
    f = run_analyze("taint", ["tainted 0"], ["tainted 4096"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_taint_negative_clean():
    assert run_analyze("taint", ["tainted 0"], ["tainted 0"], GENERIC) == []


def test_taint_allowlist_demotes():
    cfg = GENERIC + 'expected_taint_bits = ["O"]\n'
    f = run_analyze("taint", ["tainted 0"], ["tainted 4096"], cfg)
    assert f[0]["severity"] == "INFO" and f[0]["fatal_candidate"] is False


def test_taint_livepatch_K_unexpected_is_crit_fatal():  # R7-1
    f = run_analyze("taint", ["tainted 0"], ["tainted 32768"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_taint_livepatch_K_allowlisted_is_info():  # R7-1
    cfg = GENERIC + 'expected_taint_bits = ["K"]\n'
    f = run_analyze("taint", ["tainted 0"], ["tainted 32768"], cfg)
    assert f[0]["severity"] == "INFO" and f[0]["fatal_candidate"] is False


def test_taint_unknown_bit_graceful():
    f = run_analyze("taint", ["tainted 0"], ["tainted 1073741824"], GENERIC)
    assert f[0]["severity"] == "WARN" and "unknown" in f[0]["summary"]


def test_taint_container_skips():  # R10-3
    f = run_analyze("taint", ["tainted 0"], ["na container"], GENERIC)
    assert f[0]["severity"] == "NA"


def test_kernel_state_container_skips():  # R10-3
    f = run_analyze("kernel_state", ["kexec loaded 0"], ["na container"], GENERIC)
    assert f[0]["severity"] == "NA"


def test_boot_integrity_container_skips():  # R10-3
    f = run_analyze("boot_integrity", ["cmdline ro quiet"], ["na container"], GENERIC)
    assert f[0]["severity"] == "NA"


# --- modules --------------------------------------------------------------
def test_modules_positive_out_of_tree_fatal():
    f = run_analyze("modules", ["module a -", "xcheck ok"],
                    ["module a -", "module evil O", "xcheck ok"], GENERIC)
    assert any(x["severity"] == "CRIT" and x["fatal_candidate"] for x in f)


def test_modules_negative_clean():
    base = ["module a -", "module b -", "xcheck ok"]
    assert run_analyze("modules", base, base, GENERIC) == []


def test_modules_allowlist():
    cfg = GENERIC + 'expected_extra_modules = ["evil"]\n'
    f = run_analyze("modules", ["module a -", "xcheck ok"],
                    ["module a -", "module evil -", "xcheck ok"], cfg)
    assert f[0]["severity"] == "INFO"


def test_modules_xcheck_disagree_crit():
    f = run_analyze("modules", ["module a -", "xcheck ok"],
                    ["module a -", "xcheck disagree lsmod_vs_proc=x"], GENERIC)
    assert any(x["signal"] == "module_xcheck" and x["fatal_candidate"] for x in f)


# --- ports ----------------------------------------------------------------
def test_ports_positive_crit():
    f = run_analyze("ports", ["listener tcp 0.0.0.0 22 sshd"],
                    ["listener tcp 0.0.0.0 22 sshd",
                     "listener tcp 0.0.0.0 4444 nc"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_ports_negative_clean():
    base = ["listener tcp 0.0.0.0 22 sshd"]
    assert run_analyze("ports", base, base, GENERIC) == []


def test_ports_allowlist_demotes():
    cfg = GENERIC + "expected_lan_ports = [4444]\n"
    f = run_analyze("ports", ["listener tcp 0.0.0.0 22 sshd"],
                    ["listener tcp 0.0.0.0 22 sshd",
                     "listener tcp 0.0.0.0 4444 nc"], cfg)
    assert f[0]["severity"] == "INFO"


# --- listener_binding (expected_listen_binding_<port>_<proto>) ----
def _binding_findings(findings):
    return [f for f in findings if f.get("signal") == "listener_binding"]


def test_binding_exact_ip_match_no_finding():
    cfg = GENERIC + 'expected_listen_binding_179_tcp = "203.0.113.50"\n'
    f = run_analyze("ports",
                    ["listener tcp 203.0.113.50 179 bgpd"],
                    ["listener tcp 203.0.113.50 179 bgpd"], cfg)
    assert _binding_findings(f) == []


def test_binding_set_match_no_finding():
    cfg = GENERIC + 'expected_listen_binding_22_tcp = ["192.0.2.50", "127.0.0.1"]\n'
    f = run_analyze("ports",
                    ["listener tcp 127.0.0.1 22 sshd"],
                    ["listener tcp 127.0.0.1 22 sshd"], cfg)
    assert _binding_findings(f) == []


def test_binding_loopback_token_match():
    cfg = GENERIC + 'expected_listen_binding_3000_tcp = "loopback"\n'
    f = run_analyze("ports", ["listener tcp 127.0.0.1 3000 node"],
                    ["listener tcp 127.0.0.1 3000 node"], cfg)
    assert _binding_findings(f) == []


def test_binding_loopback_token_mismatch_warn():
    cfg = GENERIC + 'expected_listen_binding_3000_tcp = "loopback"\n'
    f = run_analyze("ports", ["listener tcp 0.0.0.0 3000 node"],
                    ["listener tcp 0.0.0.0 3000 node"], cfg)
    b = _binding_findings(f)
    assert b and b[0]["severity"] == "WARN"


def test_binding_local_token_match():
    cfg = GENERIC + 'expected_listen_binding_443_tcp = "local"\n'
    f = run_analyze("ports", ["listener tcp 198.51.100.1.42 443 tor"],
                    ["listener tcp 198.51.100.1.42 443 tor"], cfg)
    assert _binding_findings(f) == []


def test_binding_local_token_mismatch():
    cfg = GENERIC + 'expected_listen_binding_443_tcp = "local"\n'
    f = run_analyze("ports", ["listener tcp 0.0.0.0 443 tor"],
                    ["listener tcp 0.0.0.0 443 tor"], cfg)
    assert _binding_findings(f) and _binding_findings(f)[0]["severity"] == "WARN"


def test_binding_any_token_no_finding():
    cfg = GENERIC + 'expected_listen_binding_22_tcp = "any"\n'
    f = run_analyze("ports",
                    ["listener tcp 0.0.0.0 22 sshd"],
                    ["listener tcp 0.0.0.0 22 sshd"], cfg)
    assert _binding_findings(f) == []


def test_binding_no_entry_defaults_any():
    f = run_analyze("ports",
                    ["listener tcp 0.0.0.0 22 sshd"],
                    ["listener tcp 0.0.0.0 22 sshd"], GENERIC)
    assert _binding_findings(f) == []


def test_binding_wildcard_regression_is_crit_when_in_lan_ports():
    cfg = (GENERIC
           + "expected_lan_ports = [179]\n"
           + 'expected_listen_binding_179_tcp = "203.0.113.50"\n')
    f = run_analyze("ports",
                    ["listener tcp 203.0.113.50 179 bgpd"],
                    ["listener tcp 0.0.0.0 179 bgpd"], cfg)
    b = _binding_findings(f)
    assert b and b[0]["severity"] == "CRIT" and "regression" in b[0]["summary"]
    assert "203.0.113.50" in b[0]["summary"] and "0.0.0.0" in b[0]["summary"]


def test_binding_other_specific_ip_mismatch_is_warn():
    cfg = (GENERIC
           + "expected_lan_ports = [179]\n"
           + 'expected_listen_binding_179_tcp = "203.0.113.50"\n')
    f = run_analyze("ports",
                    ["listener tcp 203.0.113.50 179 bgpd"],
                    ["listener tcp 203.0.113.99 179 bgpd"], cfg)
    b = _binding_findings(f)
    assert b and b[0]["severity"] == "WARN"


def test_binding_ipv6_wildcard_regression_is_crit():
    cfg = (GENERIC
           + "expected_lan_ports = [179]\n"
           + 'expected_listen_binding_179_tcp = "203.0.113.50"\n')
    f = run_analyze("ports",
                    ["listener tcp 203.0.113.50 179 bgpd"],
                    ["listener tcp [::] 179 bgpd"], cfg)
    b = _binding_findings(f)
    assert b and b[0]["severity"] == "CRIT"


def test_binding_per_protocol_tcp_vs_udp_independent():
    # only tcp/53 has an expectation; udp/53 must use the default "any"
    cfg = GENERIC + 'expected_listen_binding_53_tcp = "loopback"\n'
    f = run_analyze("ports",
                    ["listener udp 0.0.0.0 53 dnsmasq"],
                    ["listener udp 0.0.0.0 53 dnsmasq"], cfg)
    assert _binding_findings(f) == []
    # tcp/53 with the same wildcard DOES fire (loopback expected)
    f = run_analyze("ports",
                    ["listener tcp 0.0.0.0 53 dnsmasq"],
                    ["listener tcp 0.0.0.0 53 dnsmasq"], cfg)
    assert _binding_findings(f) and _binding_findings(f)[0]["severity"] == "WARN"


def test_binding_relay-a_bgp_current_state_no_finding():
    """Mirrors relay-a's post-rebind BGP state: bgpd on 203.0.113.50:179."""
    cfg = (GENERIC
           + "expected_lan_ports = [22, 179, 443]\n"
           + 'expected_listen_binding_179_tcp = "203.0.113.50"\n'
           + 'expected_listen_binding_22_tcp  = "any"\n'
           + 'expected_listen_binding_443_tcp = "local"\n')
    cur = ["listener tcp 0.0.0.0 22 sshd",
           "listener tcp 203.0.113.50 179 bgpd",
           "listener tcp 198.51.100.1.1 443 tor",
           "listener tcp 198.51.100.1.99 443 tor",
           "listener tcp 127.0.0.1 5353 systemd-resolve"]
    f = run_analyze("ports", cur, cur, cfg)
    assert _binding_findings(f) == []


def test_binding_relay-a_bgp_regression_is_crit():
    """Synthetic regression: bgpd back on 0.0.0.0:179 — must page."""
    cfg = (GENERIC
           + "expected_lan_ports = [22, 179, 443]\n"
           + 'expected_listen_binding_179_tcp = "203.0.113.50"\n')
    cur = ["listener tcp 203.0.113.50 179 bgpd"]
    bad = ["listener tcp 0.0.0.0 179 bgpd"]
    f = run_analyze("ports", cur, bad, cfg)
    b = _binding_findings(f)
    assert b and b[0]["severity"] == "CRIT"
    assert "0.0.0.0" in b[0]["summary"] and "203.0.113.50" in b[0]["summary"]


# --- ssh ------------------------------------------------------------------
def test_ssh_positive_new_key_fatal():
    f = run_analyze("ssh",
                    ["authkeys root /root/.ssh/authorized_keys a 1"],
                    ["authkeys root /root/.ssh/authorized_keys b 2"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_ssh_negative_clean():
    base = ["authkeys root /root/.ssh/authorized_keys a 1", "sshd permitrootlogin no"]
    assert run_analyze("ssh", base, base, GENERIC) == []


def test_ssh_permitrootlogin_weakening_crit():
    f = run_analyze("ssh", ["sshd permitrootlogin no"],
                    ["sshd permitrootlogin yes"], GENERIC)
    assert f[0]["severity"] == "CRIT"


# --- accounts -------------------------------------------------------------
def test_accounts_positive_new_uid0_fatal():
    f = run_analyze("accounts", ["filehash /etc/passwd a", "uid0 root"],
                    ["filehash /etc/passwd a", "uid0 root", "uid0 hax"], GENERIC)
    assert any(x["signal"] == "uid0" and x["fatal_candidate"] for x in f)


def test_accounts_negative_clean():
    base = ["filehash /etc/passwd a", "uid0 root"]
    assert run_analyze("accounts", base, base, GENERIC) == []


def test_accounts_allowlist_uid0():
    cfg = GENERIC + 'expected_uid0 = ["root", "toor"]\n'
    f = run_analyze("accounts", ["filehash /etc/passwd a", "uid0 root"],
                    ["filehash /etc/passwd a", "uid0 root", "uid0 toor"], cfg)
    assert f[0]["severity"] == "INFO"


# --- ld_preload -----------------------------------------------------------
def test_ld_preload_positive_fatal():
    f = run_analyze("ld_preload", ["ldsopreload empty -"],
                    ["ldsopreload nonempty deadbeef /tmp/x.so;"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_ld_preload_negative_clean():
    assert run_analyze("ld_preload", ["ldsopreload empty -"],
                       ["ldsopreload empty -"], GENERIC) == []


# --- watchdog_meta --------------------------------------------------------
def test_watchdog_meta_positive_masked():
    f = run_analyze("watchdog_meta",
                    ["unit onionwarden-fast.timer enabled active", "selfhash a"],
                    ["unit onionwarden-fast.timer masked inactive", "selfhash a"],
                    GENERIC)
    assert any(x["severity"] == "CRIT" for x in f)


def test_watchdog_meta_negative_clean():
    base = ["unit onionwarden-fast.timer enabled active", "selfhash a", "pubkeyhash p"]
    assert run_analyze("watchdog_meta", base, base, GENERIC) == []


def test_watchdog_meta_pubkey_swap_fatal():
    f = run_analyze("watchdog_meta",
                    ["unit onionwarden-fast.timer enabled active", "selfhash a", "pubkeyhash p"],
                    ["unit onionwarden-fast.timer enabled active", "selfhash a", "pubkeyhash EVIL"],
                    GENERIC)
    assert any(x["signal"] == "pubkey_hash" and x["fatal_candidate"] for x in f)


# --- promisc --------------------------------------------------------------
def test_promisc_positive_physical_fatal():
    f = run_analyze("promisc", ["iface eth0 physical 0 0 -"],
                    ["iface eth0 physical 1 1 -"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_promisc_negative_clean():
    base = ["iface eth0 physical 0 0 -", "iface lo loopback 0 0 -"]
    assert run_analyze("promisc", base, base, GENERIC) == []


def test_promisc_virtual_excluded():
    f = run_analyze("promisc", ["iface veth0 virtual:veth 0 0 -"],
                    ["iface veth0 virtual:veth 1 1 -"], GENERIC)
    assert all(not x["fatal_candidate"] for x in f)


def test_promisc_xcheck_disagree_fatal():
    f = run_analyze("promisc", ["iface eth0 physical 0 0 -"],
                    ["iface eth0 physical 0 1 -"], GENERIC)
    assert any(x["signal"] == "promisc_xcheck" and x["fatal_candidate"] for x in f)


def test_promisc_allow_virt_churn_demotes_physical():  # R6-1
    cfg = GENERIC + "allow_virt_churn = true\n"
    f = run_analyze("promisc", ["iface eth0 physical 0 0 -"],
                    ["iface eth0 physical 1 1 -"], cfg)
    assert f[0]["severity"] == "WARN" and f[0]["fatal_candidate"] is False


def test_promisc_hypervisor_profile_demotes_physical():  # R6-3
    f = run_analyze("promisc", ["iface eth0 physical 0 0 -"],
                    ["iface eth0 physical 1 1 -"], GENERIC,
                    profile=["is_hypervisor=true"])
    assert f[0]["severity"] == "WARN" and f[0]["fatal_candidate"] is False


def test_promisc_virtual_xcheck_not_fatal():  # R6-2
    f = run_analyze("promisc", ["iface veth0 virtual:veth 0 0 -"],
                    ["iface veth0 virtual:veth 0 1 -"], GENERIC)
    xc = [x for x in f if x["signal"] == "promisc_xcheck"]
    assert xc and xc[0]["severity"] == "WARN" and xc[0]["fatal_candidate"] is False


# --- input_devices --------------------------------------------------------
def test_input_devices_positive_fatal():
    f = run_analyze("input_devices", ["collected ok"],
                    ["usbhid 03/01/01 dead:beef Kbd", "collected ok"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_input_devices_negative_clean():
    base = ["usbhid 03/01/01 0001:0001 Old", "collected ok"]
    assert run_analyze("input_devices", base, base, GENERIC) == []


def test_input_devices_physical_access_allowed_demotes():
    cfg = GENERIC + "physical_access_allowed = true\n"
    f = run_analyze("input_devices", ["collected ok"],
                    ["usbhid 03/01/01 dead:beef Kbd", "collected ok"], cfg)
    assert f[0]["severity"] == "INFO"


def test_input_devices_suppress_window_demotes_to_warn():
    f = run_analyze("input_devices", ["collected ok"],
                    ["usbhid 03/01/01 dead:beef Kbd", "collected ok"], GENERIC,
                    env={"ONIONWARDEN_SUPPRESS_PHYSICAL": "active"})
    assert f[0]["severity"] == "WARN" and f[0]["fatal_candidate"] is False


def test_input_devices_allowlist_demotes():  # R5-1
    cfg = GENERIC + 'expected_input_devices = ["dead:beef"]\n'
    f = run_analyze("input_devices", ["collected ok"],
                    ["usbhid 03/01/01 dead:beef Kbd", "collected ok"], cfg)
    assert f[0]["severity"] == "INFO" and f[0]["fatal_candidate"] is False


def test_input_devices_kmsg_hotplug_caught():  # R5-2
    f = run_analyze("input_devices", ["collected ok"],
                    ["kmsg_input EvilUSB Keyboard", "collected ok"], GENERIC)
    assert f[0]["severity"] == "CRIT" and "kernel logged" in f[0]["summary"]


# --- console_login --------------------------------------------------------
def test_console_login_positive_fatal():
    f = run_analyze("console_login", ["collected ok"],
                    ["console tty1 root", "collected ok"], GENERIC,
                    env={"ONIONWARDEN_SUPPRESS_PHYSICAL": "inactive"})
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_console_login_negative_clean():
    base = ["console tty1 root", "collected ok"]
    assert run_analyze("console_login", base, base, GENERIC) == []


def test_console_login_suppress_demotes():
    f = run_analyze("console_login", ["collected ok"],
                    ["console tty1 root", "collected ok"], GENERIC,
                    env={"ONIONWARDEN_SUPPRESS_PHYSICAL": "active"})
    assert f[0]["severity"] == "WARN"


def test_console_login_wtmp_closed_session_caught():  # R5-3
    f = run_analyze("console_login", ["collected ok"],
                    ["wtmp_login mallory tty2", "collected ok"], GENERIC)
    assert f[0]["severity"] == "CRIT" and "wtmp" in f[0]["summary"]


# --- profile --------------------------------------------------------------
def test_profile_positive_os_change_crit():
    f = run_analyze("profile", ["os_id=ubuntu"], ["os_id=freebsd"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_profile_negative_clean():
    base = ["os_id=ubuntu", "virt_type=kvm"]
    assert run_analyze("profile", base, base, GENERIC) == []


# --- suid -----------------------------------------------------------------
def test_suid_positive_fatal():
    f = run_analyze("suid", ["suid /bin/su a"],
                    ["suid /bin/su a", "suid /tmp/evil b"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_suid_negative_clean():
    base = ["suid /bin/su a"]
    assert run_analyze("suid", base, base, GENERIC) == []


def test_suid_allowlist():
    cfg = GENERIC + 'expected_suid = ["/tmp/evil"]\n'
    f = run_analyze("suid", ["suid /bin/su a"],
                    ["suid /bin/su a", "suid /tmp/evil b"], cfg)
    assert f[0]["severity"] == "INFO"


# --- filesystem -----------------------------------------------------------
def test_filesystem_positive_lost_immutable_fatal():
    f = run_analyze("filesystem",
                    ["attr /opt/onionwarden/bin/onionwarden-run ----i----"],
                    ["attr /opt/onionwarden/bin/onionwarden-run ---------"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_filesystem_negative_clean():
    base = ["attr /etc/passwd ---------", "wwfile /tmp/x"]
    assert run_analyze("filesystem", base, base, GENERIC) == []


def test_filesystem_new_world_writable_crit():
    f = run_analyze("filesystem", ["attr /etc/passwd ---------"],
                    ["attr /etc/passwd ---------", "wwfile /usr/bin/x"], GENERIC)
    assert f[0]["severity"] == "CRIT"


# --- scheduled ------------------------------------------------------------
def test_scheduled_positive_new_cron_crit():
    f = run_analyze("scheduled", ["cron /etc/crontab a"],
                    ["cron /etc/crontab a", "cron /etc/cron.d/evil b"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_scheduled_negative_clean():
    base = ["cron /etc/crontab a", "unitfile ssh.service enabled"]
    assert run_analyze("scheduled", base, base, GENERIC) == []


def test_scheduled_allowlist_unit():
    cfg = GENERIC + 'expected_extra_units = ["evil.service"]\n'
    f = run_analyze("scheduled", ["unitfile ssh.service enabled"],
                    ["unitfile ssh.service enabled", "unitfile evil.service enabled"], cfg)
    assert f[0]["severity"] == "INFO"


# --- hardware -------------------------------------------------------------
def test_hardware_positive_new_block_crit():
    f = run_analyze("hardware", ["block sda 1G disk u1 ext4"],
                    ["block sda 1G disk u1 ext4", "block sdb 1G disk u2 ext4"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_hardware_negative_clean():
    base = ["block sda 1G disk u1 ext4", "cpu nproc 4"]
    assert run_analyze("hardware", base, base, GENERIC) == []


# --- kernel_state ---------------------------------------------------------
def test_kernel_state_positive_kexec_fatal():
    f = run_analyze("kernel_state", ["kexec loaded 0"], ["kexec loaded 1"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_kernel_state_negative_clean():
    base = ["kexec loaded 0", "modules_disabled 1", "lockdown integrity"]
    assert run_analyze("kernel_state", base, base, GENERIC) == []


def test_kernel_state_modules_disabled_drop_fatal():
    f = run_analyze("kernel_state", ["modules_disabled 1"],
                    ["modules_disabled 0"], GENERIC)
    assert f[0]["fatal_candidate"] is True


# --- process_ancestry -----------------------------------------------------
def test_process_ancestry_positive_fatal():
    f = run_analyze("process_ancestry", [], ["svcshell nginx bash"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_process_ancestry_negative_clean():
    base = ["tmpexec /tmp/known"]
    assert run_analyze("process_ancestry", base, base, GENERIC) == []


# --- auth_log -------------------------------------------------------------
def test_auth_log_positive_sudo_fatal():
    f = run_analyze("auth_log", ["sudouser root"],
                    ["sudouser root", "sudouser hax"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_auth_log_negative_clean():
    base = ["sudouser root", "journal verify ok"]
    assert run_analyze("auth_log", base, base, GENERIC) == []


def test_auth_log_allowlist_admin():
    cfg = GENERIC + 'expected_admins = ["operator"]\n'
    f = run_analyze("auth_log", ["sudouser root"],
                    ["sudouser root", "sudouser operator"], cfg)
    assert f[0]["severity"] == "INFO"


# --- snap -----------------------------------------------------------------
def test_snap_positive_new_snap_warn():
    f = run_analyze("snap", ["snap core 1"], ["snap core 1", "snap evil 1"], GENERIC)
    assert f[0]["severity"] == "WARN"


def test_snap_negative_clean():
    base = ["snap core 1", "snapd 2.0"]
    assert run_analyze("snap", base, base, GENERIC) == []


def test_snap_suid_crit():
    f = run_analyze("snap", ["snap core 1"],
                    ["snap core 1", "snapsuid /snap/x/bin/evil"], GENERIC)
    assert any(x["severity"] == "CRIT" for x in f)


# --- nested_vm ------------------------------------------------------------
def test_nested_vm_positive_new_guest_crit():
    f = run_analyze("nested_vm", ["guest h1 vm1"],
                    ["guest h1 vm1", "guest h2 vm2"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_nested_vm_negative_clean():
    base = ["guest h1 vm1", "guestarg vm1 netdev=user"]
    assert run_analyze("nested_vm", base, base, GENERIC) == []


def test_nested_vm_na_not_hypervisor():
    f = run_analyze("nested_vm", [], ["na not-hypervisor"], GENERIC)
    assert f[0]["severity"] == "NA"


# --- boot_integrity -------------------------------------------------------
def test_boot_integrity_positive_uncorrelated_fatal():
    f = run_analyze("boot_integrity", ["bootfile /boot/vmlinuz-x a correlated"],
                    ["bootfile /boot/vmlinuz-x z uncorrelated"], GENERIC)
    assert f[0]["severity"] == "CRIT" and f[0]["fatal_candidate"] is True


def test_boot_integrity_correlated_demotes():
    f = run_analyze("boot_integrity", ["bootfile /boot/vmlinuz-x a correlated"],
                    ["bootfile /boot/vmlinuz-x z correlated"], GENERIC)
    assert f[0]["severity"] == "INFO"


def test_boot_integrity_negative_clean():
    base = ["bootfile /boot/vmlinuz-x a correlated", "cmdline ro quiet"]
    assert run_analyze("boot_integrity", base, base, GENERIC) == []


# --- packages -------------------------------------------------------------
def test_packages_positive_new_apt_source_crit():
    f = run_analyze("packages", ["aptsource /etc/apt/sources.list a"],
                    ["aptsource /etc/apt/sources.list a",
                     "aptsource /etc/apt/sources.list.d/evil.list b"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_packages_negative_clean():
    base = ["aptsource /etc/apt/sources.list a", "dpkgstatus h"]
    assert run_analyze("packages", base, base, GENERIC) == []


def test_packages_uncorrelated_pkgfile_crit():
    f = run_analyze("packages", ["dpkgstatus h"],
                    ["dpkgstatus h", "pkgfile /usr/bin/x uncorrelated"], GENERIC)
    assert any(x["severity"] == "CRIT" for x in f)


# --- network_deep ---------------------------------------------------------
def test_network_deep_positive_new_dns_crit():
    f = run_analyze("network_deep", ["dns 1.1.1.1"],
                    ["dns 1.1.1.1", "dns 9.9.9.9"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_network_deep_negative_clean():
    base = ["dns 1.1.1.1", "nft abc", "iface eth0"]
    assert run_analyze("network_deep", base, base, GENERIC) == []


def test_network_deep_outbound_warn():
    f = run_analyze("network_deep", ["outbound sshd 1.2.3.4:22"],
                    ["outbound sshd 1.2.3.4:22", "outbound miner 9.9.9.9:4444"],
                    GENERIC)
    assert any(x["signal"] == "outbound" for x in f)


# --- clock ----------------------------------------------------------------
def test_clock_positive_ntp_config_change_crit():
    f = run_analyze("clock", ["ntpconf /etc/chrony/chrony.conf a"],
                    ["ntpconf /etc/chrony/chrony.conf EVIL"], GENERIC)
    assert f[0]["severity"] == "CRIT"


def test_clock_negative_clean():
    base = ["ntp_sync yes", "ntpconf /etc/chrony/chrony.conf a"]
    assert run_analyze("clock", base, base, GENERIC) == []


def test_clock_unsynced_warn():
    f = run_analyze("clock", ["ntp_sync yes"], ["ntp_sync no"], GENERIC)
    assert f[0]["severity"] == "WARN"
