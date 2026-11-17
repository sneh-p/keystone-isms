"""The settings Keystone can check, per platform, and the recommended baseline for each.

Agents and firewall parsers report values only for keys listed here; anything else is dropped on arrival. Titles and
descriptions are Keystone's own wording. Recommended values follow widely used hardening practice; they are a
starting point that each organisation adjusts, not a copy of any benchmark.

A setting can depend on another one (`requires`): SSH settings only matter when an SSH server is installed, and the RDP
network-level-authentication setting only when RDP is on. When the prerequisite is false the rule is "not applicable";
when it is unknown, so is the rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AGENT_PLATFORMS = ("windows", "linux")
FIREWALL_PLATFORMS = ("fortigate", "panos", "cisco", "pfsense")
PLATFORMS = AGENT_PLATFORMS + FIREWALL_PLATFORMS
PLATFORM_LABEL = {"windows": "Windows", "linux": "Linux", "fortigate": "Fortinet FortiGate", "panos": "Palo Alto PAN-OS",
                  "cisco": "Cisco ASA / IOS", "pfsense": "pfSense / OPNsense"}
TYPES = ("bool", "int", "str", "list")
OPERATORS = {"is_true": "is on", "is_false": "is off", "eq": "equals", "ne": "is not", "gte": "at least", "lte": "at most",
             "in": "is one of", "not_in": "is none of", "empty": "is empty"}
OPERATORS_BY_TYPE = {"bool": ("is_true", "is_false"), "int": ("eq", "ne", "gte", "lte"), "str": ("eq", "ne", "in", "not_in"), "list": ("empty",)}
SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Setting:
    key: str
    platforms: tuple[str, ...]
    type: str
    title: str
    description: str
    # Recommended rule: (operator, expected value, severity, control codes). None: reported for information only.
    recommended: tuple[str, object, str, tuple[str, ...]] | None = None
    requires: str | None = None  # a bool setting that must be true for this one to apply
    max_int: int = 1_000_000
    choices: tuple[str, ...] = field(default=())


W, L = ("windows",), ("linux",)
FW = FIREWALL_PLATFORMS

SETTINGS: tuple[Setting, ...] = (
    # ---------------------------------------------------------------- Windows
    Setting("firewall_domain_enabled", W, "bool", "Firewall on: domain profile", "Windows Defender Firewall is on for the domain network profile.",
            ("is_true", None, "high", ("KC-TEC-20", "KC-TEC-01"))),
    Setting("firewall_private_enabled", W, "bool", "Firewall on: private profile", "Windows Defender Firewall is on for the private network profile.",
            ("is_true", None, "high", ("KC-TEC-20", "KC-TEC-01"))),
    Setting("firewall_public_enabled", W, "bool", "Firewall on: public profile", "Windows Defender Firewall is on for the public network profile.",
            ("is_true", None, "critical", ("KC-TEC-20", "KC-TEC-01"))),
    Setting("firewall_public_inbound_blocked", W, "bool", "Public profile blocks inbound by default", "Unsolicited inbound connections are blocked on public networks unless a rule allows them.",
            ("is_true", None, "high", ("KC-TEC-20",))),
    Setting("bitlocker_os_volume", W, "bool", "System drive encrypted (BitLocker)", "BitLocker protection is on for the operating system volume.",
            ("is_true", None, "high", ("KC-TEC-01", "KC-TEC-24"))),
    Setting("secure_boot_enabled", W, "bool", "Secure Boot on", "UEFI Secure Boot is enabled, so only signed boot loaders start.",
            ("is_true", None, "medium", ("KC-TEC-01", "KC-TEC-09"))),
    Setting("defender_realtime_enabled", W, "bool", "Microsoft Defender real-time protection on", "Real-time scanning by Microsoft Defender Antivirus is on. Hosts that run another anti-malware product report this as off.",
            ("is_true", None, "high", ("KC-TEC-07",))),
    Setting("defender_signature_age_days", W, "int", "Anti-malware signatures age (days)", "Days since Microsoft Defender's signatures were last updated.",
            ("lte", 3, "medium", ("KC-TEC-07",)), max_int=100_000),
    Setting("last_update_installed_days", W, "int", "Days since the last update was installed", "Days since Windows last installed an update (hotfix).",
            ("lte", 45, "high", ("KC-TEC-08",)), max_int=100_000),
    Setting("smb1_enabled", W, "bool", "SMBv1 enabled", "The obsolete SMB version 1 protocol is enabled on the server side.",
            ("is_false", None, "high", ("KC-TEC-09", "KC-TEC-20"))),
    Setting("smb_signing_required", W, "bool", "SMB signing required", "The SMB server requires signed sessions, which prevents relay and tampering.",
            ("is_true", None, "medium", ("KC-TEC-20", "KC-TEC-09"))),
    Setting("rdp_enabled", W, "bool", "Remote Desktop enabled", "Remote Desktop connections to this host are allowed. Reported for information."),
    Setting("rdp_nla_required", W, "bool", "Remote Desktop requires network level authentication", "Users must authenticate before a Remote Desktop session is created.",
            ("is_true", None, "high", ("KC-TEC-05", "KC-TEC-20")), requires="rdp_enabled"),
    Setting("uac_enabled", W, "bool", "User Account Control on", "User Account Control is on, so administrative actions need elevation.",
            ("is_true", None, "high", ("KC-TEC-02", "KC-TEC-09"))),
    Setting("password_min_length", W, "int", "Local password minimum length", "Minimum length the local account password policy enforces.",
            ("gte", 12, "medium", ("KC-TEC-05",)), max_int=256),
    Setting("lockout_threshold", W, "int", "Account lockout threshold", "Failed sign-in attempts before a local account is locked; 0 means never.",
            None, max_int=10_000),
    Setting("lockout_enabled", W, "bool", "Account lockout enabled", "Local accounts lock after repeated failed sign-ins (the threshold is not 0).",
            ("is_true", None, "medium", ("KC-TEC-05",))),
    Setting("guest_account_enabled", W, "bool", "Guest account enabled", "The built-in Guest account is enabled.",
            ("is_false", None, "high", ("KC-TEC-03", "KC-TEC-09"))),
    Setting("local_admin_count", W, "int", "Members of the local Administrators group", "Number of accounts and groups in the local Administrators group.",
            ("lte", 3, "medium", ("KC-TEC-02",)), max_int=10_000),
    Setting("autorun_disabled", W, "bool", "AutoRun disabled for all drives", "AutoRun is turned off for every drive type, so removable media cannot start programs on insertion.",
            ("is_true", None, "medium", ("KC-TEC-07", "KC-TEC-09"))),
    Setting("screen_lock_timeout_seconds", W, "int", "Machine inactivity lock (seconds)", "Seconds of inactivity before the machine locks (the machine inactivity limit policy); 0 means not set.",
            None, max_int=1_000_000),
    Setting("screen_lock_configured", W, "bool", "Machine locks within 15 minutes", "A machine inactivity limit of 15 minutes or less is set.",
            ("is_true", None, "medium", ("KC-TEC-01",))),
    Setting("llmnr_disabled", W, "bool", "LLMNR name resolution off", "Multicast name resolution (LLMNR) is turned off, which stops a common credential-capture technique.",
            ("is_true", None, "medium", ("KC-TEC-20", "KC-TEC-09"))),
    Setting("powershell_v2_enabled", W, "bool", "PowerShell 2.0 engine installed", "The legacy PowerShell 2.0 engine, which bypasses modern logging, is installed.",
            ("is_false", None, "medium", ("KC-TEC-09", "KC-TEC-15"))),
    Setting("lm_compatibility_level", W, "int", "NTLM authentication level", "LmCompatibilityLevel: 5 sends NTLMv2 only and refuses LM and NTLMv1; lower values allow the older, easily cracked protocols. Not set means the Windows default (3).",
            ("gte", 5, "high", ("KC-TEC-05", "KC-TEC-24")), max_int=5),
    Setting("wdigest_disabled", W, "bool", "WDigest keeps no clear-text passwords", "WDigest authentication doesn't keep sign-in passwords in memory in a recoverable form (UseLogonCredential is 0 or not set on current Windows).",
            ("is_true", None, "high", ("KC-TEC-05",))),
    Setting("lsa_protection", W, "bool", "LSA protection on", "The Local Security Authority runs as a protected process (RunAsPPL), which blocks most credential-dumping tools.",
            ("is_true", None, "medium", ("KC-TEC-05", "KC-TEC-09"))),
    Setting("ps_script_block_logging", W, "bool", "PowerShell script block logging on", "PowerShell records the script blocks it runs in the event log.",
            ("is_true", None, "low", ("KC-TEC-15",))),
    # ---------------------------------------------------------------- Linux
    Setting("firewall_active", L, "bool", "Host firewall active", "A host firewall (ufw, firewalld or an nftables/iptables rule set with a filtering policy) is active.",
            ("is_true", None, "high", ("KC-TEC-20", "KC-TEC-01"))),
    Setting("firewall_tool", L, "str", "Host firewall in use", "Which firewall the agent found active: ufw, firewalld, nftables, iptables or none. Reported for information."),
    Setting("ssh_server_installed", L, "bool", "SSH server installed", "An OpenSSH server is installed. Reported for information; the SSH settings apply only when it is."),
    Setting("ssh_permit_root_login", L, "str", "SSH root login", "The effective PermitRootLogin setting of the SSH server.",
            ("in", ["no", "prohibit-password", "without-password", "forced-commands-only"], "high", ("KC-TEC-02", "KC-TEC-05")), requires="ssh_server_installed",
            choices=("yes", "no", "prohibit-password", "without-password", "forced-commands-only")),
    Setting("ssh_password_authentication", L, "bool", "SSH password sign-in allowed", "The SSH server accepts passwords (not only keys or other methods).",
            ("is_false", None, "medium", ("KC-TEC-05",)), requires="ssh_server_installed"),
    Setting("ssh_max_auth_tries", L, "int", "SSH sign-in attempts per connection", "The effective MaxAuthTries of the SSH server: how many authentication attempts one connection may make.",
            ("lte", 4, "medium", ("KC-TEC-05",)), requires="ssh_server_installed", max_int=1000),
    Setting("ssh_x11_forwarding", L, "bool", "SSH X11 forwarding allowed", "The SSH server forwards X11 graphical sessions, which servers rarely need.",
            ("is_false", None, "low", ("KC-TEC-09",)), requires="ssh_server_installed"),
    Setting("ssh_permit_empty_passwords", L, "bool", "SSH accepts empty passwords", "The SSH server lets accounts with an empty password sign in.",
            ("is_false", None, "critical", ("KC-TEC-05",)), requires="ssh_server_installed"),
    Setting("security_updates_pending", L, "int", "Security updates pending", "Security updates the package manager reports as available but not installed.",
            ("lte", 0, "high", ("KC-TEC-08",)), max_int=100_000),
    Setting("automatic_updates_enabled", L, "bool", "Automatic security updates on", "Unattended security updates are configured (unattended-upgrades, dnf-automatic or similar).",
            ("is_true", None, "medium", ("KC-TEC-08",))),
    Setting("root_fs_encrypted", L, "bool", "Root file system encrypted", "The root file system sits on an encrypted (LUKS/dm-crypt) device.",
            ("is_true", None, "medium", ("KC-TEC-01", "KC-TEC-24"))),
    Setting("mac_enforcing", L, "bool", "SELinux or AppArmor enforcing", "A mandatory access control framework is enforcing: SELinux in enforcing mode, or AppArmor enabled with profiles loaded.",
            ("is_true", None, "medium", ("KC-TEC-09", "KC-TEC-03"))),
    Setting("auditd_running", L, "bool", "Audit daemon running", "The Linux audit daemon (auditd) is running.",
            ("is_true", None, "medium", ("KC-TEC-15",))),
    Setting("time_sync_active", L, "bool", "Clock synchronised", "Network time synchronisation is active (systemd-timesyncd, chrony or ntpd).",
            ("is_true", None, "medium", ("KC-TEC-17",))),
    Setting("password_max_days", L, "int", "Maximum password age (days)", "PASS_MAX_DAYS in /etc/login.defs for new local accounts. Reported for information: current guidance favours no forced expiry with MFA.",
            None, max_int=100_000),
    Setting("uid0_accounts", L, "int", "Accounts with UID 0 besides root", "Local accounts other than root that have user ID 0 (full root rights).",
            ("lte", 0, "critical", ("KC-TEC-02",)), max_int=10_000),
    Setting("sudo_nopasswd_rules", L, "int", "Sudo rules without a password", "Lines in the sudo configuration that grant rights with NOPASSWD.",
            ("lte", 0, "medium", ("KC-TEC-02",)), max_int=10_000),
    Setting("aslr_full", L, "bool", "Full address space layout randomisation", "kernel.randomize_va_space is 2 (full randomisation).",
            ("is_true", None, "medium", ("KC-TEC-09",))),
    Setting("ip_forwarding_enabled", L, "bool", "IP forwarding on", "The host forwards IPv4 packets between interfaces. Expected only on routers and container hosts.",
            ("is_false", None, "low", ("KC-TEC-20", "KC-TEC-22"))),
    # ---------------------------------------------------------------- firewalls (shared keys, parsed from config exports)
    Setting("mgmt_http_enabled", FW, "bool", "Management over plain HTTP", "The management interface accepts unencrypted HTTP (not only HTTPS).",
            ("is_false", None, "high", ("KC-TEC-20", "KC-TEC-24"))),
    Setting("mgmt_telnet_enabled", FW, "bool", "Management over Telnet", "The device accepts Telnet for administration.",
            ("is_false", None, "critical", ("KC-TEC-20", "KC-TEC-24"))),
    Setting("mgmt_access_restricted", ("fortigate", "panos", "cisco"), "bool", "Management limited to trusted addresses", "Administrative access is limited to listed source addresses (trusted hosts, permitted IPs or access lists).",
            ("is_true", None, "high", ("KC-TEC-02", "KC-TEC-20"))),
    Setting("ssh_v2_only", ("cisco",), "bool", "SSH version 2 only", "The SSH server is limited to protocol version 2.",
            ("is_true", None, "high", ("KC-TEC-24",))),
    Setting("ntp_configured", FW, "bool", "Time synchronisation configured", "At least one NTP server is configured.",
            ("is_true", None, "medium", ("KC-TEC-17",))),
    Setting("remote_logging", FW, "bool", "Logs sent to a remote server", "Logs go to at least one remote syslog or log collector, so they survive a compromise of the device.",
            ("is_true", None, "high", ("KC-TEC-15", "KC-TEC-16"))),
    Setting("any_any_allow_rules", FW, "int", "Allow rules from any source to any destination on any service", "Enabled rules that allow traffic with every source, destination and service left open.",
            ("lte", 0, "critical", ("KC-TEC-20", "KC-TEC-22"))),
    Setting("rules_without_logging", ("fortigate", "panos", "pfsense"), "int", "Allow rules that don't log", "Enabled allow rules with traffic logging turned off.",
            ("lte", 0, "medium", ("KC-TEC-15",))),
    Setting("admin_timeout_minutes", ("fortigate", "panos", "cisco"), "int", "Idle admin session timeout (minutes)", "Minutes an idle administrative session stays open; Cisco reports its line exec-timeout.",
            ("lte", 15, "medium", ("KC-TEC-05",)), max_int=100_000),
    Setting("strong_crypto", ("fortigate",), "bool", "Strong cryptography only", "The strong-crypto option is on, which disables weak ciphers for management and VPN.",
            ("is_true", None, "high", ("KC-TEC-24",))),
    Setting("admin_mfa_all", ("fortigate",), "bool", "Every local administrator uses two-factor authentication", "Each local administrator account has two-factor authentication configured.",
            ("is_true", None, "high", ("KC-TEC-05", "KC-TEC-02"))),
    Setting("password_encryption", ("cisco",), "bool", "Service password-encryption on", "Passwords in the configuration are not stored in clear text.",
            ("is_true", None, "medium", ("KC-TEC-24",))),
    Setting("enable_secret_used", ("cisco",), "bool", "Enable secret (hashed) instead of enable password", "Privileged mode is protected with a hashed enable secret, and no clear enable password is set.",
            ("is_true", None, "high", ("KC-TEC-02", "KC-TEC-24"))),
    Setting("aaa_enabled", ("cisco",), "bool", "AAA enabled", "aaa new-model is configured, so authentication goes through AAA.",
            ("is_true", None, "medium", ("KC-TEC-05",))),
    Setting("snmp_default_community", ("cisco", "fortigate", "pfsense"), "bool", "SNMP default community string", "An SNMP community named public or private is configured.",
            ("is_false", None, "high", ("KC-TEC-09", "KC-TEC-20"))),
    Setting("firmware_version", FW, "str", "Firmware version", "The software version recorded in the configuration export. Reported for information."),
)

BY_KEY: dict[tuple[str, str], Setting] = {(p, s.key): s for s in SETTINGS for p in s.platforms}


def settings_for(platform: str) -> list[Setting]:
    return [s for s in SETTINGS if platform in s.platforms]


def setting(platform: str, key: str) -> Setting | None:
    return BY_KEY.get((platform, key))


def describe_expected(op: str, expected) -> str:
    if op in ("is_true", "is_false", "empty"):
        return OPERATORS[op]
    if isinstance(expected, list):
        return f"{OPERATORS[op]} {', '.join(str(x) for x in expected)}"
    return f"{OPERATORS[op]} {expected}"


def clean_value(s: Setting, v):
    """Coerce a reported value to the setting's type; None when it can't be (treated as not reported)."""
    if v is None:
        return None
    if s.type == "bool":
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)) and v in (0, 1):
            return bool(v)
        if isinstance(v, str) and v.strip().lower() in ("true", "false", "yes", "no", "1", "0", "on", "off"):
            return v.strip().lower() in ("true", "yes", "1", "on")
        return None
    if s.type == "int":
        if isinstance(v, bool):
            return None
        try:
            n = int(v)
        except (TypeError, ValueError):
            return None
        return n if -1 <= n <= s.max_int else None
    if s.type == "str":
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            return None
        text = str(v).strip()[:200]
        return text.lower() if s.choices else text
    if s.type == "list":
        if not isinstance(v, list):
            return None
        return [str(x).strip()[:200] for x in v[:200] if isinstance(x, (str, int, float))]
    return None
