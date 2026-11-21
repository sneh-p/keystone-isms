"""Custom configuration checks: read-only probes an administrator defines in Keystone.

A custom check names one probe (what to read) and its parameters. Agents download the definitions for their platform
and report the value under the fact key `custom.<slug>`; firewall checks run on the uploaded export. Rules then compare
the value like any built-in setting.

Limits (enforced here, and again inside each agent, which never trusts the server's validation):
- Probes only read. There is no command, script or arbitrary-file probe.
- No regular expressions anywhere (SC-VAL-004): matching is literal (equals, contains, starts with) or numeric.
- Parameters use narrow character sets, so they can't smuggle shell syntax, path traversal or new lines.
- Probes that read file contents refuse sensitive paths: password hashes, private keys, SSH directories, home
  directories, process environments, and other names for them (the macOS data volume, /proc links). The same list is
  hard-coded in the agents, which also check the real path after following every symbolic link. Probes that only look at
  metadata (exists, mode, owner) may name those paths, so "/etc/shadow is 0640" can be checked without reading it.
- Windows registry probes read HKEY_LOCAL_MACHINE only, and never the SAM or SECURITY hives.
- macOS probes read files, property lists and app bundles under the same rules, and never keychains, the local
  directory's password store or users' home folders.
- Values are capped at 200 characters.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from keystone.core.settings import PROJECT_ROOT

from . import catalogue as cat

SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
CUSTOM_PREFIX = "custom."
MAX_CHECKS_PER_PLATFORM = 100
VALUE_MAX_INT = 4_294_967_295  # a registry DWORD

# Character sets for parameters (literal patterns; nothing user-supplied becomes a regex).
LINUX_PATH = re.compile(r"^/[A-Za-z0-9._/+@:-]{1,250}$")
MAC_PATH = re.compile(r"^/[A-Za-z0-9._/+@: -]{1,250}$")  # macOS paths often contain spaces ("Application Support")
APP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,99}$")
LAUNCHD_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
WINDOWS_PATH = re.compile(r"^[A-Za-z]:\\[A-Za-z0-9 ._\\()\-]{1,250}$")
REGISTRY_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._\\(){}\-]{0,250}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}$")
REG_VALUE_NAME = re.compile(r"^[A-Za-z0-9 ._\-]{0,128}$")
TEXT = re.compile(r"^[\x20-\x7e]{1,200}$")
SETTING_KEY = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")
SYSCTL_KEY = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_\-]+)+$")
SECEDIT_KEY = re.compile(r"^[A-Za-z]{2,60}$")
GUID = re.compile(r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$")
BUILTIN_SID = re.compile(r"^S-1-5-32-\d{3}$")
SSHD_KEY = re.compile(r"^[a-z0-9]{2,60}$")
FORTI_PATH = re.compile(r"^[a-z0-9][a-z0-9 \-]{0,100}$")
XPATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./\-@\[\]=' ]{0,250}$")

# Paths whose contents no probe may read. Mirrored, literally, in agents/linux/keystone-agent.sh (deny_path).
# macOS: the local directory (password hashes), keychains, root's and users' home folders.
DENIED_PATH_GLOBS = ("/etc/shadow*", "/etc/gshadow*", "/etc/security/opasswd*", "/etc/ssl/private/*", "/root/*", "/home/*", "*/.ssh/*",
                     "/proc/*/environ", "/proc/*/mem", "*.key", "*.pem", "*.p12", "*.pfx", "*.keytab", "*/krb5.keytab", "/var/lib/sss/*",
                     "/users/*", "/var/root/*", "/private/var/root/*", "/var/db/dslocal/*", "/private/var/db/dslocal/*", "*/keychains/*", "*.keychain*",
                     "/etc/master.passwd", "/private/etc/master.passwd",
                     # other names for the same files: the macOS data volume and mounted volumes, and Linux process links
                     "/system/volumes/data/*", "/volumes/*", "/proc/*/root/*", "/proc/*/cwd/*", "/proc/*/fd/*", "/proc/*/map_files/*")
DENIED_REGISTRY_ROOTS = ("sam", "security")


class CheckInvalid(ValueError):
    pass


@dataclass(frozen=True)
class Param:
    name: str
    label: str
    kind: str  # path | winpath | regpath | regname | name | text | key | sysctl | secedit | guid | sid | sshd | forti | xpath | appname | label | choice | int
    required: bool = True
    choices: tuple[str, ...] = ()
    hint: str = ""


@dataclass(frozen=True)
class Probe:
    key: str
    platforms: tuple[str, ...]
    label: str
    description: str
    params: tuple[Param, ...]
    # value type per mode: {mode value (or "" when the probe has no mode/field param): allowed value types}
    types: dict = field(default_factory=dict)
    mode_param: str | None = None
    reads_content: bool = False
    default_allowed: bool = False


SEPARATORS = ("whitespace", "equals", "colon")

PROBES: tuple[Probe, ...] = (
    # ---------------------------------------------------------------- Windows
    Probe("registry_value", ("windows",), "Registry value", "A value under HKEY_LOCAL_MACHINE: its data, or whether it exists.",
          (Param("path", "Key path under HKLM", "regpath", hint=r"e.g. SYSTEM\CurrentControlSet\Control\Lsa"),
           Param("name", "Value name", "regname"),
           Param("mode", "Report", "choice", choices=("value", "exists"))),
          {"value": ("int", "str"), "exists": ("bool",)}, "mode", default_allowed=True),
    Probe("service", ("windows", "linux"), "Service", "A service's state or start type (Linux: systemd unit active or enabled state). A missing service reports “absent”.",
          (Param("name", "Service or unit name", "name"), Param("field", "Report", "choice", choices=("state", "start_type"))),
          {"state": ("str",), "start_type": ("str",)}, "field"),
    Probe("software_installed", ("windows",), "Installed software", "Programs whose display name contains the text (from the uninstall registry keys).",
          (Param("name_contains", "Display name contains", "text"), Param("field", "Report", "choice", choices=("present", "version"))),
          {"present": ("bool",), "version": ("str",)}, "field"),
    Probe("file_exists", ("windows", "linux", "macos"), "File or folder exists", "Whether the path exists.",
          (Param("path", "Path", "path"),), {"": ("bool",)}),
    Probe("windows_feature", ("windows",), "Windows optional feature", "The feature's state (Enabled, Disabled), or “absent”.",
          (Param("name", "Feature name", "name"),), {"": ("str",)}),
    Probe("security_policy", ("windows",), "Local security policy", "A [System Access] value from the local security policy, e.g. PasswordComplexity or MinimumPasswordAge.",
          (Param("key", "Policy name", "secedit"),), {"": ("int", "str")}),
    Probe("audit_policy", ("windows",), "Audit policy subcategory", "The audit setting of a subcategory, by GUID: “Success and Failure”, “Success”, “Failure” or “No Auditing”.",
          (Param("guid", "Subcategory GUID", "guid"),), {"": ("str",)}),
    Probe("local_group_count", ("windows",), "Members of a built-in local group", "How many members a built-in group has, by well-known SID (e.g. S-1-5-32-555 Remote Desktop Users).",
          (Param("sid", "Group SID", "sid"),), {"": ("int",)}),
    # ---------------------------------------------------------------- Linux
    Probe("file_setting", ("linux", "macos"), "Setting in a configuration file", "The value of the first uncommented line whose key matches (keys compared without regard to case).",
          (Param("path", "File", "path"), Param("key", "Key", "key"), Param("separator", "Key and value separated by", "choice", choices=SEPARATORS)),
          {"": ("int", "str")}, reads_content=True, default_allowed=True),
    Probe("file_contains", ("linux", "macos"), "File contains text", "Whether an uncommented line contains the text, exactly as written.",
          (Param("path", "File", "path"), Param("text", "Text", "text")), {"": ("bool",)}, reads_content=True),
    Probe("file_mode", ("linux", "macos"), "File permissions or owner", "The permission bits in octal (e.g. 640), the owner or the group.",
          (Param("path", "File", "path"), Param("field", "Report", "choice", choices=("mode", "owner", "group"))),
          {"mode": ("str",), "owner": ("str",), "group": ("str",)}, "field"),
    Probe("package_installed", ("linux",), "Installed package", "Whether a package is installed (dpkg or rpm), or its version.",
          (Param("name", "Package", "name"), Param("field", "Report", "choice", choices=("present", "version"))),
          {"present": ("bool",), "version": ("str",)}, "field"),
    Probe("sysctl", ("linux", "macos"), "Kernel parameter", "A kernel parameter, e.g. net.ipv4.conf.all.accept_redirects (Linux, from /proc/sys) or net.inet.ip.forwarding (macOS).",
          (Param("key", "Parameter", "sysctl"),), {"": ("int", "str")}),
    Probe("kernel_module_loaded", ("linux",), "Kernel module loaded", "Whether a kernel module is currently loaded.",
          (Param("name", "Module", "name"),), {"": ("bool",)}),
    Probe("sshd_effective", ("linux",), "SSH server setting", "An effective SSH server setting as `sshd -T` reports it (lower-case name, e.g. logingracetime).",
          (Param("key", "Setting", "sshd"),), {"": ("int", "str")}),
    # ---------------------------------------------------------------- macOS
    Probe("plist_value", ("macos",), "Property list value", "A top-level value in a property list file (e.g. /Library/Preferences/com.apple.loginwindow.plist), or whether it is set.",
          (Param("path", "Property list file", "path", hint="e.g. /Library/Preferences/com.apple.loginwindow.plist"), Param("key", "Key", "key"),
           Param("mode", "Report", "choice", choices=("value", "exists"))),
          {"value": ("int", "str", "bool"), "exists": ("bool",)}, "mode", reads_content=True, default_allowed=True),
    Probe("app_installed", ("macos",), "Installed app", "An app in /Applications: whether it is there, or its version.",
          (Param("name", "App name (without .app)", "appname", hint="e.g. Microsoft Teams"), Param("field", "Report", "choice", choices=("present", "version"))),
          {"present": ("bool",), "version": ("str",)}, "field"),
    Probe("launchd_service", ("macos",), "Background service loaded", "Whether a system launchd service is loaded, by label (e.g. com.apple.screensharing).",
          (Param("label", "Service label", "label"),), {"": ("bool",)}),
    # ---------------------------------------------------------------- firewalls (evaluated on the uploaded export)
    Probe("fortigate_setting", ("fortigate",), "FortiGate setting", "A `set` value in a `config` block, optionally inside one `edit` entry; or how many entries the block has.",
          (Param("block", "Config block", "forti", hint="e.g. system global"), Param("edit", "Edit entry (optional)", "text", required=False),
           Param("setting", "Setting (for value)", "key", required=False), Param("mode", "Report", "choice", choices=("value", "count"))),
          {"value": ("int", "str"), "count": ("int",)}, "mode", default_allowed=True),
    Probe("panos_xpath", ("panos",), "PAN-OS configuration element", "An element of running-config.xml by path from <config>: its text, whether it exists, or how many there are.",
          (Param("path", "Element path", "xpath", hint="e.g. devices/entry/deviceconfig/system/login-banner"), Param("mode", "Report", "choice", choices=("text", "exists", "count"))),
          {"text": ("int", "str"), "exists": ("bool",), "count": ("int",)}, "mode", default_allowed=True),
    Probe("pfsense_xpath", ("pfsense",), "pfSense / OPNsense configuration element", "An element of config.xml by path from the root: its text, whether it exists, or how many there are.",
          (Param("path", "Element path", "xpath", hint="e.g. system/ssh/enable"), Param("mode", "Report", "choice", choices=("text", "exists", "count"))),
          {"text": ("int", "str"), "exists": ("bool",), "count": ("int",)}, "mode", default_allowed=True),
    Probe("cisco_line", ("cisco",), "Cisco configuration line", "Lines starting with the text (leading spaces ignored): whether there is one, how many, or the rest of the first one.",
          (Param("prefix", "Line starts with", "text"), Param("mode", "Report", "choice", choices=("present", "count", "value"))),
          {"present": ("bool",), "count": ("int",), "value": ("int", "str")}, "mode", default_allowed=True),
)
PROBE_BY_KEY = {p.key: p for p in PROBES}

KIND_RE = {"path": None, "winpath": WINDOWS_PATH, "regpath": REGISTRY_PATH, "regname": REG_VALUE_NAME, "name": NAME, "text": TEXT,
           "key": SETTING_KEY, "sysctl": SYSCTL_KEY, "secedit": SECEDIT_KEY, "guid": GUID, "sid": BUILTIN_SID, "sshd": SSHD_KEY,
           "forti": FORTI_PATH, "xpath": XPATH, "appname": APP_NAME, "label": LAUNCHD_LABEL}


def denied_path(path: str) -> bool:
    p = path.lower()
    return any(fnmatch.fnmatchcase(p, g) for g in DENIED_PATH_GLOBS)


def _check_param(platform: str, probe: Probe, prm: Param, value) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        if prm.required:
            raise CheckInvalid(f"{prm.label} is required.")
        return None
    if not isinstance(value, str):
        raise CheckInvalid(f"{prm.label} must be text.")
    v = value.strip()
    if prm.kind == "choice":
        if v not in prm.choices:
            raise CheckInvalid(f"{prm.label} must be one of {', '.join(prm.choices)}.")
        return v
    if prm.kind == "path":
        rx = WINDOWS_PATH if platform == "windows" else MAC_PATH if platform == "macos" else LINUX_PATH
        if not rx.match(v) or ".." in v or "//" in v or "/./" in v or v != v.strip():
            raise CheckInvalid(f"{prm.label}: give a full path without '..'" + (" (e.g. C:\\Windows\\...)." if platform == "windows" else " (e.g. /etc/ssh/sshd_config)."))
        if probe.reads_content and denied_path(v):
            raise CheckInvalid(f"{prm.label}: Keystone doesn't read this file's contents (passwords, keys or private data). Check its permissions with “File permissions or owner” instead.")
        return v
    if prm.kind == "regpath":
        if not REGISTRY_PATH.match(v) or ".." in v or "\\\\" in v:
            raise CheckInvalid(f"{prm.label}: give a key path under HKEY_LOCAL_MACHINE, without 'HKLM\\'.")
        if v.split("\\", 1)[0].lower() in DENIED_REGISTRY_ROOTS:
            raise CheckInvalid(f"{prm.label}: the SAM and SECURITY hives are never read.")
        return v
    pattern = KIND_RE.get(prm.kind)
    if pattern is None or not pattern.match(v):
        raise CheckInvalid(f"{prm.label}: {v[:40]!r} contains characters that aren't allowed here.")
    if prm.kind == "xpath" and (".." in v or v.startswith("/")):
        raise CheckInvalid(f"{prm.label}: give a relative path without '..'.")
    if prm.kind == "appname" and ".." in v:
        raise CheckInvalid(f"{prm.label}: give the app's name only.")
    return v


def validate(platform: str, probe_key: str, params: dict, value_type: str, default=None) -> tuple[dict, object]:
    """Check a definition. Returns cleaned parameters and the default (coerced to the value type)."""
    if platform not in cat.PLATFORMS:
        raise CheckInvalid("Unknown platform.")
    probe = PROBE_BY_KEY.get(probe_key)
    if probe is None or platform not in probe.platforms:
        raise CheckInvalid(f"This probe isn't available for {cat.PLATFORM_LABEL[platform]}.")
    if not isinstance(params, dict) or set(params) - {p.name for p in probe.params}:
        raise CheckInvalid("Unexpected parameters.")
    clean: dict[str, str] = {}
    for prm in probe.params:
        v = _check_param(platform, probe, prm, params.get(prm.name))
        if v is not None:
            clean[prm.name] = v
    mode = clean.get(probe.mode_param, "") if probe.mode_param else ""
    allowed = probe.types.get(mode, ())
    if value_type not in allowed:
        raise CheckInvalid(f"This probe reports {' or '.join(allowed) or 'nothing'} here, not {value_type}.")
    if probe_key == "fortigate_setting" and mode == "value" and not clean.get("setting"):
        raise CheckInvalid("Setting is required to report a value.")
    if default is not None and default != "":
        if not probe.default_allowed or value_type == "bool":
            raise CheckInvalid("This probe has no default value.")
        default = coerce(value_type, default)
        if default is None:
            raise CheckInvalid(f"The default must be a {'whole number' if value_type == 'int' else 'text'}.")
    else:
        default = None
    return clean, default


def coerce(value_type: str, v):
    s = cat.Setting("x", ("windows",), value_type, "", "", max_int=VALUE_MAX_INT)
    return cat.clean_value(s, v)


def as_setting(check) -> cat.Setting:
    """A custom check seen as a catalogue setting, so rules, judging and the UI treat both alike."""
    return cat.Setting(CUSTOM_PREFIX + check.slug, (check.platform,), check.value_type, check.title, check.description or "",
                       recommended=_recommended(check), max_int=VALUE_MAX_INT)


def _recommended(check):
    r = check.recommended or None
    if not r:
        return None
    return (r.get("operator"), r.get("expected"), r.get("severity", "medium"), tuple(r.get("controls") or ()))


def wire(check) -> dict:
    return {"key": CUSTOM_PREFIX + check.slug, "probe": check.probe, "type": check.value_type, "params": dict(check.params or {}),
            **({"default": check.default_value} if check.default_value is not None else {})}


def wire_lines(checks) -> str:
    """The same definitions as tab-separated lines for the POSIX agent, which can't parse JSON:
    key, probe, type, then name=value pairs (and default=...). Parameters can't contain tabs or new lines."""
    out = []
    for c in checks:
        w = wire(c)
        parts = [w["key"], w["probe"], w["type"]] + [f"{k}={v}" for k, v in sorted(w["params"].items())]
        if "default" in w:
            parts.append(f"default={w['default']}")
        out.append("\t".join(parts))
    return "\n".join(out) + ("\n" if out else "")


def probes_out() -> list[dict]:
    return [{"key": p.key, "platforms": list(p.platforms), "label": p.label, "description": p.description, "mode_param": p.mode_param,
             "types": {k: list(v) for k, v in p.types.items()}, "default_allowed": p.default_allowed, "reads_content": p.reads_content,
             "params": [{"name": x.name, "label": x.label, "kind": x.kind, "required": x.required, "choices": list(x.choices), "hint": x.hint} for x in p.params]}
            for p in PROBES]


# ---- the check library (content/config_check_library.yaml, Keystone-written) ----------------------------------------

LIBRARY_PATH = PROJECT_ROOT / "content" / "config_check_library.yaml"


def library(path: Path = LIBRARY_PATH) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(data.get("checks") or [])


def library_entry(key: str) -> dict:
    for e in library():
        if e.get("slug") == key:
            return e
    raise LookupError("No such library check.")


# ---- firewall probes, run on the parsed export at upload time --------------------------------------------------------

def firewall_value(platform: str, ctx, check) -> tuple[object, str | None]:
    """(value, error code) for one firewall custom check. Error codes: missing, error."""
    from . import parsers

    p, mode = check.params or {}, ""
    probe = PROBE_BY_KEY[check.probe]
    if probe.mode_param:
        mode = p.get(probe.mode_param, "")
    raw: object = None
    try:
        if check.probe == "fortigate_setting" and isinstance(ctx, parsers._Node):
            node = ctx.blocks.get(p["block"].lower())
            if node is not None and p.get("edit"):
                node = node.edits.get(p["edit"])
            if mode == "count":
                raw = len(node.edits) if node is not None else 0
            elif node is not None and p.get("setting", "").lower() in node.sets:
                raw = " ".join(node.sets[p["setting"].lower()])
        elif check.probe in ("panos_xpath", "pfsense_xpath") and not isinstance(ctx, (parsers._Node, list)):
            if mode == "count":
                raw = len(ctx.findall(p["path"]))
            elif mode == "exists":
                raw = ctx.find(p["path"]) is not None
            else:
                el = ctx.find(p["path"])
                raw = (el.text or "").strip() if el is not None and (el.text or "").strip() else None
        elif check.probe == "cisco_line" and isinstance(ctx, list):
            prefix = p["prefix"]
            hits = [ln.strip() for ln in ctx if ln.strip().startswith(prefix)]
            raw = bool(hits) if mode == "present" else len(hits) if mode == "count" else (hits[0][len(prefix):].strip() if hits else None)
        else:
            return None, "error"
    except (SyntaxError, KeyError, ValueError):
        return None, "error"
    if raw is None and check.default_value is not None:
        raw = check.default_value
    if raw is None:
        return None, "missing"
    v = coerce(check.value_type, raw)
    return (v, None) if v is not None else (None, "error")
