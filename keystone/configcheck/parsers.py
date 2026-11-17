"""Firewall configuration exports to facts (catalogue keys). Only these facts leave the parser: the uploaded file holds
password hashes, pre-shared keys and private keys, so it is parsed in memory and never stored (SC-FILE-001).

Settings that are absent from the export are reported as unknown (None), never as a pass, unless absence has a
clear meaning (no policy entries means no any-any rules). Exports that leave out default values give fewer results;
the page suggests exporting the full configuration.

XML is parsed with defusedxml, with DTDs refused (SC-FILE-004).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET

MAX_BYTES = 10 * 1024 * 1024


class ParseError(ValueError):
    pass


@dataclass
class Parsed:
    facts: dict
    hostname: str | None = None
    version: str | None = None
    notes: list[str] = field(default_factory=list)
    ctx: object = None  # the parsed structure, kept in memory only, for custom checks run during the same upload


def parse(platform: str, data: bytes) -> Parsed:
    if not data:
        raise ParseError("The file is empty.")
    if len(data) > MAX_BYTES:
        raise ParseError("The file is larger than 10 MB.")
    parser = {"fortigate": fortigate, "panos": panos, "cisco": cisco, "pfsense": pfsense}.get(platform)
    if parser is None:
        raise ParseError("Choose FortiGate, PAN-OS, Cisco or pfSense/OPNsense.")
    out = parser(data)
    out.facts = {k: v for k, v in out.facts.items() if v is not None}
    if not out.facts:
        raise ParseError("No settings could be read from this file. Check that it is a configuration export for the platform chosen.")
    return out


def _open_network(text: str) -> bool:
    """True for the unspecified address (an IPv4 or IPv6 "any", optionally as a /0 prefix): access from anywhere."""
    try:
        return ipaddress.ip_network(text, strict=False).network_address.is_unspecified
    except ValueError:
        return False


def _text(data: bytes) -> str:
    if b"\x00" in data[:4096]:
        raise ParseError("This looks like a binary file. Upload the configuration as text.")
    return data.decode("utf-8", errors="replace")


def _xml(data: bytes) -> Element:
    try:
        return SafeET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except SafeET.ParseError as e:
        raise ParseError("The file is not valid XML.") from e
    except (SafeET.DTDForbidden, SafeET.EntitiesForbidden, SafeET.ExternalReferenceForbidden) as e:
        raise ParseError("XML with a DTD or entities is not accepted.") from e


# ----------------------------------------------------------------------------------------------- FortiGate


@dataclass
class _Node:
    sets: dict[str, list[str]] = field(default_factory=dict)
    edits: dict[str, _Node] = field(default_factory=dict)
    blocks: dict[str, _Node] = field(default_factory=dict)


def _forti_statements(text: str):
    """Split FortiOS configuration into statements (lists of words), honouring quotes that span lines."""
    words: list[str] = []
    cur: list[str] = []
    quoted = in_word = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quoted:
            if ch == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                quoted = False
            else:
                cur.append(ch)
        elif ch == '"':
            quoted, in_word = True, True
        elif ch == "\n":
            if in_word:
                words.append("".join(cur))
            if words:
                yield words
            words, cur, in_word = [], [], False
        elif ch in " \t\r":
            if in_word:
                words.append("".join(cur))
                cur, in_word = [], False
        elif ch == "#" and not in_word and not words:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        else:
            cur.append(ch)
            in_word = True
        i += 1
    if in_word:
        words.append("".join(cur))
    if words:
        yield words


def _forti_tree(text: str) -> _Node:
    root = _Node()
    stack = [root]
    for words in _forti_statements(text):
        cmd, args = words[0].lower(), words[1:]
        top = stack[-1]
        if cmd == "config" and args:
            stack.append(top.blocks.setdefault(" ".join(args).lower(), _Node()))
        elif cmd == "edit" and args:
            stack.append(top.edits.setdefault(args[0], _Node()))
        elif cmd in ("next", "end") and len(stack) > 1:
            stack.pop()
        elif cmd == "set" and args:
            top.sets[args[0].lower()] = args[1:]
    return root


def _one(node: _Node | None, key: str) -> str | None:
    if node is None or key not in node.sets:
        return None
    vals = node.sets[key]
    return vals[0].lower() if vals else ""


def _onoff(v: str | None) -> bool | None:
    return None if v is None else v == "enable"


def fortigate(data: bytes) -> Parsed:
    text = _text(data)
    tree = _forti_tree(text)
    if "system global" not in tree.blocks and "firewall policy" not in tree.blocks:
        raise ParseError("This doesn't look like a FortiGate configuration (no 'config system global').")
    g = tree.blocks.get("system global")
    version = None
    m = re.search(r"#config-version=[A-Z0-9]+-(\d+\.\d+\.\d+)", text[:500])
    if m:
        version = m.group(1)
    names = g.sets.get("hostname") if g else None
    hostname = names[0] if names else None
    facts: dict = {"firmware_version": version}
    ifaces = tree.blocks.get("system interface")
    access = [set(x.lower() for x in e.sets.get("allowaccess", [])) for e in ifaces.edits.values()] if ifaces else []
    if ifaces is not None:
        redirect = _one(g, "admin-https-redirect")
        any_http = any("http" in a for a in access)
        facts["mgmt_http_enabled"] = False if not any_http else (True if redirect == "disable" else None if redirect is None else False)
        facts["mgmt_telnet_enabled"] = any("telnet" in a for a in access)
    admins = tree.blocks.get("system admin")
    if admins is not None and admins.edits:
        def restricted(a: _Node) -> bool:
            hosts = [v for k, v in a.sets.items() if re.fullmatch(r"(ip6-)?trusthost\d+", k)]
            return any(v and not _open_network(v[0]) for v in hosts)

        facts["mgmt_access_restricted"] = all(restricted(a) for a in admins.edits.values())
        facts["admin_mfa_all"] = all((_one(a, "two-factor") or "disable") != "disable" for a in admins.edits.values())
    ntp = tree.blocks.get("system ntp")
    if ntp is not None:
        facts["ntp_configured"] = _one(ntp, "ntpsync") != "disable" if "ntpsync" in ntp.sets else None
    log_blocks = [b for k, b in tree.blocks.items() if re.fullmatch(r"log (syslogd\d?|fortianalyzer\d?|fortianalyzer-cloud|fortiguard) setting", k)]
    if log_blocks:
        states = [_one(b, "status") for b in log_blocks]
        facts["remote_logging"] = True if "enable" in states else (None if None in states else False)
    pol = tree.blocks.get("firewall policy")
    if pol is not None:
        accepts = [p for p in pol.edits.values() if _one(p, "action") == "accept" and _one(p, "status") != "disable"]

        def anyany(p: _Node) -> bool:
            low = {k: [x.lower() for x in v] for k, v in p.sets.items()}
            return "all" in low.get("srcaddr", []) and "all" in low.get("dstaddr", []) and "all" in low.get("service", [])

        facts["any_any_allow_rules"] = sum(1 for p in accepts if anyany(p))
        facts["rules_without_logging"] = sum(1 for p in accepts if _one(p, "logtraffic") == "disable")
    if g is not None:
        t = _one(g, "admintimeout")
        facts["admin_timeout_minutes"] = int(t) if t and t.isdigit() else None
        facts["strong_crypto"] = _onoff(_one(g, "strong-crypto"))
    snmp = tree.blocks.get("system snmp community")
    if snmp is not None or g is not None:
        names = [(_one(c, "name") or "") for c in (snmp.edits.values() if snmp else [])]
        facts["snmp_default_community"] = any(n in ("public", "private") for n in names)
    return Parsed(facts=facts, hostname=hostname, version=version, ctx=tree)


# ----------------------------------------------------------------------------------------------- PAN-OS


def _t(el: Element | None, path: str) -> str | None:
    if el is None:
        return None
    x = el.find(path)
    return x.text.strip() if x is not None and x.text and x.text.strip() else None


def _members(el: Element, tag: str) -> list[str]:
    return [(m.text or "").strip().lower() for m in el.findall(f"{tag}/member")]


def panos(data: bytes) -> Parsed:
    root = _xml(data)
    if root.tag != "config":
        raise ParseError("This doesn't look like a PAN-OS configuration (the root element isn't <config>).")
    system = root.find("devices/entry/deviceconfig/system")
    version = root.get("detail-version") or root.get("version")
    facts: dict = {"firmware_version": version}
    hostname = _t(system, "hostname")
    if system is not None:
        svc = system.find("service")
        if svc is not None:
            telnet, http = _t(svc, "disable-telnet"), _t(svc, "disable-http")
            facts["mgmt_telnet_enabled"] = None if telnet is None else telnet != "yes"
            facts["mgmt_http_enabled"] = None if http is None else http != "yes"
        facts["mgmt_access_restricted"] = bool(system.findall("permitted-ip/entry"))
        facts["ntp_configured"] = bool(system.findall("ntp-servers/*/ntp-server-address"))
    syslog = root.findall("shared/log-settings/syslog/entry/server/entry") + root.findall("devices/entry/vsys/entry/log-settings/syslog/entry/server/entry")
    panorama = system is not None and (system.find("panorama") is not None or _t(system, "panorama-server") is not None)
    facts["remote_logging"] = bool(syslog) or panorama
    rules = root.findall("devices/entry/vsys/entry/rulebase/security/rules/entry")
    if root.find("devices/entry/vsys") is not None:
        allows = [r for r in rules if _t(r, "action") == "allow" and _t(r, "disabled") != "yes"]

        def anyany(r: Element) -> bool:
            return all("any" in _members(r, tag) for tag in ("source", "destination", "application", "service"))

        facts["any_any_allow_rules"] = sum(1 for r in allows if anyany(r))
        facts["rules_without_logging"] = sum(1 for r in allows if _t(r, "log-end") == "no")
    timeout = _t(root.find("devices/entry/deviceconfig/setting/management"), "idle-timeout")
    facts["admin_timeout_minutes"] = int(timeout) if timeout and timeout.isdigit() else None
    return Parsed(facts=facts, hostname=hostname, version=version, ctx=root)


# ----------------------------------------------------------------------------------------------- Cisco ASA / IOS


def _blocks(lines: list[str], prefix: str) -> list[list[str]]:
    """Indented sub-commands under each line that starts with prefix (e.g. 'line vty')."""
    out: list[list[str]] = []
    cur: list[str] | None = None
    for line in lines:
        if line.startswith(prefix):
            cur = []
            out.append(cur)
        elif cur is not None and line[:1] == " ":
            cur.append(line.strip())
        else:
            cur = None
    return out


def cisco(data: bytes) -> Parsed:
    text = _text(data)
    lines = [ln.rstrip() for ln in text.splitlines()]
    top = [ln for ln in lines if ln and ln[0] not in " !"]
    asa_m = re.search(r"^ASA Version (\S+)", text, re.M)
    ios_m = re.search(r"^version (\S+)", text, re.M)
    if not asa_m and not ios_m and not any(ln.startswith("hostname ") for ln in top):
        raise ParseError("This doesn't look like a Cisco running configuration (no version or hostname line).")
    asa = asa_m is not None
    version = asa_m.group(1) if asa_m else ios_m.group(1) if ios_m else None
    hostname = next((ln.split(None, 1)[1] for ln in top if ln.startswith("hostname ") and len(ln.split()) > 1), None)
    facts: dict = {"firmware_version": version}

    def has(rx: re.Pattern[str]) -> bool:
        return any(rx.match(ln) for ln in top)

    if asa:
        facts["mgmt_http_enabled"] = False  # ASDM is served over HTTPS only
        facts["mgmt_telnet_enabled"] = has(re.compile(r"telnet \d"))
        mgmt = [ln.split() for ln in top if re.match(r"(ssh|http) \d", ln)]
        facts["mgmt_access_restricted"] = bool(mgmt) and not any(len(p) >= 3 and _open_network(p[1]) and _open_network(p[2]) for p in mgmt)
        facts["ssh_v2_only"] = has(re.compile(r"ssh version 2\b"))
        facts["password_encryption"] = has(re.compile(r"password encryption aes\b"))
        enable = [ln for ln in top if ln.startswith("enable password ")]
        facts["enable_secret_used"] = bool(enable) and all(re.search(r"\b(encrypted|pbkdf2)\b", ln) for ln in enable)
        facts["aaa_enabled"] = has(re.compile(r"aaa authentication "))
        t = next((ln.split()[2] for ln in top if re.match(r"ssh timeout \d+", ln)), None)
        facts["admin_timeout_minutes"] = int(t) if t else None
    else:
        if has(re.compile(r"no ip http server\b")) and not has(re.compile(r"ip http server\b")):
            facts["mgmt_http_enabled"] = False
        elif has(re.compile(r"ip http server\b")):
            facts["mgmt_http_enabled"] = True
        vty = _blocks(lines, "line vty")
        if vty:
            transports = [next((c for c in b if c.startswith("transport input")), None) for b in vty]
            if any(t and re.search(r"\b(telnet|all)\b", t) for t in transports):
                facts["mgmt_telnet_enabled"] = True
            elif all(t is not None for t in transports):
                facts["mgmt_telnet_enabled"] = False
            facts["mgmt_access_restricted"] = all(any(c.startswith("access-class ") for c in b) for b in vty)
            timeouts: list[int | None] = []
            for b in vty:
                c = next((c for c in b if c.startswith("exec-timeout")), None)
                if c is None:
                    timeouts.append(None)
                else:
                    p = c.split()
                    minutes = int(p[1]) if len(p) > 1 and p[1].isdigit() else None
                    secs = int(p[2]) if len(p) > 2 and p[2].isdigit() else 0
                    timeouts.append(None if minutes is None else 100_000 if minutes == 0 and secs == 0 else minutes)
            known = [x for x in timeouts if x is not None]
            facts["admin_timeout_minutes"] = max(known) if known and len(known) == len(timeouts) else None
        facts["ssh_v2_only"] = has(re.compile(r"ip ssh version 2\b"))
        facts["password_encryption"] = has(re.compile(r"service password-encryption\b"))
        facts["enable_secret_used"] = has(re.compile(r"enable secret ")) and not has(re.compile(r"enable password "))
        facts["aaa_enabled"] = has(re.compile(r"aaa new-model\b"))
    facts["ntp_configured"] = has(re.compile(r"ntp server "))
    facts["remote_logging"] = has(re.compile(r"logging (host )?(\S+ )?\d+\.\d+\.\d+\.\d+")) or has(re.compile(r"logging host "))
    facts["any_any_allow_rules"] = sum(1 for ln in lines if re.search(r"\bpermit\s+ip\s+any[46]?\s+any[46]?(\s|$)", ln) and "inactive" not in ln)
    facts["snmp_default_community"] = any(re.match(r"snmp-server (community|host \S+ \S+ community) (public|private)\b", ln, re.I) for ln in top)
    return Parsed(facts=facts, hostname=hostname, version=version, ctx=lines)


# ----------------------------------------------------------------------------------------------- pfSense / OPNsense


def pfsense(data: bytes) -> Parsed:
    root = _xml(data)
    if root.tag not in ("pfsense", "opnsense"):
        raise ParseError("This doesn't look like a pfSense or OPNsense config.xml (the root element isn't <pfsense> or <opnsense>).")
    system = root.find("system")
    host = _t(system, "hostname")
    domain = _t(system, "domain")
    hostname = f"{host}.{domain}" if host and domain else host
    facts: dict = {"mgmt_telnet_enabled": False}  # neither offers Telnet administration
    proto = _t(system, "webgui/protocol")
    facts["mgmt_http_enabled"] = None if proto is None else proto.lower() == "http"
    if system is not None:
        facts["ntp_configured"] = bool(_t(system, "timeservers"))
    syslog = root.find("syslog")
    # pfSense: <syslog><enable/> turns remote logging on for the listed remote servers. OPNsense: enabled destinations.
    remote = syslog is not None and syslog.find("enable") is not None and any(_t(syslog, f"remoteserver{n}") for n in ("", "2", "3"))
    opn = [d for d in root.findall("OPNsense/Syslog/destinations/destination") if _t(d, "enabled") == "1"]
    facts["remote_logging"] = bool(remote or opn)
    filt = root.find("filter")
    if filt is not None:
        passes = [r for r in filt.findall("rule") if (_t(r, "type") or "pass") == "pass" and r.find("disabled") is None]

        def anyany(r: Element) -> bool:
            return r.find("source/any") is not None and r.find("destination/any") is not None and _t(r, "protocol") in (None, "any")

        facts["any_any_allow_rules"] = sum(1 for r in passes if anyany(r))
        facts["rules_without_logging"] = sum(1 for r in passes if r.find("log") is None)
    snmp = root.find("snmpd")
    if snmp is not None:
        facts["snmp_default_community"] = (_t(snmp, "rocommunity") or "").lower() in ("public", "private") and snmp.find("enable") is not None
    else:
        facts["snmp_default_community"] = False
    return Parsed(facts=facts, hostname=hostname, ctx=root)
