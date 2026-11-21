"""Keystone's own agents as a vulnerability source: the Linux packages they report, matched against OSV data that
Keystone downloads (keystone/asm/osv.py). Nothing about the hosts leaves Keystone. Decided by human:sneh, 2026-11-21."""

from __future__ import annotations

from keystone.asm import osv
from keystone.asm.vocabulary import DeviceObs, Inventory, VulnObs

from ..http import ConnectorError
from .base import InventoryProvider, SetupStep

MAX_MATCHES = 400_000


class AgentSoftwareProvider(InventoryProvider):
    key = "keystone_agents"
    name = "Keystone agents (installed software)"
    description = ("Vulnerabilities in the packages Keystone agents report on Debian, Ubuntu, AlmaLinux and Rocky Linux hosts, matched against public OSV data "
                   "that Keystone downloads. Nothing about your hosts is sent anywhere.")
    category = "vuln"
    mapping_note = ("Package lists from Keystone's agents (1.2 or later): source packages and versions from dpkg, or epoch:version-release from rpm. Advisories "
                    "from the OSV archives for each distribution; only those with a fixed version are matched.")
    needs_session = True
    fields = ()
    setup = (
        SetupStep("Install agents 1.2 or later", "Agents report installed software with each full report (Configuration → Agents). Windows and Mac apps are listed "
                  "on each host's page but not matched: use your scanner or Microsoft Defender for those."),
        SetupStep("Allow the download", "Keystone downloads the OSV file of each Linux distribution your hosts run from osv-vulnerabilities.storage.googleapis.com, "
                  "once a day and only when it changed. Allow that host through your egress firewall. The files can be a few hundred MB; they're kept in the data "
                  "directory's osv folder."),
        SetupStep("Check", "Choose Test connection: Keystone lists the hosts and Linux releases it found, without downloading anything.", kind="verify"),
    )

    def collect(self, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        raise ConnectorError("This source runs inside Keystone.")

    def collect_in(self, session, config: dict, secrets: dict, preview: bool = False) -> Inventory:
        from sqlalchemy import select

        from keystone.configcheck.models import ConfigTarget

        inv = Inventory()
        targets = [t for t in session.scalars(select(ConfigTarget).where(ConfigTarget.kind == "agent", ConfigTarget.revoked_at.is_(None), ConfigTarget.software_at.is_not(None)))
                   if t.software]
        releases = {t.id: osv.release_of(*(t.os_release or " ").split(" ", 1)) for t in targets}
        matched = [t for t in targets if releases[t.id] is not None]
        for t in matched:
            inv.devices.append(DeviceObs(external_id=f"agent:{t.id}", name=t.name, category="vuln", hostname=t.hostname or t.name, os=t.os_name, os_version=t.os_version,
                                         device_type="server" if "server" in (t.tags or []) or t.platform == "linux" else "workstation", last_seen=t.software_at))
        inv.sample_fields["agent hosts"] = sorted({r.ecosystem for r in releases.values() if r})
        skipped = len(targets) - len(matched)
        if skipped:
            inv.notes.append(f"{skipped} host(s) run a system whose packages aren't matched (Windows, macOS, or another Linux distribution)")
        if preview:
            inv.notes.append(f"{len(matched)} Linux host(s) to check: {', '.join(inv.sample_fields['agent hosts']) or 'none yet'}. Nothing was downloaded.")
            return inv
        packages: dict[str, set[str]] = {}
        for t in matched:
            rel = releases[t.id]
            if rel is not None:
                packages.setdefault(rel.ecosystem, set()).update(p[0] for p in t.software)
        complete = True
        for archive in sorted({r.archive for r in releases.values() if r}):
            ecos = {r.ecosystem for r in releases.values() if r and r.archive == archive}
            try:
                advisories = osv.read(osv.fetch(archive), ecos, packages)
            except ConnectorError as e:
                inv.notes.append(f"{archive}: {e}")
                complete = False
                continue
            for t in matched:
                rel = releases[t.id]
                if rel is None or rel.archive != archive:
                    continue
                for name, version in t.software:
                    seen: set[str] = set()
                    for adv in advisories.get((rel.ecosystem, name), []):
                        ids = osv.cves(adv) or [adv.id]
                        if seen.issuperset(ids):
                            continue  # the same CVE from another advisory
                        fixed = osv.affected(version, adv.ranges, rel.compare)
                        if fixed is None:
                            continue
                        seen.update(ids)
                        inv.vulns.append(VulnObs(device_external_id=f"agent:{t.id}", key=f"{ids[0]}:{name}"[:120],
                                                 title=f"{name} {version}: {adv.summary or adv.id} (fixed in {fixed})"[:500],
                                                 severity=adv.severity or "medium", cve=", ".join(osv.cves(adv))[:200] or None))
                        if len(inv.vulns) >= MAX_MATCHES:
                            raise ConnectorError("More matches than Keystone records in one run.")
        inv.complete.add("devices")
        if complete:
            inv.complete.add("vulns")
        return inv
