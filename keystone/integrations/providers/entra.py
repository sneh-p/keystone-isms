"""Microsoft 365 / Entra ID checks derived from the latest exposure snapshots (no live Graph access)."""

from __future__ import annotations

from .base import CheckDef, Outcome, Provider, SetupStep


class EntraProvider(Provider):
    key = "entra"
    name = "Microsoft Entra ID (from exposure snapshots)"
    description = "Uses the read-only collector snapshots you import: consent settings, expired app credentials and dormant high-risk apps."
    fields = ()
    checks = (
        CheckDef("user_consent", "Users cannot consent to apps", ("KC-ORG-15", "KC-ORG-19")),
        CheckDef("admin_consent_workflow", "Admin consent workflow enabled", ("KC-ORG-18",)),
        CheckDef("expired_credentials", "No expired app credentials left", ("KC-ORG-17",)),
        CheckDef("dormant_high_risk", "No dormant high-risk third-party apps", ("KC-ORG-22", "KC-ORG-19")),
    )
    setup = (
        SetupStep(
            "Collect and import a snapshot",
            "This integration never connects to Microsoft. A technician runs the read-only collector and imports "
            "collected.json; the checks use the latest snapshot of each tenant. Re-collect regularly (for example "
            "monthly) so results stay current.",
            link="/exposure", link_label="Get the collector",
        ),
        SetupStep(
            "Check a snapshot is there",
            "Use Test connection below. Checks show unknown when no snapshot has been imported, or when the "
            "collector could not read a dataset.",
            kind="verify",
        ),
    )

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        from keystone.tprm.exposure.exports import remediation_candidates
        from keystone.tprm.exposure.importer import tenants
        from keystone.tprm.exposure.inventory import latest_snapshot_ids
        from keystone.tprm.exposure.models import ExposureSnapshot

        snaps = latest_snapshot_ids(session)
        if not snaps:
            return [Outcome(c.key, "unknown", "No exposure snapshot imported yet") for c in self.checks]
        names = {t.id: t.name for t in tenants(session)}
        uc, acw = [], []
        for tid, sid in snaps.items():
            cp = session.get(ExposureSnapshot, sid).consent
            uc.append((names[tid], cp.users_can_consent if cp else None))
            acw.append((names[tid], cp.admin_consent_workflow_enabled if cp else None))

        def agg(key, items, good):
            if any(v is None for _, v in items):
                return Outcome(key, "unknown", "Not collected for: " + ", ".join(n for n, v in items if v is None))
            bad = [n for n, v in items if v != good]
            return Outcome(key, "pass" if not bad else "fail", "All tenants OK" if not bad else "Failing tenants: " + ", ".join(bad))

        from keystone.tprm.exposure.importer import status_ok

        rem = remediation_candidates(session)

        def from_rem(key: str, dataset: str, label: str) -> Outcome:
            # Nothing found is only a pass if every tenant's dataset was actually collected.
            missing = [names[tid] for tid, sid in snaps.items() if not status_ok(session.get(ExposureSnapshot, sid).endpoint_status, dataset)]
            found = rem[key]
            if found:
                return Outcome(key, "fail", f"{len(found)} {label}", {"apps": [r["App"] for r in found]})
            if missing:
                return Outcome(key, "unknown", f"{dataset.replace('_', ' ')} not collected for: " + ", ".join(missing))
            return Outcome(key, "pass", f"0 {label}")

        return [
            agg("user_consent", uc, False),
            agg("admin_consent_workflow", acw, True),
            from_rem("expired_credentials", "credentials", "app(s) with expired credentials"),
            from_rem("dormant_high_risk", "signin_activity", "dormant High/Critical app(s)"),
        ]
