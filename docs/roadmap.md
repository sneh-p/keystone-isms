# Roadmap: round 3 (approved by human:sneh, 2026-11-16)

Keystone is a single-organisation tool (no multi-client mode). Every item below was approved; items that add outside
access, logins, uploads or outbound connections follow the secure coding standard and are recorded in
[feature-security-designs.md](feature-security-designs.md). Status is updated as each item is committed.

| # | Item | Status |
|---|---|---|
| 1 | Docker: ClamAV and PostgreSQL services, images pinned by digest | Done (compose files not run here: no Docker on this host) |
| 2 | Backups: scheduled, verified, with a tested restore | Done |
| 3 | Health endpoint and alerts when jobs fail | Done |
| 4 | PostgreSQL support verified against a real server | Done (PostgreSQL 18, full suite) |
| 5 | gitleaks installed; React Router 7; Python type-checking gate | Done; gitleaks reports 6 fake test passwords in earlier commits (see below) |
| 6 | Vulnerability prioritisation: CISA KEV, EPSS, fix-by deadlines per severity | Done (also fixed a connector client decoding bug) |
| 7 | External attack surface (passive: certificate transparency, DNS, TLS/HTTP; verified domains only) | Done |
| 8 | Cloud posture: AWS Security Hub, Microsoft Defender for Cloud, Google Security Command Center | Done (not yet validated against live accounts) |
| 9 | Ticketing: Jira, ServiceNow, ConnectWise PSA, Autotask | Done (not yet validated against live instances) |
| 10 | Frameworks: NIS2, DORA, GDPR, ISO 27701, ISO 42001, PCI DSS, Cyber Essentials, Essential Eight | Done |
| 11 | Privacy: records of processing, DPIAs, data subject requests, breach log | Done |
| 12 | Business continuity: BIA, recovery objectives, continuity tests | Done |
| 13 | Policy e-signature and versioned PDF export | Done |
| 14 | SCIM provisioning; HR system connectors; Okta sign-in | Done (HR mappings not yet validated against live accounts) |
| 15 | Access review campaigns | Done |
| 16 | Slack and Teams notifications | Done (plus signed webhooks) |
| 17 | Scheduled report emails; board summary as PDF | Done |
| 18 | Per-record history for staff | Done (visible to anyone who can read the record) |
| 19 | API tokens and outbound webhooks | Done |
| 20 | AI: control narratives, evidence review, risk suggestions, audit-prep assistant | Control narratives and risk suggestions done; evidence review and audit-prep assistant not built (conflict with SC-LLM-004, decision needed) |

Added 2026-11-17 (requested by human:sneh): **configuration baselines** with report-only agents for Windows and Linux
and firewall configuration uploads (FortiGate, PAN-OS, Cisco ASA/IOS, pfSense/OPNsense). Done. The Linux agent was
run for real against a local Keystone. The Windows agent is tested with Pester mocks only, because there is no
Windows host here. The firewall parsers are tested with fictional exports, not real devices.

## Round 4 (requested by human:sneh, 2026-11-17): every component deepened, customisable configuration checks

| Area | Done |
|---|---|
| Configuration | Custom checks defined in Keystone: read-only probes, library of 30, re-validated by the agents, opt-out per host. Scoping by tag and host-name pattern; rule tags. Copy, JSON export/import, reset, how-to-fix text, bulk exceptions, asset links, xlsx report |
| Cross-cutting | Safe delete on 16 registers, CSV export on every searchable table, record search in ⌘K, calendar sources, comments on more records, email digest categories |
| Assets | Reviews and reminders, lifecycle dates, linked records, device links, offboarding returns |
| Controls and evidence | Evidence for several controls, accept/reject with SoD, control tests, custom mappings and controls; SoA shows evidence and tests |
| Risk | Risk treatment plan export, linked incidents and vendors, ticketing |
| Incidents | Playbooks, response actions, evidence with hash and chain of custody, NC from incident, risk link, ticketing |
| Audits and NCs | Three-year audit programme, editable findings, root-cause method, recurrence warnings |
| Suppliers | Questionnaire template editor with versions, offboarding checklist gating termination |
| People and policies | Training assignment, due dates, reminders and matrix; acknowledgement audiences; minor versions keep acceptances; version compare |
| Objectives and access reviews | Measurement history and metric links; recurring campaigns and export |

Not in round 4, each needs its own decision (SC-AGT-006): SSO group-to-role mapping, a public DSR intake form, emails
to Trust Center subscribers, an iCal feed, and automatic reminder emails to vendors.

### Round 5: guidance and consistency

| Area | Done |
|---|---|
| Guided tour | First sign-in tour for staff (role-aware, one step on phones) and for the employee portal; end at any step, take again from the account menu; seen-state stored per user |
| User guide | Rewritten as one guide for everyone who signs in, with 63 screenshots taken from a fresh demo by `scripts/guide_screenshots.py` |
| Consistency | Header actions stay on the right; toolbar buttons match field height; "and" in titles; load failures shown instead of endless placeholders; framework not found state; **New control** button for the existing custom-control API |
| Demo | Configuration baselines, hosts, a firewall and custom checks in the demo data |
| Deployment | README: tested step-by-step install on a fresh Ubuntu 24.04 server (systemd, nginx, Let's Encrypt, ClamAV), upgrade and troubleshooting |

### Round 7: help and training management

| Area | Done |
|---|---|
| In-app help | The user guide inside Keystone: contents, search, a help button on every page that opens its section, portal help |
| Logic security | Seven ways round workflows and approvals closed (risk acceptance, incidents, corrective actions, evidence requests, vendors, Trust Center links) |
| Training | Your own modules with a quiz editor, versions and retakes; built-in modules switched off or copied to edit; training done elsewhere with certificates, counted per person |

### Round 8: security expansion

| Batch | Done |
|---|---|
| 1 | Report suspicious activity from the portal; leaver access check; one exceptions register; background checks and confidentiality agreements; legal and contract obligations; change management; physical security (sites, visitor log, checks); policy exceptions |
| 2 | Security alert inbox with per-tool tokens; penetration tests and findings; application security; certificates and keys; backup jobs; indicators; NIST CSF maturity |
| 3 | Phishing simulations; look-alike domain monitoring; supplier breach news; on-call paging with escalation; DMARC report upload |

### Round 9: integrations and agents

| Batch | Done |
|---|---|
| A | Raw check results filed as evidence; tasks when a passing check starts failing, flapping checks marked; integration health (failures in a row, last success, escalation) and key expiry reminders; read-only key checks for GitHub, AWS and Microsoft 365; macOS agent; hourly agent check-ins and quiet-agent alerts; agent integrity, out-of-date agents, signed Windows agent, optional key pinning; enrolment key expiry and use limits; coverage against your other tools |
| B | Microsoft 365 checks (MFA, phishing-resistant admins, legacy sign-in, audit log search, Secure Score trend, Intune compliance); six more AWS checks and five more GitHub checks; Jamf Pro and Kandji with fleet encryption and check-in checks; agents report endpoint security, backup, log forwarding, USB storage, time sync, sudo accounts, browser versions and installed software; Linux package vulnerabilities from downloaded OSV data |
| C | Okta and Google Workspace checks; posture checks from AWS Security Hub, Defender for Cloud (with Defender plans) and Security Command Center; alerts pulled from CrowdStrike, SentinelOne, Sophos and Defender into the Alert inbox; check-ins from backup jobs and CI; rollout steps for Group Policy, Intune, RMM tools, Mac MDMs and Ansible; FortiGate and PAN-OS configurations read over their APIs; extra trusted CAs for internal servers |

Not done, each needs its own decision: SMS or phone paging (a third party holding staff phone numbers), DMARC reports
read straight from a mailbox, and takedown requests sent from Keystone.

Needs the organisation (can't be done from here): validating attack surface connectors with read-only keys, a real
TLS certificate and domain, pushing to a remote, and entering SMTP, SSO and connector credentials.

## Open items from phase A

- **gitleaks and history.** The secrets gate scans the whole branch history (there is no remote base yet). Six
  made-up test passwords sit in earlier commits; the current files no longer contain them. Clearing the gate needs a
  decision: allowlist those six findings in `.gitleaks.toml` (AppSec), or rewrite the unpushed history before the
  first push.
