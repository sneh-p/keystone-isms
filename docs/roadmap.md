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

Needs the organisation (can't be done from here): validating attack surface connectors with read-only keys, a real
TLS certificate and domain, pushing to a remote, and entering SMTP, SSO and connector credentials.

## Open items from phase A

- **gitleaks and history.** The secrets gate scans the whole branch history (there is no remote base yet). Six
  made-up test passwords sit in earlier commits; the current files no longer contain them. Clearing the gate needs a
  decision: allowlist those six findings in `.gitleaks.toml` (AppSec), or rewrite the unpushed history before the
  first push.
