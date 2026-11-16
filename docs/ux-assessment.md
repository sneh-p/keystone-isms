# UI/UX assessment and feature expansion (2026-11-16)

Method: every screen of the live demo (Alpine Ski House) captured at desktop (1440 px), tablet (834 px) and phone
(390 px) widths, in light and dark mode; an automated accessibility audit (axe-core 4.14, WCAG 2.1 A/AA plus best
practices) on every screen, an open drawer, the sign-in page, the employee portal and the public Trust Center;
keyboard focus checks; load timing; and a heuristic review of the core journeys (onboarding, tasks, controls, risks,
policies, portal, Trust Center).

## Status

| Group | Findings | Status |
|---|---|---|
| Accessibility and bugs | A1–A7, B1–B2 | Done (commit "UX phase 1"); axe-core WCAG 2.1 AA check in the e2e suite |
| Navigation and naming | N1–N4 | Done (commit "UX phase 2") |
| Dashboard and registers | D1–D3, R1–R5 | Done (commit "UX phase 3"). Also: two-column KPI grid on phones (part of M1), keyboard-operable table rows |
| Phones, Trust Center, speed | M1–M3, T1–T2, P1 | Done (commit "UX phase 4"): two-column KPIs, card lists below 640 px, full-screen dialogs; "Frameworks we align to" with per-framework aligned/certified/hidden; device checks name what failed; main bundle 428 KB → 80 KB, chart library loads with the FAIR tab |
| Features | Notifications, vendor portal, auditor workspace, SSO | Done after AppSec sign-off (docs/feature-security-designs.md) |

## Summary

The product looks consistent and modern, loads quickly (median 0.86 s per screen, no console errors), has no
horizontal overflow on phones, and the employee portal and public Trust Center are the strongest screens (the
Trust Center has no accessibility violations). The weaknesses are: accessibility details repeated on every page,
a long flat navigation, data tables that don't adapt to phones, registers without bulk actions, a dashboard that
reports but doesn't guide, and no way to tell people what needs doing (no notifications).

## What works

- One visual language: cards, badges, drawers, consistent status colours with text labels (never colour alone).
- Detail in drawers with deep links (`?open=`), a command palette (Ctrl/⌘ K), light and dark themes.
- Control detail brings readiness, tasks and evidence together; the task board makes the evidence cycle visible.
- Employee portal: one page, clear progress ("3 of 9 done"), plain language.
- Empty states explain what to do next; forms validate on the server with readable messages.

## Findings

Severity: **high** blocks or misleads users; **medium** slows them down; **low** polish.

### Accessibility (WCAG 2.1 AA)

| # | Sev | Finding | Evidence | Fix |
|---|---|---|---|---|
| A1 | high | Text below 4.5:1 contrast | 150 elements on all 30 screens in light mode; mostly the sidebar section headings (`text-muted-foreground/80`, uppercase), plus muted hints; 6 in dark mode | Raise the muted token and drop the `/80` opacity on section headings |
| A2 | high | User menu's accessible name doesn't include its visible text | Every page | Name it "Account menu: Demo Admin, Administrator" or drop the custom label |
| A3 | medium | Progress bars without an accessible name | 17 on 7 screens (dashboard, frameworks, people, policies, audits, questionnaires, portal) | `Progress` takes a label (e.g. "ISO 27001 readiness") |
| A4 | medium | Unnamed buttons | Role dropdowns in **Settings → Users** | `ariaLabel` on table selects |
| A5 | medium | No "skip to content" link | Keyboard users tab through ~30 navigation links on every page | Skip link to `main` |
| A6 | low | Heading levels skip (h1 → h3) | 7 screens | Use h2 for card titles |
| A7 | low | Sign-in page has no `main` landmark; one scrollable list isn't keyboard-focusable (audits) | — | Landmark; `tabIndex=0` on the scroll area |

### Bugs

| # | Sev | Finding | Fix |
|---|---|---|---|
| B1 | high | Risk drawer: the Likelihood and Impact selects overlap and truncate their text ("4 · Likely (about onc") | Stack the two selects or shorten the option labels |
| B2 | low | Control drawer shows the owner twice (select and "Owner —") | Drop the duplicate |

### Navigation and information architecture

| # | Sev | Finding | Fix |
|---|---|---|---|
| N1 | medium | 27 navigation items in 6 groups; at 900 px height "Operations" and below are off-screen | Collapsible groups, remembered per user; fold related screens into tabs (see N2) |
| N2 | medium | Related screens are separate destinations: *Questionnaires* and *Vendor assessments* (both vendor work), *Nonconformities*, *Audits* and *Management review* (improvement), four Settings pages | One **Vendors** area with tabs; one **Improvement** area with tabs; one **Settings** page with tabs |
| N3 | medium | Two different things are both called questionnaires: *Questionnaires* (we send to vendors) and *Security questionnaires* (customers send to us) | Rename to **Vendor questionnaires** and **Customer questionnaires** |
| N4 | low | Revisiting **Onboarding** shows step 1 again with no sign it was completed | Show "completed on …" and what re-running changes |

### Dashboard and guidance

| # | Sev | Finding | Fix |
|---|---|---|---|
| D1 | medium | The overview reports numbers but doesn't say what to do next; e.g. 107 controls have no owner and nothing points to it | A "Next steps" card from real gaps: assign owners, approve drafts, upload evidence, connect an integration |
| D2 | medium | KPI cards aren't links, and "Controls audited (3 yrs) 4.7%" is hard to interpret | Make cards clickable; plain labels ("5 of 107 controls audited in 3 years") |
| D3 | low | No trend: readiness and risk are shown only as of today | Weekly snapshots and sparklines |

### Registers and forms

| # | Sev | Finding | Fix |
|---|---|---|---|
| R1 | medium | No bulk actions: assigning owners to 107 controls or closing tasks is one record at a time | Row selection with bulk assign owner / status / due date |
| R2 | medium | Controls table: every Owner cell is "—", and an unlabelled warning icon sits between columns | Readiness and evidence columns; label the icon ("No current evidence") |
| R3 | medium | Task board: "To do" holds 57 cards with no filters except "my tasks" | Filters by owner, framework, control and due window; group by month |
| R4 | low | Drawers are always edit forms, even for read-only roles | Read view with an Edit button; unsaved-changes warning |
| R5 | low | No CSV import for registers (assets, risks, vendors, people) | Import with a preview and validation |

### Phones and tablets

| # | Sev | Finding | Fix |
|---|---|---|---|
| M1 | medium | KPI cards stack one per row: five cards fill the first screen before any content | Two-column compact KPI grid below 640 px |
| M2 | medium | Wide tables squeeze columns and cut identifiers ("RSK-") | Card list layout for registers below 640 px |
| M3 | low | Drawers keep desktop width rules | Full-screen sheets on phones |

### Trust and content

| # | Sev | Finding | Fix |
|---|---|---|---|
| T1 | medium | The public Trust Center shows four framework badges at the top while readiness is ~5%; customers may read them as certifications | Label as "Frameworks we align to", show certification status separately, let admins choose which to show |
| T2 | low | A device marked "Needs attention" in the portal doesn't say which check failed | List the missing checks |

### Performance

| # | Sev | Finding | Fix |
|---|---|---|---|
| P1 | low | Two 416 KB chunks (main bundle and the risk register, which includes the chart library) | Load charts only when the FAIR tab opens; split vendor libraries |

## Feature expansion

Compared with what customers expect from compliance platforms (and with this product's own roadmap), ordered by
value for effort.

### Tier 1: closes the biggest workflow gaps

1. **Notifications and reminders.** An in-app inbox plus email digests (SMTP) for tasks due, approvals waiting,
   policies to acknowledge, evidence expiring and integration failures. Today nothing tells anyone what to do, so
   work silently goes overdue.
2. **Vendor self-service portal.** Send a questionnaire link to the vendor; they answer and upload documents
   themselves (token in the URL fragment, as for the Trust Center). Today answers are typed in by staff.
3. **Auditor workspace.** Time-limited read-only access for an external auditor, an evidence request list ("PBC
   list") with comments, and an audit pack export (SoA, policies and evidence per control as a ZIP).
4. **Single sign-on (OIDC: Entra ID, Google, Okta).** Enterprise must-have; already on the roadmap.

### Tier 2: makes daily work faster

5. **Comments, @mentions and an activity feed** on risks, controls, tasks, incidents and policies.
6. **Bulk actions, saved views and CSV import** for every register.
7. **Trends and board reporting:** weekly snapshots, readiness and risk over time, a one-page board report (PDF).
8. **More integrations:** Microsoft Intune / Jamf (device compliance instead of self-attestation), Google Workspace
   and Okta (MFA and admin checks), HR systems for joiners and leavers, Slack / Teams for notifications.

### Tier 3: depth

9. **Risk library and scenario templates**; link incidents to the risks they realise.
10. **Policy e-signature and versioned PDF export** for regulated customers.
11. **Control testing calendar** (who tests what, when) for internal audit planning.

Security notes for any of these: the vendor portal and auditor workspace are new external access paths and new
uploads, and SSO and notifications change authentication and add outbound destinations, so each is on the
secure coding standard's escalation list (SC-AGT-006) and gets its own design review.
