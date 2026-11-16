# Workflow analysis and improvements (2026-11-16)

Method: each core ISMS workflow was traced through the services that run it, on the demo organisation (Alpine Ski
House), asking four questions at every step: what starts it, who is told, who acts (and who may not, for segregation
of duties), and where does it leave Keystone. Numbers below were measured on the demo data with the same service
functions the app uses.

## Workflows traced

| Workflow | Steps | State before this change |
|---|---|---|
| Setup | onboarding wizard, frameworks, draft policies, evidence tasks | Works; every generated task goes to the person who ran the wizard |
| Controls and evidence | owner, implementation, evidence, review cycle, expiry | Expiring or missing evidence shown on the dashboard only |
| Policies | draft, submit, approve (not the author), publish, acknowledge, review | Approvers and employees told; policy owners not told about overdue reviews or missing acceptances |
| Risks | identify, assess, treat or accept, review | Owners told about reviews and their actions; not about "above appetite, untreated" or an expired acceptance |
| Incidents | report, contain, notify regulator, close, lessons | Owner sees the incident; an incident that realises a risk didn't prompt its reassessment |
| Nonconformities | raise, corrective action, done, effectiveness check (not the owner) | Action owners told; nobody told an effectiveness check was waiting |
| Vendors | tier, questionnaire, assessment, approval (not the author), DPA, contract, review | Nothing routed to vendor owners or approvers |
| Audits | plan, evidence requests, findings, NCs, pack | Evidence requests seen only by opening the audit |
| Management review | inputs compiled from live data, decisions, actions | Works (inputs are automatic) |
| Trust Center, customer questionnaires | access requests, answer approval | Seen only on their pages |
| People | invite, portal, offboarding | Invitation links had to be copied into an email by hand |

## Findings

| # | Finding | Evidence | Effect |
|---|---|---|---|
| W1 | **Most flagged work reaches nobody.** The dashboard's "Needs attention" list is shared; "My tasks" and the notification inbox only covered some categories | 29 attention items on the demo; **7 (24%)** appeared in anyone's My tasks; vendor (7), control/evidence (5), risk appetite (1), policy drafts (9) reached no one | Work silently goes overdue; the inbox shipped in the previous change inherited the gap |
| W2 | **Approval queues have no recipient.** Vendor assessments awaiting approval, corrective actions awaiting an effectiveness check, Trust Center access requests, drafted questionnaire answers, auditor evidence requests | None of the five appeared in My tasks or the inbox | Segregation-of-duties steps stall: the second person never hears about it |
| W3 | **Unowned records can't be routed.** 5 of the 29 items sit on records without an owner (e.g. 106 of 107 controls) | Measured | Owner-based routing alone would drop them |
| W4 | **All work sits with one person.** The setup wizard assigns every generated task to whoever runs it; assigning control owners later doesn't move the tasks | 58 of 58 open tasks assigned to the ISMS manager | One person's list grows; control owners don't see their tasks |
| W5 | **Links leave Keystone by copy and paste.** Invitations, vendor portal links and Trust Center access links were shown to copy into an email, although email now exists | 3 flows | Slower, and tokens end up in chat tools |
| W6 | **Incidents don't feed risk reassessment.** An incident can name the risk it realised, but nothing prompts the risk owner to reassess (ISO 27001 8.2 / 6.1) | Linking left the review date unchanged | Risk ratings lag reality |

## Improvements made

| # | Change | Result |
|---|---|---|
| W1–W3 | **Attention routing** (`keystone/reporting/routing.py`): every attention item goes to the owner of its record; approval and verification queues go to holders of the approving permission except the person whose work is checked; items on records without an owner go to the ISMS managers as one summary line per category. Feeds My tasks and the notification inbox (hourly) | All 29 demo items now reach a named person (measured): items on owned records go to the owner (draft policies as one line per owner), and the 5 items on controls without an owner arrive as 3 summary lines for the ISMS manager |
| W4 | **Tasks follow control owners**: when an owner is set (one control or in bulk), "Also hand over their open tasks" (on by default) moves open tasks to the new owner. A task moves only if every control it serves has that owner; tasks in review stay with whoever submitted them. Each move is audited | Assigning owners redistributes the 58 tasks instead of leaving them with one person |
| W5 | **Send by email** for invitations, vendor portal links (to the contact) and Trust Center access approvals, when email is set up and `KEYSTONE_PUBLIC_URL` is set. Plain-text email; the link is built from the public address; the audit log names the recipient but never the link. If sending fails, nothing is created (the new token is rolled back) | No copy and paste needed; tokens go straight to the recipient |
| W6 | **Incidents that realise a risk** (linked at report time or later) make the risk's review due today; the risk owner sees "Review risk …" and the incident timeline records why | Reassessment starts the day the incident is linked |
| – | Dashboard "My tasks" shows the 10 most urgent and points to the bell for the rest | The card stays readable with the larger list |

Tests: `tests/test_workflows.py` (coverage of every attention category, owner vs summary routing, segregation of
duties for approvals and verification, employees and expired accounts excluded, task hand-over rules, emailed links
including rollback on failure and the public-address requirement, incident to risk).

## Second round (built 2026-11-16)

| Item | What it does | Decision taken |
|---|---|---|
| Comments and @mentions | A Discussion on risks, controls, tasks, incidents, policies, vendors, nonconformities and audits. Typing @ suggests people; a mention puts a notification in that person's inbox (it stays until read). Comments are append-only and audited; shown as plain text | Any staff member who can read the record may comment; employees can't. Uses the existing `read` permission, so the role table is unchanged |
| Workload | Per person: open, overdue and due-soon tasks, items routed to them, controls and risks owned; an Unassigned row | Read-only for all staff |
| Saved views | Name and reuse filter sets on Controls and Tasks; personal, up to 50; only filter parameters are stored | — |
| Calendar | Month view of task due dates, control, policy, risk and vendor reviews, contract ends, evidence expiry and audits, filterable by person and kind; a list on phones | Dates come from the records (nothing stored); categorical colours from the validated dataviz palette, never colour alone |
| Board summary | One-page Word report: headline figures with the change over the trend window, readiness per framework, top 5 risks, what needs attention. Export audited | — |
| Risk library | 24 Keystone-written scenarios with threat, weakness, consequence, suggested rating and treating controls; "Add from library" creates an assessed risk | Content is original; codes validated by a test |
| SSO required | Turns password sign-in off for everyone except administrators (break-glass); only while a provider is on; the last provider can't be turned off while it applies. A refused password sign-in is audited and only explained after the correct password | Administrators are the break-glass accounts |

Tests: `tests/test_collaboration.py`.
