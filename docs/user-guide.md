# User guide

Keystone follows the ISO 27001 cycle: set the context, assess risk, choose and run controls,
check how it's working, and improve. Your **Overview** page shows what needs attention and the
tasks assigned to you.

## Navigation

The sidebar groups screens by area; click a group heading to fold it away (Keystone remembers this). **Vendors**,
**Improvement** (nonconformities, audits, management review) and **Settings** each have tabs across the top.
Press Ctrl+K (⌘K on a Mac) to jump to any screen by name.

If your organisation has turned on single sign-on, choose **Sign in with Microsoft** or **Sign in with Google** on the
sign-in page; your first sign-in activates the account an administrator created for you.

The **Overview** starts with **Next steps**: up to four gaps worth closing next, worked out from your data (scope not
approved, controls without an owner, draft policies, approvals waiting, implemented controls without evidence, no
integration connected, employees with portal tasks open, Trust Center not published). Each links to a filtered list.
The figures below it link to their registers and show how they moved over the last 12 weeks: hover the small line for
a week's value. Keystone records the figures once a day; the line shows the last value of each week.

**Registers.** Filters on Controls (domain, status, owner, needs attention) and Tasks (assignee, framework, control,
due window) are kept in the page address, so you can bookmark or share a filtered view. Tick rows to change several at
once: owner and status for controls (marking not applicable stays one at a time, with a reason), assignee and due
date for open tasks (list view). When you give controls an owner, **Also hand over their open tasks** (on by default)
moves those controls' open tasks to the new owner; a task shared with another owner's control stays where it is. Every changed record gets its own audit entry, and if any one change is refused,
nothing changes. Control and risk details open read-only; choose **Edit** to change them. Keystone asks before
discarding unsaved edits.

On a phone, registers show one card per record, and dialogs open full screen.

**Import from CSV.** Assets, Risks, Vendors and People have **Import CSV**. Download the template, fill it in (one row
per record; owners by username or email; dates as YYYY-MM-DD; yes/no for flags), and choose the file. Keystone checks
every row with the same rules as the forms and lists the problems by row number. Nothing is saved until every row is
valid and you confirm; the import is all or nothing, up to 1,000 rows at a time.

## Assets

Open an asset to see everything linked to it:
- risks, incidents and vendors
- business processes that depend on it
- configuration checks on it
- devices your attack-surface tools report (with suggested matches)

The asset page also has:
- **Mark reviewed**, which sets the next review a year on. Owners are reminded two weeks before a review is due.
- Acquisition and disposal dates.
- Discussion.

When someone is offboarded, their page lists the assets they own so they can be returned or reassigned.

## Finding, exporting and deleting

- **Search**: press ⌘K (Ctrl+K) and type at least two characters. Below the pages, the palette lists matching
  records: risks, controls, policies, tasks, incidents, vendors, assets, nonconformities, audits, processing
  activities, business processes, and hosts and firewalls. You can also type a reference such as `RSK-0012`.
- **Export CSV** on any searchable table downloads what the table shows, with its current search and sort. Cells a
  spreadsheet would run as formulas are prefixed with an apostrophe.
- **Delete** removes a record created by mistake. Keystone refuses while anything depends on the record or anything
  about it was approved, accepted, signed, notified or verified, and says what to do instead (close, retire,
  terminate). The audit log keeps the deleted record's last values.

## Notifications

The bell at the top of every page (and of the employee portal) lists what needs you: tasks and
reviews due within two weeks, approvals waiting, policies to accept, failed integrations, and
vendor questionnaires that came back. Anything the dashboard flags goes to the owner of the record: a risk above
appetite to its risk owner, expiring evidence to the control owner, a vendor's missing DPA to the vendor owner, and so
on. Approvals and effectiveness checks go to people allowed to approve, never to the person whose work it is. Items
on records without an owner reach the ISMS managers as one summary line each. Choosing an item opens it and marks it
read. If an
administrator has set up email, you also get a daily digest of unread items; turn it off under
**My account**.

Under **My account → Notifications** choose which categories the daily email includes. The bell always shows
everything.

The **calendar** also shows these dates:
- data subject request deadlines
- review dates of processing activities, DPIAs and business-impact entries
- continuity tests and plan exercises
- access reviews
- nonconformity and corrective-action due dates
- objective target dates
- when an uploaded firewall configuration goes out of date

## Attack surface

**Risk → Attack surface** shows every device, account, vulnerability and configuration setting your connected tools
report, and where they miss your **baselines** (for example "Disk encryption on" for workstations, "MFA registered for
every enabled account", "Critical vulnerabilities fixed within 7 days"). Start with **Baselines → Add recommended
baselines** and adjust scope and severity. **Findings** lists the gaps; they close when the tools report the fix.
Missing coverage is a finding too, for example a device the RMM manages but no EDR agent reports. If a gap is accepted
for a while, someone with risk-acceptance rights can approve an **exception** with a reason and an end date.

## Configuration

**Risk → Configuration** shows whether your Windows and Linux hosts and your firewalls are set up the way your
baselines require.
- **Hosts and firewalls** lists each one with its status. Open one to see every rule's result, the reported settings
  and the history of what changed.
- A setting that wasn't reported shows as **Unknown**, never as passing. **Not applicable** means a prerequisite is
  off, for example SSH rules on a host without an SSH server.
- **Baselines** holds the required settings per platform; open a baseline to change values, severities and linked
  controls.
- To accept a failing setting for a while, someone with risk-acceptance rights grants an **exception** with a reason
  and an end date, on one host or, from the baseline, on every host where that rule fails.
- **Custom checks** are extra settings your administrators defined (marked "Custom"). Failing results show "How to
  fix" when the rule or check has instructions.
- **Compliance report** downloads every result as a spreadsheet; it's also on each host's and baseline's page.

## Working together

- **Discussion:** risks, controls, tasks, incidents, policies, vendors, nonconformities and audits have a discussion.
  Type @ and choose a person to mention them; they get a notification.
- **Calendar** (Compliance → Calendar): what is due when (tasks, reviews, contract ends, expiring evidence, audits),
  by person and kind. Change the record to move an entry.
- **Workload** (Operations → Workload): open and overdue work per person, and what nobody owns yet.
- **Saved views:** on Controls and Tasks, set filters and choose **Views → Save current filters**.
- **Board summary:** Reports → Board summary (Word), one page for management.
- **Risk library:** Risk register → **Add from library** starts a risk from a common scenario with a suggested
  rating and treating controls; adjust both to your situation.

## Getting started (ISMS manager)

1. **Onboarding wizard**: after the first sign-in, describe the company (size, where systems are
   hosted, the data you handle, whether you build software or run offices) and choose the
   frameworks. Keystone loads the frameworks, writes the scope, creates draft policies from its
   templates, creates evidence tasks and marks controls that clearly don't apply as not
   applicable, with the reason. You can run it again; existing records are kept.
2. **Policies**: review the generated drafts, adapt them and send them for approval.
3. **Organisation & scope**: record internal and external issues, interested parties, ISMS
   roles and security objectives. Approve the scope. Editing the scope later clears the
   approval.
4. **Assets**: list the information, systems, services and sites in scope, with owners and
   confidentiality, integrity and availability ratings.

## Tasks

Tasks are the recurring work that produces evidence, such as "review admin accounts" or "test a
backup restore". Each is linked to controls and has an assignee, a due date and a frequency.
Start a task, add a note or attach files, and submit it for review. Someone other than the
assignee approves it: the note or files are filed as evidence on every linked control, and the
next occurrence is scheduled. Overdue tasks make their controls not ready.

## People and the employee portal

Add people under **People** and choose **Email invitation** (when email is set up) or create an
invitation link and send it yourself. In the portal,
employees accept the policies that need acknowledgement, complete short training modules with a
quiz, and confirm their device checklist (disk encryption, screen lock, anti-malware, updates,
firewall, password manager). A device marked "Needs attention" lists the checks still to confirm. The People
page shows who is complete. When someone leaves, work
through the offboarding checklist; completing it disables their account.

## Trust Center

Frameworks appear on the public page under **Frameworks we align to**, which says that alignment is not a
certification. In **Settings**, set each framework to *Aligned*, *Certified* (only if you hold a current certificate
or attestation report; certified frameworks are shown separately at the top) or *Hidden*.

Publish a public page for customers at `/trust/<your-slug>`: an overview, the frameworks you
work to, controls that are passing, published policies, subprocessors and FAQs. Reports and
other documents can be public or require an approved request and a signed NDA. Review requests
under **Trust Center → Requests**; approving produces a private link, emailed to the requester when
email is set up (otherwise copy it to them).

## Integrations

Connect a website, GitHub, AWS or the imported Entra data to run read-only checks on a
schedule. The **Attack surface sources** (Microsoft 365, EDR, RMM and vulnerability tools) feed
**Attack surface** instead; see that section. **Connect** shows a setup guide with commands to copy for creating a read-only
credential and checking that it is read-only; **Test connection** tries the settings before you
save. Passing checks become evidence on their controls. A failing, erroring or unknown
check shows on the control and makes it not ready.

## Customer questionnaires

Under **Customer questionnaires**, upload a questionnaire a customer sent you (.xlsx or .csv) or paste the questions. Keystone finds the
question column, plus any answer column. For each question you can:

- **Fill from the knowledge base**: close matches to approved knowledge-base answers are filled
  in automatically, and similar answers are suggested on each question.
- **Draft with AI** (if an administrator turned AI on): Claude drafts answers from your
  approved policies and knowledge base, with quoted sources. Answers marked "No verified source"
  or "Not covered by sources" need particular care.
- Write or edit the answer yourself.

Every answer is approved by a person. **Export** writes the approved answers into the customer's
own spreadsheet, in their answer column (or a new "Answer" column). Add good approved answers to
the knowledge base so the next questionnaire is faster.

## Risk

- **Treatment plan** downloads the risk treatment plan (ISO 27001 6.1.3 e). It lists each open risk with its owner,
  levels, treatment option and controls, one row per treatment action, plus any acceptance and the next review date.
- **Linked records.** A risk shows the incidents where it materialised and the vendors involved, and a risk can be
  sent to your ticketing system.


- Add each risk with its threat, vulnerability and consequence. Rate **inherent** likelihood and
  impact (before controls) and **residual** (with controls). The matrix and the risk appetite
  are in `config/risk_matrix.yaml`.
- Pick a treatment (mitigate, accept, transfer, avoid), link the controls that treat it, and add
  treatment actions with owners and dates.
- **Acceptance** needs the `risk.accept` permission and a justification. The approver can't be
  the risk owner. Risks above appetite can be accepted for at most a year.
- **FAIR**: on a risk, enter ranges (minimum / most likely / maximum) for threat event
  frequency, threat capability, control strength and loss magnitude, then run the simulation.
  You get expected annual loss, percentiles and a loss exceedance curve. Results support
  decisions; they are not predictions.

## Controls, evidence and the Statement of Applicability

- **Evidence for several controls.** One document can support several controls ("Controls" on the evidence). It
  then counts for each of them.
- **Accept or reject evidence.** Someone other than the person who added it decides. Rejected evidence shows the
  reason and no longer counts as current.
- **Control tests.** Auditors and ISMS managers record design or operating-effectiveness tests: the method, the
  sample, the result and the evidence examined. The control owner can't test their own control. An ineffective result
  can raise a nonconformity straight away.
- **Your own mappings and controls.** Map a control to more requirements ("Map to a requirement"), or create your
  own controls (KC-CUS-nn) for requirements you meet differently. Keystone's own mappings can't be removed.
- **Statement of Applicability.** It shows each requirement's current evidence and latest test result, and the
  exports include them.


- **Controls**: set each control's status, owner and how it's implemented. "Not applicable"
  needs a reason. Record reviews to keep the review cycle current.
- **Evidence**: attach files, links or notes with a "valid until" date. Keystone warns 30 days
  before evidence expires and lists implemented controls that have no current evidence.
- **Statement of Applicability**: built automatically for each framework from your controls and
  linked risks. Record a decision to override applicability, approve a version when it's ready,
  and export to Excel or Word. Keystone shows what has changed since the last approved version.

## Third parties

**Vendor portal.** In a vendor questionnaire, enter the contact and choose **Email link to the contact** (when
email is set up) or **Create vendor link** to copy it yourself. They answer the questions and upload supporting documents (PDF, PNG, JPG, DOCX or XLSX,
up to 10 MB each, 20 files) themselves; every file is virus-scanned. Links don't expire unless
you set a date, and you can revoke one at any time (creating a new link replaces the old one).
Once the vendor submits, the questionnaire is read-only for them and its owner is notified.

- **Vendors**: the tier comes from data sensitivity, operational criticality, access level and
  personal data (rules in `config/tprm.yaml`). Overriding the tier needs a reason.
- **Questionnaires**: send the baseline template, enter answers as they arrive, then review.
  "No" and "partial" answers become findings linked to controls.
- **Vendor assessments**: a FAIR assessment of a loss scenario. Submit it for approval; someone
  other than the author approves it.

## Entra exposure

1. A technician gets the collector and a ready-to-copy command from the **Collector** tab, runs
   it, and you import `collected.json` on the **Import** tab. Red
   banners mean an endpoint failed: results that depend on it are shown as unknown, never as safe.
2. **Exposure map**: every third-party app with its exposure level and the plain-English reasons
   for it, its permissions, credentials and last sign-in, plus changes since the last snapshot
   (new app-only critical permissions come first).
3. **Vendor matching**: confirm which vendor owns each app publisher. One confirmation applies
   to every tenant.
4. On a **vendor assessment**, scope it to a tenant and generate suggestions. Integration depth,
   loss magnitude ranges and control-strength adjustments are suggested with reasons. Nothing
   changes until you accept them. Threat event frequency is never suggested.
5. **Remediation candidates**: dormant high-risk apps, unverified publishers with user consent,
   expired credentials, credentials added to vendor apps, and tenants where users can consent.
   Export them to Excel for the Entra administrators.

## Reports and scheduled emails

**Reports** downloads the one-page **board summary** as PDF or Word, every register as Excel, and each Statement of
Applicability. People who manage the organisation's settings can also set up **scheduled emails**: a report sent
weekly, monthly or quarterly to chosen Keystone users. The report is built with the permissions of whoever last saved
the schedule, and only recipients who can still read the ISMS (active, with an email address) receive it. Outside
addresses can't be added. Email must be set up under Settings → Email.

## Record history

Under each record's **Discussion** (risks, controls, policies, vendors, incidents, tasks, nonconformities and audits),
**Show history** lists who changed what and when, with old and new values, from the audit log. Anyone who can read the
record can see it; redacted fields such as secrets stay hidden.

## Privacy

**Compliance → Privacy** holds four registers:

- **Records of processing** (GDPR Article 30): each activity's purpose, lawful basis, people and data, processors
  (from the vendor register), systems (from the asset register), transfers outside the EEA and their safeguard, and
  retention. Keystone refuses a legitimate-interest record without the interest, special category data without an
  Article 9 condition, and transfers without a safeguard.
- **DPIAs** (Article 35): describe the processing and why it's necessary, list risks to people with likelihood,
  severity, measures and residual risk, record the DPO's advice, and submit. Someone with risk-acceptance rights who
  didn't write it decides. A high residual risk is flagged: the authority must be consulted first.
- **Data subject requests** (visible only to people who handle privacy): due one month after receipt; one extension of
  two more months needs a reason. Identity must be verified before work starts. Closing needs a note of what was done or
  why it was refused. Names and contact details are removed a year after closing (`KEYSTONE_DSR_REDACT_DAYS`) and never
  appear in the audit log.
- **Breach log**: every incident involving personal data, with its 72-hour deadline from the incident and an
  assessment of the data, people affected, consequences, measures and risk to people, including why it was or
  wasn't notified.

## Business continuity

**Operations → Business continuity** has three tabs:

- **Business impact analysis**: each process's criticality, impact of a day's outage, maximum tolerable disruption,
  RTO and RPO (the RTO can't exceed the maximum), the systems and suppliers it depends on, and manual workarounds.
  Critical and high processes without a plan are flagged.
- **Plans**: which processes each plan covers, the recovery strategy and who activates it, and how often it must be
  tested. A plan never tested is due now.
- **Tests**: plan an exercise (tabletop, walkthrough, simulation, backup restore, full interruption), then record the
  result with the recovery time and data loss achieved for each process. Keystone compares them with the RTO and RPO,
  won't record a test as passed if an objective was missed, files evidence on the continuity controls, and can raise a
  nonconformity for the issues in one step.

## Policies

Create a document, write a version (Markdown or an attached file) and submit it. An approver
other than the author approves it, or returns it with a reason. Approving publishes the version,
sets the next review date and, if acknowledgement is required, asks every active user to
acknowledge it. A new version needs new acknowledgements. Employees acknowledge policies in
their portal.

**Electronic signatures.** Approving and acknowledging are signed: you type your full name as Keystone knows it.
Keystone records the name, the time, and (for acknowledgements) your IP address and browser, together with a SHA-256
fingerprint of the exact version text and file. If an approved version's stored text ever stops matching its
fingerprint, it can't be signed any more.

**PDF**: History → **PDF** downloads any version with its approval signature and fingerprint on every page footer;
drafts carry a DRAFT mark. People who can edit policies can also download **PDF + signatures**, which adds the
acknowledgement register (who signed, when, and whether each signature matches the version's fingerprint).

**AI assist** (when AI is on): describe the change you want, for example "add a section on
privileged access". Claude proposes a revision, shown as a diff with points to check. Accepting it
puts the text in a draft version; it still goes through review and approval.

## Incidents

- **Playbook.** Each category has a response checklist (in `config/incidents.yaml`; adjust it to your environment).
  Tick steps as they're done; the incident records who ticked each one and when.
- **Response actions.** Give actions an owner and a due date. An incident can't close as resolved while actions
  are still open.
- **Evidence** (ISO 27001 A.5.28). Keystone hashes each file (SHA-256) when it's added and checks the hash again on
  every download. The chain of custody records each download. Only incident handlers can download evidence, and an
  incident with evidence can't be deleted.
- **Linked records.** Link the risk that materialised, which brings that risk's review forward. Raise a
  nonconformity from the incident's lessons, or send the incident to your ticketing system.


Report what happened as soon as you know. Work it through triage, containment, eradication and
recovery, adding timeline entries as you go (entries can't be edited later). If personal data
is involved, Keystone shows the regulator-notification deadline (72 hours by default). An
incident can't be closed without a root cause and lessons learned, or while a required
notification is outstanding. False positives can be closed from triage.

## Nonconformities, audits and management review

- **Audit programme** (Audits → Programme). For each applicable control it shows when it was last audited in the
  three-year cycle and when it's next planned. Filter to the controls that have neither.
- **Findings** can be edited or deleted while the audit is in progress or reporting. A finding that raised a
  nonconformity keeps it.
- **Nonconformities** record how the root cause was found: 5 whys, fishbone, fault tree or other. Keystone warns
  when similar nonconformities appeared in the last three years (same control or requirement, or a similar title),
  so you can check whether earlier corrective actions worked.


**Working with auditors.** Give an external auditor an account with the Auditor role and an
expiry date. In an audit, the auditor adds **evidence requests**; people who manage evidence
answer by linking evidence and a note, and the auditor accepts or reopens each request. The
**Audit pack (ZIP)** holds the Statement of Applicability, approved policies, current evidence for
the audit's controls and everything linked to requests, with a manifest of SHA-256 hashes. PDFs,
images and text files open in Keystone's viewer (the eye icon); other files download.

- **Nonconformities**: record containment and the root cause, add corrective actions, and
  complete them. Someone other than the action owner checks that each action was effective. An
  ineffective action sends the nonconformity back for a new plan.
- **Audits**: plan the scope (controls) and the lead auditor; Keystone blocks auditors from
  auditing controls they own. Major and minor nonconformities recorded as findings open
  nonconformity records automatically. The page also shows which controls haven't been audited
  in the last three years.
- **Management review**: create a review and Keystone compiles the ISO 9.3.2 inputs from live
  records (previous actions, issues, nonconformities, monitoring results, audits, objectives,
  risks, incidents and third parties). Record attendees and decisions, track decisions as
  improvement items, and finalise. Finalised reviews are frozen records.

## System health (administrators)

**Settings → System health** shows whether everything Keystone relies on is working: the database, the scheduler,
the virus scanner and email, each scheduled job's last run, and recent backups (each one test-restored before it's
marked *Verified*). **Back up now** takes an extra backup. If a job keeps failing or no verified backup exists from
the last day, administrators get an inbox notification (and an email when email is set up) that links here.
