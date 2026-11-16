# User guide

Keystone follows the ISO 27001 cycle: set the context, assess risk, choose and run controls,
check how it's working, and improve. Your **Overview** page shows what needs attention and the
tasks assigned to you.

## Navigation

The sidebar groups screens by area; click a group heading to fold it away (Keystone remembers this). **Vendors**,
**Improvement** (nonconformities, audits, management review) and **Settings** each have tabs across the top.
Press Ctrl+K (⌘K on a Mac) to jump to any screen by name.

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

Add people under **People**, create an invitation link and send it to them. In the portal,
employees accept the policies that need acknowledgement, complete short training modules with a
quiz, and confirm their device checklist (disk encryption, screen lock, anti-malware, updates,
firewall, password manager). The People page shows who is complete. When someone leaves, work
through the offboarding checklist; completing it disables their account.

## Trust Center

Publish a public page for customers at `/trust/<your-slug>`: an overview, the frameworks you
work to, controls that are passing, published policies, subprocessors and FAQs. Reports and
other documents can be public or require an approved request and a signed NDA. Review requests
under **Trust Center → Requests**; approving produces a private link to send to the requester.

## Integrations

Connect a website, GitHub, AWS or the imported Entra data to run read-only checks on a
schedule. **Connect** shows a setup guide with commands to copy for creating a read-only
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

- **Controls**: set each control's status, owner and how it's implemented. "Not applicable"
  needs a reason. Record reviews to keep the review cycle current.
- **Evidence**: attach files, links or notes with a "valid until" date. Keystone warns 30 days
  before evidence expires and lists implemented controls that have no current evidence.
- **Statement of Applicability**: built automatically for each framework from your controls and
  linked risks. Record a decision to override applicability, approve a version when it's ready,
  and export to Excel or Word. Keystone shows what has changed since the last approved version.

## Third parties

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

## Policies

Create a document, write a version (Markdown or an attached file) and submit it. An approver
other than the author approves it, or returns it with a reason. Approving publishes the version,
sets the next review date and, if acknowledgement is required, asks every active user to
acknowledge it. A new version needs new acknowledgements. Employees acknowledge policies in
their portal.

**AI assist** (when AI is on): describe the change you want, for example "add a section on
privileged access". Claude proposes a revision, shown as a diff with points to check. Accepting it
puts the text in a draft version; it still goes through review and approval.

## Incidents

Report what happened as soon as you know. Work it through triage, containment, eradication and
recovery, adding timeline entries as you go (entries can't be edited later). If personal data
is involved, Keystone shows the regulator-notification deadline (72 hours by default). An
incident can't be closed without a root cause and lessons learned, or while a required
notification is outstanding. False positives can be closed from triage.

## Nonconformities, audits and management review

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
