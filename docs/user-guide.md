# User guide

Keystone follows the ISO 27001 cycle: set the context, assess risk, choose and run controls,
check how it's working, and improve. Your **Overview** page shows what needs attention and the
tasks assigned to you.

## Getting started (ISMS manager)

1. **Frameworks**: load the bundled content. Turn off frameworks you don't use.
2. **Organisation & scope**: record internal and external issues, interested parties, ISMS
   roles and security objectives. Write the scope, then approve it. Editing the scope later
   clears the approval.
3. **Assets**: list the information, systems, services and sites in scope, with owners and
   confidentiality, integrity and availability ratings.

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

1. A technician runs the collector and you import `collected.json` (**Exposure import**). Red
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
acknowledge it. A new version needs new acknowledgements.

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
