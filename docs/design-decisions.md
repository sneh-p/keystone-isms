# Design decisions and deviations

This records choices made while building Keystone where the original specifications were
silent, ambiguous, or conflicted with how Microsoft Graph or the standards actually work.

## Scope

- **From "Vendor Exposure Map for an MSP" to "Keystone ISMS for one organisation".** The
  original spec targeted an MSP collecting client tenants over GDAP and feeding VendorFAIR. The
  project was renamed and widened to a full ISMS for a single organisation. The exposure map
  became part of third-party risk; "client tenants" became the organisation's own Entra tenants
  (main tenant and subsidiaries). GDAP, PIM and Autotask wording became optional (a generic
  change or ticket reference). The `collected.json` schema did not change.
- **VendorFAIR.** No VendorFAIR code existed, so Keystone contains its own FAIR engine, vendor
  register and vendor assessments; the exposure module's suggestions target those.

## Framework content

- Only NIST CSF 2.0 ships with full text (public domain). ISO/IEC 27001, the AICPA TSC and CIS
  Controls are copyrighted (CIS under CC BY-NC-ND), so Keystone ships identifiers with short
  titles in its own words, and an import for licensed official text that is stored only in the
  database. A loader check rejects restricted packs with long text or a `licensed_text` field.
- The common control set is the ISMS clauses (14 controls) plus one control per Annex A control
  (93): 107 in total. Every leaf requirement of all four frameworks is mapped (tested). The
  crosswalk is original work and labelled as a starting point.

## Microsoft Graph realities (collector)

- **Third-party credentials are mostly invisible.** A multi-tenant vendor app's secrets live in
  the vendor's tenant. The collector reads app-registration credentials (internal apps) and
  credentials on service principals in the tenant. A credential on a *third-party* service
  principal is flagged (rule C4) as a possible persistence technique.
- **No `$batch`.** Graph JSON batching is a POST, which the GET-only rule forbids, so per-app
  `appRoleAssignments` calls are made one by one (Microsoft-owned apps are skipped).
- **Write-scope detection** also matches `AccessAsUser` (e.g. `Directory.AccessAsUser.All`).
- **The `credentials` dataset is `null` if either of its two endpoints fails**, so a partial
  credential list is never mistaken for a complete one. The two consent-policy endpoints are
  independent, so each can be `null` on its own.
- Graph's `principalId` on app role assignments (the client app) is exported as
  `servicePrincipalId`, so no `principalId` key appears anywhere in the output.
- **P1 detection** requires `AAD_PREMIUM`/`AAD_PREMIUM_P2` with provisioning status `Success`
  on an enabled SKU. Without P1, the sign-in report is not queried and its status is
  `unavailable_license`.
- **Absent from a successful sign-in report** counts as dormant (decided with the user), with
  the reason "No sign-in recorded". Dormancy is `null` only when the report itself was
  unavailable.
- Managed identities (null owner) are classified `internal`. Other null owners are `unknown`
  and flagged for review. They are never assumed to be Microsoft.

## Exposure rules

- Added fallback **R8** (Low) for apps that match no rule (e.g. SSO-only apps). R6 reads
  "delegated **high or above**" so that user-consented critical permissions on verified apps
  are not left unscored.
- Additional critical permissions beyond the seed list are marked `# added` in
  `config/permission_tiers.yaml`.
- Every matching rule is recorded as a reason; the first sets the level. R0 (incomplete data) is
  a modifier and never lowers the level.
- `user_consent_count` is the largest per-resource count, a lower bound on distinct users,
  because the collector deliberately exports counts rather than user IDs.
- Integration depth: any app-only permission is "Tenant-wide application access", with rule ID1
  for high or critical permissions and ID1b for lower tiers, since app-only access is
  tenant-wide by nature.
- Control-strength suggestions start from the assessment's current range, or from
  `control_strength_default` in `config/fair_suggestions.yaml` when it has none.

## Platform

- Streamlit has no authentication, so Keystone has local accounts, roles, segregation of duties
  and a hash-chained audit log. OIDC single sign-on is on the roadmap.
- Reloading the browser starts a new Streamlit session, so you sign in again. This is a
  deliberate choice not to keep login tokens in cookies.
- SQLite by default; models avoid SQLite-only types so PostgreSQL works. Migrations are applied
  at start-up. The audit-log immutability triggers exist for SQLite and PostgreSQL.
- The Docker image has not been built in the development environment (Docker was unavailable).
