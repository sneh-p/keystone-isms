# Entra vendor exposure collector

`Invoke-VendorExposureCollector.ps1` makes a **read-only** inventory of the third-party
applications in your Microsoft Entra ID tenant(s): who publishes them, what they can access,
how consent was given, their credentials and when they last signed in. It writes
`collected.json` for import into Keystone ISMS (**Entra exposure → Exposure import**) plus CSVs
for a quick look.

For Entra exposure, Keystone itself never connects to Microsoft Graph: this script does, and it runs
interactively on a technician's workstation with that person's own delegated sign-in. (Attack surface
management has a separate, optional **Microsoft 365** source that the server calls read-only with an app
registration; it doesn't use or change this collector. See the administrator guide.)

## What it will and won't do

| It does | It never does |
|---|---|
| `GET` requests to `graph.microsoft.com` only, through one wrapper (`Invoke-GraphGet`) that throws on any other method or host | Change anything in the tenant: no app removal, no grant revocation, no setting changes |
| Sign in interactively with delegated, read-only scopes | Use app registrations, client secrets, certificates or unattended runs |
| Count users per delegated grant | Export user IDs, names, token values, password hints or key material |
| Record `null` plus an `endpoint_status` entry when an endpoint fails | Turn "could not check" into "nothing found" |
| Call only Microsoft Graph | Send telemetry or upload anything |

The Pester tests in `tests/collector/` check these rules, including a parse-tree check that
Graph is only ever called through the wrapper.

## Prerequisites

- **PowerShell 7.4 or later** (`pwsh`). Windows PowerShell 5.1 is not supported.
- The **`Microsoft.Graph.Authentication`** module only. The full Graph SDK is not needed.

  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  ```

- A **read-only Entra role** for the person running it. **Global Reader** is recommended: it
  can read service principals, permission grants, policies and sign-in reports, and nothing
  else. With a weaker role, some endpoints return `forbidden`. They are recorded as `null`,
  and Keystone shows them as unknown, never as safe.
- **Entra ID P1 or P2** for sign-in activity. Without it, the sign-in report is skipped and
  dormancy is shown as unknown. Everything else still works.

## Before you run it

1. **Activate your role.** If you use Privileged Identity Management, activate Global Reader
   (or your read role) first and give the change or ticket reference as the reason.
2. **Microsoft Graph Command Line Tools consent.** `Connect-MgGraph` signs in through
   Microsoft's "Microsoft Graph Command Line Tools" enterprise app. If that app has never been
   consented in the tenant, Entra shows a consent prompt. **Cancel it** unless granting that
   consent has been approved for your tenant: accepting it creates a permission grant in the
   tenant. The collector never calls a consent or grant API itself, and with Global Reader you
   could not consent anyway. If you cancel, the tenant is recorded as failed and nothing else
   happens.
3. **Write-capable scopes.** If an administrator previously consented the Command Line Tools
   app with write scopes (for example `User.ReadWrite.All`), your token carries them too. The
   collector warns, sets `write_scopes_present: true` and carries on. It still only issues
   `GET` requests. That standing consent is a finding worth reviewing.

## Running it

One tenant:

```powershell
./Invoke-VendorExposureCollector.ps1 -TenantId contoso.onmicrosoft.com -TenantName "Head office" -TicketNumber CHG-1042
```

Several tenants (for example subsidiaries), from a CSV with columns `TenantId,TenantName`
(see `tenants.example.csv`):

```powershell
./Invoke-VendorExposureCollector.ps1 -TenantListCsv ./tenants.csv -TicketNumber CHG-1042
```

Batch mode signs in to each tenant in turn, keeps going if one fails, and prints a summary
table: tenant, status (`ok`, `partial`, `failed`, `invalid_output`), record counts and failed
endpoints.

Options:

| Parameter | Meaning |
|---|---|
| `-TicketNumber` | Optional change or ticket reference, stored in the output for the audit trail |
| `-OutputRoot` | Where output folders go (default `./output`) |
| `-SkipSignInActivity` | Don't query the beta sign-in activity report |

## Output

```
output/<TenantName>_<yyyy-MM-dd>/
  collected.json          import this into Keystone
  service_principals.csv
  app_permissions.csv
  delegated_grants.csv
  credentials.csv
  signin_activity.csv
  collector.log
```

`collected.json` is checked against `schemas/collected.schema.json` before it is written. If
it fails, it is written as `collected.INVALID.json` instead. Don't import that file; report it.
A CSV is not written when its dataset could not be collected.

### Handle the output as sensitive

The output folder is a **map of your attack surface**: which apps can read mail, which have
tenant-wide rights, and which credentials are old. Store it on an **encrypted volume**,
restrict access to the people doing the import, and **delete it after import** according to
your retention policy. Don't email it or commit it to source control (`output/` is
git-ignored).

## Reading the results

### `endpoint_status`

Every dataset has an entry:

| `status` | Meaning |
|---|---|
| `ok` | Collected successfully. An empty list really means "none found". |
| `forbidden` | Your role could not read it (HTTP 401/403). The dataset is `null`. |
| `unavailable_license` | Needs Entra ID P1/P2 (sign-in activity only). The dataset is `null`. |
| `skipped` | Not attempted, either by option or because a dataset it depends on failed. |
| `error` | Any other failure, with the HTTP status and message. The dataset is `null`. |

### `null` versus `[]`

- `[]` (an empty list): the collector checked and found nothing.
- `null`: the collector **could not check**.

Keystone keeps this distinction all the way through. Apps scored with missing data are
flagged `incomplete_data` (rule R0). Dormancy is shown as unknown when sign-in data is
unavailable. Credential findings are shown as unknown when credential data is missing. Unknown
is never treated as safe.

### Credentials of third-party apps

A multi-tenant vendor app's own secrets live in the **vendor's** tenant and can't be seen from
yours. The collector can only see:

- credentials on **app registrations in your tenant** (your internal apps), and
- credentials added to **service principals in your tenant**.

A secret or certificate on a **third-party app's service principal** in your tenant is unusual
and is a known attacker persistence technique. Keystone flags it (rule C4) so you can confirm
who added it.

### Throttling

On HTTP 429 or 503 the collector waits for `Retry-After` (or 2, 4, 8, 16 or 32 seconds) and
retries up to 5 times per request.

## Testing the collector

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-Pester ./tests/collector -Output Detailed
Invoke-ScriptAnalyzer -Path ./collector -Recurse -Severity Error,Warning
```

The tests mock `Connect-MgGraph`, `Get-MgContext` and `Invoke-MgGraphRequest`; nothing is
sent to Microsoft. Before the first real run, try it against a test or lab tenant.
