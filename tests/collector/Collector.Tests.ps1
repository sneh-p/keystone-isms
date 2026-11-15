#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Pester tests for the Entra vendor exposure collector. Microsoft Graph is never called:
# Connect-MgGraph, Get-MgContext, Disconnect-MgGraph and Invoke-MgGraphRequest are mocked.

BeforeAll {
    $script:Root = Resolve-Path (Join-Path $PSScriptRoot '..' '..')
    $script:CollectorPath = Join-Path $script:Root 'collector' 'Invoke-VendorExposureCollector.ps1'
    $script:SchemaPath = Join-Path $script:Root 'schemas' 'collected.schema.json'
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $tokens = $null; $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:CollectorPath, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Collector has parse errors: $errors" }

    # Load the collector's functions (without running its main block) for unit tests.
    foreach ($fn in $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $script:GraphHost = 'graph.microsoft.com'
    $script:MaxRetries = 5
    $script:LogPath = $null
    $script:WriteScopePattern = '(?i)write|fullcontrol|send|manage|accessasuser'

    function global:New-GraphError([int] $Status, [int] $RetryAfter = 0, [string] $Message = 'Graph error') {
        $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
        if ($RetryAfter) { $resp.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([TimeSpan]::FromSeconds($RetryAfter)) }
        $ex = [System.Exception]::new($Message)
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp
        $ex
    }

    # ---------------------------------------------------------------- fake tenant
    $global:KST = @{
        Tenant   = '11111111-1111-4111-8111-111111111111'
        MsOwner  = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
        Vendor   = '22222222-2222-4222-8222-222222222222'
        GraphSp  = '33333333-3333-4333-8333-333333333333'
        VendorSp = '44444444-4444-4444-8444-444444444444'
        MsAppSp  = '55555555-5555-4555-8555-555555555555'
        Role     = '66666666-6666-4666-8666-666666666666'
        User1    = '77777777-7777-4777-8777-777777777777'
        User2    = '88888888-8888-4888-8888-888888888888'
        App      = '99999999-9999-4999-8999-999999999999'
        Key1     = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        Key2     = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    }
    $T = $global:KST

    function New-Sp($Id, $AppId, $Name, $Owner, $Extra = @{}) {
        $sp = @{ id = $Id; appId = $AppId; displayName = $Name; servicePrincipalType = 'Application'; appOwnerOrganizationId = $Owner; publisherName = $Name
            verifiedPublisher = @{ displayName = $null; verifiedPublisherId = $null; addedDateTime = $null }; accountEnabled = $true; appRoleAssignmentRequired = $false
            tags = @('WindowsAzureActiveDirectoryIntegratedApp'); homepage = 'https://vendor.example'; replyUrls = @('https://vendor.example/cb'); passwordCredentials = @(); keyCredentials = @() }
        foreach ($k in $Extra.Keys) { $sp[$k] = $Extra[$k] }
        $sp
    }

    $global:KSResponses = @{
        'v1.0/organization'                    = @{ value = @(@{ id = $T.Tenant; displayName = 'Contoso Test'; verifiedDomains = @(@{ name = 'other.example'; isDefault = $false }, @{ name = 'contoso.example'; isDefault = $true }) }) }
        'v1.0/subscribedSkus'                  = @{ value = @(@{ skuPartNumber = 'SPB'; capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' }, @{ servicePlanName = 'EXCHANGE_S_STANDARD'; provisioningStatus = 'Success' }) }) }
        'v1.0/policies/authorizationPolicy'    = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } }
        'v1.0/policies/adminConsentRequestPolicy' = @{ isEnabled = $false }
        'v1.0/servicePrincipals?page1'         = @{
            value             = @(
                (New-Sp $T.GraphSp '00000003-0000-0000-c000-000000000000' 'Microsoft Graph' $T.MsOwner),
                (New-Sp $T.MsAppSp 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' 'Microsoft Teams' $T.MsOwner)
            )
            '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=page2'
        }
        'v1.0/servicePrincipals?page2'         = @{ value = @(
                (New-Sp $T.VendorSp 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' 'Northwind Signatures' $T.Vendor @{ passwordCredentials = @(@{ keyId = $T.Key1; displayName = 'added-by-helpdesk'; hint = 'Zx9'; secretText = $null; startDateTime = [datetime]'2026-02-01T00:00:00Z'; endDateTime = '2028-02-01T00:00:00Z' }) })
            )
        }
        "v1.0/servicePrincipals/$($T.VendorSp)/appRoleAssignments" = @{ value = @(@{ principalId = $T.VendorSp; principalType = 'ServicePrincipal'; resourceId = $T.GraphSp; resourceDisplayName = 'Microsoft Graph'; appRoleId = $T.Role; createdDateTime = [datetime]'2025-03-10T09:00:00Z' }) }
        "v1.0/servicePrincipals/$($T.GraphSp)" = @{ id = $T.GraphSp; appRoles = @(@{ id = $T.Role; value = 'Mail.Read' }) }
        'v1.0/oauth2PermissionGrants'          = @{ value = @(
                @{ clientId = $T.VendorSp; consentType = 'Principal'; principalId = $T.User1; resourceId = $T.GraphSp; scope = 'User.Read openid' },
                @{ clientId = $T.VendorSp; consentType = 'Principal'; principalId = $T.User2; resourceId = $T.GraphSp; scope = ' Mail.Read ' },
                @{ clientId = $T.VendorSp; consentType = 'Principal'; principalId = $T.User1; resourceId = $T.GraphSp; scope = 'User.Read' },
                @{ clientId = $T.VendorSp; consentType = 'AllPrincipals'; principalId = $null; resourceId = $T.GraphSp; scope = 'offline_access' }
            )
        }
        'v1.0/applications'                    = @{ value = @(@{ id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'; appId = $T.App; passwordCredentials = @(@{ keyId = $T.Key2; displayName = 'old-secret'; hint = 'abc'; startDateTime = '2024-01-01T00:00:00Z'; endDateTime = '2025-01-01T00:00:00Z' }); keyCredentials = @() }) }
        'beta/reports/servicePrincipalSignInActivities' = @{ value = @(@{ appId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'; id = 'x'; lastSignInActivity = @{ lastSignInDateTime = '2026-10-01T10:00:00Z'; lastSignInRequestId = 'req-1' } }) }
    }
    $global:KSFailures = @{}   # route -> exception to throw

    function global:Resolve-Route([string] $Uri) {
        $u = [Uri]$Uri
        $path = $u.AbsolutePath.TrimStart('/')
        if ($path -eq 'v1.0/servicePrincipals') { return ($u.Query -match 'skiptoken=page2') ? 'v1.0/servicePrincipals?page2' : 'v1.0/servicePrincipals?page1' }
        $path
    }

    $script:FakeGraph = {
        param($Method, $Uri)
        $route = Resolve-Route $Uri
        if ($global:KSFailures.ContainsKey($route)) { throw $global:KSFailures[$route] }
        if (-not $global:KSResponses.ContainsKey($route)) { throw (New-GraphError 404 0 "No fake for $route") }
        $global:KSResponses[$route]
    }

    function Invoke-Collector([hashtable] $Params) {
        & $script:CollectorPath @Params 6>$null 3>$null
    }

    function Read-Collected([string] $Root) {
        $file = Get-ChildItem -LiteralPath $Root -Recurse -Filter 'collected*.json' | Select-Object -First 1
        @{ File = $file; Text = (Get-Content -LiteralPath $file.FullName -Raw); Doc = (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable -DateKind String) }
    }
}

AfterAll {
    Remove-Variable -Scope Global -Name KSScopes, KSFailures, KSResponses, KST, KScalls -ErrorAction SilentlyContinue
    Remove-Item function:global:New-GraphError, function:global:Resolve-Route -ErrorAction SilentlyContinue
}

Describe 'Static safety checks' {
    It 'calls Invoke-MgGraphRequest only inside Invoke-GraphGet' {
        $calls = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MgGraphRequest' }, $true)
        $calls.Count | Should -BeGreaterThan 0
        foreach ($c in $calls) {
            $p = $c.Parent
            while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
            $p.Name | Should -Be 'Invoke-GraphGet' -Because "Invoke-MgGraphRequest at line $($c.Extent.StartLineNumber) must go through the GET-only wrapper"
        }
    }

    It 'passes only -Method GET to Invoke-MgGraphRequest' {
        $calls = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MgGraphRequest' }, $true)
        foreach ($c in $calls) { $c.Extent.Text | Should -Match '-Method GET\b' }
    }

    It 'uses no other HTTP or Graph SDK cmdlets' {
        $names = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
        $forbidden = $names | Where-Object { $_ -match '^(Invoke-RestMethod|Invoke-WebRequest|Start-BitsTransfer|New-Mg|Update-Mg|Remove-Mg|Set-Mg|Grant-|Revoke-)' -or ($_ -match '^Get-Mg' -and $_ -ne 'Get-MgContext') }
        $forbidden | Should -BeNullOrEmpty
        ($script:Ast.Extent.Text -match 'System\.Net\.(Http\.HttpClient|WebClient)') | Should -BeFalse
    }

    It 'never references secret fields for export' {
        $script:Ast.Extent.Text | Should -Not -Match "Get-Value \`$\w+ 'hint'"
        $script:Ast.Extent.Text | Should -Not -Match "Get-Value \`$\w+ 'secretText'"
    }

    It 'is clean under PSScriptAnalyzer (errors and warnings)' {
        $findings = Invoke-ScriptAnalyzer -Path $script:CollectorPath -Severity Error, Warning
        $findings | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-GraphGet' {
    It 'refuses methods other than GET' {
        foreach ($m in 'POST', 'PATCH', 'PUT', 'DELETE') {
            { Invoke-GraphGet -Uri 'v1.0/organization' -Method $m } | Should -Throw "*only permits GET*"
        }
    }

    It 'refuses non-Graph hosts, including in nextLink' {
        Mock Invoke-MgGraphRequest { @{ value = @(1); '@odata.nextLink' = 'https://evil.example/steal' } }
        { Invoke-GraphGet -Uri 'https://evil.example/v1.0/me' } | Should -Throw '*non-Graph*'
        { Invoke-GraphGet -Uri 'v1.0/organization' -All } | Should -Throw '*non-Graph*'
        { Invoke-GraphGet -Uri 'http://graph.microsoft.com/v1.0/organization' } | Should -Throw '*non-Graph*'
    }

    It 'follows @odata.nextLink paging' {
        Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*skiptoken=2*' } { @{ value = @('c') } }
        Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -notlike '*skiptoken*' } { @{ value = @('a', 'b'); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?$skiptoken=2' } }
        $r = Invoke-GraphGet -Uri 'v1.0/x' -All
        $r | Should -Be @('a', 'b', 'c')
        Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly -ParameterFilter { $Method -eq 'GET' }
    }

    It 'retries 429 honouring Retry-After, then succeeds' {
        $global:KScalls = 0
        Mock Wait-Backoff {}
        Mock Invoke-MgGraphRequest { $global:KScalls++; if ($global:KScalls -lt 3) { throw (New-GraphError 429 7 'Too many requests') }; @{ value = @('ok') } }
        Invoke-GraphGet -Uri 'v1.0/x' -All | Should -Be @('ok')
        Should -Invoke Wait-Backoff -Times 2 -Exactly -ParameterFilter { $Seconds -eq 7 }
    }

    It 'uses exponential backoff without Retry-After and gives up after 5 retries' {
        Mock Wait-Backoff {}
        Mock Invoke-MgGraphRequest { throw (New-GraphError 503 0 'Service unavailable') }
        { Invoke-GraphGet -Uri 'v1.0/x' } | Should -Throw
        Should -Invoke Invoke-MgGraphRequest -Times 6 -Exactly
        Should -Invoke Wait-Backoff -Times 1 -Exactly -ParameterFilter { $Seconds -eq 2 }
        Should -Invoke Wait-Backoff -Times 1 -Exactly -ParameterFilter { $Seconds -eq 32 }
    }

    It 'does not retry 403' {
        Mock Wait-Backoff {}
        Mock Invoke-MgGraphRequest { throw (New-GraphError 403 0 'Forbidden') }
        { Invoke-GraphGet -Uri 'v1.0/x' } | Should -Throw
        Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
    }
}

Describe 'Full collection (mocked tenant)' {
    BeforeEach {
        $global:KSFailures = @{}
        $global:KSScopes = @('Application.Read.All', 'AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'openid')
        Mock Connect-MgGraph {}
        Mock Disconnect-MgGraph {}
        Mock Get-MgContext { [pscustomobject]@{ Account = 'tech01@contoso.example'; Scopes = $global:KSScopes; TenantId = $global:KST.Tenant } }
        Mock Invoke-MgGraphRequest $script:FakeGraph
        Mock Wait-Backoff {}
    }

    It 'produces schema-valid output with the expected datasets' {
        $out = Join-Path $TestDrive 'ok'
        $summary = Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'Contoso / Test'; TicketNumber = 'CHG-1'; OutputRoot = $out }
        $summary.Status | Should -Be 'ok'
        $c = Read-Collected $out
        $c.File.Name | Should -Be 'collected.json'
        $c.File.Directory.Name | Should -Match '^Contoso _ Test_\d{4}-\d{2}-\d{2}$'
        Test-Json -Json $c.Text -SchemaFile $script:SchemaPath | Should -BeTrue
        $d = $c.Doc
        $d.metadata.default_domain | Should -Be 'contoso.example'
        $d.metadata.entra_p1_available | Should -BeTrue
        $d.metadata.write_scopes_present | Should -BeFalse
        $d.metadata.ticket_number | Should -Be 'CHG-1'
        $d.metadata.microsoft_owned_skipped_count | Should -Be 2
        @($d.service_principals).Count | Should -Be 3
        @($d.app_role_assignments).Count | Should -Be 1
        $d.app_role_assignments[0].appRoleValue | Should -Be 'Mail.Read'
        $d.app_role_assignments[0].createdDateTime | Should -Be '2025-03-10T09:00:00Z'
        $d.consent_posture.authorization_policy.permissionGrantPoliciesAssigned | Should -Contain 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
        @($d.credentials).Count | Should -Be 2
        ($d.credentials | Where-Object ownerType -eq 'servicePrincipal').keyId | Should -Be $global:KST.Key1
        $d.signin_activity[0].lastSignInActivity.lastSignInDateTime | Should -Be '2026-10-01T10:00:00Z'
        foreach ($f in 'service_principals.csv', 'app_permissions.csv', 'delegated_grants.csv', 'credentials.csv', 'signin_activity.csv', 'collector.log') {
            Join-Path $c.File.Directory.FullName $f | Should -Exist
        }
    }

    It 'only ever calls Graph with GET and never asks for app roles of Microsoft apps' {
        Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = (Join-Path $TestDrive 'get') } | Out-Null
        Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Method -ne 'GET' } -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Uri -like "*$($global:KST.MsAppSp)/appRoleAssignments*" } -Times 0 -Exactly
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { -not ($Scopes | Where-Object { $_ -match '(?i)write' }) }
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
    }

    It 'aggregates delegated grants into user counts and exports no principal IDs, hints or secrets' {
        $out = Join-Path $TestDrive 'pii'
        Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out } | Out-Null
        $c = Read-Collected $out
        $user = $c.Doc.delegated_grants | Where-Object consentType -eq 'Principal'
        $user.principalCount | Should -Be 2
        $user.scopes | Should -Be @('Mail.Read', 'openid', 'User.Read')
        ($c.Doc.delegated_grants | Where-Object consentType -eq 'AllPrincipals').principalCount | Should -Be 0
        $all = (Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        $all | Should -Not -Match '"principalId"'
        $all | Should -Not -Match $global:KST.User1
        $all | Should -Not -Match $global:KST.User2
        $all | Should -Not -Match '(?i)"hint"|Zx9|secretText|req-1'
    }

    It 'records a forbidden endpoint as null with endpoint_status, never as []' {
        $global:KSFailures['v1.0/applications'] = New-GraphError 403 0 'Authorization_RequestDenied: Insufficient privileges.'
        $out = Join-Path $TestDrive 'forbidden'
        $summary = Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out }
        $summary.Status | Should -Be 'partial'
        $summary.FailedEndpoints | Should -Match 'credentials.applications=forbidden'
        $c = Read-Collected $out
        Test-Json -Json $c.Text -SchemaFile $script:SchemaPath | Should -BeTrue
        $c.Text | Should -Match '"credentials":\s*null'
        $c.Doc.metadata.endpoint_status['credentials.applications'].status | Should -Be 'forbidden'
        $c.Doc.metadata.endpoint_status['credentials.applications'].http_status | Should -Be 403
        Join-Path $c.File.Directory.FullName 'credentials.csv' | Should -Not -Exist
    }

    It 'marks sign-in activity unavailable_license on a premium-licence 403' {
        $global:KSFailures['beta/reports/servicePrincipalSignInActivities'] = New-GraphError 403 0 "Neither tenant is B2C or tenant doesn't have premium license"
        $out = Join-Path $TestDrive 'lic'
        Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out } | Out-Null
        $c = Read-Collected $out
        $c.Doc.signin_activity | Should -BeNullOrEmpty
        $c.Text | Should -Match '"signin_activity":\s*null'
        $c.Doc.metadata.endpoint_status.signin_activity.status | Should -Be 'unavailable_license'
        $c.Doc.metadata.endpoint_status.signin_activity.api_version | Should -Be 'beta'
    }

    It 'does not query sign-in activity when no P1 plan is present' {
        $saved = $global:KSResponses['v1.0/subscribedSkus']
        $global:KSResponses['v1.0/subscribedSkus'] = @{ value = @(@{ skuPartNumber = 'O365_BUSINESS'; capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanName = 'EXCHANGE_S_STANDARD'; provisioningStatus = 'Success' }) }) }
        try {
            $out = Join-Path $TestDrive 'nop1'
            Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out } | Out-Null
            $c = Read-Collected $out
            $c.Doc.metadata.entra_p1_available | Should -BeFalse
            $c.Doc.metadata.endpoint_status.signin_activity.status | Should -Be 'unavailable_license'
            Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*servicePrincipalSignInActivities*' } -Times 0 -Exactly
        }
        finally { $global:KSResponses['v1.0/subscribedSkus'] = $saved }
    }

    It 'treats a failed service principal read as null and skips dependent datasets' {
        $global:KSFailures['v1.0/servicePrincipals?page1'] = New-GraphError 500 0 'boom'
        $out = Join-Path $TestDrive 'nosp'
        Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out } | Out-Null
        $c = Read-Collected $out
        Test-Json -Json $c.Text -SchemaFile $script:SchemaPath | Should -BeTrue
        $c.Doc.service_principals | Should -BeNullOrEmpty
        $c.Doc.metadata.endpoint_status.service_principals.status | Should -Be 'error'
        $c.Doc.metadata.endpoint_status.app_role_assignments.status | Should -Be 'skipped'
        $c.Text | Should -Match '"app_role_assignments":\s*null'
        $c.Text | Should -Match '"credentials":\s*null'
    }

    It 'flags write-capable scopes on the token without aborting' {
        $global:KSScopes += 'Mail.Send', 'Directory.AccessAsUser.All'
        $out = Join-Path $TestDrive 'write'
        $summary = Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out }
        $summary.Status | Should -Be 'ok'
        (Read-Collected $out).Doc.metadata.write_scopes_present | Should -BeTrue
        Get-Content (Join-Path (Read-Collected $out).File.Directory.FullName 'collector.log') -Raw | Should -Match 'standing consent'
    }

    It 'skips sign-in activity with -SkipSignInActivity' {
        $out = Join-Path $TestDrive 'skip'
        Invoke-Collector @{ TenantId = $global:KST.Tenant; TenantName = 'T'; OutputRoot = $out; SkipSignInActivity = $true } | Out-Null
        (Read-Collected $out).Doc.metadata.endpoint_status.signin_activity.status | Should -Be 'skipped'
    }

    It 'continues past a failed tenant in batch mode and returns a summary' {
        $csv = Join-Path $TestDrive 'tenants.csv'
        "TenantId,TenantName`nbad.example,Broken Sub`n$($global:KST.Tenant),Main" | Set-Content $csv
        Mock Connect-MgGraph -ParameterFilter { $TenantId -eq 'bad.example' } { throw 'AADSTS50020: user account does not exist in tenant' }
        $out = Join-Path $TestDrive 'batch'
        $results = Invoke-Collector @{ TenantListCsv = $csv; OutputRoot = $out }
        $results.Count | Should -Be 2
        ($results | Where-Object Tenant -eq 'Broken Sub').Status | Should -Be 'failed'
        ($results | Where-Object Tenant -eq 'Broken Sub').FailedEndpoints | Should -Match 'AADSTS50020'
        ($results | Where-Object Tenant -eq 'Main').Status | Should -Be 'ok'
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
    }

    It 'rejects a batch CSV without the required columns' {
        $csv = Join-Path $TestDrive 'bad.csv'
        "Id,Name`nx,y" | Set-Content $csv
        { Invoke-Collector @{ TenantListCsv = $csv; OutputRoot = (Join-Path $TestDrive 'b2') } } | Should -Throw '*TenantId,TenantName*'
    }
}
