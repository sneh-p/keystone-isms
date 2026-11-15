#Requires -Version 7.4
<#
.SYNOPSIS
    Read-only inventory of third-party applications in your Microsoft Entra ID tenant(s),
    for import into Keystone ISMS (Third parties > Entra exposure).

.DESCRIPTION
    Signs in interactively with delegated, read-only scopes, reads service principals,
    application and delegated permissions, consent settings, credential metadata and
    sign-in activity, and writes collected.json plus CSVs to
    <OutputRoot>/<TenantName>_<yyyy-MM-dd>/.

    Safety properties (see collector/README.md):
      * Every Graph call goes through Invoke-GraphGet, which only issues GET requests to
        graph.microsoft.com. Anything else throws.
      * No tokens, secret hints or key material are written. Delegated grants are reduced
        to per-app user COUNTS; no user IDs or names are exported.
      * An endpoint that fails is recorded as null (could not check), never [] (none found).
      * Nothing is changed in the tenant. The script never calls a consent or grant API.

.PARAMETER TenantId
    Entra tenant ID (GUID) or verified domain to collect.
.PARAMETER TenantName
    Friendly name used for the output folder and in Keystone.
.PARAMETER TenantListCsv
    Batch mode: CSV with columns TenantId,TenantName (e.g. subsidiaries).
.PARAMETER TicketNumber
    Optional change or ticket reference recorded in the output for the audit trail.
.PARAMETER OutputRoot
    Where output folders are created. Store on an encrypted volume.
.PARAMETER SkipSignInActivity
    Do not query the (beta) sign-in activity report.

.EXAMPLE
    ./Invoke-VendorExposureCollector.ps1 -TenantId contoso.example -TenantName "Head office" -TicketNumber CHG-1042
.EXAMPLE
    ./Invoke-VendorExposureCollector.ps1 -TenantListCsv ./tenants.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Single')] [string] $TenantId,
    [Parameter(Mandatory, ParameterSetName = 'Single')] [string] $TenantName,
    [Parameter(Mandatory, ParameterSetName = 'Batch')]  [string] $TenantListCsv,
    [string] $TicketNumber,
    [string] $OutputRoot = './output',
    [switch] $SkipSignInActivity
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CollectorVersion = '0.1.0'
$script:SchemaVersion = '1.0'
$script:GraphHost = 'graph.microsoft.com'
$script:ReadScopes = @('Application.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All')
$script:WriteScopePattern = '(?i)write|fullcontrol|send|manage|accessasuser'
$script:MaxRetries = 5
$script:LogPath = $null
$script:EndpointStatus = [ordered]@{}

# ----------------------------------------------------------------------------- helpers

function Write-CollectorLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string] $Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message
    if ($script:LogPath) { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding utf8 }
    switch ($Level) {
        'WARN' { Write-Warning $Message }
        'ERROR' { Write-Warning "ERROR: $Message" }
        default { Write-Information $Message -InformationAction Continue }
    }
}

function Wait-Backoff {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int] $Seconds)
    Start-Sleep -Seconds $Seconds
}

function Get-GraphErrorInfo {
    <# Extract HTTP status, Retry-After and a short message from a Graph error. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] $ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    $status = $null
    $retryAfter = $null
    $response = $null
    if ($ex.PSObject.Properties['Response']) { $response = $ex.Response }
    if ($response -and $response.PSObject.Properties['StatusCode']) { $status = [int]$response.StatusCode }
    elseif ($ex.PSObject.Properties['StatusCode'] -and $ex.StatusCode) { $status = [int]$ex.StatusCode }
    if ($response -and $response.PSObject.Properties['Headers'] -and $response.Headers.RetryAfter) {
        $ra = $response.Headers.RetryAfter
        if ($ra.Delta) { $retryAfter = [int][Math]::Ceiling($ra.Delta.TotalSeconds) }
    }
    $message = ($ex.Message -replace '\s+', ' ').Trim()
    if ($message.Length -gt 500) { $message = $message.Substring(0, 500) }
    @{ Status = $status; RetryAfter = $retryAfter; Message = $message }
}

function Assert-GraphUri {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Uri)
    $parsed = [Uri]$Uri
    if (-not $parsed.IsAbsoluteUri -or $parsed.Scheme -ne 'https' -or $parsed.Host -ne $script:GraphHost) {
        throw "Refusing to call non-Graph URI: $Uri"
    }
}

function Invoke-GraphGet {
    <#
    .SYNOPSIS
        The ONLY function allowed to call Microsoft Graph. GET only, graph.microsoft.com only.
        Handles @odata.nextLink paging (-All) and 429/503 throttling with Retry-After.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Uri,
        [string] $Method = 'GET',
        [switch] $All
    )
    if ($Method -ne 'GET') { throw "Invoke-GraphGet only permits GET requests (got '$Method')." }
    # Relative paths (no scheme) are resolved against Graph; anything with a scheme is checked as-is.
    if ($Uri -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*:') { $Uri = "https://$($script:GraphHost)/$($Uri.TrimStart('/'))" }
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        Assert-GraphUri -Uri $next
        $attempt = 0
        while ($true) {
            try {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable -ErrorAction Stop
                break
            }
            catch {
                $info = Get-GraphErrorInfo -ErrorRecord $_
                if ($info.Status -in 429, 503 -and $attempt -lt $script:MaxRetries) {
                    $attempt++
                    $delay = if ($info.RetryAfter) { $info.RetryAfter } else { [Math]::Min([Math]::Pow(2, $attempt), 60) }
                    Write-CollectorLog "Throttled ($($info.Status)) on $next; retry $attempt/$($script:MaxRetries) in ${delay}s" 'WARN'
                    Wait-Backoff -Seconds $delay
                    continue
                }
                throw
            }
        }
        if (-not $All) { return $resp }
        if ($resp -and $resp.ContainsKey('value')) { foreach ($v in $resp['value']) { $results.Add($v) } }
        $next = if ($resp -and $resp.ContainsKey('@odata.nextLink')) { $resp['@odata.nextLink'] } else { $null }
    }
    , $results.ToArray()
}

function Get-Value {
    <# Safe hashtable/PSObject property read under StrictMode. #>
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    $null
}

function ConvertTo-GraphDate {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $null
}

function ConvertTo-StringArray {
    param($Value)
    if ($null -eq $Value) { return , @() }
    , @($Value | ForEach-Object { [string]$_ })
}

function Write-EndpointStatus {
    [CmdletBinding()]
    param([string] $Key, [string] $Status, $HttpStatus, [string] $Message = '', $RecordCount = $null, [string] $ApiVersion = 'v1.0')
    $script:EndpointStatus[$Key] = [ordered]@{
        status       = $Status
        http_status  = if ($null -ne $HttpStatus) { [int]$HttpStatus } else { $null }
        message      = $Message
        record_count = if ($null -ne $RecordCount) { [int]$RecordCount } else { $null }
        api_version  = $ApiVersion
    }
}

function Invoke-Dataset {
    <# Run one collection step. On failure: status entry + $null result (never an empty list). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Key, [Parameter(Mandatory)][scriptblock] $Collect, [string] $ApiVersion = 'v1.0', [scriptblock] $Count = { param($d) @($d).Count })
    try {
        $data = & $Collect
        $n = & $Count $data
        Write-EndpointStatus -Key $Key -Status 'ok' -HttpStatus 200 -RecordCount $n -ApiVersion $ApiVersion
        Write-CollectorLog "${Key}: ok ($n records)"
        return , $data
    }
    catch {
        $info = Get-GraphErrorInfo -ErrorRecord $_
        $status = switch ($info.Status) { 403 { 'forbidden' } 401 { 'forbidden' } default { 'error' } }
        if ($Key -eq 'signin_activity' -and $info.Status -eq 403 -and $info.Message -match '(?i)premium|licen[cs]e|B2C') { $status = 'unavailable_license' }
        Write-EndpointStatus -Key $Key -Status $status -HttpStatus $info.Status -Message $info.Message -ApiVersion $ApiVersion
        Write-CollectorLog "${Key}: $status (HTTP $($info.Status)) $($info.Message)" 'WARN'
        return $null
    }
}

function Get-MicrosoftOwnerTenantId {
    $path = Join-Path $PSScriptRoot '..' 'config' 'microsoft_owner_tenants.json'
    $ids = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
    if (Test-Path -LiteralPath $path) {
        $cfg = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $ids = @($cfg.tenant_ids | ForEach-Object { $_.id })
    }
    , @($ids | ForEach-Object { $_.ToLowerInvariant() })
}

function ConvertTo-CredentialRecord {
    param([string] $OwnerType, $Owner, $KeyInfo, [string] $Kind)
    # Only metadata. 'hint', 'secretText', 'key' and 'customKeyIdentifier' are never copied.
    [ordered]@{
        ownerType      = $OwnerType
        ownerObjectId  = [string](Get-Value $Owner 'id')
        ownerAppId     = [string](Get-Value $Owner 'appId')
        credentialType = $Kind
        keyId          = [string](Get-Value $KeyInfo 'keyId')
        displayName    = Get-Value $KeyInfo 'displayName'
        startDateTime  = ConvertTo-GraphDate (Get-Value $KeyInfo 'startDateTime')
        endDateTime    = ConvertTo-GraphDate (Get-Value $KeyInfo 'endDateTime')
    }
}

function Get-SafeFolderName {
    param([string] $Name)
    $safe = ($Name -replace '[^A-Za-z0-9._ -]', '_').Trim(' ', '.')
    if (-not $safe) { $safe = 'tenant' }
    $safe.Substring(0, [Math]::Min(80, $safe.Length))
}

# ----------------------------------------------------------------------------- collection

function Get-TenantExposure {
    <# Collect all datasets for the currently connected tenant. Returns the collected document. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $TenantName, [string] $TicketNumber, [switch] $SkipSignInActivity, [string[]] $MicrosoftOwners)

    $script:EndpointStatus = [ordered]@{}
    $ctx = Get-MgContext
    $scopes = @($ctx.Scopes | Sort-Object -Unique)
    $writeScopes = @($scopes | Where-Object { $_ -match $script:WriteScopePattern })
    if ($writeScopes.Count -gt 0) {
        Write-CollectorLog ("Token carries write-capable scopes previously consented to Graph Command Line Tools: {0}. This standing consent is itself a finding. The collector still only issues GET requests." -f ($writeScopes -join ', ')) 'WARN'
    }

    # --- tenant
    $tenant = Invoke-Dataset -Key 'tenant' -Collect {
        $orgs = Invoke-GraphGet -Uri 'v1.0/organization?$select=id,displayName,verifiedDomains' -All
        if ($orgs.Count -eq 0) { throw 'organization endpoint returned no rows' }
        $org = $orgs[0]
        $default = @((Get-Value $org 'verifiedDomains') | Where-Object { Get-Value $_ 'isDefault' }) | Select-Object -First 1
        [ordered]@{ id = [string](Get-Value $org 'id'); displayName = [string](Get-Value $org 'displayName'); defaultDomain = Get-Value $default 'name' }
    } -Count { param($d) if ($d) { 1 } else { 0 } }

    # --- licensing
    $licensing = Invoke-Dataset -Key 'licensing' -Collect {
        $plans = [System.Collections.Generic.List[object]]::new()
        foreach ($sku in (Invoke-GraphGet -Uri 'v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans' -All)) {
            foreach ($p in @(Get-Value $sku 'servicePlans')) {
                if ($null -eq $p) { continue }
                $plans.Add([ordered]@{
                        servicePlanName    = [string](Get-Value $p 'servicePlanName')
                        provisioningStatus = [string](Get-Value $p 'provisioningStatus')
                        skuPartNumber      = [string](Get-Value $sku 'skuPartNumber')
                        capabilityStatus   = [string](Get-Value $sku 'capabilityStatus')
                    })
            }
        }
        [ordered]@{ service_plans = $plans.ToArray() }
    } -Count { param($d) @($d.service_plans).Count }
    $p1 = $null
    if ($null -ne $licensing) {
        $p1 = [bool](@($licensing.service_plans | Where-Object { $_.servicePlanName -in 'AAD_PREMIUM', 'AAD_PREMIUM_P2' -and $_.provisioningStatus -eq 'Success' -and $_.capabilityStatus -eq 'Enabled' }).Count)
    }

    # --- consent posture (two independent endpoints)
    $authz = Invoke-Dataset -Key 'consent_posture.authorization_policy' -Collect {
        $pol = Invoke-GraphGet -Uri 'v1.0/policies/authorizationPolicy?$select=defaultUserRolePermissions'
        [ordered]@{ permissionGrantPoliciesAssigned = ConvertTo-StringArray (Get-Value (Get-Value $pol 'defaultUserRolePermissions') 'permissionGrantPoliciesAssigned') }
    } -Count { 1 }
    $acr = Invoke-Dataset -Key 'consent_posture.admin_consent_request_policy' -Collect {
        $pol = Invoke-GraphGet -Uri 'v1.0/policies/adminConsentRequestPolicy?$select=isEnabled'
        [ordered]@{ isEnabled = [bool](Get-Value $pol 'isEnabled') }
    } -Count { 1 }
    $consent = if ($null -eq $authz -and $null -eq $acr) { $null } else { [ordered]@{ authorization_policy = $authz; admin_consent_request_policy = $acr } }

    # --- service principals (+ their credential metadata)
    $spCreds = [System.Collections.Generic.List[object]]::new()
    $sps = Invoke-Dataset -Key 'service_principals' -Collect {
        $select = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,publisherName,verifiedPublisher,accountEnabled,appRoleAssignmentRequired,tags,homepage,replyUrls,passwordCredentials,keyCredentials'
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($sp in (Invoke-GraphGet -Uri "v1.0/servicePrincipals?`$top=999&`$select=$select" -All)) {
            $vp = Get-Value $sp 'verifiedPublisher'
            $out.Add([ordered]@{
                    id                        = [string](Get-Value $sp 'id')
                    appId                     = [string](Get-Value $sp 'appId')
                    displayName               = Get-Value $sp 'displayName'
                    servicePrincipalType      = Get-Value $sp 'servicePrincipalType'
                    appOwnerOrganizationId    = Get-Value $sp 'appOwnerOrganizationId'
                    publisherName             = Get-Value $sp 'publisherName'
                    verifiedPublisher         = [ordered]@{
                        displayName         = Get-Value $vp 'displayName'
                        verifiedPublisherId = Get-Value $vp 'verifiedPublisherId'
                        addedDateTime       = ConvertTo-GraphDate (Get-Value $vp 'addedDateTime')
                    }
                    accountEnabled            = Get-Value $sp 'accountEnabled'
                    appRoleAssignmentRequired = Get-Value $sp 'appRoleAssignmentRequired'
                    tags                      = ConvertTo-StringArray (Get-Value $sp 'tags')
                    homepage                  = Get-Value $sp 'homepage'
                    replyUrls                 = ConvertTo-StringArray (Get-Value $sp 'replyUrls')
                })
            foreach ($c in @(Get-Value $sp 'passwordCredentials')) { if ($c) { $spCreds.Add((ConvertTo-CredentialRecord 'servicePrincipal' $sp $c 'password')) } }
            foreach ($c in @(Get-Value $sp 'keyCredentials')) { if ($c) { $spCreds.Add((ConvertTo-CredentialRecord 'servicePrincipal' $sp $c 'certificate')) } }
        }
        , $out.ToArray()
    }
    if ($null -eq $sps) {
        Write-EndpointStatus -Key 'credentials.service_principals' -Status $script:EndpointStatus['service_principals'].status -HttpStatus $script:EndpointStatus['service_principals'].http_status -Message 'Depends on service_principals.'
    }
    else {
        Write-EndpointStatus -Key 'credentials.service_principals' -Status 'ok' -HttpStatus 200 -RecordCount $spCreds.Count
    }

    # --- application permissions granted to non-Microsoft service principals
    $skipped = $null
    $assignments = $null
    if ($null -eq $sps) {
        Write-EndpointStatus -Key 'app_role_assignments' -Status 'skipped' -HttpStatus $null -Message 'service_principals could not be read.'
    }
    else {
        $skipped = @($sps | Where-Object { $_.appOwnerOrganizationId -and $_.appOwnerOrganizationId.ToLowerInvariant() -in $MicrosoftOwners }).Count
        $assignments = Invoke-Dataset -Key 'app_role_assignments' -Collect {
            $roleCache = @{}
            $out = [System.Collections.Generic.List[object]]::new()
            foreach ($sp in $sps) {
                if ($sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId.ToLowerInvariant() -in $MicrosoftOwners) { continue }
                try { $rows = Invoke-GraphGet -Uri "v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" -All }
                catch {
                    if ((Get-GraphErrorInfo -ErrorRecord $_).Status -eq 404) { Write-CollectorLog "Service principal $($sp.id) disappeared during collection; skipped." 'WARN'; continue }
                    throw
                }
                foreach ($a in $rows) {
                    if ((Get-Value $a 'principalType') -and (Get-Value $a 'principalType') -ne 'ServicePrincipal') { continue }
                    $resourceId = [string](Get-Value $a 'resourceId')
                    if (-not $roleCache.ContainsKey($resourceId)) {
                        $map = @{}
                        try {
                            $res = Invoke-GraphGet -Uri "v1.0/servicePrincipals/${resourceId}?`$select=id,appRoles"
                            foreach ($r in @(Get-Value $res 'appRoles')) { if ($r) { $map[[string](Get-Value $r 'id')] = Get-Value $r 'value' } }
                        }
                        catch { Write-CollectorLog "Could not resolve app roles for resource $resourceId; values left null." 'WARN' }
                        $roleCache[$resourceId] = $map
                    }
                    $roleId = [string](Get-Value $a 'appRoleId')
                    $out.Add([ordered]@{
                            servicePrincipalId  = [string](Get-Value $a 'principalId')
                            resourceId          = $resourceId
                            resourceDisplayName = Get-Value $a 'resourceDisplayName'
                            appRoleId           = $roleId
                            appRoleValue        = $roleCache[$resourceId][$roleId]
                            createdDateTime     = ConvertTo-GraphDate (Get-Value $a 'createdDateTime')
                        })
                }
            }
            , $out.ToArray()
        }
    }

    # --- delegated grants, aggregated: no principal IDs leave this function
    $grants = Invoke-Dataset -Key 'delegated_grants' -Collect {
        $agg = [ordered]@{}
        foreach ($g in (Invoke-GraphGet -Uri 'v1.0/oauth2PermissionGrants?$select=clientId,consentType,principalId,resourceId,scope' -All)) {
            $consentType = [string](Get-Value $g 'consentType')
            $key = '{0}|{1}|{2}' -f (Get-Value $g 'clientId'), (Get-Value $g 'resourceId'), $consentType
            if (-not $agg.Contains($key)) {
                $agg[$key] = @{ clientId = [string](Get-Value $g 'clientId'); resourceId = [string](Get-Value $g 'resourceId'); consentType = $consentType; scopes = [System.Collections.Generic.HashSet[string]]::new(); principals = [System.Collections.Generic.HashSet[string]]::new() }
            }
            foreach ($s in ([string](Get-Value $g 'scope') -split '\s+')) { if ($s) { [void]$agg[$key].scopes.Add($s) } }
            $pid_ = Get-Value $g 'principalId'
            if ($consentType -eq 'Principal' -and $pid_) { [void]$agg[$key].principals.Add([string]$pid_) }
        }
        , @($agg.Values | ForEach-Object {
                [ordered]@{ clientId = $_.clientId; resourceId = $_.resourceId; consentType = $_.consentType; scopes = @($_.scopes | Sort-Object); principalCount = $_.principals.Count }
            })
    }

    # --- application registration credentials (internal apps)
    $appCreds = Invoke-Dataset -Key 'credentials.applications' -Collect {
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($app in (Invoke-GraphGet -Uri 'v1.0/applications?$select=id,appId,passwordCredentials,keyCredentials' -All)) {
            foreach ($c in @(Get-Value $app 'passwordCredentials')) { if ($c) { $out.Add((ConvertTo-CredentialRecord 'application' $app $c 'password')) } }
            foreach ($c in @(Get-Value $app 'keyCredentials')) { if ($c) { $out.Add((ConvertTo-CredentialRecord 'application' $app $c 'certificate')) } }
        }
        , $out.ToArray()
    }
    $credentials = if ($null -eq $appCreds -or $null -eq $sps) { $null } else { , @($appCreds + $spCreds.ToArray()) }

    # --- sign-in activity (beta; needs Entra ID P1/P2)
    $signins = $null
    if ($SkipSignInActivity) {
        Write-EndpointStatus -Key 'signin_activity' -Status 'skipped' -HttpStatus $null -Message 'Skipped by -SkipSignInActivity.' -ApiVersion 'beta'
    }
    elseif ($p1 -eq $false) {
        Write-EndpointStatus -Key 'signin_activity' -Status 'unavailable_license' -HttpStatus $null -Message 'No Entra ID P1/P2 service plan found; sign-in activity report not queried.' -ApiVersion 'beta'
    }
    else {
        $signins = Invoke-Dataset -Key 'signin_activity' -ApiVersion 'beta' -Collect {
            $kinds = 'lastSignInActivity', 'delegatedClientSignInActivity', 'delegatedResourceSignInActivity', 'applicationAuthenticationClientSignInActivity', 'applicationAuthenticationResourceSignInActivity'
            , @((Invoke-GraphGet -Uri 'beta/reports/servicePrincipalSignInActivities' -All) | ForEach-Object {
                    $row = [ordered]@{ appId = [string](Get-Value $_ 'appId') }
                    foreach ($k in $kinds) { $row[$k] = [ordered]@{ lastSignInDateTime = ConvertTo-GraphDate (Get-Value (Get-Value $_ $k) 'lastSignInDateTime') } }
                    $row
                })
        }
    }

    $tenantIdValue = if ($tenant) { $tenant.id } else { [string]$ctx.TenantId }
    [ordered]@{
        schema_version       = $script:SchemaVersion
        collector_version    = $script:CollectorVersion
        metadata             = [ordered]@{
            tenant_id                     = $tenantIdValue
            tenant_name                   = $TenantName
            default_domain                = if ($tenant) { $tenant.defaultDomain } else { $null }
            collected_at_utc              = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            operator_upn                  = [string]$ctx.Account
            ticket_number                 = if ($TicketNumber) { $TicketNumber } else { $null }
            granted_scopes                = $scopes
            write_scopes_present          = ($writeScopes.Count -gt 0)
            entra_p1_available            = $p1
            microsoft_owned_skipped_count = $skipped
            endpoint_status               = $script:EndpointStatus
        }
        tenant               = $tenant
        licensing            = $licensing
        consent_posture      = $consent
        service_principals   = $sps
        app_role_assignments = $assignments
        delegated_grants     = $grants
        credentials          = $credentials
        signin_activity      = $signins
    }
}

# ----------------------------------------------------------------------------- output

function Export-CollectorOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Document, [Parameter(Mandatory)][string] $Folder)
    $json = ConvertTo-Json -InputObject $Document -Depth 20
    $schema = Join-Path $PSScriptRoot '..' 'schemas' 'collected.schema.json'
    $valid = $true
    if (Test-Path -LiteralPath $schema) {
        $valid = Test-Json -Json $json -SchemaFile $schema -ErrorAction SilentlyContinue
    }
    $name = if ($valid) { 'collected.json' } else { 'collected.INVALID.json' }
    Set-Content -LiteralPath (Join-Path $Folder $name) -Value $json -Encoding utf8
    if (-not $valid) { Write-CollectorLog 'Output failed schema validation; written as collected.INVALID.json. Do not import it.' 'ERROR' }

    $csv = @{
        'service_principals.csv' = { $Document.service_principals | ForEach-Object { [pscustomobject]@{ id = $_.id; appId = $_.appId; displayName = $_.displayName; type = $_.servicePrincipalType; ownerOrgId = $_.appOwnerOrganizationId; publisherName = $_.publisherName; verifiedPublisher = $_.verifiedPublisher.displayName; accountEnabled = $_.accountEnabled; homepage = $_.homepage; replyUrls = ($_.replyUrls -join ' ') } } }
        'app_permissions.csv'    = { $Document.app_role_assignments | ForEach-Object { [pscustomobject]$_ } }
        'delegated_grants.csv'   = { $Document.delegated_grants | ForEach-Object { [pscustomobject]@{ clientId = $_.clientId; resourceId = $_.resourceId; consentType = $_.consentType; scopes = ($_.scopes -join ' '); userCount = $_.principalCount } } }
        'credentials.csv'        = { $Document.credentials | ForEach-Object { [pscustomobject]$_ } }
        'signin_activity.csv'    = { $Document.signin_activity | ForEach-Object { [pscustomobject]@{ appId = $_.appId; lastSignIn = $_.lastSignInActivity.lastSignInDateTime; delegatedClient = $_.delegatedClientSignInActivity.lastSignInDateTime; appOnlyClient = $_.applicationAuthenticationClientSignInActivity.lastSignInDateTime } } }
    }
    $sources = @{ 'service_principals.csv' = 'service_principals'; 'app_permissions.csv' = 'app_role_assignments'; 'delegated_grants.csv' = 'delegated_grants'; 'credentials.csv' = 'credentials'; 'signin_activity.csv' = 'signin_activity' }
    foreach ($file in $csv.Keys) {
        if ($null -eq $Document[$sources[$file]]) { Write-CollectorLog "$file not written: dataset could not be collected (null)."; continue }
        & $csv[$file] | Export-Csv -LiteralPath (Join-Path $Folder $file) -NoTypeInformation -Encoding utf8 -UseQuotes AsNeeded
    }
    $valid
}

function Invoke-TenantCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Id, [Parameter(Mandatory)][string] $Name, [string] $Ticket, [string] $Root, [switch] $SkipSignIn, [string[]] $MicrosoftOwners)
    $folder = Join-Path $Root ('{0}_{1}' -f (Get-SafeFolderName $Name), (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'))
    $null = New-Item -ItemType Directory -Path $folder -Force
    $script:LogPath = Join-Path $folder 'collector.log'
    $summary = [ordered]@{ Tenant = $Name; Status = 'ok'; ServicePrincipals = $null; AppPermissions = $null; DelegatedGrants = $null; FailedEndpoints = ''; Output = $folder }
    Write-CollectorLog "Collecting tenant '$Name' ($Id), collector $($script:CollectorVersion)"
    Write-CollectorLog 'Reminder: activate your read-only role (e.g. Global Reader via PIM) before signing in. If a consent prompt for Microsoft Graph Command Line Tools appears, cancel it unless consenting has been approved.'
    $connected = $false
    try {
        Connect-MgGraph -TenantId $Id -Scopes $script:ReadScopes -NoWelcome -ErrorAction Stop
        $connected = $true
        $doc = Get-TenantExposure -TenantName $Name -TicketNumber $Ticket -SkipSignInActivity:$SkipSignIn -MicrosoftOwners $MicrosoftOwners
        $valid = Export-CollectorOutput -Document $doc -Folder $folder
        $failed = @($doc.metadata.endpoint_status.GetEnumerator() | Where-Object { $_.Value.status -ne 'ok' } | ForEach-Object { "$($_.Key)=$($_.Value.status)" })
        $summary.ServicePrincipals = if ($null -ne $doc.service_principals) { @($doc.service_principals).Count } else { 'n/a' }
        $summary.AppPermissions = if ($null -ne $doc.app_role_assignments) { @($doc.app_role_assignments).Count } else { 'n/a' }
        $summary.DelegatedGrants = if ($null -ne $doc.delegated_grants) { @($doc.delegated_grants).Count } else { 'n/a' }
        $summary.FailedEndpoints = $failed -join ', '
        if (-not $valid) { $summary.Status = 'invalid_output' } elseif ($failed) { $summary.Status = 'partial' }
    }
    catch {
        $summary.Status = 'failed'
        $summary.FailedEndpoints = (Get-GraphErrorInfo -ErrorRecord $_).Message
        Write-CollectorLog "Tenant '$Name' failed: $($summary.FailedEndpoints)" 'ERROR'
    }
    finally {
        if ($connected) { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue }
        $script:LogPath = $null
    }
    [pscustomobject]$summary
}

# ----------------------------------------------------------------------------- main

$owners = Get-MicrosoftOwnerTenantId
$targets = if ($PSCmdlet.ParameterSetName -eq 'Batch') {
    $rows = @(Import-Csv -LiteralPath $TenantListCsv)
    if (-not $rows -or -not ($rows[0].PSObject.Properties['TenantId'] -and $rows[0].PSObject.Properties['TenantName'])) { throw "$TenantListCsv must have columns TenantId,TenantName" }
    $rows
}
else { , [pscustomobject]@{ TenantId = $TenantId; TenantName = $TenantName } }

$results = foreach ($t in $targets) {
    Invoke-TenantCollection -Id $t.TenantId -Name $t.TenantName -Ticket $TicketNumber -Root $OutputRoot -SkipSignIn:$SkipSignInActivity -MicrosoftOwners $owners
}
if ($PSCmdlet.ParameterSetName -eq 'Batch') {
    $results | Format-Table Tenant, Status, ServicePrincipals, AppPermissions, DelegatedGrants, FailedEndpoints -AutoSize -Wrap | Out-Host
}
$results
