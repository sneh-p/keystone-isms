<#
.SYNOPSIS
    Keystone configuration agent for Windows. Report-only: reads security settings and sends them to Keystone over
    HTTPS. It never changes the computer's configuration and never runs commands it is sent.

.DESCRIPTION
    Install (from an elevated PowerShell prompt):
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\keystone-agent.ps1 -Install -Server "https://keystone.example.org" -EnrolmentKey "kenr_..."
    Print what would be sent, without sending anything:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\keystone-agent.ps1 -Collect
    Remove:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\keystone-agent.ps1 -Uninstall

    Install copies this script to "%ProgramFiles%\Keystone Agent", writes the server address and the one-time enrolment
    key to "%ProgramData%\Keystone Agent" (readable only by SYSTEM and Administrators), and registers the scheduled task
    "Keystone Agent", which runs as SYSTEM at startup and every few hours. On its first run the task exchanges the
    enrolment key for this computer's own device token, stores the token encrypted with DPAPI for the SYSTEM account,
    and deletes the enrolment key.

    Options at install: -Tags web,dmz (groups this computer for scoped baselines), -Hours 1|2|4|8|12|24, and
    -NoCustomChecks (turns custom checks off on this computer; Keystone then shows them as unknown).

    Custom checks: administrators can define extra read-only checks in Keystone. The agent downloads their definitions
    and evaluates each one itself, within limits written into this script, not set by the server: a fixed list of
    probes (registry value under HKLM, service, installed software, file exists, optional feature, local security
    policy, audit policy, built-in group member count); strict checks on every parameter; never the SAM or SECURITY
    hives; no commands, scripts or regular expressions from the server; at most 100 checks; values capped at 200
    characters.

    Works with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][switch]$Install,
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][string]$Server,
    [Parameter(ParameterSetName = 'Install')][string]$EnrolmentKey,
    [Parameter(ParameterSetName = 'Install')][ValidateSet(1, 2, 4, 8, 12, 24)][int]$Hours = 4,
    [Parameter(ParameterSetName = 'Install')][string[]]$Tags = @(),
    [Parameter(ParameterSetName = 'Install')][switch]$NoCustomChecks,
    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)][switch]$Uninstall,
    [Parameter(ParameterSetName = 'Collect', Mandatory = $true)][switch]$Collect,
    [Parameter(ParameterSetName = 'Run')][switch]$Run
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:AgentVersion = '1.1.0'
$script:MaxChecks = 100
$script:TaskName = 'Keystone Agent'
$script:ProgramDir = Join-Path $env:ProgramFiles 'Keystone Agent'
$script:DataDir = Join-Path $env:ProgramData 'Keystone Agent'
$script:ConfigPath = Join-Path $script:DataDir 'config.json'
$script:TokenPath = Join-Path $script:DataDir 'token.bin'
$script:LogPath = Join-Path $script:DataDir 'last-run.log'

# ----------------------------------------------------------------------------------------------- helpers

function Invoke-Safely {
    <# Runs a probe; any error means "not known" ($null), never a pass. #>
    param([scriptblock]$Probe)
    try { & $Probe } catch { $null }
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function Test-ServerAddress {
    param([string]$Address)
    if ($Address -match '^https://[A-Za-z0-9.\-]+(:\d{1,5})?/?$') { return $true }
    if ($Address -match '^http://(localhost|127\.0\.0\.1)(:\d{1,5})?/?$') { return $true }  # local testing only
    return $false
}

function Get-SecurityPolicy {
    <# The [System Access] values of the local security policy from secedit (locale-independent keys). #>
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ks-" + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet
        $policy = @{}
        foreach ($line in (Get-Content -Path $tmp -ErrorAction Stop)) {
            if ($line -match '^\s*([A-Za-z]{2,60})\s*=\s*(.{0,200})$') {
                $value = $Matches[2].Trim()
                $policy[$Matches[1]] = if ($value -match '^-?\d{1,10}$') { [long]$value } else { $value }
            }
        }
        return $policy
    } finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------------------------------------- collection

function Get-KeystoneFact {
    <# Reads every setting the Keystone catalogue knows for Windows. Unknown values are left out. #>
    $facts = [ordered]@{}

    $profiles = Invoke-Safely { Get-NetFirewallProfile -PolicyStore ActiveStore }
    if ($profiles) {
        foreach ($p in $profiles) {
            $name = ([string]$p.Name).ToLowerInvariant()
            if ($name -in @('domain', 'private', 'public')) { $facts["firewall_${name}_enabled"] = [bool]($p.Enabled -eq $true -or [string]$p.Enabled -eq 'True') }
            if ($name -eq 'public') { $facts['firewall_public_inbound_blocked'] = ([string]$p.DefaultInboundAction -in @('Block', 'NotConfigured')) }
        }
    }

    $bl = Invoke-Safely { Get-BitLockerVolume -MountPoint $env:SystemDrive }
    if ($bl) { $facts['bitlocker_os_volume'] = ([string]$bl.ProtectionStatus -eq 'On') }

    try { $facts['secure_boot_enabled'] = [bool](Confirm-SecureBootUEFI) }
    catch [System.PlatformNotSupportedException] { $facts['secure_boot_enabled'] = $false }  # legacy BIOS: Secure Boot isn't possible
    catch { $null = $_ }

    $mp = Invoke-Safely { Get-MpComputerStatus }
    if ($mp) {
        $facts['defender_realtime_enabled'] = [bool]$mp.RealTimeProtectionEnabled
        if ($null -ne $mp.AntivirusSignatureAge) { $facts['defender_signature_age_days'] = [int]$mp.AntivirusSignatureAge }
    }

    $latest = Invoke-Safely { Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
    if ($latest) { $facts['last_update_installed_days'] = [int][math]::Floor(((Get-Date) - [datetime]$latest.InstalledOn).TotalDays) }

    $smb = Invoke-Safely { Get-SmbServerConfiguration }
    if ($smb) {
        $facts['smb1_enabled'] = [bool]$smb.EnableSMB1Protocol
        $facts['smb_signing_required'] = [bool]$smb.RequireSecuritySignature
    }

    $deny = Get-RegistryValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($null -ne $deny) { $facts['rdp_enabled'] = ([int]$deny -eq 0) }
    $nla = Get-RegistryValue 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($null -ne $nla) { $facts['rdp_nla_required'] = ([int]$nla -eq 1) }

    $lua = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    if ($null -ne $lua) { $facts['uac_enabled'] = ([int]$lua -eq 1) }

    $policy = Invoke-Safely { Get-SecurityPolicy }
    if ($policy) {
        if ($policy.ContainsKey('MinimumPasswordLength')) { $facts['password_min_length'] = $policy['MinimumPasswordLength'] }
        if ($policy.ContainsKey('LockoutBadCount')) {
            $facts['lockout_threshold'] = $policy['LockoutBadCount']
            $facts['lockout_enabled'] = ($policy['LockoutBadCount'] -gt 0)
        }
    }

    $guest = Invoke-Safely { Get-LocalUser | Where-Object { $_.SID.Value -match '^S-1-5-21-.*-501$' } | Select-Object -First 1 }
    if ($guest) { $facts['guest_account_enabled'] = [bool]$guest.Enabled }

    $admins = Invoke-Safely { @(Get-LocalGroupMember -SID 'S-1-5-32-544') }
    if ($null -ne $admins) { $facts['local_admin_count'] = [int]$admins.Count }

    $autorun = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    $facts['autorun_disabled'] = ($null -ne $autorun -and [int]$autorun -eq 255)

    $idle = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
    $idleSeconds = if ($null -eq $idle) { 0 } else { [int]$idle }
    $facts['screen_lock_timeout_seconds'] = $idleSeconds
    $facts['screen_lock_configured'] = ($idleSeconds -gt 0 -and $idleSeconds -le 900)

    $mcast = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    $facts['llmnr_disabled'] = ($null -ne $mcast -and [int]$mcast -eq 0)

    $ps2 = Invoke-Safely { Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' }
    if ($ps2) { $facts['powershell_v2_enabled'] = ([string]$ps2.State -eq 'Enabled') }

    $sbl = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    $facts['ps_script_block_logging'] = ($null -ne $sbl -and [int]$sbl -eq 1)

    $lm = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    $facts['lm_compatibility_level'] = if ($null -eq $lm) { 3 } else { [int]$lm }  # not set: the Windows default, 3
    $wdigest = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $facts['wdigest_disabled'] = ($null -eq $wdigest -or [int]$wdigest -eq 0)
    $ppl = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    $facts['lsa_protection'] = ($null -ne $ppl -and [int]$ppl -in @(1, 2))

    return $facts
}

# ----------------------------------------------------------------------------------------------- custom checks

function Test-ProbeParam {
    <# The agent's own limits on custom check parameters; the server's validation is not trusted. #>
    param([string]$Kind, [string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    switch ($Kind) {
        'regpath' { return ($Value -match '^[A-Za-z0-9][A-Za-z0-9 ._\\(){}\-]{0,250}$') -and ($Value -notmatch '\.\.|\\\\') -and ($Value.Split('\')[0] -notin @('SAM', 'SECURITY')) }
        'regname' { return $Value -match '^[A-Za-z0-9 ._\-]{0,128}$' }
        'name' { return $Value -match '^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}$' }
        'text' { return $Value -match '^[\x20-\x7e]{1,200}$' }
        'path' { return ($Value -match '^[A-Za-z]:\\[A-Za-z0-9 ._\\()\-]{1,250}$') -and ($Value -notmatch '\.\.') }
        'secedit' { return $Value -match '^[A-Za-z]{2,60}$' }
        'guid' { return $Value -match '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$' }
        'sid' { return $Value -match '^S-1-5-32-\d{3}$' }
        default { return $false }
    }
}

function Invoke-KeystoneProbe {
    <# One custom check. Returns @{ Value = ...; Error = $null | 'refused' | 'missing' | 'unsupported' | 'error' }. #>
    param([object]$Check)
    $p = $Check.params
    $get = { param($n) if ($p -and ($p.PSObject.Properties.Name -contains $n)) { [string]$p.$n } else { '' } }
    $refused = @{ Value = $null; Error = 'refused' }
    $missing = @{ Value = $null; Error = 'missing' }
    try {
        switch ([string]$Check.probe) {
            'registry_value' {
                $path = & $get 'path'; $name = & $get 'name'; $mode = & $get 'mode'
                if (-not (Test-ProbeParam 'regpath' $path) -or -not (Test-ProbeParam 'regname' ('x' + $name)) -or $mode -notin @('value', 'exists')) { return $refused }
                $item = Get-ItemProperty -LiteralPath ('HKLM:\' + $path) -Name $name -ErrorAction SilentlyContinue
                $present = ($null -ne $item) -and ($item.PSObject.Properties.Name -contains $name)
                if ($mode -eq 'exists') { return @{ Value = $present; Error = $null } }
                if (-not $present) { return $missing }
                return @{ Value = $item.$name; Error = $null }
            }
            'service' {
                $name = & $get 'name'; $field = & $get 'field'
                if (-not (Test-ProbeParam 'name' $name) -or $field -notin @('state', 'start_type')) { return $refused }
                $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($null -eq $svc) { return @{ Value = 'absent'; Error = $null } }
                $value = if ($field -eq 'state') { [string]$svc.Status } else { [string]$svc.StartType }
                return @{ Value = $value.ToLowerInvariant(); Error = $null }
            }
            'software_installed' {
                $text = & $get 'name_contains'; $field = & $get 'field'
                if (-not (Test-ProbeParam 'text' $text) -or $field -notin @('present', 'version')) { return $refused }
                $roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                $hit = Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and ([string]$_.DisplayName).IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
                    Select-Object -First 1
                if ($field -eq 'present') { return @{ Value = ($null -ne $hit); Error = $null } }
                if ($null -eq $hit -or -not ($hit.PSObject.Properties.Name -contains 'DisplayVersion')) { return $missing }
                return @{ Value = [string]$hit.DisplayVersion; Error = $null }
            }
            'file_exists' {
                $path = & $get 'path'
                if (-not (Test-ProbeParam 'path' $path)) { return $refused }
                return @{ Value = (Test-Path -LiteralPath $path); Error = $null }
            }
            'windows_feature' {
                $name = & $get 'name'
                if (-not (Test-ProbeParam 'name' $name)) { return $refused }
                $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
                if ($null -eq $feature) { return @{ Value = 'absent'; Error = $null } }
                return @{ Value = ([string]$feature.State).ToLowerInvariant(); Error = $null }
            }
            'security_policy' {
                $key = & $get 'key'
                if (-not (Test-ProbeParam 'secedit' $key)) { return $refused }
                $policy = Get-SecurityPolicy
                if (-not $policy.ContainsKey($key)) { return $missing }
                return @{ Value = $policy[$key]; Error = $null }
            }
            'audit_policy' {
                $guid = & $get 'guid'
                if (-not (Test-ProbeParam 'guid' $guid)) { return $refused }
                $id = '{' + $guid.Trim('{', '}') + '}'
                $row = & auditpol.exe /get "/subcategory:$id" /r | ConvertFrom-Csv | Select-Object -First 1
                if ($null -eq $row) { return $missing }
                return @{ Value = ([string]$row.'Inclusion Setting').ToLowerInvariant(); Error = $null }
            }
            'local_group_count' {
                $sid = & $get 'sid'
                if (-not (Test-ProbeParam 'sid' $sid)) { return $refused }
                return @{ Value = @(Get-LocalGroupMember -SID $sid).Count; Error = $null }
            }
            default { return @{ Value = $null; Error = 'unsupported' } }
        }
    } catch {
        return @{ Value = $null; Error = 'error' }
    }
}

function Get-KeystoneCustomFact {
    <# Evaluates downloaded definitions. Returns @{ Facts = @{}; Errors = @{} } keyed by "custom.<slug>". #>
    param([object[]]$Checks)
    $facts = [ordered]@{}; $errors = [ordered]@{}
    foreach ($check in @($Checks | Select-Object -First $script:MaxChecks)) {
        $key = [string]$check.key
        if ($key -notmatch '^custom\.[a-z][a-z0-9_]{1,40}$') { continue }
        $result = Invoke-KeystoneProbe -Check $check
        $value = $result.Value
        if ($result.Error -eq 'missing' -and $check.PSObject.Properties.Name -contains 'default' -and $null -ne $check.default) { $value = $check.default; $result.Error = $null }
        if ($result.Error) { $errors[$key] = $result.Error; continue }
        switch ([string]$check.type) {
            'bool' { if ($value -is [bool]) { $facts[$key] = $value } else { $errors[$key] = 'error' } }
            'int' { $n = 0L; if ([long]::TryParse([string]$value, [ref]$n)) { $facts[$key] = $n } else { $errors[$key] = 'error' } }
            default { $text = [string]$value; $facts[$key] = $text.Substring(0, [math]::Min(200, $text.Length)) }
        }
    }
    @{ Facts = $facts; Errors = $errors }
}

function Get-KeystoneReport {
    param([object[]]$Checks = @(), [switch]$CustomChecksDisabled)
    $os = Invoke-Safely { Get-CimInstance -ClassName Win32_OperatingSystem }
    $facts = Get-KeystoneFact
    $custom = Get-KeystoneCustomFact -Checks $Checks
    foreach ($k in $custom.Facts.Keys) { $facts[$k] = $custom.Facts[$k] }
    $report = [ordered]@{
        hostname      = [string]$env:COMPUTERNAME
        os_name       = if ($os) { [string]$os.Caption } else { 'Windows' }
        os_version    = if ($os) { [string]$os.Version } else { $null }
        agent_version = $script:AgentVersion
        facts         = $facts
        check_errors  = $custom.Errors
    }
    if ($CustomChecksDisabled) { $report['custom_checks'] = 'disabled' }
    $report
}

# ----------------------------------------------------------------------------------------------- transport

function Send-KeystoneRequest {
    param([string]$Address, [string]$Path, [hashtable]$Headers, [object]$Body)
    if (-not (Test-ServerAddress $Address)) { throw "The server address must start with https://" }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
    $json = $Body | ConvertTo-Json -Depth 5 -Compress
    $uri = $Address.TrimEnd('/') + '/api/agent/v1/' + $Path
    # Certificates are validated by the platform; the agent never turns validation off.
    Invoke-RestMethod -Method Post -Uri $uri -Headers $Headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 60 -UseBasicParsing -MaximumRedirection 0
}

function Get-KeystoneCheckList {
    <# The custom check definitions for this computer (read-only probes, evaluated by Invoke-KeystoneProbe). #>
    param([string]$Address, [string]$Token)
    if (-not (Test-ServerAddress $Address)) { throw "The server address must start with https://" }
    $uri = $Address.TrimEnd('/') + '/api/agent/v1/checks'
    $reply = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60 -UseBasicParsing -MaximumRedirection 0
    @($reply.checks | Select-Object -First $script:MaxChecks)
}

function Protect-Token {
    param([string]$Token)
    Add-Type -AssemblyName System.Security
    $bytes = [Text.Encoding]::UTF8.GetBytes($Token)
    [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Unprotect-Token {
    param([byte[]]$Data)
    Add-Type -AssemblyName System.Security
    [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($Data, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
}

function Write-RunLog {
    param([string]$Message)
    $line = '{0:u} {1}' -f (Get-Date).ToUniversalTime(), $Message
    Set-Content -Path $script:LogPath -Value $line -Encoding UTF8
}

function Invoke-KeystoneRun {
    $config = Get-Content -Path $script:ConfigPath -Raw | ConvertFrom-Json
    if (-not (Test-Path $script:TokenPath)) {
        if (-not $config.enrolment_key) { throw 'Not enrolled and no enrolment key. Reinstall with -EnrolmentKey.' }
        $os = Invoke-Safely { Get-CimInstance -ClassName Win32_OperatingSystem }
        $reply = Send-KeystoneRequest -Address $config.server -Path 'enrol' -Headers @{} -Body ([ordered]@{
                enrolment_key = [string]$config.enrolment_key; hostname = [string]$env:COMPUTERNAME; platform = 'windows'
                os_name = if ($os) { [string]$os.Caption } else { 'Windows' }; os_version = if ($os) { [string]$os.Version } else { $null }
                agent_version = $script:AgentVersion
                tags = @(if ($config.PSObject.Properties.Name -contains 'tags') { $config.tags } else { @() })
            })
        if (-not ($reply.token -match '^kagt_[A-Za-z0-9_\-]+$')) { throw "The server's reply had no device token." }
        [IO.File]::WriteAllBytes($script:TokenPath, (Protect-Token $reply.token))
        $config = [ordered]@{ server = [string]$config.server; custom_checks = -not ($config.PSObject.Properties.Name -contains 'custom_checks' -and $config.custom_checks -eq $false) }  # the enrolment key is no longer needed
        $config | ConvertTo-Json | Set-Content -Path $script:ConfigPath -Encoding UTF8
        $config = [pscustomobject]$config
    }
    $token = Unprotect-Token ([IO.File]::ReadAllBytes($script:TokenPath))
    $customOff = ($config.PSObject.Properties.Name -contains 'custom_checks') -and ($config.custom_checks -eq $false)
    $checks = @()
    if (-not $customOff) {
        try { $checks = Get-KeystoneCheckList -Address $config.server -Token $token }
        catch { Write-RunLog 'Could not fetch custom checks; sending the built-in settings only.' }
    }
    $null = Send-KeystoneRequest -Address $config.server -Path 'report' -Headers @{ Authorization = "Bearer $token" } -Body (Get-KeystoneReport -Checks $checks -CustomChecksDisabled:$customOff)
    Write-RunLog 'Report sent.'
}

# ----------------------------------------------------------------------------------------------- install

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-PrivateAcl {
    <# Only SYSTEM and Administrators can read the data folder (config, token, log). #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Restrict access to SYSTEM and Administrators')) { return }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $who = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Install-KeystoneAgent {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Address, [string]$Key, [int]$Every, [string[]]$TagList = @(), [switch]$CustomOff)
    if (-not (Test-Administrator)) { throw 'Run the installer from an elevated PowerShell prompt (Run as administrator).' }
    $Address = $Address.TrimEnd('/')
    if (-not (Test-ServerAddress $Address)) { throw 'The server address must start with https://' }
    if (-not $Key) {
        $secure = Read-Host -Prompt 'Enrolment key' -AsSecureString
        $Key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    }
    if (-not ($Key -match '^kenr_[A-Za-z0-9_\-]+$')) { throw 'That is not a Keystone enrolment key (it starts with kenr_).' }
    $TagList = @($TagList | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($t in $TagList) { if ($t -notmatch '^[a-z0-9][a-z0-9_-]{0,39}$') { throw "Tag '$t': lower-case letters, digits, - and _ only." } }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install the Keystone agent')) { return }

    $null = New-Item -ItemType Directory -Force -Path $script:ProgramDir, $script:DataDir
    Set-PrivateAcl -Path $script:DataDir
    Copy-Item -Path $PSCommandPath -Destination (Join-Path $script:ProgramDir 'keystone-agent.ps1') -Force
    Remove-Item -Path $script:TokenPath -Force -ErrorAction SilentlyContinue  # a reinstall enrols again
    [ordered]@{ server = $Address; enrolment_key = $Key; tags = $TagList; custom_checks = -not $CustomOff } | ConvertTo-Json | Set-Content -Path $script:ConfigPath -Encoding UTF8

    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Run' -f (Join-Path $script:ProgramDir 'keystone-agent.ps1')
    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $atStartup = New-ScheduledTaskTrigger -AtStartup
    $atStartup.Delay = 'PT5M'
    $repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours $Every)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
    $null = Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger @($atStartup, $repeat) -Principal $principal -Settings $settings `
        -Description 'Keystone configuration agent (report-only): sends security settings to Keystone.' -Force
    Start-ScheduledTask -TaskName $script:TaskName
    Write-Output "Installed. The task '$($script:TaskName)' runs as SYSTEM every $Every hour(s); it is enrolling now. See $($script:LogPath)."
}

function Uninstall-KeystoneAgent {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not (Test-Administrator)) { throw 'Run from an elevated PowerShell prompt (Run as administrator).' }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Remove the Keystone agent')) { return }
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $script:DataDir, $script:ProgramDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output 'Removed. Delete the device in Keystone (Configuration > Targets) to remove its results.'
}

# ----------------------------------------------------------------------------------------------- entry point

if ($MyInvocation.InvocationName -ne '.') {
    if ($Install) { Install-KeystoneAgent -Address $Server -Key $EnrolmentKey -Every $Hours -TagList $Tags -CustomOff:$NoCustomChecks }
    elseif ($Uninstall) { Uninstall-KeystoneAgent }
    elseif ($Collect) { Get-KeystoneReport | ConvertTo-Json -Depth 5 }
    elseif ($Run -or $PSCmdlet.ParameterSetName -eq 'Run') {
        try { Invoke-KeystoneRun }
        catch { Write-RunLog ("Failed: " + $_.Exception.Message); throw }
    }
}
