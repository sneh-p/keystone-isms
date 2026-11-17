<#
.SYNOPSIS
    Keystone configuration agent for Windows. Report-only: reads security settings and sends them to Keystone over
    HTTPS. It never changes the computer's configuration, and Keystone cannot send it commands.

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

    Works with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][switch]$Install,
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][string]$Server,
    [Parameter(ParameterSetName = 'Install')][string]$EnrolmentKey,
    [Parameter(ParameterSetName = 'Install')][ValidateSet(1, 2, 4, 8, 12, 24)][int]$Hours = 4,
    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)][switch]$Uninstall,
    [Parameter(ParameterSetName = 'Collect', Mandatory = $true)][switch]$Collect,
    [Parameter(ParameterSetName = 'Run')][switch]$Run
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:AgentVersion = '1.0.0'
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
    <# Local password and lockout policy from secedit (locale-independent keys). #>
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ks-" + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet
        $policy = @{}
        foreach ($line in (Get-Content -Path $tmp -ErrorAction Stop)) {
            if ($line -match '^\s*(MinimumPasswordLength|LockoutBadCount)\s*=\s*(\d+)') { $policy[$Matches[1]] = [int]$Matches[2] }
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

    return $facts
}

function Get-KeystoneReport {
    $os = Invoke-Safely { Get-CimInstance -ClassName Win32_OperatingSystem }
    [ordered]@{
        hostname      = [string]$env:COMPUTERNAME
        os_name       = if ($os) { [string]$os.Caption } else { 'Windows' }
        os_version    = if ($os) { [string]$os.Version } else { $null }
        agent_version = $script:AgentVersion
        facts         = Get-KeystoneFact
    }
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
            })
        if (-not ($reply.token -match '^kagt_[A-Za-z0-9_\-]+$')) { throw "The server's reply had no device token." }
        [IO.File]::WriteAllBytes($script:TokenPath, (Protect-Token $reply.token))
        $config = [ordered]@{ server = [string]$config.server }  # the enrolment key is no longer needed
        $config | ConvertTo-Json | Set-Content -Path $script:ConfigPath -Encoding UTF8
        $config = [pscustomobject]$config
    }
    $token = Unprotect-Token ([IO.File]::ReadAllBytes($script:TokenPath))
    $null = Send-KeystoneRequest -Address $config.server -Path 'report' -Headers @{ Authorization = "Bearer $token" } -Body (Get-KeystoneReport)
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
    param([string]$Address, [string]$Key, [int]$Every)
    if (-not (Test-Administrator)) { throw 'Run the installer from an elevated PowerShell prompt (Run as administrator).' }
    $Address = $Address.TrimEnd('/')
    if (-not (Test-ServerAddress $Address)) { throw 'The server address must start with https://' }
    if (-not $Key) {
        $secure = Read-Host -Prompt 'Enrolment key' -AsSecureString
        $Key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    }
    if (-not ($Key -match '^kenr_[A-Za-z0-9_\-]+$')) { throw 'That is not a Keystone enrolment key (it starts with kenr_).' }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install the Keystone agent')) { return }

    $null = New-Item -ItemType Directory -Force -Path $script:ProgramDir, $script:DataDir
    Set-PrivateAcl -Path $script:DataDir
    Copy-Item -Path $PSCommandPath -Destination (Join-Path $script:ProgramDir 'keystone-agent.ps1') -Force
    Remove-Item -Path $script:TokenPath -Force -ErrorAction SilentlyContinue  # a reinstall enrols again
    [ordered]@{ server = $Address; enrolment_key = $Key } | ConvertTo-Json | Set-Content -Path $script:ConfigPath -Encoding UTF8

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
    if ($Install) { Install-KeystoneAgent -Address $Server -Key $EnrolmentKey -Every $Hours }
    elseif ($Uninstall) { Uninstall-KeystoneAgent }
    elseif ($Collect) { Get-KeystoneReport | ConvertTo-Json -Depth 5 }
    elseif ($Run -or $PSCmdlet.ParameterSetName -eq 'Run') {
        try { Invoke-KeystoneRun }
        catch { Write-RunLog ("Failed: " + $_.Exception.Message); throw }
    }
}
