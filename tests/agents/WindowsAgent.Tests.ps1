#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Pester tests for the Windows configuration agent. Nothing on the machine is read or changed and no request is
# sent: the Windows cmdlets, the registry reader, secedit, DPAPI and the HTTP call are mocked.
# Run: pwsh -NoProfile -c "Invoke-Pester ./tests/agents"

BeforeAll {
    $script:Root = Resolve-Path (Join-Path $PSScriptRoot '..' '..')
    $script:AgentPath = Join-Path $script:Root 'agents' 'windows' 'keystone-agent.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AgentPath, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Agent has parse errors: $errors" }
    # Load the agent's functions without running its entry point.
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $script:AgentVersion = '1.0.0'

    # Stand-ins for Windows-only commands so they can be mocked on any platform.
    foreach ($name in 'Get-NetFirewallProfile', 'Get-BitLockerVolume', 'Confirm-SecureBootUEFI', 'Get-MpComputerStatus', 'Get-HotFix',
        'Get-SmbServerConfiguration', 'Get-LocalUser', 'Get-LocalGroupMember', 'Get-WindowsOptionalFeature', 'Get-CimInstance') {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$name" -Value { param() throw 'not mocked' }
        }
    }

    function global:Set-HardenedMachine {
        Mock Get-NetFirewallProfile { @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = $true; DefaultInboundAction = 'Block' },
                [pscustomobject]@{ Name = 'Private'; Enabled = $true; DefaultInboundAction = 'Block' },
                [pscustomobject]@{ Name = 'Public'; Enabled = $true; DefaultInboundAction = 'Block' }) }
        Mock Get-BitLockerVolume { [pscustomobject]@{ ProtectionStatus = 'On' } }
        Mock Confirm-SecureBootUEFI { $true }
        Mock Get-MpComputerStatus { [pscustomobject]@{ RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 1 } }
        Mock Get-HotFix { @([pscustomobject]@{ InstalledOn = (Get-Date).AddDays(-10) }, [pscustomobject]@{ InstalledOn = (Get-Date).AddDays(-40) }) }
        Mock Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true } }
        Mock Get-LocalUser { @([pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' }; Enabled = $true },
                [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-501' }; Enabled = $false }) }
        Mock Get-LocalGroupMember { @('a', 'b') }
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = 'Disabled' } }
        Mock Get-SecurityPolicy { @{ MinimumPasswordLength = 14; LockoutBadCount = 5 } }
        $global:KsRegistry = @{
            'fDenyTSConnections' = 0; 'UserAuthentication' = 1; 'EnableLUA' = 1; 'NoDriveTypeAutoRun' = 255
            'InactivityTimeoutSecs' = 600; 'EnableMulticast' = 0; 'EnableScriptBlockLogging' = 1
        }
        Mock Get-RegistryValue { $global:KsRegistry[$Name] }
    }
}

Describe 'Get-KeystoneFact' {
    It 'reports a hardened machine as such' {
        Set-HardenedMachine
        $f = Get-KeystoneFact
        foreach ($k in 'firewall_domain_enabled', 'firewall_private_enabled', 'firewall_public_enabled', 'firewall_public_inbound_blocked', 'bitlocker_os_volume',
            'secure_boot_enabled', 'defender_realtime_enabled', 'smb_signing_required', 'rdp_enabled', 'rdp_nla_required', 'uac_enabled', 'lockout_enabled',
            'autorun_disabled', 'screen_lock_configured', 'llmnr_disabled', 'ps_script_block_logging') {
            $f[$k] | Should -BeTrue -Because $k
        }
        foreach ($k in 'smb1_enabled', 'guest_account_enabled', 'powershell_v2_enabled') { $f[$k] | Should -BeFalse -Because $k }
        $f['defender_signature_age_days'] | Should -Be 1
        $f['last_update_installed_days'] | Should -Be 10
        $f['password_min_length'] | Should -Be 14
        $f['lockout_threshold'] | Should -Be 5
        $f['local_admin_count'] | Should -Be 2
        $f['screen_lock_timeout_seconds'] | Should -Be 600
    }

    It 'reports weak settings as off, not as unknown' {
        Set-HardenedMachine
        Mock Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; Enabled = $false; DefaultInboundAction = 'Allow' }) }
        Mock Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $true; RequireSecuritySignature = $false } }
        Mock Get-SecurityPolicy { @{ MinimumPasswordLength = 0; LockoutBadCount = 0 } }
        Mock Get-RegistryValue { $null }
        $f = Get-KeystoneFact
        $f['firewall_public_enabled'] | Should -BeFalse
        $f['firewall_public_inbound_blocked'] | Should -BeFalse
        $f['smb1_enabled'] | Should -BeTrue
        $f['lockout_enabled'] | Should -BeFalse
        $f['autorun_disabled'] | Should -BeFalse  # policy not set
        $f['llmnr_disabled'] | Should -BeFalse
        $f['screen_lock_configured'] | Should -BeFalse
        $f.Contains('rdp_enabled') | Should -BeFalse  # the registry value is missing: unknown, left out
    }

    It 'leaves out what it cannot read instead of guessing' {
        Set-HardenedMachine
        Mock Get-MpComputerStatus { throw 'Defender not installed' }
        Mock Get-BitLockerVolume { throw 'BitLocker not available on this edition' }
        Mock Get-NetFirewallProfile { throw 'access denied' }
        Mock Confirm-SecureBootUEFI { throw [System.UnauthorizedAccessException]::new('denied') }
        $f = Get-KeystoneFact
        foreach ($k in 'defender_realtime_enabled', 'defender_signature_age_days', 'bitlocker_os_volume', 'firewall_public_enabled', 'secure_boot_enabled') {
            $f.Contains($k) | Should -BeFalse -Because $k
        }
    }

    It 'reports Secure Boot as off on legacy BIOS' {
        Set-HardenedMachine
        Mock Confirm-SecureBootUEFI { throw [System.PlatformNotSupportedException]::new('Cmdlet not supported on this platform') }
        (Get-KeystoneFact)['secure_boot_enabled'] | Should -BeFalse
    }
}

Describe 'Test-ServerAddress' {
    It 'accepts HTTPS and local HTTP only' {
        Test-ServerAddress 'https://keystone.example.org' | Should -BeTrue
        Test-ServerAddress 'https://keystone.example.org:8443/' | Should -BeTrue
        Test-ServerAddress 'http://localhost:8000' | Should -BeTrue
        Test-ServerAddress 'http://keystone.example.org' | Should -BeFalse
        Test-ServerAddress 'https://keystone.example.org/x?y' | Should -BeFalse
        Test-ServerAddress 'ftp://keystone.example.org' | Should -BeFalse
    }
}

Describe 'Invoke-KeystoneRun' {
    BeforeEach {
        $script:DataDir = Join-Path $TestDrive 'data'
        Remove-Item -Path $script:DataDir -Recurse -Force -ErrorAction SilentlyContinue  # TestDrive is shared within a Describe
        $null = New-Item -ItemType Directory -Force -Path $script:DataDir
        $script:ConfigPath = Join-Path $script:DataDir 'config.json'
        $script:TokenPath = Join-Path $script:DataDir 'token.bin'
        $script:LogPath = Join-Path $script:DataDir 'last-run.log'
        Mock Protect-Token { [Text.Encoding]::UTF8.GetBytes("protected:$Token") }
        Mock Unprotect-Token { ([Text.Encoding]::UTF8.GetString($Data)) -replace '^protected:', '' }
        Mock Get-KeystoneReport { [ordered]@{ hostname = 'PC-01'; facts = @{ uac_enabled = $true } } }
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        Mock Send-KeystoneRequest {
            $script:Calls.Add([pscustomobject]@{ Path = $Path; Headers = $Headers; Body = $Body })
            if ($Path -eq 'enrol') { [pscustomobject]@{ device_id = 7; token = 'kagt_abc-DEF_123' } } else { [pscustomobject]@{ accepted = 1 } }
        }
    }

    It 'enrols once, keeps only the protected token, forgets the enrolment key and reports' {
        @{ server = 'https://keystone.example.org'; enrolment_key = 'kenr_secret' } | ConvertTo-Json | Set-Content $script:ConfigPath
        Invoke-KeystoneRun
        $script:Calls.Path | Should -Be @('enrol', 'report')
        $script:Calls[0].Body.enrolment_key | Should -Be 'kenr_secret'
        $script:Calls[0].Body.platform | Should -Be 'windows'
        $script:Calls[1].Headers.Authorization | Should -Be 'Bearer kagt_abc-DEF_123'
        (Get-Content $script:ConfigPath -Raw) | Should -Not -Match 'kenr_'
        [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($script:TokenPath)) | Should -Be 'protected:kagt_abc-DEF_123'
        (Get-Content $script:LogPath -Raw) | Should -Not -Match 'kagt_|kenr_'

        $script:Calls.Clear()
        Invoke-KeystoneRun
        $script:Calls.Path | Should -Be @('report')  # enrolled already
    }

    It 'refuses a reply without a well-formed token' {
        @{ server = 'https://keystone.example.org'; enrolment_key = 'kenr_secret' } | ConvertTo-Json | Set-Content $script:ConfigPath
        Mock Send-KeystoneRequest { [pscustomobject]@{ token = 'not-a-token' } }
        { Invoke-KeystoneRun } | Should -Throw '*no device token*'
        Test-Path $script:TokenPath | Should -BeFalse
    }

    It 'needs an enrolment key when it has no token' {
        @{ server = 'https://keystone.example.org' } | ConvertTo-Json | Set-Content $script:ConfigPath
        { Invoke-KeystoneRun } | Should -Throw '*enrolment key*'
    }
}

Describe 'Send-KeystoneRequest' {
    It 'refuses plain HTTP to a remote server before sending anything' {
        Mock Invoke-RestMethod { throw 'must not be called' }
        { Send-KeystoneRequest -Address 'http://keystone.example.org' -Path 'report' -Headers @{} -Body @{} } | Should -Throw '*https*'
        Should -Invoke Invoke-RestMethod -Times 0
    }

    It 'posts JSON to the agent API without following redirects' {
        Mock Invoke-RestMethod { [pscustomobject]@{ ok = $true } }
        $null = Send-KeystoneRequest -Address 'https://keystone.example.org/' -Path 'report' -Headers @{ Authorization = 'Bearer kagt_x' } -Body @{ facts = @{} }
        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
            $Uri -eq 'https://keystone.example.org/api/agent/v1/report' -and $Method -eq 'Post' -and $MaximumRedirection -eq 0 -and $ContentType -eq 'application/json'
        }
    }
}
