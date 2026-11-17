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
    $script:AgentVersion = '1.1.0'
    $script:MaxChecks = 100

    # Stand-ins for Windows-only commands so they can be mocked on any platform.
    foreach ($name in 'Get-NetFirewallProfile', 'Get-BitLockerVolume', 'Confirm-SecureBootUEFI', 'Get-MpComputerStatus', 'Get-HotFix',
        'Get-SmbServerConfiguration', 'Get-LocalUser', 'Get-LocalGroupMember', 'Get-WindowsOptionalFeature', 'Get-CimInstance', 'Get-Service') {
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
            'LmCompatibilityLevel' = 5; 'RunAsPPL' = 1
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
            'autorun_disabled', 'screen_lock_configured', 'llmnr_disabled', 'ps_script_block_logging', 'wdigest_disabled', 'lsa_protection') {
            $f[$k] | Should -BeTrue -Because $k
        }
        foreach ($k in 'smb1_enabled', 'guest_account_enabled', 'powershell_v2_enabled') { $f[$k] | Should -BeFalse -Because $k }
        $f['defender_signature_age_days'] | Should -Be 1
        $f['last_update_installed_days'] | Should -Be 10
        $f['password_min_length'] | Should -Be 14
        $f['lockout_threshold'] | Should -Be 5
        $f['local_admin_count'] | Should -Be 2
        $f['screen_lock_timeout_seconds'] | Should -Be 600
        $f['lm_compatibility_level'] | Should -Be 5
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
            if ($Path -eq 'enrol') { [pscustomobject]@{ device_id = 7; token = 'kagt_test' } } else { [pscustomobject]@{ accepted = 1 } }
        }
    }

    It 'enrols once, keeps only the protected token, forgets the enrolment key and reports' {
        @{ server = 'https://keystone.example.org'; enrolment_key = 'kenr_secret' } | ConvertTo-Json | Set-Content $script:ConfigPath
        Invoke-KeystoneRun
        $script:Calls.Path | Should -Be @('enrol', 'report')
        $script:Calls[0].Body.enrolment_key | Should -Be 'kenr_secret'
        $script:Calls[0].Body.platform | Should -Be 'windows'
        $script:Calls[1].Headers.Authorization | Should -Be 'Bearer kagt_test'
        (Get-Content $script:ConfigPath -Raw) | Should -Not -Match 'kenr_'
        [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($script:TokenPath)) | Should -Be 'protected:kagt_test'
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

Describe 'Custom checks' {
    BeforeAll {
        function global:New-Check([string]$Key, [string]$Probe, [string]$Type, [hashtable]$Params, $Default = $null) {
            $c = [pscustomobject]@{ key = $Key; probe = $Probe; type = $Type; params = [pscustomobject]$Params }
            if ($null -ne $Default) { $c | Add-Member -NotePropertyName default -NotePropertyValue $Default }
            $c
        }
    }

    It 'reads a registry value and applies the default when it is missing' {
        Mock Get-ItemProperty { if ($Name -eq 'Enabled') { [pscustomobject]@{ Enabled = 0 } } else { $null } }
        $r = Get-KeystoneCustomFact -Checks @(
            (New-Check 'custom.tls10' 'registry_value' 'int' @{ path = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; name = 'Enabled'; mode = 'value' }),
            (New-Check 'custom.tls11' 'registry_value' 'int' @{ path = 'SYSTEM\X'; name = 'Missing'; mode = 'value' } 1),
            (New-Check 'custom.nodefault' 'registry_value' 'int' @{ path = 'SYSTEM\X'; name = 'Missing'; mode = 'value' }),
            (New-Check 'custom.present' 'registry_value' 'bool' @{ path = 'SYSTEM\X'; name = 'Enabled'; mode = 'exists' }))
        $r.Facts['custom.tls10'] | Should -Be 0
        $r.Facts['custom.tls11'] | Should -Be 1
        $r.Errors['custom.nodefault'] | Should -Be 'missing'
        $r.Facts['custom.present'] | Should -BeTrue
    }

    It 'refuses what the agent does not allow, whatever the server sent' {
        Mock Get-ItemProperty { throw 'must not be read' }
        Mock Test-Path { throw 'must not be read' }
        $r = Get-KeystoneCustomFact -Checks @(
            (New-Check 'custom.sam' 'registry_value' 'str' @{ path = 'SAM\SAM\Domains'; name = 'F'; mode = 'value' }),
            (New-Check 'custom.security' 'registry_value' 'str' @{ path = 'security\Policy'; name = 'x'; mode = 'value' }),
            (New-Check 'custom.traversal' 'registry_value' 'str' @{ path = 'SOFTWARE\..\SAM'; name = 'x'; mode = 'value' }),
            (New-Check 'custom.badpath' 'file_exists' 'bool' @{ path = 'C:\Windows\..\Users\a\secret.txt' }),
            (New-Check 'custom.inject' 'service' 'str' @{ name = 'svc; Remove-Item C:\'; field = 'state' }),
            (New-Check 'custom.command' 'run_command' 'str' @{ command = 'whoami' }),
            (New-Check 'NOT-A-KEY' 'file_exists' 'bool' @{ path = 'C:\Windows' }))
        $r.Errors['custom.sam'] | Should -Be 'refused'
        $r.Errors['custom.security'] | Should -Be 'refused'
        $r.Errors['custom.traversal'] | Should -Be 'refused'
        $r.Errors['custom.badpath'] | Should -Be 'refused'
        $r.Errors['custom.inject'] | Should -Be 'refused'
        $r.Errors['custom.command'] | Should -Be 'unsupported'
        $r.Facts.Count | Should -Be 0
        $r.Errors.Contains('NOT-A-KEY') | Should -BeFalse  # keys outside custom.* are ignored entirely
        Should -Invoke Get-ItemProperty -Times 0
    }

    It 'reads services, policy and group counts, and reports type mismatches as errors' {
        Mock Get-Service { if ($Name -eq 'RemoteRegistry') { [pscustomobject]@{ Status = 'Stopped'; StartType = 'Disabled' } } else { $null } }
        Mock Get-SecurityPolicy { @{ PasswordComplexity = 1; NewAdministratorName = '"Administrator"' } }
        Mock Get-LocalGroupMember { @('a', 'b', 'c') }
        $r = Get-KeystoneCustomFact -Checks @(
            (New-Check 'custom.rr' 'service' 'str' @{ name = 'RemoteRegistry'; field = 'start_type' }),
            (New-Check 'custom.gone' 'service' 'str' @{ name = 'NoSuchService'; field = 'state' }),
            (New-Check 'custom.complexity' 'security_policy' 'int' @{ key = 'PasswordComplexity' }),
            (New-Check 'custom.name_as_int' 'security_policy' 'int' @{ key = 'NewAdministratorName' }),
            (New-Check 'custom.rdp_users' 'local_group_count' 'int' @{ sid = 'S-1-5-32-555' }))
        $r.Facts['custom.rr'] | Should -Be 'disabled'
        $r.Facts['custom.gone'] | Should -Be 'absent'
        $r.Facts['custom.complexity'] | Should -Be 1
        $r.Errors['custom.name_as_int'] | Should -Be 'error'
        $r.Facts['custom.rdp_users'] | Should -Be 3
    }

    It 'stops at 100 checks' {
        Mock Test-Path { $true }
        $many = 1..150 | ForEach-Object { New-Check ("custom.c$_") 'file_exists' 'bool' @{ path = 'C:\Windows' } }
        (Get-KeystoneCustomFact -Checks $many).Facts.Count | Should -Be 100
    }
}

Describe 'Custom checks in a run' {
    BeforeEach {
        $script:DataDir = Join-Path $TestDrive 'data2'
        Remove-Item -Path $script:DataDir -Recurse -Force -ErrorAction SilentlyContinue
        $null = New-Item -ItemType Directory -Force -Path $script:DataDir
        $script:ConfigPath = Join-Path $script:DataDir 'config.json'
        $script:TokenPath = Join-Path $script:DataDir 'token.bin'
        $script:LogPath = Join-Path $script:DataDir 'last-run.log'
        [IO.File]::WriteAllBytes($script:TokenPath, [Text.Encoding]::UTF8.GetBytes('kagt_x'))
        Mock Unprotect-Token { 'kagt_x' }
        Mock Get-KeystoneFact { [ordered]@{ uac_enabled = $true } }
        Mock Get-CimInstance { $null }
        Mock Get-KeystoneCheckList { @([pscustomobject]@{ key = 'custom.fe'; probe = 'file_exists'; type = 'bool'; params = [pscustomobject]@{ path = 'C:\Windows' } }) }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq 'C:\Windows' }
        $script:Sent = $null
        Mock Send-KeystoneRequest { $script:Sent = $Body; [pscustomobject]@{ accepted = 1 } }
    }

    It 'fetches and evaluates custom checks' {
        @{ server = 'https://keystone.example.org'; custom_checks = $true } | ConvertTo-Json | Set-Content $script:ConfigPath
        Invoke-KeystoneRun
        Should -Invoke Get-KeystoneCheckList -Times 1
        $script:Sent.facts['custom.fe'] | Should -BeTrue
        $script:Sent.Contains('custom_checks') | Should -BeFalse
    }

    It 'never fetches them when the computer opted out' {
        @{ server = 'https://keystone.example.org'; custom_checks = $false } | ConvertTo-Json | Set-Content $script:ConfigPath
        Invoke-KeystoneRun
        Should -Invoke Get-KeystoneCheckList -Times 0
        $script:Sent.custom_checks | Should -Be 'disabled'
        $script:Sent.facts.Contains('custom.fe') | Should -BeFalse
    }

    It 'still reports the built-in settings when the definitions cannot be fetched' {
        @{ server = 'https://keystone.example.org'; custom_checks = $true } | ConvertTo-Json | Set-Content $script:ConfigPath
        Mock Get-KeystoneCheckList { throw 'network down' }
        Invoke-KeystoneRun
        $script:Sent.facts['uac_enabled'] | Should -BeTrue
    }
}
