# Keep every remediation idempotent: inspect current state, change only noncompliant
# settings, preserve unrelated/compliant configuration, and verify applied changes.
# RestrictTo is the only parameter with a position, so "RestrictTo=Edge,OS" is bound to it.
param([switch]$Analyze, [switch]$Help, [string[]]$RestrictTo)

# Security hardening of this elevated session. It must stay the first code in the
# script, before any command that could load a module, and uses no cmdlets itself.
# 1. Load PowerShell modules only from Windows and Program Files. An elevated session
#    otherwise also searches the Documents folder of the signed-in user first, where a
#    non-elevated process can plant a module named like a command this script uses and
#    so run code as an administrator.
# 2. Start Windows tools by full path from the system directory, never through the
#    current folder or PATH, and take system folders from Windows, not from
#    environment variables, which the signed-in user can override.
$env:PSModulePath = @(
    [System.IO.Path]::Combine($PSHOME, 'Modules')
    [System.IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'WindowsPowerShell\Modules')
    [System.IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\Modules')
) -join ';'
$script:SeceditPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'secedit.exe')
$script:AuditpolPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'auditpol.exe')
$script:WevtutilPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'wevtutil.exe')

# Help and option check. They run before the organization check below, so the help also
# works on a PC that this script refuses to change.
if ($Help) {
    Write-Host @'
Remediations.cmd applies the security baseline to this stand-alone Windows 11 PC.

Usage:
  Remediations.cmd               Apply the baseline (needs an elevated prompt)
  Remediations.cmd Analyze       List every setting the baseline checks, one line each, as
                                 "original value -> value now". Settings that changed are
                                 shown in yellow (needs an elevated prompt)
  Remediations.cmd -RestrictTo Edge,OS
                                 Apply only the listed systems, separated by commas: OS
                                 (Windows itself), Edge and Chrome (their browser policies).
                                 RestrictTo=Edge,OS works too. Unknown names are ignored
                                 with a warning. Without RestrictTo everything is applied.
  Remediations.cmd ?             Show this help (-?, /?, help and -help work too;
                                 no elevation needed)

The options are not case sensitive.

Analyze reads the rollback snapshot that Remediations.cmd saved the first time it ran,
and the current state of this PC. It changes nothing. Rollback.cmd restores the original
values. See Design.md for details.
'@
    exit 0
}


# This baseline is only for stand-alone Windows 11 PCs. On a PC that an organization
# manages (Active Directory domain and its Group Policy, Microsoft Entra ID, MDM such as
# Intune, or a Configuration Manager client), the organization's policies own these
# settings. Local changes could conflict with them, be overwritten at the next policy
# refresh, or block access to work resources. This check only reads state and runs
# before anything is written, including the rollback folder. If a signal cannot be read,
# that counts as a finding, so the script stops instead of guessing.
function Get-OrganizationManagementFinding {
    $findings = [System.Collections.Generic.List[string]]::new()

    # Active Directory domain membership. Domain Group Policy needs a domain join, so
    # this also covers corporate Group Policy.
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($computerSystem.PartOfDomain) {
            $findings.Add("Joined to the Active Directory domain '$($computerSystem.Domain)' (Group Policy can apply).")
        }
    }
    catch {
        $findings.Add("Could not read domain membership from Win32_ComputerSystem: $($_.Exception.Message)")
    }

    # Microsoft Entra join (cloud or hybrid). Windows keeps one subkey per join here.
    $entraJoinInfoPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    try {
        if (Test-Path -LiteralPath $entraJoinInfoPath) {
            if (@(Get-ChildItem -LiteralPath $entraJoinInfoPath -ErrorAction Stop).Count -gt 0) {
                $findings.Add("Joined to Microsoft Entra ID (registry $entraJoinInfoPath).")
            }
        }
    }
    catch {
        $findings.Add("Could not read $entraJoinInfoPath`: $($_.Exception.Message)")
    }

    # dsregcmd also reports hybrid and on-premises (ADFS) joins and a work or school
    # account registered for the current user (Settings > Accounts > Access work or
    # school). Its field names are not translated. The registry and CIM checks above
    # cover domain and Entra joins, so if dsregcmd cannot run, a warning is enough.
    $dsregcmdPath = Join-Path ([Environment]::SystemDirectory) 'dsregcmd.exe'
    try {
        $dsregOutput = & $dsregcmdPath /status 2>&1
        if ($LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE" }
        $dsregFields = [ordered]@{
            AzureAdJoined    = 'Joined to Microsoft Entra ID (dsregcmd AzureAdJoined : YES).'
            EnterpriseJoined = 'Joined to an on-premises device registration service (dsregcmd EnterpriseJoined : YES).'
            DomainJoined     = 'Joined to an Active Directory domain (dsregcmd DomainJoined : YES).'
            WorkplaceJoined  = 'A work or school account is registered on this PC (dsregcmd WorkplaceJoined : YES). See Settings > Accounts > Access work or school.'
        }
        foreach ($field in $dsregFields.Keys) {
            if (@($dsregOutput | Where-Object { "$_" -match "^\s*$field\s*:\s*YES\s*$" }).Count -gt 0) {
                $findings.Add($dsregFields[$field])
            }
        }
    }
    catch {
        Write-Warning "Could not run dsregcmd.exe /status ($($_.Exception.Message)). Work or school account registration was not checked; domain, Entra ID and MDM checks still apply."
    }

    # MDM enrollment (Intune or another MDM server). An unmanaged PC also has many
    # entries under Enrollments, some active with built-in providers such as
    # 'Local Authority', so only entries that point to an MDM server count: a discovery
    # URL, the Intune provider ID 'MS DM Server', or an OMA-DM server account.
    $enrollmentsPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    $omaDmAccountsPath = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
    try {
        if (Test-Path -LiteralPath $enrollmentsPath) {
            foreach ($enrollmentKey in @(Get-ChildItem -LiteralPath $enrollmentsPath -ErrorAction Stop)) {
                $enrollment = Get-ItemProperty -LiteralPath $enrollmentKey.PSPath -ErrorAction Stop
                $isActive = $enrollment.EnrollmentState -eq 1
                $hasMdmServer = -not [string]::IsNullOrWhiteSpace($enrollment.DiscoveryServiceFullURL) -or
                    $enrollment.ProviderID -eq 'MS DM Server'
                if ($isActive -and $hasMdmServer) {
                    $account = if ($enrollment.UPN) { ", account $($enrollment.UPN)" } else { '' }
                    $findings.Add("Enrolled in MDM (provider '$($enrollment.ProviderID)'$account, registry $enrollmentsPath\$($enrollmentKey.PSChildName)).")
                }
            }
        }
        if (Test-Path -LiteralPath $omaDmAccountsPath) {
            $omaDmAccounts = @(Get-ChildItem -LiteralPath $omaDmAccountsPath -ErrorAction Stop)
            if ($omaDmAccounts.Count -gt 0) {
                $findings.Add("Has $($omaDmAccounts.Count) OMA-DM (MDM) server account(s) under $omaDmAccountsPath.")
            }
        }
    }
    catch {
        $findings.Add("Could not read the MDM enrollment state: $($_.Exception.Message)")
    }

    # Management agents installed as services.
    $managementServices = [ordered]@{
        CcmExec                   = 'Microsoft Configuration Manager client'
        IntuneManagementExtension = 'Microsoft Intune Management Extension'
    }
    foreach ($serviceName in $managementServices.Keys) {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            $findings.Add("The $($managementServices[$serviceName]) is installed (service $serviceName).")
        }
    }

    return , $findings.ToArray()
}

$organizationManagementFindings = Get-OrganizationManagementFinding
if ($organizationManagementFindings.Count -gt 0) {
    throw ("Remediations.ps1 is only for stand-alone Windows 11 PCs. This PC appears to be managed by an organization, so no changes were made:`n - " +
        ($organizationManagementFindings -join "`n - ") +
        "`nThe organization's policies should set these settings; ask your IT administrator. Audit.ps1 can still be run because it only reads settings. If Remediations.ps1 ran before this PC was joined or enrolled, Rollback.cmd can still undo those changes.")
}

$script:UndoStateDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SecurityBaseline'
$script:UndoStatePath = Join-Path $script:UndoStateDirectory 'Remediations.rollback.clixml'
$script:LegacyUndoStatePath = Join-Path $script:UndoStateDirectory 'Remediations.undo.clixml'

# ---- Analyze: lists the snapshot's original values next to the current ones. Read-only. ----

# Turns a value into short text for one line: no data type, control characters removed
# (so a value can never send escape sequences to the console), and cut after 60 characters.
function Format-AnalyzeValue {
    param($Value)

    if ($null -eq $Value) { return '(none)' }
    if ($Value -is [bool]) { return $(if ($Value) { 'True' } else { 'False' }) }
    if ($Value -is [byte[]]) {
        $text = (@($Value | ForEach-Object { $_.ToString('x2') }) -join '')
    } elseif ($Value -is [System.Array]) {
        $text = (@($Value | ForEach-Object { [string]$_ }) -join ', ')
        if ($text.Length -eq 0) { $text = '(empty)' }
    } else {
        $text = [string]$Value
        if ($text.Length -eq 0) { $text = '(empty)' }
    }
    $text = $text -replace '[\x00-\x1F\x7F]', ' '
    if ($text.Length -gt 60) { $text = $text.Substring(0, 57) + '...' }
    return $text
}

function Add-AnalyzeRow {
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Label,
        [string]$Original,
        [string]$Current,
        # The key Set-SettingOutcome uses for this setting, for the change report of a run.
        [string]$Key
    )

    $script:AnalyzeRows.Add([pscustomobject]@{
        Section = $Section
        Label = $Label
        Original = $Original
        Current = $Current
        Key = $Key
        Text = ('{0} {1} -> {2}' -f $Label, $Original, $Current)
        Changed = ($Original -cne $Current)
    })
}

function ConvertTo-AnalyzeAccountName {
    param([string]$Account)

    $name = $Account.Trim()
    if ($name.StartsWith('*')) {
        try {
            $name = ([System.Security.Principal.SecurityIdentifier]$name.Substring(1)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $name.Substring(1)
        }
    }
    return ($name -replace '^[^\\]*\\', '')
}

# Parses the "Key = Value" lines of one section of a secedit export into a hashtable.
function Get-AnalyzePolicySection {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Section)

    $settings = @{}
    $match = [regex]::Match($Text, '(?ims)^\[' + [regex]::Escape($Section) + '\]\s*(.*?)(?=^\[|\z)')
    if ($match.Success) {
        foreach ($line in ($match.Groups[1].Value -split '\r?\n')) {
            if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$') { $settings[$Matches[1]] = $Matches[2] }
        }
    }
    return $settings
}

# Exports the current policy to a temporary file in the administrators-only snapshot
# folder, reads it, and deletes it again.
function Export-AnalyzeCurrentPolicy {
    param([Parameter(Mandatory)][string]$Area)

    $file = Join-Path $script:UndoStateDirectory ('Analyze-{0}.inf' -f [guid]::NewGuid().ToString('N'))
    try {
        $output = (& $script:SeceditPath /export /cfg $file /areas $Area 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "secedit export failed: $output" }
        return (Get-Content -LiteralPath $file -Raw -ErrorAction Stop)
    }
    finally {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
}

# Returns Defender's extended cloud check time in seconds. On Windows 10 22H2 (seen with
# Defender platform 4.18.26100.4), Get-MpPreference reports CloudExtendedTimeout as 0 although
# Defender has stored 50 (MpBafsExtendedTimeout under HKLM\SOFTWARE\Microsoft\Windows
# Defender\MpEngine); Windows 11 with the same platform reports 50. So when the cmdlet reports
# less than 50, the stored value decides: the policy value if there is one (it overrides the
# local value), otherwise the local value. Read-only. Keep identical in Audit.ps1.
function Get-DefenderCloudExtendedTimeout {
    $reported = (Get-MpPreference -ErrorAction Stop).CloudExtendedTimeout
    if ($null -ne $reported -and [int]$reported -ge 50) { return [int]$reported }
    foreach ($keyPath in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine', 'HKLM:\SOFTWARE\Microsoft\Windows Defender\MpEngine') {
        $stored = (Get-ItemProperty -LiteralPath $keyPath -Name 'MpBafsExtendedTimeout' -ErrorAction SilentlyContinue).MpBafsExtendedTimeout
        if ($null -ne $stored) { return [int]$stored }
    }
    return $reported
}

# Reads the current value of every setting recorded in a snapshot and returns one row per
# setting: Section, Label, Original (as recorded), Current (read now) and Key (the key that
# Set-SettingOutcome uses). Read-only. Used by Analyze and by the change report of a run.
function Get-SnapshotRows {
    param([Parameter(Mandatory)]$State)

    $state = $State
    $script:AnalyzeRows = [System.Collections.Generic.List[object]]::new()
    $unknown = 'unknown'

    # Registry values. The value name is joined to the key path, and the data type and
    # whether the value existed are left out: an absent value shows as (none).
    foreach ($entry in @($state['RegistryValues'].Values | Sort-Object { $_.Path }, { $_.Name })) {
        $current = $unknown
        try {
            if (Test-Path -LiteralPath $entry.Path) {
                $key = Get-Item -LiteralPath $entry.Path -ErrorAction Stop
                $current = Format-AnalyzeValue $key.GetValue([string]$entry.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            } else {
                $current = '(none)'
            }
        } catch { }
        $original = if ($entry.Exists) { Format-AnalyzeValue $entry.Data } else { '(none)' }
        Add-AnalyzeRow -Section 'Registry' -Label ('{0}\{1}' -f $entry.Path, $entry.Name) -Original $original -Current $current -Key ('Registry|{0}|{1}' -f $entry.Path, $entry.Name)
    }

    # Services, by display name: start mode, and the running state when that changed too.
    if (@($state['Services'].Keys).Count -gt 0) {
        $services = @{}
        try { foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) { $services[$service.Name] = $service } } catch { }
        $modeNames = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled'; Boot = 'Boot'; System = 'System' }
        foreach ($serviceName in @($state['Services'].Keys | Sort-Object)) {
            $saved = $state['Services'][$serviceName]
            $service = $services[$serviceName]
            $display = if ($service -and $service.DisplayName) { $service.DisplayName } else { $serviceName }
            $originalMode = if ($modeNames.ContainsKey([string]$saved.StartMode)) { $modeNames[[string]$saved.StartMode] } else { [string]$saved.StartMode }
            $originalText = Format-AnalyzeValue $originalMode
            if ($null -eq $service) {
                $currentText = if ($services.Count -gt 0) { 'removed' } else { $unknown }
            } else {
                $currentMode = if ($modeNames.ContainsKey([string]$service.StartMode)) { $modeNames[[string]$service.StartMode] } else { [string]$service.StartMode }
                $currentText = Format-AnalyzeValue $currentMode
                if ($saved.State -and ([string]$saved.State -ne [string]$service.State)) {
                    $originalText = '{0} ({1})' -f $originalText, $saved.State
                    $currentText = '{0} ({1})' -f $currentText, $service.State
                }
            }
            Add-AnalyzeRow -Section 'Services' -Label (Format-AnalyzeValue $display) -Original $originalText -Current $currentText -Key "Service|$serviceName"
        }
    }

    # Local security policy (password, lockout and account policy) and user rights.
    if ($state['SecurityPolicyFile'] -and (Test-Path -LiteralPath $state['SecurityPolicyFile'] -PathType Leaf)) {
        $savedPolicy = Get-AnalyzePolicySection -Text (Get-Content -LiteralPath $state['SecurityPolicyFile'] -Raw -ErrorAction Stop) -Section 'System Access'
        $currentPolicy = $null
        try { $currentPolicy = Get-AnalyzePolicySection -Text (Export-AnalyzeCurrentPolicy -Area 'SECURITYPOLICY') -Section 'System Access' } catch { }
        foreach ($name in @('PasswordHistorySize', 'MaximumPasswordAge', 'MinimumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'ClearTextPassword',
                'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount', 'AllowAdministratorLockout', 'LSAAnonymousNameLookup', 'ForceLogoffWhenHourExpire')) {
            $original = if ($savedPolicy.ContainsKey($name)) { Format-AnalyzeValue $savedPolicy[$name] } else { '(none)' }
            $current = if ($null -eq $currentPolicy) { $unknown } elseif ($currentPolicy.ContainsKey($name)) { Format-AnalyzeValue $currentPolicy[$name] } else { '(none)' }
            Add-AnalyzeRow -Section 'Local security policy' -Label $name -Original $original -Current $current -Key 'Local security policy'
        }
    }
    if ($state['UserRightsPolicyFile'] -and (Test-Path -LiteralPath $state['UserRightsPolicyFile'] -PathType Leaf)) {
        $rightNames = @{
            SeTrustedCredManAccessPrivilege = 'Access Credential Manager as a trusted caller'
            SeNetworkLogonRight = 'Access this computer from the network'
            SeTcbPrivilege = 'Act as part of the operating system'
            SeIncreaseQuotaPrivilege = 'Adjust memory quotas for a process'
            SeInteractiveLogonRight = 'Allow log on locally'
            SeRemoteInteractiveLogonRight = 'Allow log on through Remote Desktop Services'
            SeBackupPrivilege = 'Back up files and directories'
            SeSystemtimePrivilege = 'Change the system time'
            SeCreatePagefilePrivilege = 'Create a pagefile'
            SeCreateTokenPrivilege = 'Create a token object'
            SeCreateGlobalPrivilege = 'Create global objects'
            SeCreatePermanentPrivilege = 'Create permanent shared objects'
            SeCreateSymbolicLinkPrivilege = 'Create symbolic links'
            SeDebugPrivilege = 'Debug programs'
            SeDenyNetworkLogonRight = 'Deny access to this computer from the network'
            SeDenyBatchLogonRight = 'Deny log on as a batch job'
            SeDenyServiceLogonRight = 'Deny log on as a service'
            SeDenyInteractiveLogonRight = 'Deny log on locally'
            SeDenyRemoteInteractiveLogonRight = 'Deny log on through Remote Desktop Services'
            SeEnableDelegationPrivilege = 'Enable accounts to be trusted for delegation'
            SeRemoteShutdownPrivilege = 'Force shutdown from a remote system'
            SeImpersonatePrivilege = 'Impersonate a client after authentication'
            SeIncreaseBasePriorityPrivilege = 'Increase scheduling priority'
            SeLoadDriverPrivilege = 'Load and unload device drivers'
            SeLockMemoryPrivilege = 'Lock pages in memory'
            SeRelabelPrivilege = 'Modify an object label'
            SeSystemEnvironmentPrivilege = 'Modify firmware environment values'
            SeManageVolumePrivilege = 'Perform volume maintenance tasks'
            SeProfileSingleProcessPrivilege = 'Profile single process'
            SeSystemProfilePrivilege = 'Profile system performance'
            SeAssignPrimaryTokenPrivilege = 'Replace a process level token'
            SeRestorePrivilege = 'Restore files and directories'
            SeShutdownPrivilege = 'Shut down the system'
            SeTakeOwnershipPrivilege = 'Take ownership of files or other objects'
        }
        $savedRights = Get-AnalyzePolicySection -Text (Get-Content -LiteralPath $state['UserRightsPolicyFile'] -Raw -ErrorAction Stop) -Section 'Privilege Rights'
        $currentRights = $null
        try { $currentRights = Get-AnalyzePolicySection -Text (Export-AnalyzeCurrentPolicy -Area 'USER_RIGHTS') -Section 'Privilege Rights' } catch { }
        $managed = @($state['UserRightsManagedRights'] | Where-Object { $_ })
        if ($managed.Count -eq 0) { $managed = @($savedRights.Keys) }
        $toNames = {
            param($Accounts)
            $names = @(([string]$Accounts -split ',') | Where-Object { $_.Trim() } | ForEach-Object { ConvertTo-AnalyzeAccountName $_ } | Sort-Object)
            if ($names.Count -eq 0) { '(nobody)' } else { Format-AnalyzeValue $names }
        }
        foreach ($right in @($managed | Sort-Object)) {
            $original = & $toNames $savedRights[$right]
            $current = if ($null -eq $currentRights) { $unknown } else { & $toNames $currentRights[$right] }
            $label = if ($rightNames.ContainsKey($right)) { $rightNames[$right] } else { $right }
            Add-AnalyzeRow -Section 'User rights' -Label $label -Original $original -Current $current -Key 'User rights'
        }
    }

    # Optional features, Guest account, SMB signing.
    foreach ($featureName in @($state['OptionalFeatures'].Keys | Sort-Object)) {
        $current = $unknown
        try { $current = Format-AnalyzeValue (Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop).State } catch { }
        Add-AnalyzeRow -Section 'Windows features' -Label (Format-AnalyzeValue $featureName) -Original (Format-AnalyzeValue $state['OptionalFeatures'][$featureName]) -Current $current -Key "Optional feature|$featureName"
    }
    if ($state['GuestAccount']) {
        $current = $unknown
        try { $current = if ((Get-LocalUser -SID ([System.Security.Principal.SecurityIdentifier]$state['GuestAccount'].SID) -ErrorAction Stop).Enabled) { 'Enabled' } else { 'Disabled' } } catch { }
        Add-AnalyzeRow -Section 'Accounts' -Label 'Guest account' -Original $(if ($state['GuestAccount'].Enabled) { 'Enabled' } else { 'Disabled' }) -Current $current -Key 'Guest account'
    }
    foreach ($smb in @(@('SmbServerRequireSecuritySignature', 'SMB server requires signing', 'Get-SmbServerConfiguration', 'SMB server signing'), @('SmbClientRequireSecuritySignature', 'SMB client requires signing', 'Get-SmbClientConfiguration', 'SMB client signing'))) {
        if ($null -ne $state[$smb[0]]) {
            $current = $unknown
            try { $current = Format-AnalyzeValue ([bool](& $smb[2] -ErrorAction Stop).RequireSecuritySignature) } catch { }
            Add-AnalyzeRow -Section 'Network' -Label $smb[1] -Original (Format-AnalyzeValue ([bool]$state[$smb[0]])) -Current $current -Key $smb[3]
        }
    }

    # Firewall profiles, audit policy and event logs.
    foreach ($profileName in @($state['FirewallProfiles'].Keys | Sort-Object)) {
        $saved = $state['FirewallProfiles'][$profileName]
        $now = $null
        try { $now = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop } catch { }
        foreach ($property in @(@('Enabled', 'enabled'), @('DefaultInboundAction', 'default inbound'), @('DefaultOutboundAction', 'default outbound'), @('NotifyOnListen', 'notifications'))) {
            if ($saved.PSObject.Properties[$property[0]]) {
                $current = if ($now) { Format-AnalyzeValue $now.($property[0]) } else { $unknown }
                Add-AnalyzeRow -Section 'Firewall' -Label ('Firewall {0} {1}' -f (Format-AnalyzeValue $profileName), $property[1]) -Original (Format-AnalyzeValue $saved.($property[0])) -Current $current -Key $(if ($property[0] -eq 'NotifyOnListen') { "Firewall notifications|$profileName" } else { "Firewall profile|$profileName" })
            }
        }
    }
    $auditText = { param($Success, $Failure) if ($Success -and $Failure) { 'Success and Failure' } elseif ($Success) { 'Success' } elseif ($Failure) { 'Failure' } else { 'No Auditing' } }
    foreach ($subcategory in @($state['AuditPolicy'].Keys | Sort-Object)) {
        $current = $unknown
        try {
            $output = (& $script:AuditpolPath /get /subcategory:"$subcategory" 2>&1 | Out-String)
            $match = [regex]::Match($output, "(?im)^\s*$([regex]::Escape($subcategory))\s+(No Auditing|Success(?: and Failure)?|Failure)\s*$")
            if ($LASTEXITCODE -eq 0 -and $match.Success) { $current = $match.Groups[1].Value }
        } catch { }
        $saved = $state['AuditPolicy'][$subcategory]
        Add-AnalyzeRow -Section 'Audit policy' -Label ('Audit ' + (Format-AnalyzeValue $subcategory)) -Original (& $auditText $saved.Success $saved.Failure) -Current $current -Key "Audit policy|$subcategory"
    }
    $logSizes = @{}
    foreach ($logName in @($state['EventLogMaximumSizes'].Keys)) { $logSizes[$logName] = $state['EventLogMaximumSizes'][$logName] }
    if ($null -ne $state['SecurityLogMaximumSize'] -and -not $logSizes.ContainsKey('Security')) { $logSizes['Security'] = $state['SecurityLogMaximumSize'] }
    foreach ($logName in @($logSizes.Keys | Sort-Object)) {
        $current = $unknown
        try {
            $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList ([string]$logName)
            try { $current = '{0} MB' -f [Math]::Round($config.MaximumSizeInBytes / 1MB, 1) } finally { $config.Dispose() }
        } catch { }
        Add-AnalyzeRow -Section 'Event logs' -Label ('{0} event log size' -f (Format-AnalyzeValue $logName)) -Original ('{0} MB' -f [Math]::Round([double]$logSizes[$logName] / 1MB, 1)) -Current $current -Key "Event log size|$logName"
    }

    # Microsoft Defender settings and exploit mitigations.
    $defender = $null
    try { $defender = Get-MpPreference -ErrorAction Stop } catch { }
    $modeName = { param($Value) switch ([string]$Value) { '0' { 'Disabled' } '1' { 'Enabled' } '2' { 'Audit' } '3' { 'Block disk modification only' } '4' { 'Audit disk modification only' } default { [string]$Value } } }
    $levelName = { param($Value) switch ([string]$Value) { '0' { 'Default' } '1' { 'Moderate' } '2' { 'High' } '4' { 'High plus' } '6' { 'Zero tolerance' } default { [string]$Value } } }
    $defenderSettings = @(
        @{ Key = 'DefenderControlledFolderAccess'; Property = 'EnableControlledFolderAccess'; Label = 'Defender Controlled Folder Access'; Name = $modeName }
        @{ Key = 'DefenderNetworkProtection'; Property = 'EnableNetworkProtection'; Label = 'Defender Network Protection'; Name = $modeName }
        @{ Key = 'DefenderPuaProtection'; Property = 'PUAProtection'; Label = 'Defender PUA Protection'; Name = $modeName }
        @{ Key = 'DefenderCloudBlockLevel'; Property = 'CloudBlockLevel'; Label = 'Defender cloud block level'; Name = $levelName }
        @{ Key = 'DefenderCloudExtendedTimeout'; Property = 'CloudExtendedTimeout'; Label = 'Defender extended cloud check (seconds)'; Name = { param($Value) [string]$Value } }
        @{ Key = 'DefenderRemovableDriveScanningDisabled'; Property = 'DisableRemovableDriveScanning'; Label = 'Defender removable drive scanning disabled'; Name = { param($Value) [string][bool]$Value } }
    )
    foreach ($setting in $defenderSettings) {
        if ($null -ne $state[$setting.Key]) {
            $currentValue = if ($defender) { $defender.($setting.Property) } else { $null }
            if ($setting.Key -eq 'DefenderCloudExtendedTimeout') {
                try { $currentValue = Get-DefenderCloudExtendedTimeout } catch { $currentValue = $null }
            }
            $current = if ($null -ne $currentValue) { Format-AnalyzeValue (& $setting.Name $currentValue) } else { $unknown }
            Add-AnalyzeRow -Section 'Defender' -Label $setting.Label -Original (Format-AnalyzeValue (& $setting.Name $state[$setting.Key])) -Current $current -Key "Defender|$($setting.Key)"
        }
    }
    if ($null -ne $state['DefenderAsrRuleIds']) {
        $actionName = { param($Value) switch ([string]$Value) { '0' { 'Disabled' } '1' { 'Block' } '2' { 'Audit' } '6' { 'Warn' } default { [string]$Value } } }
        $savedIds = @($state['DefenderAsrRuleIds'] | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
        $savedActions = @($state['DefenderAsrRuleActions'])
        $savedMap = @{}
        for ($i = 0; $i -lt $savedIds.Count; $i++) { if ($i -lt $savedActions.Count) { $savedMap[([string]$savedIds[$i]).ToLowerInvariant()] = $savedActions[$i] } }
        $currentMap = $null
        if ($defender) {
            $currentMap = @{}
            $currentIds = @($defender.AttackSurfaceReductionRules_Ids | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
            $currentActions = @($defender.AttackSurfaceReductionRules_Actions)
            for ($i = 0; $i -lt $currentIds.Count; $i++) { if ($i -lt $currentActions.Count) { $currentMap[([string]$currentIds[$i]).ToLowerInvariant()] = $currentActions[$i] } }
        }
        $ruleIds = @(@($savedMap.Keys) + $(if ($currentMap) { @($currentMap.Keys) } else { @() }) | Sort-Object -Unique)
        foreach ($ruleId in $ruleIds) {
            $original = if ($savedMap.ContainsKey($ruleId)) { Format-AnalyzeValue (& $actionName $savedMap[$ruleId]) } else { '(none)' }
            $current = if ($null -eq $currentMap) { $unknown } elseif ($currentMap.ContainsKey($ruleId)) { Format-AnalyzeValue (& $actionName $currentMap[$ruleId]) } else { '(none)' }
            Add-AnalyzeRow -Section 'Defender' -Label ('Defender ASR rule ' + (Format-AnalyzeValue $ruleId)) -Original $original -Current $current -Key 'Defender|ASR rules'
        }
    }
    if (@($state['ExploitMitigations'].Keys).Count -gt 0) {
        $mitigationMap = @{ DEP = @('Dep', 'Enable', 'DEP'); CFG = @('Cfg', 'Enable', 'CFG'); BottomUp = @('Aslr', 'BottomUp', 'Bottom-Up ASLR'); SEHOP = @('Sehop', 'Enable', 'SEHOP') }
        $system = $null
        try { $system = Get-ProcessMitigation -System -ErrorAction Stop } catch { }
        foreach ($mitigationName in @($state['ExploitMitigations'].Keys | Sort-Object)) {
            $current = $unknown
            $map = $mitigationMap[$mitigationName]
            if ($system -and $map -and $system.PSObject.Properties[$map[0]]) {
                $property = $system.($map[0]).PSObject.Properties[$map[1]]
                if ($property) { $current = Format-AnalyzeValue $property.Value }
            }
            $label = if ($map) { $map[2] } else { [string]$mitigationName }
            Add-AnalyzeRow -Section 'Exploit mitigations' -Label ('Exploit mitigation ' + (Format-AnalyzeValue $label)) -Original (Format-AnalyzeValue $state['ExploitMitigations'][$mitigationName]) -Current $current -Key "Exploit mitigation|$label"
        }
    }
    $script:AnalyzeRows.ToArray()
}

# The security reason for a changed setting, for the change report. It is taken from
# AuditCheckDetails.json next to this script: the CIS rationale when the setting belongs to a
# CIS recommendation (found by the CIS number in the recorded description, or by the setting's
# name in the recommendation title), otherwise the rationale of the matching audit check.
function Get-ChangeReason {
    param([string]$Key, $Row, $Details, $State)

    if ($null -eq $Details) { return 'See SecurityBaselineSettings.html (AuditCheckDetails.json was not found next to Remediations.ps1).' }
    $cisById = @{}
    foreach ($recommendation in @($Details.cisRecommendations)) { $cisById[[string]$recommendation.id] = $recommendation }
    $fromCis = {
        param($Recommendation)
        if ($Recommendation -and $Recommendation.rationale) { "CIS $($Recommendation.id): $($Recommendation.rationale)" }
    }
    $byTitle = {
        param([string]$Pattern)
        $Details.cisRecommendations | Where-Object { $_.title -match $Pattern } | Select-Object -First 1
    }
    $fromCheck = {
        param([string]$Name)
        $check = $Details.checks | Where-Object { $_.name -eq $Name } | Select-Object -First 1
        if ($check -and $check.rationale) { $check.rationale }
        elseif ($check -and $check.cisIds) { & $fromCis $cisById[[string]@($check.cisIds)[0]] }
    }
    $kind, $rest = $Key -split '\|', 2
    $reason = $null
    $description = $null
    switch ($kind) {
        'Registry' {
            $entry = $State['RegistryValues'][$rest]
            $description = if ($entry -and $entry.PSObject.Properties['Description']) { [string]$entry.Description } else { $null }
            if ($description -match 'CIS (\d+(?:\.\d+)+)') { $reason = & $fromCis $cisById[$Matches[1]] }
            if (-not $reason) {
                # Settings that are not CIS recommendations, by their registry value.
                $checkName = switch -Regex ($rest) {
                    '\|EnableMulticast$'                         { 'LLMNR Name Resolution' }
                    'Microsoft\\Edge\|SmartScreenEnabled$'       { 'Microsoft Defender SmartScreen (Edge)' }
                    'Microsoft\\Edge\|SmartScreenPuaEnabled$'    { 'Edge SmartScreen Potentially Unwanted App Blocking' }
                    'Microsoft\\Edge\|InternetExplorerIntegration' { 'Edge Internet Explorer Mode' }
                    '\|DisableInternetExplorerLaunchViaCOM$'     { 'Internet Explorer Launch via COM Automation' }
                    '\|DisableWidgetsOnLockScreen$'              { 'Lock Screen Widgets Disabled' }
                    'SecurityProviders\\SCHANNEL'                { 'TLS/SSL Protocol Versions (Schannel)' }
                    'Teredo|Tcpip6\\Parameters\|DisabledComponents$' { 'Teredo Tunneling' }
                    'NetBT\\Parameters'                          { 'NetBIOS over TCP/IP' }
                    'DoHPolicy|DnsClient\|EnableAutoDoh'         { 'DNS over HTTPS (DoH)' }
                    'AppHost\|EnableWebContentEvaluation$'       { 'SmartScreen for Microsoft Store Apps' }
                    '\|CachedLogonsCount$'                       { 'Cached Logon Credentials' }
                    default                                      { $null }
                }
                if ($checkName) { $reason = & $fromCheck $checkName }
            }
            if (-not $reason) {
                # Browser settings whose audit checks have no rationale in AuditCheckDetails.json;
                # the text is the reason given in SecurityBaselineSettings.html.
                $reason = switch -Regex ($rest) {
                    '\\ExtensionInstall(Allow|Block)list\|'  { 'Allow-listing extensions reduces exposure to malicious or over-privileged add-ons that can read or alter browsing data. Extensions outside the list are disabled, not removed.' }
                    '\|PasswordExportEnabled$'               { 'Disabling password export reduces the chance that saved credentials are copied into an unprotected file.' }
                    '\|BrowsingDataLifetime$'                { 'Automatically deletes old browsing history, download history and cached files, limiting how much browsing activity is kept on the PC.' }
                    default                                  { $null }
                }
            }
        }
        'Registry list'          { $reason = $null; $description = "The list of values in $rest" }
        'Service'                { $reason = & $fromCis (& $byTitle "\($([regex]::Escape($rest))\)") }
        'Audit policy'           { $reason = & $fromCis (& $byTitle "'Audit $([regex]::Escape($rest))'") }
        'Event log size'         { $reason = & $fromCis (& $byTitle "'$([regex]::Escape($rest)): Specify the maximum log file size") }
        'Guest account'          { $reason = & $fromCis (& $byTitle "'Accounts: Guest account status'") }
        'SMB server signing'     { $reason = & $fromCis (& $byTitle "'Microsoft network server: Digitally sign communications \(always\)'") }
        'SMB client signing'     { $reason = & $fromCis (& $byTitle "'Microsoft network client: Digitally sign communications \(always\)'") }
        'Firewall notifications' { $reason = & $fromCis (& $byTitle "'Windows Firewall: $([regex]::Escape($rest)): Settings: Display a notification'") }
        'Firewall profile' {
            $part = if ($Row.Label -match 'inbound') { 'Inbound connections' } elseif ($Row.Label -match 'outbound') { 'Outbound connections' } else { 'Firewall state' }
            $reason = & $fromCis (& $byTitle "'Windows Firewall: $([regex]::Escape($rest)): $part'")
        }
        'Local security policy' {
            $policyTitles = @{
                PasswordHistorySize = 'Enforce password history'; MaximumPasswordAge = 'Maximum password age'; MinimumPasswordAge = 'Minimum password age'
                MinimumPasswordLength = 'Minimum password length'; PasswordComplexity = 'Password must meet complexity requirements'
                ClearTextPassword = 'Store passwords using reversible encryption'; LockoutBadCount = 'Account lockout threshold'
                LockoutDuration = 'Account lockout duration'; ResetLockoutCount = 'Reset account lockout counter after'
                AllowAdministratorLockout = 'Allow Administrator account lockout'; LSAAnonymousNameLookup = 'Network access: Allow anonymous SID/Name translation'
                ForceLogoffWhenHourExpire = 'Network security: Force logoff when logon hours expire'
            }
            if ($policyTitles.ContainsKey([string]$Row.Label)) { $reason = & $fromCis (& $byTitle "'$([regex]::Escape($policyTitles[[string]$Row.Label]))'") }
        }
        'User rights'            { $reason = & $fromCis (& $byTitle "'$([regex]::Escape([string]$Row.Label))'") }
        'Optional feature'       { if ($rest -match 'PowerShellV2') { $reason = & $fromCheck 'Windows PowerShell 2.0' } }
        'Exploit mitigation'     { $reason = & $fromCheck 'Windows Exploit Protection' }
        'Defender' {
            $checkName = switch ($rest) {
                'DefenderControlledFolderAccess'         { 'Controlled Folder Access (Ransomware)' }
                'DefenderNetworkProtection'              { 'Defender Network Protection' }
                'DefenderPuaProtection'                  { 'Potentially Unwanted App (PUA) Protection' }
                'DefenderCloudBlockLevel'                { 'Defender Cloud Protection Level' }
                'DefenderCloudExtendedTimeout'           { 'Defender Extended Cloud Check' }
                'DefenderRemovableDriveScanningDisabled' { 'Defender Removable Drive Scanning' }
                'ASR rules'                              { 'Defender Attack Surface Reduction (ASR) Rules' }
                default                                  { $null }
            }
            if ($checkName) { $reason = & $fromCheck $checkName }
        }
    }
    if ($reason) { return (($reason -replace '\s+', ' ').Trim()) }
    if ($description) { return "$description. See SecurityBaselineSettings.html for why it is part of the baseline." }
    return 'See SecurityBaselineSettings.html for why this setting is part of the baseline.'
}

# Writes the change report of this run: one table row per setting that the run changed, with
# the value before the run, the value after it and the security reason. The old value is the
# one read when the run started; a setting recorded for the first time in this run has its
# old value in the snapshot. The file goes to the administrators-only snapshot folder.
# Returns its path, or $null when nothing was changed.
function Write-RemediationReport {
    $corrected = @($script:RunCorrectedKeys)
    if ($corrected.Count -eq 0) { return $null }
    $after = @(Get-SnapshotRows -State $script:UndoState)
    $before = @{}
    foreach ($row in @($script:RowsAtRunStart)) { $before["$($row.Key)|$($row.Label)"] = $row }
    $details = $null
    $detailsPath = Join-Path $(if ($PSScriptRoot) { $PSScriptRoot } else { $script:ScriptDirectory }) 'AuditCheckDetails.json'
    if (Test-Path -LiteralPath $detailsPath -PathType Leaf) {
        try { $details = [System.IO.File]::ReadAllText($detailsPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json } catch { $details = $null }
    }
    $cell = { param([string]$Text) (($Text -replace '[\r\n]+', ' ') -replace '\|', '\|').Trim() }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# Security baseline changes on $([Environment]::MachineName)")
    $lines.Add('')
    $lines.Add("Remediations.ps1 run of $((Get-Date).ToString('yyyy-MM-dd HH:mm')).$(if ($null -ne $script:SelectedSystems) { " Restricted to: $($script:SelectedSystems -join ', ')." })")
    $lines.Add('Each row is one setting that this run changed: its value before the run, its value after the run, and why the baseline wants it. Rollback.cmd restores the values the PC had before the first run (Remediations.cmd Analyze lists them).')
    $lines.Add('')
    $lines.Add('| Setting | Old value | New value | Why (security) |')
    $lines.Add('|---|---|---|---|')
    $listed = 0
    foreach ($key in $corrected) {
        $rows = if ($key.StartsWith('Registry list|')) {
            $prefix = 'Registry|' + $key.Substring('Registry list|'.Length) + '|'
            @($after | Where-Object { $_.Key -and $_.Key.StartsWith($prefix) })
        } else {
            @($after | Where-Object { $_.Key -eq $key })
        }
        $keyListed = 0
        foreach ($row in $rows) {
            $previous = $before["$($row.Key)|$($row.Label)"]
            $old = if ($previous) { $previous.Current } else { $row.Original }
            if ($old -ceq $row.Current) { continue }
            $reason = Get-ChangeReason -Key $(if ($key.StartsWith('Registry list|')) { $row.Key } else { $key }) -Row $row -Details $details -State $script:UndoState
            $lines.Add(('| {0} | {1} | {2} | {3} |' -f (& $cell $row.Label), (& $cell $old), (& $cell $row.Current), (& $cell $reason)))
            $keyListed++
        }
        if ($keyListed -eq 0) {
            # Changed, but no value differs that this report can read (for example a key that was created).
            $kind, $rest = $key -split '\|', 2
            $settingName = if ($kind -in @('Registry', 'Registry list')) { $rest -replace '\|', '\' } elseif ($rest) { "$kind $rest" } else { $kind }
            $lines.Add(('| {0} | not recorded | changed | {1} |' -f (& $cell $settingName), (& $cell (Get-ChangeReason -Key $key -Row $null -Details $details -State $script:UndoState))))
            $keyListed++
        }
        $listed += $keyListed
    }
    $lines.Add('')
    $lines.Add("$listed changed settings.")
    $reportPath = Join-Path $script:UndoStateDirectory ('Remediations-report-{0}.md' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [System.IO.File]::WriteAllText($reportPath, (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    return $reportPath
}

function Show-RollbackAnalysis {
    $snapshotPath = $script:UndoStatePath
    if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) { $snapshotPath = $script:LegacyUndoStatePath }
    if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) {
        Write-Host "There is no snapshot to analyze: $script:UndoStatePath does not exist. Remediations.cmd has not run yet, or Rollback.cmd already restored the original values."
        return 1
    }
    $state = Import-Clixml -LiteralPath $snapshotPath -ErrorAction Stop
    if ($state['Version'] -notin @(1, 2)) { throw "Unsupported snapshot version: $($state['Version'])." }
    $null = Get-SnapshotRows -State $state

    # Print every setting; the ones that differ from the original are highlighted in yellow.
    $created = try { ([datetime]$state['Created']).ToString('yyyy-MM-dd HH:mm') } catch { 'unknown' }
    $computer = if ($state['ComputerName']) { Format-AnalyzeValue $state['ComputerName'] } else { 'unknown' }
    Write-Host "Snapshot created $created on $computer. Format: setting original -> now"
    $changed = 0
    foreach ($section in @($script:AnalyzeRows | ForEach-Object { $_.Section } | Select-Object -Unique)) {
        Write-Host ''
        Write-Host $section -ForegroundColor Cyan
        foreach ($row in @($script:AnalyzeRows | Where-Object { $_.Section -eq $section })) {
            if ($row.Changed) {
                Write-Host $row.Text -ForegroundColor Yellow
                $changed++
            } else {
                Write-Host $row.Text
            }
        }
    }
    Write-Host ''
    Write-Host "$($script:AnalyzeRows.Count) settings listed; $changed differ from their original value (yellow)."
    return 0
}

if ($Analyze) {
    # The snapshot folder is only readable by administrators.
    $analyzeIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object System.Security.Principal.WindowsPrincipal($analyzeIdentity)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Error. Analyze must run elevated, because the snapshot folder is only readable by administrators.'
        exit 1
    }
    if ($PSBoundParameters.ContainsKey('RestrictTo')) { Write-Warning 'RestrictTo does not apply to Analyze, which always lists the whole snapshot.' }
    exit (Show-RollbackAnalysis)
}

# RestrictTo: the systems to remediate. $script:SelectedSystems is $null when everything is
# remediated. Names are matched without regard to case; unknown names are ignored with a
# warning, and the run stops (before it changes anything) only if no supported name is left.
$script:SupportedSystems = @('OS', 'Edge', 'Chrome')
$script:SelectedSystems = $null
if ($PSBoundParameters.ContainsKey('RestrictTo')) {
    $selectedSystems = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(@($RestrictTo) -replace '^\s*[-/]?RestrictTo\s*[=:]', '' -split '[,;\s]+' | Where-Object { $_ })) {
        $system = $script:SupportedSystems | Where-Object { $_ -eq $item } | Select-Object -First 1
        if ($system) {
            if (-not $selectedSystems.Contains($system)) { $selectedSystems.Add($system) }
        } else {
            Write-Warning "RestrictTo: '$item' is not a supported system and is ignored. Supported: $($script:SupportedSystems -join ', ')."
        }
    }
    if ($selectedSystems.Count -eq 0) {
        Write-Host "Error: RestrictTo names no supported system ($($script:SupportedSystems -join ', ')), so nothing was changed." -ForegroundColor Red
        exit 1
    }
    $script:SelectedSystems = $selectedSystems.ToArray()
    Write-Host "Restricted to: $($script:SelectedSystems -join ', '). The other systems are not changed." -ForegroundColor Yellow
}
function Test-SystemSelected {
    param([Parameter(Mandatory)][string]$System)
    $null -eq $script:SelectedSystems -or $script:SelectedSystems -contains $System
}
# rollback.ps1 is kept next to the rollback snapshot, not next to this script, so the
# script folder can be read-only (for example a synced or write-protected folder).
$script:RollbackScriptPath = Join-Path $script:UndoStateDirectory 'rollback.ps1'

# The rollback state is applied later with administrator rights, so only SYSTEM and
# Administrators may write to its folder. ProgramData lets ordinary users create files
# in new subfolders; without this, a standard user could plant or edit a file (for
# example rollback.ps1 or a saved security policy) that an administrator later runs.
# The folder gets its own access list without inheritance, and a file owned by anyone
# other than SYSTEM or Administrators stops the script. This protects the tool's own
# state and is not a baseline setting, so rollback does not undo it.
# A folder that already exists is used only if it is a real folder (not a junction or
# symbolic link, which would redirect the access list and the files to another place)
# that SYSTEM or Administrators own. Any user can create a folder or link with this
# name in ProgramData before the first run, and its creator could keep access to it.
function Protect-AdministratorsOnlyDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $trustedOwners = @($systemSid.Value, $administratorsSid.Value)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inheritance, 'None', 'Allow'))
    }

    $existing = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        # Created together with its access list, so the permissions inherited from
        # ProgramData (users may create files) never apply to it, not even briefly.
        [void][System.IO.Directory]::CreateDirectory($Path, $acl)
    } else {
        if (-not $existing.PSIsContainer -or ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "'$Path' is not a normal folder (it is a file, a junction or a symbolic link), so it was not created by this script and could redirect its files to another place. No changes were made. Check it, delete it, and run Remediations.ps1 again."
        }
        $existingOwner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($existingOwner -notin $trustedOwners) {
            throw "'$Path' is owned by $existingOwner, not by SYSTEM or Administrators, so another account created it and may still have access to it. No changes were made. Check its contents, delete the folder, and run Remediations.ps1 again."
        }
        # SetAccessControl writes only the changed parts (owner and permissions). Set-Acl can
        # also try to write the audit part (SACL), which fails without SeSecurityPrivilege.
        $existing.SetAccessControl($acl)
    }

    $untrusted = @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop | Where-Object {
        $owner = (Get-Acl -LiteralPath $_.FullName -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $owner -notin $trustedOwners
    })
    if ($untrusted.Count -gt 0) {
        throw "These files in '$Path' are not owned by SYSTEM or Administrators and may have been planted or changed by another account: $(@($untrusted.FullName) -join ', '). No changes were made. Check them, delete them if you did not create them, and run Remediations.ps1 again."
    }
}
Protect-AdministratorsOnlyDirectory -Path $script:UndoStateDirectory

# Only one Remediations.ps1 or rollback.ps1 may run at a time on this PC. Two runs at once would
# each keep their own copy of the snapshot, so the last one to save would overwrite the other's
# records (and a run that starts after another has changed a setting would record that new value
# as the "original"), and they would run secedit, auditpol and DISM against each other. The lock
# is the file SecurityBaseline.lock in the administrators-only snapshot folder, opened with no sharing
# and DeleteOnClose: Windows deletes the file and frees the lock when the run ends, also when it
# crashes or is stopped, so no stale lock stays behind. The name is fixed on purpose: every
# instance must open the same file to see the others. rollback.ps1 takes the same lock.
$script:RunLockPath = Join-Path $script:UndoStateDirectory 'SecurityBaseline.lock'
$script:RunLock = $null
try {
    $script:RunLock = [System.IO.FileStream]::new($script:RunLockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::DeleteOnClose)
}
catch {
    $lockError = $_.Exception.GetBaseException()
    if ($lockError -is [System.IO.IOException] -and ($lockError.HResult -band 0xFFFF) -in @(32, 33)) {
        Write-Host "Error: another Remediations.ps1 or rollback.ps1 is already running (it holds '$script:RunLockPath'). This run was stopped before it changed anything. Wait until the other run has finished, then run it again." -ForegroundColor Red
        exit 1
    }
    throw "Could not take the run lock '$script:RunLockPath', so nothing was changed: $($lockError.Message)"
}
# The rest of the script runs inside this try block so that the lock is released when it ends,
# also in a PowerShell window that stays open (a file stream is not closed by itself there).
try {

# Earlier versions wrote rollback.ps1 next to this script. That copy is outdated and
# would no longer be found by Rollback.cmd, so remove it when the folder allows it.
$legacyRollbackScriptPath = Join-Path $PSScriptRoot 'rollback.ps1'
if (Test-Path -LiteralPath $legacyRollbackScriptPath -PathType Leaf) {
    try {
        Remove-Item -LiteralPath $legacyRollbackScriptPath -Force -ErrorAction Stop
        Write-Host "Removed the outdated $legacyRollbackScriptPath; rollback.ps1 is now kept in $script:UndoStateDirectory." -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Could not remove the outdated $legacyRollbackScriptPath ($($_.Exception.Message)). Delete it by hand; the current rollback script is $script:RollbackScriptPath."
    }
}

function Write-GeneratedRollbackScript {
    $rollbackTokens = $null
    $rollbackParseErrors = $null
    $remediationAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $PSCommandPath,
        [ref]$rollbackTokens,
        [ref]$rollbackParseErrors
    )
    if ($rollbackParseErrors.Count -gt 0) {
        throw "Could not parse Remediations.ps1 to generate rollback.ps1: $($rollbackParseErrors[0].Message)"
    }
    $rollbackFunction = $remediationAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Invoke-Rollback'
    }, $true)
    if ($null -eq $rollbackFunction) {
        throw 'Could not find the Invoke-Rollback implementation in Remediations.ps1.'
    }

    $rollbackLines = @(
        '#requires -Version 5.1'
        '# Generated by Remediations.ps1 because one or more settings were changed.'
        '# Recorded rollback entries:'
    )
    foreach ($change in $script:UndoState['Changes']) {
        $rollbackLines += "# - $change"
    }
    $rollbackLines += ''
    $rollbackLines += '[CmdletBinding()]'
    $rollbackLines += 'param()'
    $rollbackLines += ''
    $rollbackLines += $rollbackFunction.Extent.Text
    $rollbackLines += ''
    $rollbackLines += 'Invoke-Rollback'
    $rollbackLines | Set-Content -LiteralPath $script:RollbackScriptPath -Encoding UTF8 -Force -ErrorAction Stop
}

if ((Test-Path -LiteralPath $script:UndoStatePath -PathType Leaf) -and
    (Test-Path -LiteralPath $script:LegacyUndoStatePath -PathType Leaf)) {
    throw "Both rollback snapshots exist: '$script:UndoStatePath' and '$script:LegacyUndoStatePath'. Resolve the snapshots before running remediation to avoid overwriting rollback state."
}
$loadingLegacyUndoState = -not (Test-Path -LiteralPath $script:UndoStatePath -PathType Leaf) -and
    (Test-Path -LiteralPath $script:LegacyUndoStatePath -PathType Leaf)
$undoStatePathToLoad = if ($loadingLegacyUndoState) { $script:LegacyUndoStatePath } else { $script:UndoStatePath }

if (Test-Path -LiteralPath $undoStatePathToLoad -PathType Leaf) {
    $script:UndoState = Import-Clixml -LiteralPath $undoStatePathToLoad -ErrorAction Stop
    if ($script:UndoState.Version -ne 2) {
        if ($script:UndoState.Version -eq 1) {
            if ($loadingLegacyUndoState) {
                Move-Item -LiteralPath $script:LegacyUndoStatePath -Destination $script:UndoStatePath -ErrorAction Stop
            }
            Write-GeneratedRollbackScript
            throw "A version 1 rollback snapshot is pending and may include unchanged settings. No remediation changes were made. A self-contained rollback.ps1 has been generated for this snapshot. Run it from an elevated PowerShell prompt, then run Remediations.ps1 again."
        }
        throw "Unsupported pending rollback snapshot version: $($script:UndoState.Version)."
    }
    if ($null -eq $script:UndoState['Changes']) {
        throw 'The pending rollback snapshot does not contain change-only records. Roll it back before running this remediation script.'
    }
    if ($loadingLegacyUndoState) {
        Move-Item -LiteralPath $script:LegacyUndoStatePath -Destination $script:UndoStatePath -ErrorAction Stop
    }
} else {
    if (Test-Path -LiteralPath $script:RollbackScriptPath -PathType Leaf) {
        Remove-Item -LiteralPath $script:RollbackScriptPath -Force -ErrorAction Stop
    }
    $script:UndoState = [ordered]@{
        Version = 2
        Created = Get-Date
        # The computer the snapshot was created on.
        ComputerName = [Environment]::MachineName
        Changes = @()
        # For every setting the script checked: when it was first seen, whether it was then
        # already in its expected state or was corrected by this script, and when it was
        # last corrected. See Set-SettingOutcome.
        SettingOutcomes = [ordered]@{}
        RegistryKeys = @{}
        RegistryValues = @{}
        RegistryKeysWithCompleteValueSet = @{}
        Services = @{}
        OptionalFeatures = @{}
        AuditPolicy = @{}
        FirewallProfiles = @{}
        # Legacy field, filled only by older versions of this script (Security log only).
        SecurityLogMaximumSize = $null
        # Original maximum size in bytes of each event log whose size was raised, by log name.
        EventLogMaximumSizes = @{}
        SecurityPolicyFile = $null
        UserRightsPolicyFile = $null
        GuestAccount = $null
        SmbServerRequireSecuritySignature = $null
        SmbClientRequireSecuritySignature = $null
        DefenderControlledFolderAccess = $null
        DefenderNetworkProtection = $null
        DefenderPuaProtection = $null
        DefenderCloudBlockLevel = $null
        DefenderCloudExtendedTimeout = $null
        DefenderRemovableDriveScanningDisabled = $null
        UserRightsManagedRights = $null
        DefenderAsrRuleIds = $null
        DefenderAsrRuleActions = $null
        ExploitMitigations = @{}
    }
}

if (@($script:UndoState['Changes']).Count -gt 0) {
    Write-GeneratedRollbackScript
}

if ($null -eq $script:UndoState['Changes']) {
    $script:UndoState['Changes'] = @()
}
# Snapshots from older versions of this script do not have this field yet.
if ($null -eq $script:UndoState['EventLogMaximumSizes']) {
    $script:UndoState['EventLogMaximumSizes'] = @{}
}

# Changes made during this run. The rollback snapshot can span several runs, so
# its change list cannot tell which settings changed now. These drive the
# restart / sign-out summary printed at the end of the script.
$script:RunChangeCount = 0
# The settings this run changes, by Set-SettingOutcome key, for the change report.
$script:RunCorrectedKeys = [System.Collections.Generic.List[string]]::new()
# $true while the snapshot in memory holds records that are not on disk yet. Settings are
# recorded even when they need no change (so rollback can restore the real starting point),
# and such records are written by Save-UndoState at the next change or at the end of the run.
$script:UndoStateDirty = $false

$script:RestartReasons = [System.Collections.Generic.List[string]]::new()
$script:SignOutReasons = [System.Collections.Generic.List[string]]::new()

function Register-PendingRestart {
    param(
        [Parameter(Mandatory)][int]$ChangeCountBefore,
        [Parameter(Mandatory)][string]$Reason,
        [switch]$SignOutOnly
    )

    # Record the reason only if the step changed something during this run.
    if ($script:RunChangeCount -le $ChangeCountBefore) { return }
    # Assign the list directly: an empty list returned from an if-expression is unrolled to $null.
    $reasons = $script:RestartReasons
    if ($SignOutOnly) { $reasons = $script:SignOutReasons }
    if (-not $reasons.Contains($Reason)) { $reasons.Add($Reason) }
}

function Add-UndoChange {
    param([Parameter(Mandatory)][string]$Description)

    $script:RunChangeCount++

    $description = ($Description -replace '[\r\n]+', ' ').Trim()
    if ($description -and $description -notin $script:UndoState['Changes']) {
        $script:UndoState['Changes'] = @($script:UndoState['Changes']) + $description
    }
}

function Format-RegistryUndoChange {
    param([Parameter(Mandatory)][psobject]$Entry)

    $valueDescription = if ($Entry.Exists) {
        $originalData = ConvertTo-Json -InputObject $Entry.Data -Compress -Depth 5
        "restore $($Entry.Kind) value $originalData"
    } else {
        'remove the value because it was absent before remediation'
    }
    "Registry $($Entry.Path)\$($Entry.Name): $valueDescription"
}

function Save-UndoState {
    $temporaryPath = "$script:UndoStatePath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $script:UndoState | Export-Clixml -LiteralPath $temporaryPath -Depth 20 -Force -ErrorAction Stop
        Move-Item -LiteralPath $temporaryPath -Destination $script:UndoStatePath -Force -ErrorAction Stop
        $script:UndoStateDirty = $false
        Write-GeneratedRollbackScript
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop
        }
    }
}

# The keys (as used by Set-SettingOutcome) of the settings a snapshot from an older version of
# this script has records for. Such a snapshot recorded only settings that were changed, so
# these settings were corrected by an earlier run.
function Get-LegacyRecordedKey {
    param([Parameter(Mandatory)]$State)

    $keys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($entry in @($State['RegistryValues'].Values)) { [void]$keys.Add("Registry|$($entry.Path)|$($entry.Name)") }
    foreach ($name in @($State['RegistryKeysWithCompleteValueSet'].Keys)) { [void]$keys.Add("Registry list|$name") }
    foreach ($name in @($State['Services'].Keys)) { [void]$keys.Add("Service|$name") }
    foreach ($name in @($State['FirewallProfiles'].Keys)) {
        [void]$keys.Add("Firewall profile|$name")
        if ($State['FirewallProfiles'][$name].PSObject.Properties['NotifyOnListen']) { [void]$keys.Add("Firewall notifications|$name") }
    }
    foreach ($name in @($State['AuditPolicy'].Keys)) { [void]$keys.Add("Audit policy|$name") }
    foreach ($name in @($State['EventLogMaximumSizes'].Keys)) { [void]$keys.Add("Event log size|$name") }
    if ($null -ne $State['SecurityLogMaximumSize']) { [void]$keys.Add('Event log size|Security') }
    foreach ($name in @($State['OptionalFeatures'].Keys)) { [void]$keys.Add("Optional feature|$name") }
    foreach ($name in @($State['ExploitMitigations'].Keys)) { [void]$keys.Add("Exploit mitigation|$(if ($name -eq 'BottomUp') { 'Bottom-Up ASLR' } else { $name })") }
    foreach ($name in 'DefenderControlledFolderAccess', 'DefenderNetworkProtection', 'DefenderPuaProtection') {
        if ($null -ne $State[$name]) { [void]$keys.Add("Defender|$name") }
    }
    if ($null -ne $State['DefenderAsrRuleIds']) { [void]$keys.Add('Defender|ASR rules') }
    if ($null -ne $State['SmbServerRequireSecuritySignature']) { [void]$keys.Add('SMB server signing') }
    if ($null -ne $State['SmbClientRequireSecuritySignature']) { [void]$keys.Add('SMB client signing') }
    if ($null -ne $State['GuestAccount']) { [void]$keys.Add('Guest account') }
    if ($State['SecurityPolicyFile']) { [void]$keys.Add('Local security policy') }
    if ($State['UserRightsPolicyFile']) { [void]$keys.Add('User rights') }
    , $keys
}

# Records what happened to a setting the script checked: AlreadyInExpectedState (no change
# was needed), Corrected (the script changed it) or NotCorrected (the change was skipped or
# failed). FirstOutcome is what happened the first time the setting was seen and does not
# change; LastCorrected is when the script last corrected it (empty if it never did).
function Set-SettingOutcome {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateSet('AlreadyInExpectedState', 'Corrected', 'NotCorrected')][string]$Outcome
    )

    # For the change report of this run (Write-RemediationReport).
    if ($Outcome -eq 'Corrected' -and $null -ne $script:RunCorrectedKeys -and -not $script:RunCorrectedKeys.Contains($Key)) { $script:RunCorrectedKeys.Add($Key) }
    $outcomes = $script:UndoState['SettingOutcomes']
    # Written as text with the time zone, which is smaller in the snapshot than a date object.
    $now = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    $entry = $outcomes[$Key]
    if ($null -eq $entry) {
        if ($null -ne $script:LegacyRecordedKeys -and $script:LegacyRecordedKeys.Contains($Key)) {
            # Recorded by an earlier run of an older version, which recorded only settings it
            # changed: the setting was corrected then. When is not known; the snapshot's
            # creation date is the earliest it can have been.
            $outcomes[$Key] = [pscustomobject]@{
                FirstSeen = ([datetime]$script:UndoState['Created']).ToString('yyyy-MM-ddTHH:mm:sszzz')
                FirstOutcome = 'Corrected'
                LastCorrected = $(if ($Outcome -eq 'Corrected') { $now } else { $null })
            }
        } else {
            $outcomes[$Key] = [pscustomobject]@{
                FirstSeen = $now
                FirstOutcome = $Outcome
                LastCorrected = $(if ($Outcome -eq 'Corrected') { $now } else { $null })
            }
        }
        $script:UndoStateDirty = $true
    } elseif ($Outcome -eq 'Corrected') {
        $entry.LastCorrected = $now
        $script:UndoStateDirty = $true
    }
}

# For a setting that is left unchanged because it is already compliant, in code that does
# not call one of the Set-Idempotent* functions.
function Save-AlreadyCompliantValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)

    Save-RegistryValueState -Path $Path -Name $Name -RecordChange:$false -Baseline
    Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome AlreadyInExpectedState
}

# Snapshots from older versions of this script do not have these fields yet. The snapshot
# lives on this computer, so this computer's name is the best answer for them.
$script:LegacyRecordedKeys = [System.Collections.Generic.HashSet[string]]::new()
if ($null -eq $script:UndoState['SettingOutcomes']) {
    $script:UndoState['SettingOutcomes'] = [ordered]@{}
    $script:LegacyRecordedKeys = Get-LegacyRecordedKey -State $script:UndoState
    $script:UndoStateDirty = $true
}
if (-not $script:UndoState['ComputerName']) { $script:UndoState['ComputerName'] = [Environment]::MachineName; $script:UndoStateDirty = $true }

# The values of the settings an earlier run recorded, read before this run changes anything,
# so the change report can show what each setting was just before this run. Settings that
# this run records for the first time take their old value from the snapshot instead.
$script:RowsAtRunStart = @()
if (@($script:UndoState['SettingOutcomes'].Keys).Count -gt 0 -or @($script:UndoState['RegistryValues'].Keys).Count -gt 0) {
    try {
        $script:RowsAtRunStart = @(Get-SnapshotRows -State $script:UndoState)
    } catch {
        Write-Warning "Could not read the current settings for the change report; its old values come from the snapshot: $_"
    }
}

function Invoke-Rollback {
    $ErrorActionPreference = 'Stop'
    # This function becomes the whole of rollback.ps1, so it repeats the hardening from
    # the top of Remediations.ps1: modules only from Windows and Program Files, Windows
    # tools by full path, and system folders from Windows instead of environment variables.
    $env:PSModulePath = @(
        [System.IO.Path]::Combine($PSHOME, 'Modules')
        [System.IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'WindowsPowerShell\Modules')
        [System.IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\Modules')
    ) -join ';'
    $script:SeceditPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'secedit.exe')
    $script:AuditpolPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'auditpol.exe')
    $script:WevtutilPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'wevtutil.exe')
    $script:undoStatePath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SecurityBaseline') 'Remediations.rollback.clixml'
    if (-not (Test-Path -LiteralPath $script:undoStatePath -PathType Leaf)) {
        throw "Undo snapshot not found: $script:undoStatePath. Remediations.ps1 must create a snapshot before its changes can be undone."
    }

    # Only one Remediations.ps1 or rollback.ps1 may run at a time (see Remediations.ps1): the
    # same lock file, opened with no sharing and DeleteOnClose, so Windows frees it when this
    # run ends, also after a crash.
    $runLockPath = Join-Path (Split-Path -Parent $script:undoStatePath) 'SecurityBaseline.lock'
    $runLock = $null
    try {
        $runLock = [System.IO.FileStream]::new($runLockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::DeleteOnClose)
    }
    catch {
        $lockError = $_.Exception.GetBaseException()
        if ($lockError -is [System.IO.IOException] -and ($lockError.HResult -band 0xFFFF) -in @(32, 33)) {
            throw "Another Remediations.ps1 or rollback.ps1 is already running (it holds '$runLockPath'). Nothing was restored. Wait until the other run has finished, then run the rollback again."
        }
        throw "Could not take the run lock '$runLockPath', so nothing was restored: $($lockError.Message)"
    }
    try {
    $script:undoState = Import-Clixml -LiteralPath $script:undoStatePath -ErrorAction Stop
    if ($script:undoState.Version -notin @(1, 2)) {
        throw "Unsupported undo snapshot version: $($script:undoState.Version)."
    }
    $script:undoErrors = [System.Collections.Generic.List[string]]::new()
    function Invoke-UndoStep {
        param(
            [Parameter(Mandatory)][string]$Description,
            [switch]$SuppressSuccess,
            [Parameter(Mandatory)][scriptblock]$Action
        )
        try {
            & $Action
            if (-not $SuppressSuccess) {
                Write-Host "Restored $Description." -ForegroundColor Green
            }
        }
        catch {
            $script:undoErrors.Add("$Description`: $($_.Exception.Message)")
            Write-Warning "Failed to restore $Description`: $($_.Exception.Message)"
        }
    }

    function Format-UndoRegistryValue {
        param(
            [Parameter(Mandatory)][bool]$Exists,
            [string]$Kind,
            $Data
        )

        if (-not $Exists) { return 'absent' }
        $displayData = if ($Data -is [string]) {
            ConvertTo-Json -InputObject $Data -Compress
        } elseif ($Data -is [array]) {
            ConvertTo-Json -InputObject $Data -Compress -Depth 5
        } else {
            [string]$Data
        }
        "$Kind $displayData"
    }

    function ConvertTo-RegistryLocation {
        param([Parameter(Mandatory)][string]$Path)

        $registryPath = $Path
        if (Test-Path -LiteralPath $Path -PathType Container) {
            $registryPath = (Get-Item -LiteralPath $Path -ErrorAction Stop).Name
        } elseif ($Path -match '^(?:Microsoft\.PowerShell\.Core\\)?Registry::(HKEY_[A-Z_]+)(?:\\(.*))?$') {
            $registryPath = $Matches[1]
            if ($Matches[2]) { $registryPath += "\$($Matches[2])" }
        } elseif ($Path -match '^(HKLM|HKCU|HKCR|HKU|HKCC):\\?(.*)$') {
            $hiveName = switch ($Matches[1].ToUpperInvariant()) {
                'HKLM' { 'HKEY_LOCAL_MACHINE' }
                'HKCU' { 'HKEY_CURRENT_USER' }
                'HKCR' { 'HKEY_CLASSES_ROOT' }
                'HKU' { 'HKEY_USERS' }
                'HKCC' { 'HKEY_CURRENT_CONFIG' }
            }
            $registryPath = $hiveName
            if ($Matches[2]) { $registryPath += "\$($Matches[2])" }
        }

        if ($registryPath -notmatch '^(HKEY_[A-Z_]+)(?:\\(.*))?$') {
            throw "Unsupported registry path: $Path"
        }
        [pscustomobject]@{
            Hive = [string]$Matches[1]
            SubKey = [string]$Matches[2]
        }
    }

    function Invoke-WithWritableRegistryKey {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][bool]$Create,
            [Parameter(Mandatory)][scriptblock]$Action
        )

        $location = ConvertTo-RegistryLocation -Path $Path
        $hive = switch ($location.Hive) {
            'HKEY_LOCAL_MACHINE' { [Microsoft.Win32.RegistryHive]::LocalMachine }
            'HKEY_CURRENT_USER' { [Microsoft.Win32.RegistryHive]::CurrentUser }
            'HKEY_CLASSES_ROOT' { [Microsoft.Win32.RegistryHive]::ClassesRoot }
            'HKEY_USERS' { [Microsoft.Win32.RegistryHive]::Users }
            'HKEY_CURRENT_CONFIG' { [Microsoft.Win32.RegistryHive]::CurrentConfig }
            default { throw "Unsupported registry hive: $($location.Hive)" }
        }

        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Default)
        try {
            $key = if ($Create) {
                if ([string]::IsNullOrEmpty($location.SubKey)) { $baseKey } else { $baseKey.CreateSubKey($location.SubKey) }
            } elseif ([string]::IsNullOrEmpty($location.SubKey)) {
                $baseKey
            } else {
                $baseKey.OpenSubKey($location.SubKey, $true)
            }
            if ($null -eq $key) { return }
            try {
                & $Action $key
            }
            finally {
                if (-not [object]::ReferenceEquals($key, $baseKey)) {
                    $key.Dispose()
                }
            }
        }
        finally {
            $baseKey.Dispose()
        }
    }

    # Restore registry values and remove nodes created by remediation.
    if ($script:undoState.RegistryValues.Count -gt 0 -or
        $script:undoState.RegistryKeysWithCompleteValueSet.Count -gt 0 -or
        @($script:undoState.RegistryKeys.GetEnumerator() | Where-Object { -not [bool]$_.Value }).Count -gt 0) {
        Invoke-UndoStep -Description 'registry values and newly created registry nodes' -SuppressSuccess -Action {
            $currentValues = @{}
            foreach ($entry in $script:undoState.RegistryValues.Values) {
                $currentValue = [pscustomobject]@{
                    Exists = $false
                    Kind = $null
                    Data = $null
                }
                Invoke-WithWritableRegistryKey -Path $entry.Path -Create $false -Action {
                    param($key)
                    if ($key.GetValueNames() -contains [string]$entry.Name) {
                        $currentValue.Exists = $true
                        $currentValue.Kind = [string]$key.GetValueKind([string]$entry.Name)
                        $currentValue.Data = $key.GetValue(
                            [string]$entry.Name,
                            $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                        )
                    }
                }
                $currentValues["$($entry.Path)|$($entry.Name)"] = $currentValue
            }

            foreach ($path in $script:undoState.RegistryKeysWithCompleteValueSet.Keys) {
                Invoke-WithWritableRegistryKey -Path $path -Create $false -Action {
                    param($key)
                    foreach ($name in @($key.GetValueNames())) {
                        $key.DeleteValue($name, $false)
                    }
                }
            }

            foreach ($entry in $script:undoState.RegistryValues.Values) {
                $valueKey = "$($entry.Path)|$($entry.Name)"
                $currentValue = $currentValues[$valueKey]
                if ($entry.Exists) {
                    $unchanged = $currentValue.Exists -and
                        $currentValue.Kind -eq $entry.Kind -and
                        (ConvertTo-Json -InputObject $currentValue.Data -Compress -Depth 5) -eq
                        (ConvertTo-Json -InputObject $entry.Data -Compress -Depth 5)
                    if ($unchanged) { continue }
                    $kind = [System.Enum]::Parse(
                        [Microsoft.Win32.RegistryValueKind],
                        [string]$entry.Kind
                    )
                    Invoke-WithWritableRegistryKey -Path $entry.Path -Create $true -Action {
                        param($key)
                        $key.SetValue([string]$entry.Name, $entry.Data, $kind)
                    }
                } else {
                    if (-not $currentValue.Exists) { continue }
                    Invoke-WithWritableRegistryKey -Path $entry.Path -Create $false -Action {
                        param($key)
                        if ($key.GetValueNames() -contains [string]$entry.Name) {
                            $key.DeleteValue([string]$entry.Name, $false)
                        }
                    }
                }

                $displayName = if ($entry.PSObject.Properties['Description'] -and $entry.Description) {
                    [string]$entry.Description
                } elseif ($entry.Name -eq 'SmartScreenEnabled' -and $entry.Path -match '\\Microsoft\\Edge$') {
                    'Microsoft Defender SmartScreen for Edge'
                } else {
                    "Registry value $($entry.Name)"
                }
                $fromValue = Format-UndoRegistryValue -Exists:$currentValue.Exists -Kind $currentValue.Kind -Data $currentValue.Data
                $toValue = Format-UndoRegistryValue -Exists:$entry.Exists -Kind $entry.Kind -Data $entry.Data
                Write-Host "Rolled back $displayName from $fromValue to $toValue." -ForegroundColor Green
            }

            $newKeys = @($script:undoState.RegistryKeys.GetEnumerator() |
                Where-Object { -not [bool]$_.Value } |
                Sort-Object { $_.Key.Length } -Descending)
            foreach ($keyEntry in $newKeys) {
                if (Test-Path -LiteralPath $keyEntry.Key -PathType Container) {
                    Remove-Item -LiteralPath $keyEntry.Key -Recurse -Force -ErrorAction Stop
                }
            }
        }
    }

    # Restore the built-in Guest account to its original state: enabled again if it was
    # enabled, disabled again if it was disabled and has been enabled since.
    if ($null -ne $script:undoState.GuestAccount) {
        Invoke-UndoStep -Description 'the built-in Guest account state' -Action {
            $guestSid = [System.Security.Principal.SecurityIdentifier]$script:undoState.GuestAccount.SID
            $guestNow = Get-LocalUser -SID $guestSid -ErrorAction Stop
            if ($script:undoState.GuestAccount.Enabled -and -not $guestNow.Enabled) {
                Enable-LocalUser -SID $guestSid -ErrorAction Stop
            } elseif (-not $script:undoState.GuestAccount.Enabled -and $guestNow.Enabled) {
                Disable-LocalUser -SID $guestSid -ErrorAction Stop
            }
        }
    }

    # Restore the local password, account-lockout and account policy settings.
    # Only the [System Access] settings that Remediations.ps1 changes are applied.
    # The saved export also holds the security-option registry values, the account
    # names and the Administrator/Guest account states as they were when it was taken,
    # which is after the registry remediation. Applying those would undo the registry
    # and Guest account rollback above, so they are left out.
    if ($script:undoState.SecurityPolicyFile) {
        Invoke-UndoStep -Description 'local security policy' -Action {
            if (-not (Test-Path -LiteralPath $script:undoState.SecurityPolicyFile -PathType Leaf)) {
                throw "Saved security policy file is missing: $($script:undoState.SecurityPolicyFile)"
            }
            $managedSettings = @(
                'PasswordHistorySize', 'MaximumPasswordAge', 'MinimumPasswordAge', 'MinimumPasswordLength',
                'PasswordComplexity', 'ClearTextPassword', 'LockoutBadCount', 'LockoutDuration',
                'ResetLockoutCount', 'AllowAdministratorLockout', 'LSAAnonymousNameLookup', 'ForceLogoffWhenHourExpire'
            )
            $savedText = Get-Content -LiteralPath $script:undoState.SecurityPolicyFile -Raw -ErrorAction Stop
            $systemAccess = [regex]::Match($savedText, '(?ims)^\[System Access\]\s*(.*?)(?=^\[|\z)')
            if (-not $systemAccess.Success) {
                throw 'Could not find the System Access section in the saved security policy file.'
            }
            $restoreLines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[System Access]')
            foreach ($line in ($systemAccess.Groups[1].Value -split '\r?\n')) {
                if ($line -match '^\s*([A-Za-z]+)\s*=\s*(-?\d+)\s*$' -and $Matches[1] -in $managedSettings) {
                    $restoreLines += "$($Matches[1]) = $($Matches[2])"
                }
            }
            $undoDirectory = Split-Path -Parent $script:undoStatePath
            $restorePath = Join-Path $undoDirectory 'Remediations.security-policy.restore.inf'
            $databasePath = Join-Path $undoDirectory 'Remediations.undo.sdb'
            try {
                $restoreLines | Set-Content -LiteralPath $restorePath -Encoding Unicode -Force -ErrorAction Stop
                $output = (& $script:SeceditPath /configure /db $databasePath /cfg $restorePath /areas SECURITYPOLICY /quiet 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw "secedit.exe exited with code $LASTEXITCODE. $output" }
            }
            finally {
                if (Test-Path -LiteralPath $restorePath) { Remove-Item -LiteralPath $restorePath -Force -ErrorAction Stop }
            }
        }
    }
    # Restore user rights. A right that had no accounts before remediation is missing
    # from the saved export, and secedit leaves a missing right unchanged. Such rights
    # are added as empty assignments, so accounts added by remediation are removed.
    if ($script:undoState['UserRightsPolicyFile']) {
        Invoke-UndoStep -Description 'user rights assignments' -Action {
            if (-not (Test-Path -LiteralPath $script:undoState['UserRightsPolicyFile'] -PathType Leaf)) {
                throw "Saved user-rights policy file is missing: $($script:undoState['UserRightsPolicyFile'])"
            }
            $savedText = Get-Content -LiteralPath $script:undoState['UserRightsPolicyFile'] -Raw -ErrorAction Stop
            $privilegeRights = [regex]::Match($savedText, '(?ims)^\[Privilege Rights\]\s*(.*?)(?=^\[|\z)')
            if (-not $privilegeRights.Success) {
                throw 'Could not find the Privilege Rights section in the saved user-rights policy file.'
            }
            $restoreLines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
            $savedRights = @()
            foreach ($line in ($privilegeRights.Groups[1].Value -split '\r?\n')) {
                if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$') {
                    $restoreLines += "$($Matches[1]) = $($Matches[2])"
                    $savedRights += $Matches[1]
                }
            }
            # Snapshots from older script versions have no list of managed rights.
            foreach ($right in @($script:undoState['UserRightsManagedRights'])) {
                if ($right -and $right -notin $savedRights) { $restoreLines += "$right = " }
            }
            $undoDirectory = Split-Path -Parent $script:undoStatePath
            $restorePath = Join-Path $undoDirectory 'Remediations.user-rights.restore.inf'
            $databasePath = Join-Path $undoDirectory 'Remediations.user-rights.undo.sdb'
            try {
                $restoreLines | Set-Content -LiteralPath $restorePath -Encoding Unicode -Force -ErrorAction Stop
                $output = (& $script:SeceditPath /configure /db $databasePath /cfg $restorePath /areas USER_RIGHTS /quiet 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw "secedit.exe exited with code $LASTEXITCODE. $output" }
            }
            finally {
                if (Test-Path -LiteralPath $restorePath) { Remove-Item -LiteralPath $restorePath -Force -ErrorAction Stop }
            }
        }
    }

    # Restore service startup mode and running/stopped state.
    if ($script:undoState.Services.Count -gt 0) {
        Invoke-UndoStep -Description 'service startup modes and running states' -Action {
            # Three passes, because the saved services are in no particular order and some
            # depend on others: a service cannot start while a service it depends on is still
            # disabled. First the startup mode of every service, then the stops, then the
            # starts (Windows starts the services a started service depends on by itself).
            $serviceNames = @($script:undoState.Services.Keys)
            foreach ($serviceName in $serviceNames) {
                $original = $script:undoState.Services[$serviceName]
                $startupType = switch ([string]$original.StartMode) {
                    'Auto' { 'Automatic' }
                    'Manual' { 'Manual' }
                    'Disabled' { 'Disabled' }
                    default { throw "Unsupported original startup mode '$($original.StartMode)' for service '$serviceName'." }
                }
                Set-Service -Name $serviceName -StartupType $startupType -ErrorAction Stop
            }
            foreach ($serviceName in $serviceNames) {
                $original = $script:undoState.Services[$serviceName]
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                if ($original.State -ne 'Running' -and $service.Status -eq 'Running') {
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                }
            }
            foreach ($serviceName in $serviceNames) {
                $original = $script:undoState.Services[$serviceName]
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                if ($original.State -eq 'Running' -and $service.Status -ne 'Running') {
                    Start-Service -Name $serviceName -ErrorAction Stop
                }
            }
        }
    }

    # Restore the optional Windows PowerShell v2 features: enabled again if they were
    # enabled, disabled again if they were disabled and have been enabled since.
    if ($script:undoState.OptionalFeatures.Count -gt 0) {
        Invoke-UndoStep -Description 'Windows optional feature states' -Action {
            foreach ($featureName in @($script:undoState.OptionalFeatures.Keys)) {
                if ([string]$script:undoState.OptionalFeatures[$featureName] -eq 'Enabled') {
                    Enable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop | Out-Null
                } else {
                    $featureNow = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
                    if ($null -ne $featureNow -and $featureNow.State -eq 'Enabled') {
                        Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop | Out-Null
                    }
                }
            }
        }
    }

    # Restore the original advanced audit policy subcategory settings.
    if ($script:undoState.AuditPolicy.Count -gt 0) {
        Invoke-UndoStep -Description 'Advanced Audit Policy subcategories' -Action {
            foreach ($subcategory in $script:undoState.AuditPolicy.Keys) {
                $original = $script:undoState.AuditPolicy[$subcategory]
                $success = if ($original.Success) { 'enable' } else { 'disable' }
                $failure = if ($original.Failure) { 'enable' } else { 'disable' }
                $output = (& $script:AuditpolPath /set /subcategory:"$subcategory" /success:$success /failure:$failure 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw "auditpol.exe failed for '$subcategory': $output" }
            }
        }
    }

    # Restore enabled and default inbound/outbound actions for each firewall profile.
    if ($script:undoState.FirewallProfiles.Count -gt 0) {
        Invoke-UndoStep -Description 'Windows Firewall profile defaults' -Action {
            foreach ($profileName in $script:undoState.FirewallProfiles.Keys) {
                $firewallProfile = $script:undoState.FirewallProfiles[$profileName]
                Set-NetFirewallProfile -Profile $profileName `
                    -Enabled ([System.Convert]::ToBoolean($firewallProfile.Enabled)) `
                    -DefaultInboundAction $firewallProfile.DefaultInboundAction `
                    -DefaultOutboundAction $firewallProfile.DefaultOutboundAction `
                    -ErrorAction Stop
                if ($firewallProfile.PSObject.Properties['NotifyOnListen']) {
                    Set-NetFirewallProfile -Profile $profileName -NotifyOnListen ([string]$firewallProfile.NotifyOnListen) -ErrorAction Stop
                }
            }
        }
    }

    # Restore the original event log maximum sizes. SecurityLogMaximumSize is the
    # field used by older versions of Remediations.ps1 for the Security log.
    if ($null -ne $script:undoState.SecurityLogMaximumSize) {
        Invoke-UndoStep -Description 'Security event log maximum size' -Action {
            $output = (& $script:WevtutilPath sl Security "/ms:$($script:undoState.SecurityLogMaximumSize)" 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) { throw "wevtutil.exe failed: $output" }
        }
    }
    if ($null -ne $script:undoState.EventLogMaximumSizes) {
        foreach ($eventLogName in @($script:undoState.EventLogMaximumSizes.Keys)) {
            Invoke-UndoStep -Description "$eventLogName event log maximum size" -Action {
                $output = (& $script:WevtutilPath sl $eventLogName "/ms:$($script:undoState.EventLogMaximumSizes[$eventLogName])" 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw "wevtutil.exe failed: $output" }
            }
        }
    }

    # Restore SMB server and client signing configuration.
    if ($null -ne $script:undoState.SmbServerRequireSecuritySignature) {
        Invoke-UndoStep -Description 'SMB Server security-signature requirement' -Action {
            Set-SmbServerConfiguration -RequireSecuritySignature ([bool]$script:undoState.SmbServerRequireSecuritySignature) -Force -ErrorAction Stop
        }
    }
    if ($null -ne $script:undoState.SmbClientRequireSecuritySignature) {
        Invoke-UndoStep -Description 'SMB Client security-signature requirement' -Action {
            Set-SmbClientConfiguration -RequireSecuritySignature ([bool]$script:undoState.SmbClientRequireSecuritySignature) -Force -ErrorAction Stop
        }
    }

    # Restore Defender Controlled Folder Access and Network Protection modes.
    if ($null -ne $script:undoState.DefenderControlledFolderAccess) {
        Invoke-UndoStep -Description 'Defender Controlled Folder Access mode' -Action {
            $mode = switch ([int]$script:undoState.DefenderControlledFolderAccess) {
                0 { 'Disabled' }
                1 { 'Enabled' }
                2 { 'AuditMode' }
                3 { 'BlockDiskModificationOnly' }
                4 { 'AuditDiskModificationOnly' }
                default { throw "Unsupported Controlled Folder Access mode: $($script:undoState.DefenderControlledFolderAccess)" }
            }
            Set-MpPreference -EnableControlledFolderAccess $mode -ErrorAction Stop
        }
    }
    if ($null -ne $script:undoState.DefenderNetworkProtection) {
        Invoke-UndoStep -Description 'Defender Network Protection mode' -Action {
            $mode = switch ([int]$script:undoState.DefenderNetworkProtection) {
                0 { 'Disabled' }
                1 { 'Enabled' }
                2 { 'AuditMode' }
                default { throw "Unsupported Network Protection mode: $($script:undoState.DefenderNetworkProtection)" }
            }
            Set-MpPreference -EnableNetworkProtection $mode -ErrorAction Stop
        }
    }
    # Snapshots from older script versions do not have this entry.
    if ($null -ne $script:undoState['DefenderPuaProtection']) {
        Invoke-UndoStep -Description 'Defender Potentially Unwanted App (PUA) Protection mode' -Action {
            $mode = switch ([int]$script:undoState['DefenderPuaProtection']) {
                0 { 'Disabled' }
                1 { 'Enabled' }
                2 { 'AuditMode' }
                default { throw "Unsupported PUA Protection mode: $($script:undoState['DefenderPuaProtection'])" }
            }
            Set-MpPreference -PUAProtection $mode -ErrorAction Stop
        }
    }

    # Restore the Defender cloud block level, extended cloud check time and removable drive
    # scanning. Snapshots from older script versions do not have these entries.
    if ($null -ne $script:undoState['DefenderCloudBlockLevel']) {
        Invoke-UndoStep -Description 'Defender cloud protection level' -Action {
            $level = switch ([int]$script:undoState['DefenderCloudBlockLevel']) {
                0 { 'Default' }
                1 { 'Moderate' }
                2 { 'High' }
                4 { 'HighPlus' }
                6 { 'ZeroTolerance' }
                default { throw "Unsupported cloud block level: $($script:undoState['DefenderCloudBlockLevel'])" }
            }
            Set-MpPreference -CloudBlockLevel $level -ErrorAction Stop
        }
    }
    if ($null -ne $script:undoState['DefenderCloudExtendedTimeout']) {
        Invoke-UndoStep -Description 'Defender extended cloud check time' -Action {
            Set-MpPreference -CloudExtendedTimeout ([uint32]$script:undoState['DefenderCloudExtendedTimeout']) -ErrorAction Stop
        }
    }
    if ($null -ne $script:undoState['DefenderRemovableDriveScanningDisabled']) {
        Invoke-UndoStep -Description 'Defender removable drive scanning' -Action {
            Set-MpPreference -DisableRemovableDriveScanning ([bool]$script:undoState['DefenderRemovableDriveScanningDisabled']) -ErrorAction Stop
        }
    }

    # Restore the complete pre-remediation ASR ID/action lists.
    if ($null -ne $script:undoState.DefenderAsrRuleIds) {
        Invoke-UndoStep -Description 'Defender Attack Surface Reduction rule configuration' -Action {
            # Older snapshots may hold @($null) for "no rules"; treat that as an empty list.
            $originalAsrIds = @($script:undoState.DefenderAsrRuleIds | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
            if ($originalAsrIds.Count -eq 0) {
                # No rules before remediation: Set-MpPreference cannot take an empty list,
                # so remove the rules that are configured now.
                $configuredAsrIds = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
                if ($configuredAsrIds.Count -gt 0) {
                    Remove-MpPreference -AttackSurfaceReductionRules_Ids $configuredAsrIds -ErrorAction Stop
                }
            } else {
                Set-MpPreference `
                    -AttackSurfaceReductionRules_Ids $originalAsrIds `
                    -AttackSurfaceReductionRules_Actions @($script:undoState.DefenderAsrRuleActions) `
                    -ErrorAction Stop
            }
        }
    }

    # Disable only system exploit mitigations that were explicitly OFF before enabling.
    if ($script:undoState.ExploitMitigations.Count -gt 0) {
        Invoke-UndoStep -Description 'Windows system exploit mitigation states' -Action {
            foreach ($mitigationName in $script:undoState.ExploitMitigations.Keys) {
                Set-ProcessMitigation -System -Disable $mitigationName -ErrorAction Stop
            }
        }
    }

    if ($script:undoErrors.Count -gt 0) {
        throw "Undo was incomplete. The snapshot was retained at '$script:undoStatePath' so the failed restorations can be retried:`n - $($script:undoErrors -join "`n - ")"
    }

    if ($script:undoState.SecurityPolicyFile -and (Test-Path -LiteralPath $script:undoState.SecurityPolicyFile)) {
        Remove-Item -LiteralPath $script:undoState.SecurityPolicyFile -Force -ErrorAction Stop
    }
    if ($script:undoState['UserRightsPolicyFile'] -and (Test-Path -LiteralPath $script:undoState['UserRightsPolicyFile'])) {
        Remove-Item -LiteralPath $script:undoState['UserRightsPolicyFile'] -Force -ErrorAction Stop
    }
    Remove-Item -LiteralPath $script:undoStatePath -Force -ErrorAction Stop
    # rollback.ps1 is kept next to the snapshot.
    $generatedRollbackPath = Join-Path (Split-Path -Parent $script:undoStatePath) 'rollback.ps1'
    if (Test-Path -LiteralPath $generatedRollbackPath -PathType Leaf) {
        Remove-Item -LiteralPath $generatedRollbackPath -Force -ErrorAction Stop
    }
    Write-Host 'All saved pre-remediation settings have been restored. A restart may be required for some changes to take effect.' -ForegroundColor Green
    }
    finally {
        if ($null -ne $runLock) { $runLock.Dispose() }
    }
}

function Save-RegistryKeyExistence {
    param([Parameter(Mandatory)][string]$Path)

    $normalizedPath = $Path.TrimEnd('\')
    $parts = $normalizedPath -split '\\'
    for ($length = 1; $length -le $parts.Count; $length++) {
        $keyPath = $parts[0..($length - 1)] -join '\'
        # The first part alone (a drive such as HKLM: or a provider root such as Registry::HKEY_USERS) is kept as it is.
        if ($length -gt 1 -and $keyPath -notmatch '^[A-Za-z]+:$') {
            $keyPath = $parts[0] + '\' + ($parts[1..($length - 1)] -join '\')
        } else {
            $keyPath += '\'
        }
        if (-not $script:UndoState.RegistryKeys.ContainsKey($keyPath)) {
            $script:UndoState.RegistryKeys[$keyPath] = Test-Path -LiteralPath $keyPath -PathType Container
            $script:UndoStateDirty = $true
        }
    }
}

function Save-RegistryValueState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [bool]$RecordChange = $true,
        [string]$Description,
        # Record the state of a setting that is checked, whether or not it will be changed.
        # Only a key that exists is recorded: a key that does not exist yet is recorded when
        # (and only if) this script creates it, because rollback deletes keys recorded as new.
        [switch]$Baseline
    )

    if ($Baseline -and -not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Save-RegistryKeyExistence -Path $Path
    $valueKey = "$Path|$Name"
    if (-not $script:UndoState.RegistryValues.ContainsKey($valueKey)) {
        $exists = $false
        $kind = $null
        $data = $null
        if (Test-Path -LiteralPath $Path -PathType Container) {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($key.GetValueNames() -contains $Name) {
                $exists = $true
                $kind = [string]$key.GetValueKind($Name)
                $data = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        $script:UndoState.RegistryValues[$valueKey] = [pscustomobject]@{
            Path = $Path
            Name = $Name
            Exists = $exists
            Kind = $kind
            Data = $data
        }
        $script:UndoStateDirty = $true
    }

    if ($Description) {
        $entry = $script:UndoState.RegistryValues[$valueKey]
        if ($entry.PSObject.Properties['Description']) {
            $entry.Description = $Description
        } else {
            $entry | Add-Member -MemberType NoteProperty -Name Description -Value $Description
        }
    }

    if ($RecordChange) {
        Add-UndoChange -Description (Format-RegistryUndoChange -Entry $script:UndoState.RegistryValues[$valueKey])
        Save-UndoState
    }
}

function Save-RegistryKeyValuesState {
    param([Parameter(Mandatory)][string]$Path)

    if ($script:UndoState.RegistryKeysWithCompleteValueSet.ContainsKey($Path)) { return }
    Save-RegistryKeyExistence -Path $Path
    $script:UndoState.RegistryKeysWithCompleteValueSet[$Path] = $true
    $script:UndoStateDirty = $true
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in @($key.GetValueNames())) {
            Save-RegistryValueState -Path $Path -Name $name -RecordChange:$false
        }
    }
}

# Records the startup mode and state of a service the first time it is seen. -BaselineOnly
# records a service that is checked but needs no change (StartMode and State can be passed
# in when the caller has them already); without it, the change is listed as well, using the
# recorded original, which is the first state ever seen.
function Save-ServiceState {
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$BaselineOnly,
        [string]$StartMode,
        [string]$State
    )

    if (-not $script:UndoState.Services.ContainsKey($Name)) {
        if (-not $StartMode) {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
            if ($null -eq $service) { return }
            $StartMode = [string]$service.StartMode
            $State = [string]$service.State
        }
        # Rollback restores only these startup modes (drivers have Boot or System).
        if ($BaselineOnly -and $StartMode -notin @('Auto', 'Manual', 'Disabled')) { return }
        $script:UndoState.Services[$Name] = [pscustomobject]@{
            StartMode = $StartMode
            State = $State
        }
        $script:UndoStateDirty = $true
    }
    if (-not $BaselineOnly) {
        $saved = $script:UndoState.Services[$Name]
        Add-UndoChange -Description "Service ${Name}: restore startup mode $($saved.StartMode) and state $($saved.State)"
        Save-UndoState
    }
}

# Exports the local security policy the first time. -BaselineOnly records it without
# listing a change (the policy is checked, whether or not it needs a change).
function Save-SecurityPolicyState {
    param([switch]$BaselineOnly)

    if (-not $script:UndoState.SecurityPolicyFile) {
        $policyPath = Join-Path $script:UndoStateDirectory 'Remediations.security-policy.inf'
        $output = (& $script:SeceditPath /export /cfg $policyPath /areas SECURITYPOLICY 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
            throw "Could not save the original local security policy for undo: $output"
        }
        $script:UndoState.SecurityPolicyFile = $policyPath
        $script:UndoStateDirty = $true
    }
    if (-not $BaselineOnly) {
        Add-UndoChange -Description 'Local security policy: restore the exported pre-remediation policy'
        Save-UndoState
    }
}

# Exports the user rights the first time. -BaselineOnly records them without listing a
# change (the rights are checked, whether or not they need a change).
function Save-UserRightsPolicyState {
    param(
        [Parameter(Mandatory)][string[]]$ManagedRights,
        [switch]$BaselineOnly
    )

    # The export omits rights that have no accounts, so rollback also needs the names
    # of the rights that remediation sets. Snapshots from older script versions do not
    # have this list yet; add it without replacing their saved export.
    if (-not $script:UndoState['UserRightsManagedRights']) {
        $script:UndoState['UserRightsManagedRights'] = @($ManagedRights)
        $script:UndoStateDirty = $true
    }
    if (-not $script:UndoState['UserRightsPolicyFile']) {
        $policyPath = Join-Path $script:UndoStateDirectory 'Remediations.user-rights.inf'
        $output = (& $script:SeceditPath /export /cfg $policyPath /areas USER_RIGHTS 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
            throw "Could not save the original user-rights policy for undo: $output"
        }
        $script:UndoState['UserRightsPolicyFile'] = $policyPath
        $script:UndoStateDirty = $true
    }
    if (-not $BaselineOnly) {
        Add-UndoChange -Description 'User rights assignments: restore the exported pre-remediation policy'
        Save-UndoState
    }
}

function Get-UserRightsFromExport {
    param([Parameter(Mandatory)][string]$PolicyFile)
    $text = Get-Content -LiteralPath $PolicyFile -Raw -ErrorAction Stop
    $section = [regex]::Match($text, '(?ims)^\[Privilege Rights\]\s*(.*?)(?=^\[|\z)')
    if (-not $section.Success) { throw 'Could not find the Privilege Rights section in the exported policy.' }
    $rights = @{}
    foreach ($line in ($section.Groups[1].Value -split '\r?\n')) {
        if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$') {
            $rights[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } )
        }
    }
    return $rights
}

function Test-UserRightSidSetEqual {
    param([string[]]$First, [string[]]$Second)
    $firstSet = @($First | Sort-Object -Unique)
    $secondSet = @($Second | Sort-Object -Unique)
    if ($firstSet.Count -ne $secondSet.Count) { return $false }
    return @($firstSet | Where-Object { $_ -notin $secondSet }).Count -eq 0
}

function Set-CisUserRights {
    function ConvertTo-PolicySid {
        param([string]$Account)
        if ($Account -match '^\*?S-1-') { return ('*' + $Account.TrimStart('*')) }
        $accountNames = if ($Account.Contains('\')) { @($Account) } else { @("$env:COMPUTERNAME\$Account", $Account) }
        foreach ($accountName in $accountNames) {
            try { return ('*' + ([System.Security.Principal.NTAccount]::new($accountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value) } catch { }
        }
        throw "Could not resolve user-right account '$Account' to a SID."
    }
    # CIS 2.2.13: with Hyper-V installed, NT VIRTUAL MACHINE\Virtual Machines (S-1-5-83-0)
    # also needs "Create symbolic links", or new virtual machines cannot be created.
    # The vmms service exists only when the Hyper-V role is installed.
    $symbolicLinkAccounts = if (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue) {
        @('*S-1-5-32-544', '*S-1-5-83-0')
    } else {
        @('*S-1-5-32-544')
    }
    $rights = @(
        @{ Name='SeTrustedCredManAccessPrivilege'; Accounts=@() }
        @{ Name='SeNetworkLogonRight'; Accounts=@('*S-1-5-32-544','*S-1-5-32-555') }
        @{ Name='SeTcbPrivilege'; Accounts=@() }
        @{ Name='SeIncreaseQuotaPrivilege'; Accounts=@('*S-1-5-32-544','*S-1-5-19','*S-1-5-20') }
        @{ Name='SeInteractiveLogonRight'; Accounts=@('*S-1-5-32-544','*S-1-5-32-545') }
        @{ Name='SeRemoteInteractiveLogonRight'; Accounts=@('*S-1-5-32-544','*S-1-5-32-555') }
        @{ Name='SeBackupPrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeSystemtimePrivilege'; Accounts=@('*S-1-5-32-544','*S-1-5-19') }
        @{ Name='SeCreatePagefilePrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeCreateTokenPrivilege'; Accounts=@() }
        @{ Name='SeCreateGlobalPrivilege'; Accounts=@('*S-1-5-32-544','*S-1-5-19','*S-1-5-20','*S-1-5-6') }
        @{ Name='SeCreatePermanentPrivilege'; Accounts=@() }
        @{ Name='SeCreateSymbolicLinkPrivilege'; Accounts=$symbolicLinkAccounts }
        @{ Name='SeDebugPrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeDenyNetworkLogonRight'; Accounts=@('*S-1-5-32-546'); Include=$true }
        @{ Name='SeDenyBatchLogonRight'; Accounts=@('*S-1-5-32-546'); Include=$true }
        @{ Name='SeDenyServiceLogonRight'; Accounts=@('*S-1-5-32-546'); Include=$true }
        @{ Name='SeDenyInteractiveLogonRight'; Accounts=@('*S-1-5-32-546'); Include=$true }
        @{ Name='SeDenyRemoteInteractiveLogonRight'; Accounts=@('*S-1-5-32-546'); Include=$true }
        @{ Name='SeEnableDelegationPrivilege'; Accounts=@() }
        @{ Name='SeRemoteShutdownPrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeImpersonatePrivilege'; Accounts=@('*S-1-5-32-544','*S-1-5-19','*S-1-5-20','*S-1-5-6','RESTRICTED SERVICES\PrintSpoolerService') }
        @{ Name='SeIncreaseBasePriorityPrivilege'; Accounts=@('*S-1-5-32-544','*S-1-5-90-0') }
        @{ Name='SeLoadDriverPrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeLockMemoryPrivilege'; Accounts=@() }
        @{ Name='SeRelabelPrivilege'; Accounts=@() }
        @{ Name='SeSystemEnvironmentPrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeManageVolumePrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeProfileSingleProcessPrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeSystemProfilePrivilege'; Accounts=@('*S-1-5-32-544','NT SERVICE\WdiServiceHost') }
        @{ Name='SeAssignPrimaryTokenPrivilege'; Accounts=@('*S-1-5-19','*S-1-5-20') }
        @{ Name='SeRestorePrivilege'; Accounts=@('*S-1-5-32-544') }
        @{ Name='SeShutdownPrivilege'; Accounts=@('*S-1-5-32-544','*S-1-5-32-545') }
        @{ Name='SeTakeOwnershipPrivilege'; Accounts=@('*S-1-5-32-544') }
    )
    # Accounts that only exist on some Windows versions. PrintSpoolerService is a
    # virtual account introduced in Windows 11 22H2; on Windows 10 it cannot be
    # resolved, so it is dropped instead of failing every user-right assignment.
    $optionalAccounts = @('RESTRICTED SERVICES\PrintSpoolerService')
    foreach ($right in $rights) {
        $right.Accounts = @($right.Accounts | Where-Object {
            $account = $_
            if ($account -notin $optionalAccounts) { return $true }
            try { [void](ConvertTo-PolicySid $account); return $true }
            catch {
                Write-Host "Skipping '$account' for $($right.Name): the account does not exist on this Windows version." -ForegroundColor DarkGray
                return $false
            }
        })
    }
    $currentFile = Join-Path $script:UndoStateDirectory ("CisUserRights-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    $policyFile = Join-Path $script:UndoStateDirectory ("CisUserRights-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    $databaseFile = Join-Path $script:UndoStateDirectory ("CisUserRights-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
    try {
        $export = (& $script:SeceditPath /export /cfg $currentFile /areas USER_RIGHTS 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "Could not export current user-right assignments: $export" }
        $current = Get-UserRightsFromExport -PolicyFile $currentFile
        $lines = [System.Collections.Generic.List[string]]::new()
        $needsUpdate = $false
        $lines.Add('[Unicode]'); $lines.Add('Unicode=yes'); $lines.Add('[Version]'); $lines.Add('signature="$CHICAGO$"'); $lines.Add('Revision=1'); $lines.Add('[Privilege Rights]')
        foreach ($right in $rights) {
            $accounts = @($right.Accounts)
            if ($right.Include -and $current.ContainsKey($right.Name)) {
                $accounts = @($accounts + $current[$right.Name] | Sort-Object -Unique)
            }
            $accounts = @($accounts | ForEach-Object { ConvertTo-PolicySid $_ } | Sort-Object -Unique)
            $currentAccounts = if ($current.ContainsKey($right.Name)) { @($current[$right.Name] | ForEach-Object { ConvertTo-PolicySid $_ } | Sort-Object -Unique) } else { @() }
            if (-not (Test-UserRightSidSetEqual -First $accounts -Second $currentAccounts)) { $needsUpdate = $true }
            $lines.Add("$($right.Name) = $($accounts -join ',')")
        }
        # A snapshot from an older script version has a saved export but no list of
        # managed rights; add the list so its rollback also clears rights that were empty.
        if ($script:UndoState['UserRightsPolicyFile'] -and -not $script:UndoState['UserRightsManagedRights']) {
            $script:UndoState['UserRightsManagedRights'] = @($rights | ForEach-Object { $_.Name })
            Save-UndoState
        }
        # The user rights are recorded for rollback even when they need no change.
        Save-UserRightsPolicyState -ManagedRights @($rights | ForEach-Object { $_.Name }) -BaselineOnly
        if (-not $needsUpdate) {
            Write-Host 'CIS Level 1 user-right assignments are already configured.' -ForegroundColor Green
            Set-SettingOutcome -Key 'User rights' -Outcome AlreadyInExpectedState
            return
        }
        $lines | Set-Content -LiteralPath $policyFile -Encoding Unicode -ErrorAction Stop
        Save-UserRightsPolicyState -ManagedRights @($rights | ForEach-Object { $_.Name })
        $configure = (& $script:SeceditPath /configure /db $databaseFile /cfg $policyFile /areas USER_RIGHTS /quiet 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "Could not apply CIS user-right assignments: $configure" }
        # Save-UserRightsPolicyState has counted this change (Add-UndoChange).
        $verifyFile = Join-Path $script:UndoStateDirectory ("CisUserRights-Verify-{0}.inf" -f [guid]::NewGuid().ToString('N'))
        try {
            $verifyOutput = (& $script:SeceditPath /export /cfg $verifyFile /areas USER_RIGHTS 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) { throw "Could not verify applied user-right assignments: $verifyOutput" }
            $verified = Get-UserRightsFromExport -PolicyFile $verifyFile
            foreach ($right in $rights) {
                $expected = @($right.Accounts)
                if ($right.Include -and $current.ContainsKey($right.Name)) { $expected = @($expected + $current[$right.Name] | Sort-Object -Unique) }
                $expected = @($expected | ForEach-Object { ConvertTo-PolicySid $_ } | Sort-Object -Unique)
                $observed = if ($verified.ContainsKey($right.Name)) { @($verified[$right.Name] | ForEach-Object { ConvertTo-PolicySid $_ } | Sort-Object -Unique) } else { @() }
                if (-not (Test-UserRightSidSetEqual -First $expected -Second $observed)) {
                    throw "Verification failed for $($right.Name). Expected SIDs: $($expected -join ', '); observed: $($observed -join ', ')."
                }
            }
        }
        finally {
            if (Test-Path -LiteralPath $verifyFile) { Remove-Item -LiteralPath $verifyFile -Force -ErrorAction Stop }
        }
        Write-Host 'Applied CIS Level 1 user-right assignments.' -ForegroundColor Yellow
        Set-SettingOutcome -Key 'User rights' -Outcome Corrected
    }
    finally {
        foreach ($file in @($currentFile,$policyFile,$databaseFile)) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction Stop }
        }
    }
}

function Test-BrowserInstalled {
    param(
        [Parameter(Mandatory)][ValidateSet('Edge','Chrome')][string]$Browser
    )

    $relativePath = switch ($Browser) {
        'Edge' { 'Microsoft\Edge\Application\msedge.exe' }
        'Chrome' { 'Google\Chrome\Application\chrome.exe' }
    }
    $candidatePaths = [System.Collections.Generic.List[string]]::new()

    foreach ($programFiles in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($programFiles) {
            $candidatePaths.Add((Join-Path $programFiles $relativePath))
        }
    }

    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    if (Test-Path -LiteralPath $profileListPath -PathType Container) {
        foreach ($profileKey in Get-ChildItem -LiteralPath $profileListPath -ErrorAction Stop) {
            $profileProperties = Get-ItemProperty -LiteralPath $profileKey.PSPath -ErrorAction Stop
            $profilePath = if ($profileProperties.PSObject.Properties['ProfileImagePath']) {
                $profileProperties.ProfileImagePath
            }
            if ($profilePath) {
                $expandedProfilePath = [Environment]::ExpandEnvironmentVariables([string]$profilePath)
                $candidatePaths.Add((Join-Path $expandedProfilePath "AppData\Local\$relativePath"))
            }
        }
    }

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) { return $true }
    }
    return $false
}

function Set-IdempotentDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)][string]$Description,
        # Optional. Receives the current DWORD and returns $true when that value is
        # also compliant (for example a stricter one). Such a value is left unchanged.
        # Keep it aligned with the values the matching Audit.ps1 check accepts.
        [scriptblock]$Accept
    )

    # A failure is reported with Write-Error and does not throw, so one failed
    # setting does not stop the remediations that follow it.
    try {
        # The state of the setting is recorded for rollback even when it needs no change.
        Save-RegistryValueState -Path $Path -Name $Name -Description $Description -RecordChange:$false -Baseline
        $pathExists = Test-Path -LiteralPath $Path -PathType Container
        $key = if ($pathExists) { Get-Item -LiteralPath $Path -ErrorAction Stop } else { $null }
        $currentValue = if ($pathExists) { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name } else { $null }
        $isDword = $false
        if ($null -ne $currentValue) {
            $isDword = $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord
        }
        if ($isDword -and $null -ne $Accept -and $currentValue -ne $Value -and (& $Accept $currentValue)) {
            Write-Host "$Description is already compliant (DWORD $currentValue); left unchanged." -ForegroundColor Green
            Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome AlreadyInExpectedState
            return
        }
        $valueNeedsUpdate = $null -eq $currentValue -or $currentValue -ne $Value -or -not $isDword
        if (-not $pathExists -or $valueNeedsUpdate) {
            Save-RegistryValueState -Path $Path -Name $Name -Description $Description
        }
        if (-not $pathExists) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        if ($valueNeedsUpdate) {
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }

        $updatedKey = Get-Item -LiteralPath $Path -ErrorAction Stop
        $updatedValue = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($updatedValue -ne $Value -or $updatedKey.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
            throw "Verification failed for $Name (expected DWORD $Value, observed $updatedValue)."
        }

        if (-not $pathExists -or $valueNeedsUpdate) {
            Write-Host "$Description updated to DWORD $Value." -ForegroundColor Yellow
            Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome Corrected
        } else {
            Write-Host "$Description is already configured as DWORD $Value." -ForegroundColor Green
            Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome AlreadyInExpectedState
        }
    }
    catch {
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome NotCorrected
        Write-Error "Failed to configure ${Description}: $($_.Exception.Message)"
    }
}

function Set-IdempotentString {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Description,
        # Optional. Other REG_SZ values that are also compliant (for example stricter
        # ones) and are left unchanged. Keep aligned with the matching Audit.ps1 check.
        [string[]]$AcceptedValues = @()
    )

    try {
        # The state of the setting is recorded for rollback even when it needs no change.
        Save-RegistryValueState -Path $Path -Name $Name -RecordChange:$false -Baseline
        $pathExists = Test-Path -LiteralPath $Path -PathType Container
        $key = if ($pathExists) { Get-Item -LiteralPath $Path -ErrorAction Stop } else { $null }
        $currentValue = $null
        $isString = $false
        if ($pathExists -and $key.GetValueNames() -contains $Name) {
            $currentValue = $key.GetValue($Name)
            $isString = $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::String
        }
        if ($isString -and $currentValue -cne $Value -and $currentValue -cin $AcceptedValues) {
            Write-Host "$Description is already compliant (REG_SZ $currentValue); left unchanged." -ForegroundColor Green
            Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome AlreadyInExpectedState
            return
        }
        $valueNeedsUpdate = -not $isString -or $currentValue -cne $Value
        if (-not $pathExists -or $valueNeedsUpdate) {
            Save-RegistryValueState -Path $Path -Name $Name
        }
        if (-not $pathExists) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        if ($valueNeedsUpdate) {
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType String -Force -ErrorAction Stop | Out-Null
        }

        $updatedKey = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($updatedKey.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::String -or $updatedKey.GetValue($Name) -cne $Value) {
            throw "Verification failed for $Name."
        }
        Write-Host "$Description is configured." -ForegroundColor Green
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome $(if (-not $pathExists -or $valueNeedsUpdate) { 'Corrected' } else { 'AlreadyInExpectedState' })
    }
    catch {
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome NotCorrected
        Write-Error "Failed to configure ${Description}: $($_.Exception.Message)"
    }
}

function Set-IdempotentMultiString {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Values,
        [Parameter(Mandatory)][string]$Description
    )

    try {
        # The state of the setting is recorded for rollback even when it needs no change.
        Save-RegistryValueState -Path $Path -Name $Name -RecordChange:$false -Baseline
        $pathExists = Test-Path -LiteralPath $Path -PathType Container
        $key = if ($pathExists) { Get-Item -LiteralPath $Path -ErrorAction Stop } else { $null }
        $currentValues = @()
        $isMultiString = $false
        if ($pathExists -and $key.GetValueNames() -contains $Name) {
            $currentValues = @($key.GetValue($Name))
            $isMultiString = $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::MultiString
        }
        $valuesMatch = $isMultiString -and $currentValues.Count -eq $Values.Count
        if ($valuesMatch) {
            foreach ($value in $Values) {
                if (@($currentValues | Where-Object { $_ -ieq $value }).Count -ne 1) {
                    $valuesMatch = $false
                    break
                }
            }
        }
        if (-not $pathExists -or -not $valuesMatch) {
            Save-RegistryValueState -Path $Path -Name $Name
        }
        if (-not $pathExists) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        if (-not $valuesMatch) {
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Values -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
        }

        $updatedKey = Get-Item -LiteralPath $Path -ErrorAction Stop
        $updatedValues = @($updatedKey.GetValue($Name))
        if ($updatedKey.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::MultiString -or
            $updatedValues.Count -ne $Values.Count -or
            @($Values | Where-Object { $expected = $_; @($updatedValues | Where-Object { $_ -ieq $expected }).Count -ne 1 }).Count -gt 0) {
            throw "Verification failed for $Name."
        }
        Write-Host "$Description is configured." -ForegroundColor Green
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome $(if (-not $pathExists -or -not $valuesMatch) { 'Corrected' } else { 'AlreadyInExpectedState' })
    }
    catch {
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome NotCorrected
        Write-Error "Failed to configure ${Description}: $($_.Exception.Message)"
    }
}

function Remove-IdempotentRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description
    )

    try {
        $removedNow = $false
        if (Test-Path -LiteralPath $Path) {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            # Recorded even when the value is absent, so rollback removes it if it appears later.
            Save-RegistryValueState -Path $Path -Name $Name -RecordChange:$false -Baseline
            if ($key.GetValueNames() -contains $Name) {
                Save-RegistryValueState -Path $Path -Name $Name
                Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
                $removedNow = $true
            }
            $updatedKey = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($updatedKey.GetValueNames() -contains $Name) {
                throw "Verification failed: $Name is still present."
            }
        }
        Write-Host "$Description is absent." -ForegroundColor Green
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome $(if ($removedNow) { 'Corrected' } else { 'AlreadyInExpectedState' })
    }
    catch {
        Set-SettingOutcome -Key "Registry|$Path|$Name" -Outcome NotCorrected
        Write-Error "Failed to remove ${Description}: $($_.Exception.Message)"
    }
}

# Names of the services that depend on a service, directly or through other services,
# and are not stopped. Windows refuses to stop a service while such a service runs.
function Get-RunningDependentServiceName {
    param([Parameter(Mandatory)][string]$Name)

    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Name)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        # The getter is called as a method on purpose. Read as a property
        # (.DependentServices), PowerShell hides an error such as "Access is denied" and
        # returns nothing, which would look like "no dependent services".
        try {
            $dependents = @((Get-Service -Name $current -ErrorAction Stop).get_DependentServices())
        } catch {
            $reason = $_.Exception
            while ($reason.InnerException) { $reason = $reason.InnerException }
            throw "Could not read the services that depend on ${current}: $($reason.Message)"
        }
        foreach ($dependent in $dependents) {
            if ($null -eq $dependent -or -not $dependent.ServiceName) {
                throw "Could not read the services that depend on ${current}: Windows returned an entry without a name."
            }
            if ($dependent.Status -ne 'Stopped' -and $found.Add($dependent.ServiceName)) {
                $queue.Enqueue($dependent.ServiceName)
            }
        }
    }
    @($found)
}

# -BaselineServiceName: the services this baseline disables. A running service that
# depends on the one to disable is stopped with it only if it is in this list. Any other
# running dependent (for example the Workstation service, which carries network drives
# and shares) is something this baseline does not manage, so then the service is left
# completely alone and the reason is printed. That is the safer choice: the audit
# reports the service, and the operator decides.
function Set-CisServiceDisabled {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$BaselineServiceName = @()
    )

    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($null -eq $service) {
            Write-Host "Service $Name is not installed." -ForegroundColor Green
            return
        }
        Save-ServiceState -Name $Name -BaselineOnly -StartMode ([string]$service.StartMode) -State ([string]$service.State)

        # Checked before anything is changed, so a skipped service is left exactly as it was.
        $runningDependents = @()
        if ($service.State -ne 'Stopped') {
            $runningDependents = @(Get-RunningDependentServiceName -Name $Name)
            $unmanagedDependents = @($runningDependents | Where-Object { $_ -notin $BaselineServiceName })
            if ($unmanagedDependents.Count -gt 0) {
                Write-Host ("Skipped service ${Name} (State=$($service.State), StartMode=$($service.StartMode)): stopping it would also stop " +
                    "$($unmanagedDependents -join ', '), which this baseline does not manage. Check what depends on ${Name}, " +
                    "then stop and disable it by hand if that is acceptable.") -ForegroundColor Yellow
                Set-SettingOutcome -Key "Service|$Name" -Outcome NotCorrected
                return
            }
        }

        $changed = $false
        if ($service.StartMode -ne 'Disabled' -or $service.State -ne 'Stopped') {
            Save-ServiceState -Name $Name
        }
        if ($service.StartMode -ne 'Disabled') {
            Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
            $changed = $true
        }
        $stoppedDependents = @()
        if ($service.State -ne 'Stopped') {
            # Windows stops a service only together with the running services that depend
            # on it (for example XblGameSave depends on XblAuthManager), so they are stopped
            # too (-Force). Their state is saved first, so rollback.ps1 starts them again.
            # Their startup type is not changed here: a dependent service that this baseline
            # also disables gets that when its own turn comes, and any other one cannot
            # start anyway while the service it depends on is disabled.
            $stoppedDependents = $runningDependents
            foreach ($dependentName in $stoppedDependents) {
                Save-ServiceState -Name $dependentName
            }
            Stop-Service -Name $Name -Force -ErrorAction Stop
            $changed = $true
        }

        $updatedService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($null -eq $updatedService -or $updatedService.StartMode -ne 'Disabled' -or $updatedService.State -ne 'Stopped') {
            $state = if ($null -eq $updatedService) { 'not found after configuration' } else { "State=$($updatedService.State), StartMode=$($updatedService.StartMode)" }
            throw "Verification failed for service $Name ($state)."
        }

        if ($changed) {
            Write-Host "Stopped and disabled service $Name." -ForegroundColor Yellow
            Set-SettingOutcome -Key "Service|$Name" -Outcome Corrected
            foreach ($dependentName in $stoppedDependents) { Set-SettingOutcome -Key "Service|$dependentName" -Outcome Corrected }
            if ($stoppedDependents.Count -gt 0) {
                Write-Host "  Also stopped, because they depend on ${Name}: $($stoppedDependents -join ', '). They cannot run while $Name is disabled; rollback.ps1 starts them again." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Service $Name is already stopped and disabled." -ForegroundColor Green
            Set-SettingOutcome -Key "Service|$Name" -Outcome AlreadyInExpectedState
        }
    }
    catch {
        Set-SettingOutcome -Key "Service|$Name" -Outcome NotCorrected
        throw "Failed to disable service ${Name}: $($_.Exception.Message)"
    }
}

# ---- OS (Windows) settings, part 1 of 3. Skipped when RestrictTo does not include OS. The
# blocks are not indented, to keep the settings readable. Functions that the browser
# settings use are defined outside these blocks.
if (Test-SystemSelected 'OS') {

# Service hardening disables optional Windows features including location, remote desktop,
# hotspot, Xbox, and network discovery services. Bluetooth, printing, Windows Push
# Notifications, and their related services are intentionally left unchanged.
$cisServicesToDisable = @(
    'Browser'
    'MapsBroker'
    'GameInputSvc'
    'lfsvc'
    'IISADMIN'
    'irmon'
    'lltdsvc'
    'FTPSVC'
    'MSiSCSI'
    'sshd'
    'PNRPsvc'
    'p2psvc'
    'p2pimsvc'
    'PNRPAutoReg'
    'wercplsupport'
    'RasAuto'
    'SessionEnv'
    'TermService'
    'UmRdpService'
    'RpcLocator'
    'RemoteRegistry'
    'RemoteAccess'
    'LanmanServer'
    'simptcp'
    'SNMP'
    'sacsvr'
    'SSDPSRV'
    'upnphost'
    'WMSvc'
    'WerSvc'
    'Wecsvc'
    'WMPNetworkSvc'
    'icssvc'
    'PushToInstall'
    'WinRM'
    'W3SVC'
    'XboxGipSvc'
    'XblAuthManager'
    'XblGameSave'
    'XboxNetApiSvc'
)
# One WMI query reads the state of all services, so a service that is already stopped
# and disabled, or not installed, is recognized without queries of its own (a query per
# service takes about half a second, and each service needed two). Only a service that
# needs a change goes through Set-CisServiceDisabled, which reads its current state
# again, saves the undo state, changes the service and verifies the result. If the list
# cannot be read or is empty, every service goes through Set-CisServiceDisabled.
$serviceSnapshot = $null
try {
    $serviceSnapshot = @{}
    foreach ($entry in @(Get-CimInstance -ClassName Win32_Service -Property Name, State, StartMode -ErrorAction Stop)) {
        $serviceSnapshot[$entry.Name] = $entry
    }
    if ($serviceSnapshot.Count -eq 0) { $serviceSnapshot = $null }
}
catch {
    $serviceSnapshot = $null
}
foreach ($serviceName in $cisServicesToDisable) {
    try {
        if ($null -ne $serviceSnapshot) {
            $knownService = $serviceSnapshot[$serviceName]
            if ($null -eq $knownService) {
                Write-Host "Service $serviceName is not installed." -ForegroundColor Green
                continue
            }
            Save-ServiceState -Name $serviceName -BaselineOnly -StartMode ([string]$knownService.StartMode) -State ([string]$knownService.State)
            if ($knownService.StartMode -eq 'Disabled' -and $knownService.State -eq 'Stopped') {
                Write-Host "Service $serviceName is already stopped and disabled." -ForegroundColor Green
                Set-SettingOutcome -Key "Service|$serviceName" -Outcome AlreadyInExpectedState
                continue
            }
        }
        Set-CisServiceDisabled -Name $serviceName -BaselineServiceName $cisServicesToDisable
    }
    catch {
        Write-Error $_
    }
}

}
# ---- end of OS settings, part 1

function Set-BrowserExtensionPolicyList {
    param(
        [Parameter(Mandatory)][string]$BrowserName,
        [Parameter(Mandatory)][string]$PolicyRoot,
        [Parameter(Mandatory)][string]$PolicyName,
        [Parameter(Mandatory)][string[]]$Values
    )

    $policyPath = Join-Path $PolicyRoot $PolicyName
    try {
        $changed = $false
        $undoCaptured = $false
        # An existing list is recorded in full, even when it needs no change.
        if (Test-Path -LiteralPath $policyPath) {
            Save-RegistryKeyValuesState -Path $policyPath
        }
        if (-not (Test-Path -LiteralPath $policyPath)) {
            Save-RegistryKeyValuesState -Path $policyPath
            $undoCaptured = $true
            Add-UndoChange -Description "Registry key ${policyPath}: remove node created for browser extension policies"
            Save-UndoState
            New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
            $changed = $true
        }

        $key = Get-Item -LiteralPath $policyPath -ErrorAction Stop
        $expectedNames = @()
        for ($index = 0; $index -lt $Values.Count; $index++) {
            $valueName = [string]($index + 1)
            $expectedNames += $valueName
            $currentValue = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $isString = $false
            if ($null -ne $currentValue) {
                $isString = $key.GetValueKind($valueName) -eq [Microsoft.Win32.RegistryValueKind]::String
            }

            if ($null -eq $currentValue -or $currentValue -cne $Values[$index] -or -not $isString) {
                if (-not $undoCaptured) {
                    Save-RegistryKeyValuesState -Path $policyPath
                    $undoCaptured = $true
                }
                Save-RegistryValueState -Path $policyPath -Name $valueName -RecordChange:$false
                Add-UndoChange -Description (Format-RegistryUndoChange -Entry $script:UndoState.RegistryValues["$policyPath|$valueName"])
                Save-UndoState
                New-ItemProperty -LiteralPath $policyPath -Name $valueName -Value $Values[$index] -PropertyType String -Force -ErrorAction Stop | Out-Null
                $changed = $true
            }
        }

        $key = Get-Item -LiteralPath $policyPath -ErrorAction Stop
        foreach ($valueName in @($key.GetValueNames())) {
            if ($valueName -notin $expectedNames) {
                if (-not $undoCaptured) {
                    Save-RegistryKeyValuesState -Path $policyPath
                    $undoCaptured = $true
                }
                # A value added after the first snapshot (for example by hand) has no
                # saved state yet; record it now so the change can be described and undone.
                Save-RegistryValueState -Path $policyPath -Name $valueName -RecordChange:$false
                Add-UndoChange -Description (Format-RegistryUndoChange -Entry $script:UndoState.RegistryValues["$policyPath|$valueName"])
                Save-UndoState
                Remove-ItemProperty -LiteralPath $policyPath -Name $valueName -ErrorAction Stop
                $changed = $true
            }
        }

        $key = Get-Item -LiteralPath $policyPath -ErrorAction Stop
        $actualNames = @($key.GetValueNames() | Sort-Object)
        $sortedExpectedNames = @($expectedNames | Sort-Object)
        if (Compare-Object -ReferenceObject $sortedExpectedNames -DifferenceObject $actualNames) {
            throw "Verification failed for ${PolicyName}: registry values do not match the requested list."
        }
        for ($index = 0; $index -lt $Values.Count; $index++) {
            $valueName = [string]($index + 1)
            if ($key.GetValue($valueName) -cne $Values[$index] -or
                $key.GetValueKind($valueName) -ne [Microsoft.Win32.RegistryValueKind]::String) {
                throw "Verification failed for $PolicyName value $valueName."
            }
        }

        if ($changed) {
            Write-Host "Updated $BrowserName policy $PolicyName." -ForegroundColor Yellow
            Set-SettingOutcome -Key "Registry list|$policyPath" -Outcome Corrected
        } else {
            Write-Host "$BrowserName policy $PolicyName is already configured." -ForegroundColor Green
            Set-SettingOutcome -Key "Registry list|$policyPath" -Outcome AlreadyInExpectedState
        }
    }
    catch {
        Set-SettingOutcome -Key "Registry list|$policyPath" -Outcome NotCorrected
        Write-Error "Failed to configure $BrowserName policy ${PolicyName}: $($_.Exception.Message)"
    }
}

# ---- OS (Windows) settings, part 2 of 3 (not indented).
if (Test-SystemSelected 'OS') {

$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
Set-IdempotentDword -Path $Path -Name 'EnableMulticast' -Value 0 -Description 'LLMNR disablement'

# Disable the Teredo IPv6-over-IPv4 tunnel ("Set Teredo State" policy = Disabled).
# Teredo can expose the computer to inbound IPv6 traffic that bypasses the NAT
# protection of a home router; Microsoft no longer operates public Teredo servers.
# The policy takes effect after the IP Helper service restarts or Windows restarts.
$changesBefore = $script:RunChangeCount
try {
    Set-IdempotentString -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' -Name 'Teredo_State' -Value 'Disabled' -Description 'Teredo tunneling disablement'
}
catch {
    Write-Error "Failed to disable Teredo tunneling: $_"
}
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'Teredo tunneling disablement'

# Allow only TLS 1.2 and newer in Schannel, the TLS library used by Windows, .NET,
# browsers based on Windows networking, Remote Desktop and most Windows services.
# SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 are disabled for both the client and server
# roles, and TLS 1.2 is enabled explicitly. TLS 1.3 is enabled explicitly on Windows 11
# (build 22000 and later), which supports it for both roles. On Windows 10 TLS 1.3 is
# not supported as a client, so it is left at the Windows default there. Rollback
# restores the previous values and removes keys that did not exist. Schannel reads
# these at startup, so a restart is required.
$changesBefore = $script:RunChangeCount
try {
    $schannelProtocolsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    foreach ($protocol in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
        foreach ($role in @('Client', 'Server')) {
            $protocolPath = "$schannelProtocolsPath\$protocol\$role"
            Set-IdempotentDword -Path $protocolPath -Name 'Enabled' -Value 0 -Description "Schannel $protocol $role disablement (Enabled)"
            Set-IdempotentDword -Path $protocolPath -Name 'DisabledByDefault' -Value 1 -Description "Schannel $protocol $role disablement (DisabledByDefault)"
        }
    }
    foreach ($role in @('Client', 'Server')) {
        $protocolPath = "$schannelProtocolsPath\TLS 1.2\$role"
        Set-IdempotentDword -Path $protocolPath -Name 'Enabled' -Value 1 -Description "Schannel TLS 1.2 $role enablement (Enabled)"
        Set-IdempotentDword -Path $protocolPath -Name 'DisabledByDefault' -Value 0 -Description "Schannel TLS 1.2 $role enablement (DisabledByDefault)"
    }
    $tlsOsBuild = [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber
    if ($tlsOsBuild -ge 22000) {
        foreach ($role in @('Client', 'Server')) {
            $protocolPath = "$schannelProtocolsPath\TLS 1.3\$role"
            Set-IdempotentDword -Path $protocolPath -Name 'Enabled' -Value 1 -Description "Schannel TLS 1.3 $role enablement (Enabled)"
            Set-IdempotentDword -Path $protocolPath -Name 'DisabledByDefault' -Value 0 -Description "Schannel TLS 1.3 $role enablement (DisabledByDefault)"
        }
    } else {
        Write-Host "Schannel TLS 1.3 is not remediated: Windows 10 (build $tlsOsBuild) does not support TLS 1.3 as a client, so it is left at the Windows default." -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Failed to restrict Schannel to TLS 1.2 and newer: $_"
}
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'TLS/SSL protocol versions (Schannel)'

# LSA protection (RunAsPPL) is enabled only where it is supported, hassle-free and
# needs no action beyond a restart. Windows 11 22H2 (build 22621) and later support
# RunAsPPL = 2, which enables LSA protection without a UEFI lock, so rollback.ps1 can
# undo it. Windows 10 supports only RunAsPPL = 1; on Secure Boot PCs that value is
# also stored in a UEFI variable that a registry rollback cannot remove (Microsoft's
# LSA protection opt-out tool is required), so it is not set automatically there.
# An existing value of 1 or 2 is compliant and left unchanged.
$changesBefore = $script:RunChangeCount
try {
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $currentRunAsPpl = (Get-ItemProperty -LiteralPath $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
    $osBuild = [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber
    if ($currentRunAsPpl -in @(1, 2)) {
        Write-Host "LSA protection (RunAsPPL) is already enabled (RunAsPPL = $currentRunAsPpl)." -ForegroundColor Green
        Save-AlreadyCompliantValue -Path $lsaPath -Name 'RunAsPPL'
    } elseif ($osBuild -ge 22621) {
        Set-IdempotentDword -Path $lsaPath -Name 'RunAsPPL' -Value 2 -Description 'LSA protection (RunAsPPL = 2, without UEFI lock)'
    } else {
        Write-Warning "LSA protection (RunAsPPL) was not enabled: Windows build $osBuild supports it only with a UEFI lock that rollback cannot undo. Enable it manually if you accept that."
    }
}
catch {
    Write-Error "Failed to configure LSA protection (RunAsPPL): $_"
}
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'LSA protection (RunAsPPL)'

}
# ---- end of OS settings, part 2

# Each browser has its own allow-list, because the same extension has a different
# ID in the Microsoft Edge Add-ons store and in the Chrome Web Store. When both
# browsers are installed, each one is configured with its own list.
# Keep these lists identical to the ones in Audit.ps1.
$edgeApprovedExtensionIds = @(
    'bbcinlkgjjkejfdpemiealijmmooekmp'  # LastPass Password Manager (Microsoft Edge Add-ons ID)
    'ghbmnnjooekpmoecnnnilnnbdlolhkhi'  # Google Docs Offline (Chrome Web Store ID; not offered in the Edge Add-ons store)
    'jmjflgjpcpepeafmmgdpfkogkghcpiha'  # Microsoft Edge relevant text changes (default Edge component)
    'gcllgfdnfnllodcaambdaknbipemelie'  # Proton Pass (Microsoft Edge Add-ons ID)
    'ndcileolkflehcjpmjnfbnaibdcgglog'  # AdBlock (Microsoft Edge Add-ons ID)
    'cimighlppcgcoapaliogpjjdehbnofhn'  # uBlock Origin Lite (Microsoft Edge Add-ons ID)
    'aapbdbdomjkkjkaonfhkkikfgjllcleb'  # Google Translate (Chrome Web Store ID; not offered in the Edge Add-ons store)
    'jbkfoedolllekgbhcbcoahefnbanhhlh'  # Bitwarden Password Manager (Microsoft Edge Add-ons ID)
    'dppgmdbiimibapkepcbdbmkaabgiofem'  # 1Password Password Manager (Microsoft Edge Add-ons ID)
    'gehmmocbbkpblljhkekmfhjpfbkclbph'  # Dashlane Password Manager (Microsoft Edge Add-ons ID)
    'mfbcdcnpokpoajjciilocoachedjkima'  # iCloud Passwords by Apple (Microsoft Edge Add-ons ID)
)
$chromeApprovedExtensionIds = @(
    'hdokiejnpimakedhajhdlcegeplioahd'  # LastPass Password Manager (Chrome Web Store ID)
    'ghbmnnjooekpmoecnnnilnnbdlolhkhi'  # Google Docs Offline (Chrome Web Store ID)
    'ghmbeldphafepmbegfdlkpapadhbakde'  # Proton Pass (Chrome Web Store ID)
    'gighmmpiobklfepjocnamgkkbiglidom'  # AdBlock (Chrome Web Store ID)
    'ddkjiahejlhfcafbddmgiahcphecmpfh'  # uBlock Origin Lite (Chrome Web Store ID)
    'aapbdbdomjkkjkaonfhkkikfgjllcleb'  # Google Translate (Chrome Web Store ID)
    'nngceckbapebfimnlniiiahkandclblb'  # Bitwarden Password Manager (Chrome Web Store ID)
    'aeblfdkhhhdcdjpifhhbdiojplfjncoa'  # 1Password Password Manager (Chrome Web Store ID)
    'fdjamakpfbbddfjaooikfcpapjohcfmg'  # Dashlane Password Manager (Chrome Web Store ID)
    'pejdijmoenmkgeppbflobdenhhabjlaj'  # iCloud Passwords by Apple (Chrome Web Store ID)
)
# Chrome policies from the CIS Google Chrome Group Policy Benchmark v1.1.1: only the
# recommendations with a clear security value on a stand-alone PC (Safe Browsing, blocked
# malicious downloads, updates, no remote debugging, application-bound encryption; see
# Design.md). Values and their meaning follow Google's own policy definitions. Value is what
# Remediations.ps1 writes; AlsoAccepted lists other values that are just as safe and are left
# unchanged. Keep this list identical in Audit.ps1 and Remediations.ps1.
$chromePolicySettings = @(
    @{ Check = 'Chrome Safe Browsing Protection Level'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'SafeBrowsingProtectionLevel'; Value = 1; AlsoAccepted = @(2); Expected = 'SafeBrowsingProtectionLevel = DWORD 1 (standard) or 2 (enhanced) (CIS Chrome 2.15.2)' }
    @{ Check = 'Chrome Safe Browsing Warnings Cannot Be Bypassed'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'DisableSafeBrowsingProceedAnyway'; Value = 1; Expected = 'DisableSafeBrowsingProceedAnyway = DWORD 1 (CIS Chrome 2.15.3)' }
    @{ Check = 'Chrome Download Restrictions'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'DownloadRestrictions'; Value = 4; AlsoAccepted = @(1, 2, 3); Expected = 'DownloadRestrictions = DWORD 4 (block malicious downloads) or the stricter 1, 2 or 3 (CIS Chrome 2.42)' }
    @{ Check = 'Chrome Component Updates'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'ComponentUpdatesEnabled'; Value = 1; Expected = 'ComponentUpdatesEnabled = DWORD 1 (CIS Chrome 2.37)' }
    @{ Check = 'Chrome Automatic Updates'; Path = 'HKLM:\SOFTWARE\Policies\Google\Update'; Name = 'Update{8A69D345-D564-463C-AFF1-A69D9E530F96}'; Value = 1; AlsoAccepted = @(3); Expected = 'Google Update policy for Chrome = DWORD 1 (always allow updates) or 3 (automatic updates only) (CIS Chrome 4.2)' }
    @{ Check = 'Chrome Remote Debugging Disabled'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'RemoteDebuggingAllowed'; Value = 0; Expected = 'RemoteDebuggingAllowed = DWORD 0 (CIS Chrome 2.69)' }
    @{ Check = 'Chrome Application-Bound Encryption'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'ApplicationBoundEncryptionEnabled'; Value = 1; Expected = 'ApplicationBoundEncryptionEnabled = DWORD 1 (CIS Chrome 2.88)' }
)
$browserPolicyRoots = @(
    @{
        Name = 'Edge'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        ApprovedExtensionIds = $edgeApprovedExtensionIds
    }
    @{
        Name = 'Chrome'
        Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        ApprovedExtensionIds = $chromeApprovedExtensionIds
    }
)
foreach ($browserPolicy in $browserPolicyRoots) {
    # RestrictTo can select Edge and Chrome by name.
    if (-not (Test-SystemSelected $browserPolicy.Name)) {
        continue
    }
    if (-not (Test-BrowserInstalled -Browser $browserPolicy.Name)) {
        continue
    }

    if ($browserPolicy.Name -eq 'Chrome') {
        foreach ($setting in $chromePolicySettings) {
            $settingParameters = @{ Path = $setting.Path; Name = $setting.Name; Value = $setting.Value; Description = $setting.Check }
            if ($setting.ContainsKey('AlsoAccepted')) {
                $alsoAccepted = @($setting.AlsoAccepted)
                $settingParameters.Accept = { param($v) $v -in $alsoAccepted }.GetNewClosure()
            }
            Set-IdempotentDword @settingParameters
        }
    }
    if ($browserPolicy.Name -eq 'Edge') {
        Set-IdempotentDword -Path $browserPolicy.Path -Name 'PasswordExportEnabled' -Value 0 -Description 'Edge password export disablement'
        Set-IdempotentDword -Path $browserPolicy.Path -Name 'SmartScreenEnabled' -Value 1 -Description 'Microsoft Defender SmartScreen for Edge'
        Set-IdempotentDword -Path $browserPolicy.Path -Name 'SmartScreenPuaEnabled' -Value 1 -Description 'Edge SmartScreen potentially unwanted app blocking'
        # Internet Explorer mode off (the old IE engine inside Edge): no IE mode by setting or site list,
        # and users cannot reload a site in IE mode.
        Set-IdempotentDword -Path $browserPolicy.Path -Name 'InternetExplorerIntegrationLevel' -Value 0 -Description 'Edge Internet Explorer integration level (None)'
        Set-IdempotentDword -Path $browserPolicy.Path -Name 'InternetExplorerIntegrationReloadInIEModeAllowed' -Value 0 -Description 'Edge reload of sites in Internet Explorer mode not allowed'
    }
    # Delete browsing history, download history and cache older than 30 days.
    # Edge ignores this policy while Edge sync is on.
    # An existing value is kept when it already deletes these data types within 720 hours.
    $browsingDataLifetimeDescription = "$($browserPolicy.Name) browsing data lifetime (30 days)"
    $existingLifetime = Get-ItemProperty -LiteralPath $browserPolicy.Path -Name 'BrowsingDataLifetime' -ErrorAction SilentlyContinue
    $lifetimeCompliant = $false
    # The browsers accept only a JSON list, not a single object.
    if ($null -ne $existingLifetime -and ([string]$existingLifetime.BrowsingDataLifetime).TrimStart().StartsWith('[')) {
        try {
            # Windows PowerShell 5.1 returns a JSON array as one object; piping it unrolls the entries.
            $parsedLifetime = ConvertFrom-Json -InputObject ([string]$existingLifetime.BrowsingDataLifetime) -ErrorAction Stop
            $lifetimeEntries = @($parsedLifetime | ForEach-Object { $_ })
            $lifetimeKind = (Get-Item -LiteralPath $browserPolicy.Path -ErrorAction Stop).GetValueKind('BrowsingDataLifetime')
            $lifetimeCompliant = $lifetimeKind -eq [Microsoft.Win32.RegistryValueKind]::String -and @(
                foreach ($dataType in @('browsing_history', 'download_history', 'cached_images_and_files')) {
                    $lifetimeEntries | Where-Object {
                        @($_.data_types) -contains $dataType -and $_.time_to_live_in_hours -is [ValueType] -and
                            $_.time_to_live_in_hours -ge 1 -and $_.time_to_live_in_hours -le 720
                    } | Select-Object -First 1
                }
            ).Count -eq 3
        } catch {
            $lifetimeCompliant = $false
        }
    }
    if ($lifetimeCompliant) {
        Write-Host "$browsingDataLifetimeDescription is already configured." -ForegroundColor Green
        Save-AlreadyCompliantValue -Path $browserPolicy.Path -Name 'BrowsingDataLifetime'
    } else {
        Set-IdempotentString -Path $browserPolicy.Path -Name 'BrowsingDataLifetime' -Value '[{"data_types":["browsing_history","download_history","cached_images_and_files"],"time_to_live_in_hours":720}]' -Description $browsingDataLifetimeDescription
    }
    Set-BrowserExtensionPolicyList -BrowserName $browserPolicy.Name -PolicyRoot $browserPolicy.Path -PolicyName 'ExtensionInstallBlocklist' -Values @('*')
    Set-BrowserExtensionPolicyList -BrowserName $browserPolicy.Name -PolicyRoot $browserPolicy.Path -PolicyName 'ExtensionInstallAllowlist' -Values $browserPolicy.ApprovedExtensionIds
}

# ---- OS (Windows) settings, part 3 of 3 (not indented).
if (Test-SystemSelected 'OS') {

# Reads optional features by name. Listing every feature (Get-WindowsOptionalFeature -Online
# without -FeatureName) takes about ten times longer than asking for a few by name, and a name
# that does not exist on this Windows version simply returns nothing.
function Get-OptionalFeatureByName {
    param([Parameter(Mandatory)][string[]]$Name)
    foreach ($featureName in $Name) { Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop }
}

$powerShell2FeatureNames = @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')
$changesBefore = $script:RunChangeCount
try {
    $powerShell2Features = @(Get-OptionalFeatureByName -Name $powerShell2FeatureNames | Where-Object { $_ })
    # The state of each feature is recorded the first time, whether it is enabled or not.
    foreach ($feature in $powerShell2Features) {
        if (-not $script:UndoState.OptionalFeatures.ContainsKey($feature.FeatureName)) {
            $script:UndoState.OptionalFeatures[$feature.FeatureName] = [string]$feature.State
            $script:UndoStateDirty = $true
        }
    }
    foreach ($feature in @($powerShell2Features | Where-Object { $_.State -ne 'Enabled' })) {
        Set-SettingOutcome -Key "Optional feature|$($feature.FeatureName)" -Outcome AlreadyInExpectedState
    }
    foreach ($feature in @($powerShell2Features | Where-Object { $_.State -eq 'Enabled' })) {
        Add-UndoChange -Description "Windows optional feature $($feature.FeatureName): restore state $($script:UndoState.OptionalFeatures[$feature.FeatureName])"
        Save-UndoState
        Disable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "Disabled Windows optional feature $($feature.FeatureName)." -ForegroundColor Yellow
        Set-SettingOutcome -Key "Optional feature|$($feature.FeatureName)" -Outcome Corrected
    }

    $powerShell2Features = @(Get-OptionalFeatureByName -Name $powerShell2FeatureNames | Where-Object { $_ })
    $enabledFeatures = @($powerShell2Features | Where-Object { $_.State -eq 'Enabled' })
    $pendingFeatures = @($powerShell2Features | Where-Object { $_.State -notin @('Disabled', 'DisabledWithPayloadRemoved') })
    if ($enabledFeatures.Count -gt 0) {
        throw "PowerShell 2.0 feature disable verification failed: $(@($enabledFeatures | ForEach-Object { "$($_.FeatureName)=$($_.State)" }) -join ', ')."
    }
    if ($pendingFeatures.Count -gt 0) {
        Write-Warning "Windows PowerShell 2.0 feature state requires a restart or could not be verified as disabled: $(@($pendingFeatures | ForEach-Object { "$($_.FeatureName)=$($_.State)" }) -join ', ')."
    } elseif ($powerShell2Features.Count -eq 0) {
        Write-Host "Windows PowerShell 2.0 optional features are not present." -ForegroundColor Green
    } else {
        Write-Host "Windows PowerShell 2.0 optional features are disabled." -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to disable or verify Windows PowerShell 2.0 optional features: $_"
}
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'Windows PowerShell 2.0 feature removal'

# Cache at most two previous logons (REG_SZ). An existing value of 1 is stricter,
# is also accepted by Audit.ps1, and is left unchanged.
Set-IdempotentString -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value '2' -AcceptedValues @('1') -Description 'Cached logon credentials limit (CachedLogonsCount)'

# Disable the built-in Guest account by its well-known SID, so renaming it
# does not prevent remediation.
try {
    $guestAccounts=@(Get-LocalUser -ErrorAction Stop | Where-Object { ([string]$_.SID) -match '-501$' })
    if ($guestAccounts.Count -ne 1) {
        throw "Expected to find exactly one built-in Guest account (SID ending in -501); found $($guestAccounts.Count)."
    }

    $guestAccount=$guestAccounts[0]
    # The original state is recorded the first time only, even when the account is already disabled.
    if ($null -eq $script:UndoState['GuestAccount']) {
        $script:UndoState['GuestAccount'] = [pscustomobject]@{
            SID = [string]$guestAccount.SID
            Enabled = [bool]$guestAccount.Enabled
        }
        $script:UndoStateDirty = $true
    }
    if ($guestAccount.Enabled) {
        Add-UndoChange -Description "Built-in Guest account $($guestAccount.SID): restore the original enabled state ($($script:UndoState['GuestAccount'].Enabled))"
        Save-UndoState
        Disable-LocalUser -SID $guestAccount.SID -ErrorAction Stop
        $guestAccount=Get-LocalUser -SID $guestAccount.SID -ErrorAction Stop
        if ($guestAccount.Enabled) {
            throw 'The built-in Guest account remained enabled after the disable operation.'
        }
        Write-Host "Disabled the built-in Guest account ($($guestAccount.Name))." -ForegroundColor Yellow
        Set-SettingOutcome -Key 'Guest account' -Outcome Corrected
    } else {
        Write-Host "The built-in Guest account ($($guestAccount.Name)) is already disabled." -ForegroundColor Green
        Set-SettingOutcome -Key 'Guest account' -Outcome AlreadyInExpectedState
    }
}
catch {
    Set-SettingOutcome -Key 'Guest account' -Outcome NotCorrected
    Write-Error "Failed to disable the built-in Guest account: $_"
}

# Configure legacy authentication and name-resolution protections.
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Description 'CIS 2.3.11.6 NTLMv2-only LAN Manager authentication'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Description 'LAN Manager hash storage prevention'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Description 'WDigest credential caching prevention'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 0 -Description 'mDNS disablement'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride' -Value 1 -Description 'WPAD disablement'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 2 -Description 'Strict anonymous access restriction'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Description 'CIS 2.3.10.2: anonymous SAM account enumeration restriction'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Value 1 -Description 'CIS 2.3.10.4: network credential storage prevention'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Description 'CIS 2.3.10.5: exclude anonymous users from Everyone permissions'
Remove-IdempotentRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionPipes' -Description 'CIS 2.3.10.6 anonymous named-pipe list'
Set-IdempotentMultiString -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' -Name 'Machine' -Values @(
    'System\CurrentControlSet\Control\ProductOptions'
    'System\CurrentControlSet\Control\Server Applications'
    'Software\Microsoft\Windows NT\CurrentVersion'
) -Description 'CIS 2.3.10.7 remotely accessible registry paths'
Set-IdempotentMultiString -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' -Name 'Machine' -Values @(
    'System\CurrentControlSet\Control\Print\Printers'
    'System\CurrentControlSet\Services\Eventlog'
    'Software\Microsoft\OLAP Server'
    'Software\Microsoft\Windows NT\CurrentVersion\Print'
    'Software\Microsoft\Windows NT\CurrentVersion\Windows'
    'System\CurrentControlSet\Control\ContentIndex'
    'System\CurrentControlSet\Control\Terminal Server'
    'System\CurrentControlSet\Control\Terminal Server\UserConfig'
    'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration'
    'Software\Microsoft\Windows NT\CurrentVersion\Perflib'
    'System\CurrentControlSet\Services\SysmonLog'
) -Description 'CIS 2.3.10.8 remotely accessible registry paths and subpaths'
Set-IdempotentString -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'restrictremotesam' -Value 'O:BAG:BAD:(A;;RC;;;BA)' -Description 'CIS 2.3.10.10 remote SAM RPC access restriction'
Remove-IdempotentRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionShares' -Description 'CIS 2.3.10.11 anonymous share list'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -Value 0 -Description 'CIS 2.3.10.12 classic local account network authentication'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'AllowLLTDIOOnDomain' -Value 0 -Description 'CIS 18.6.9.1 LLTDIO on domain networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'AllowLLTDIOOnPublicNet' -Value 0 -Description 'CIS 18.6.9.1 LLTDIO on public networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableLLTDIO' -Value 0 -Description 'CIS 18.6.9.1 LLTDIO driver'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'ProhibitLLTDIOOnPrivateNet' -Value 0 -Description 'CIS 18.6.9.1 LLTDIO on private networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'AllowRspndrOnDomain' -Value 0 -Description 'CIS 18.6.9.2 RSPNDR on domain networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'AllowRspndrOnPublicNet' -Value 0 -Description 'CIS 18.6.9.2 RSPNDR on public networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableRspndr' -Value 0 -Description 'CIS 18.6.9.2 RSPNDR driver'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'ProhibitRspndrOnPrivateNet' -Value 0 -Description 'CIS 18.6.9.2 RSPNDR on private networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Value 1 -Description 'CIS 18.6.10.2 Microsoft Peer-to-Peer Networking Services'
Set-IdempotentString -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Value 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1' -Description 'CIS 18.6.14.1 hardened NETLOGON path'
Set-IdempotentString -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Value 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1' -Description 'CIS 18.6.14.1 hardened SYSVOL path'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'EnableRegistrars' -Value 0 -Description 'CIS 18.6.20.1 Windows Connect Now registrars'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'DisableUPnPRegistrar' -Value 0 -Description 'CIS 18.6.20.1 Windows Connect Now UPnP registrar'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'DisableInBand802DOT11Registrar' -Value 0 -Description 'CIS 18.6.20.1 Windows Connect Now in-band 802.11 registrar'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'DisableFlashConfigRegistrar' -Value 0 -Description 'CIS 18.6.20.1 Windows Connect Now flash configuration registrar'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'DisableWPDRegistrar' -Value 0 -Description 'CIS 18.6.20.1 Windows Connect Now WPD registrar'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Value 1 -Description 'CIS 18.6.20.2 Windows Connect Now wizard'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Value 0 -Description 'CIS 18.6.23.2.1 automatic Wi-Fi Sense connections'
# CIS 18.6 network settings disable LLTD network discovery, peer-to-peer networking, Windows
# Connect Now setup, and automatic Wi-Fi Sense hotspot connections. Standard Wi-Fi
# connectivity remains available; NETLOGON and SYSVOL UNC hardening applies when those
# domain paths are accessed.

# CIS 2.3.11 hardening restricts legacy Kerberos, LDAP, and NTLM negotiation. Older network
# systems or applications may fail to authenticate; incoming and outgoing NTLM auditing
# will add events to the NTLM operational log.
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Value 1 -Description 'CIS 2.3.11.1 Local System computer identity for NTLM'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AllowNullSessionFallback' -Value 0 -Description 'CIS 2.3.11.2 LocalSystem NULL session fallback disabled'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' -Name 'AllowOnlineID' -Value 0 -Description 'CIS 2.3.11.3 PKU2U online identity authentication disabled'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Value 2147483640 -Description 'CIS 2.3.11.4 Kerberos encryption types'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientConfidentiality' -Value 1 -Description 'CIS 2.3.11.7 LDAP client encryption negotiation' -Accept { param($v) $v -eq 2 }
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Value 1 -Description 'CIS 2.3.11.8 LDAP client signing negotiation' -Accept { param($v) $v -eq 2 }
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinClientSec' -Value 537395200 -Description 'CIS 2.3.11.9 NTLM client session security'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Value 537395200 -Description 'CIS 2.3.11.10 NTLM server session security'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -Value 2 -Description 'CIS 2.3.11.11 audit incoming NTLM traffic'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Value 1 -Description 'CIS 2.3.11.12 audit outgoing NTLM traffic' -Accept { param($v) $v -eq 2 }
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' -Value 1 -Description 'CIS 2.3.4.1: administrator-only printer driver installation'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint' -Value 2 -Description 'CIS 18.7.1 disable Print Spooler client connections'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'RedirectionguardPolicy' -Value 1 -Description 'CIS 18.7.2 Print Spooler Redirection Guard'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcUseNamedPipeProtocol' -Value 0 -Description 'CIS 18.7.3 outgoing print RPC over TCP'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcAuthentication' -Value 0 -Description 'CIS 18.7.4 outgoing print RPC default authentication'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcProtocols' -Value 5 -Description 'CIS 18.7.5 incoming print RPC over TCP'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'ForceKerberosForRpc' -Value 0 -Description 'CIS 18.7.6 negotiate authentication for incoming print RPC' -Accept { param($v) $v -eq 1 }
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcTcpPort' -Value 0 -Description 'CIS 18.7.7 dynamic print RPC TCP port'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' -Name 'RpcAuthnLevelPrivacyEnabled' -Value 1 -Description 'CIS 18.7.8 print RPC packet privacy'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\WPP' -Name 'WindowsProtectedPrintGroupPolicyState' -Value 1 -Description 'CIS 18.7.9 Windows Protected Print'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Description 'CIS 18.7.10 administrator-only print driver installation'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'CopyFilesPolicy' -Value 1 -Description 'CIS 18.7.11 restrict queue-specific print files to color profiles'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -Value 0 -Description 'CIS 18.7.12 Point and Print new-connection warning and elevation'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'UpdatePromptSettings' -Value 0 -Description 'CIS 18.7.13 Point and Print update warning and elevation'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' -Name 'RequireIpps' -Value 1 -Description 'CIS 18.7.14 require IPPS for IPP printers'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' -Name 'SecurityFlagsBlockUnknownCA' -Value 1 -Description 'CIS 18.7.15 reject IPP certificates from invalid authorities'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' -Name 'SecurityFlagsBlockCertWrongUsage' -Value 1 -Description 'CIS 18.7.16 reject IPP non-server certificates'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' -Name 'SecurityFlagsBlockCertCNInvalid' -Value 1 -Description 'CIS 18.7.17 reject IPP certificates with invalid names'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' -Name 'SecurityFlagsBlockCertDateInvalid' -Value 1 -Description 'CIS 18.7.18 reject IPP certificates with invalid dates'
# Microsoft security baseline for Windows 11 26H2 (not a CIS recommendation): programs cannot
# start Internet Explorer 11 through COM automation.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableInternetExplorerLaunchViaCOM' -Value 1 -Description 'Internet Explorer launch via COM automation disablement'
# Not a CIS or Microsoft baseline recommendation: turn off the lock screen widgets ("Weather and
# more"), which show content fetched from the internet before anyone has signed in.
# DisableWidgetsOnLockScreen = 0 hides them and 1 shows them (tested on Windows 11 build 10.0.26300).
# That matches the values table of Microsoft's Policy CSP page (https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests): 0 = Enabled,
# 1 = Disabled, read as the state of the policy "Disable Widgets On Lock Screen". The behavior is
# as documented; only the name of the value is misleading, because it suggests the opposite.
# Keep this in step with the check 'Lock Screen Widgets Disabled' in Audit.ps1.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'DisableWidgetsOnLockScreen' -Value 0 -Description 'Lock screen widgets disablement (DisableWidgetsOnLockScreen = 0 turns them off)'
# Microsoft security baseline for Windows 11 26H2 (not a CIS recommendation): Windows Ready Print
# driver ranking (prefer the Microsoft IPP Class Driver for IPP printers). Not remediated:
# Windows creates its policy key (HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\
# DriverRanking) so that only SYSTEM can change it; administrators may only read it. Taking
# over that key would weaken a protection Windows put there. The feature is on by default,
# so this script only reports the effective state (the same order as in Audit.ps1: the policy
# value, else the local setting, else on) and never writes it.
try {
    $driverRankingPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'
    $driverRankingValues = @{}
    if (Test-Path -LiteralPath $driverRankingPath) {
        $driverRankingKey = Get-Item -LiteralPath $driverRankingPath -ErrorAction Stop
        foreach ($valueName in $driverRankingKey.GetValueNames()) { $driverRankingValues[$valueName] = $driverRankingKey.GetValue($valueName) }
    }
    $driverRankingOff = $null
    foreach ($valueName in @('UseWindowsReadyPrintDriverRankingGroupPolicy', 'UseWindowsReadyPrintDriverRanking')) {
        if ($driverRankingValues.ContainsKey($valueName)) {
            if ([string]$driverRankingValues[$valueName] -eq '0') { $driverRankingOff = $valueName }
            break
        }
    }
    if ($driverRankingOff) {
        Write-Warning "Windows Ready Print driver ranking is turned off ($driverRankingOff = 0) and this script does not change it, because Windows lets only SYSTEM change its policy key. Audit.ps1 reports it as a failure. To turn it on again, remove that value as SYSTEM, or change the policy where it was set."
    } else {
        Write-Host 'Windows Ready Print driver ranking is already on (it is on by default), so nothing needs to be changed. This script never writes it, because Windows lets only SYSTEM change its policy key.' -ForegroundColor Green
    }
}
catch {
    Write-Warning "Windows Ready Print driver ranking could not be read, so its state is unknown: $_"
}


# Additional CIS Level 1 settings covered by Audit.ps1.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Description 'CIS 2.3.7.2 hide last signed-in user'
Set-IdempotentString -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Value '1' -Description 'CIS 2.3.7.7 lock workstation when smart card is removed' -AcceptedValues @('2', '3')
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoDisconnect' -Value 15 -Description 'CIS 2.3.9.1 SMB server idle session timeout' -Accept { param($v) $v -ge 1 -and $v -le 15 }
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableForcedLogOff' -Value 1 -Description 'CIS 2.3.9.3 disconnect SMB clients when logon hours expire'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SmbServerNameHardeningLevel' -Value 1 -Description 'CIS 2.3.9.4 SMB server SPN target name validation' -Accept { param($v) $v -eq 2 }
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Description 'CIS 18.5.2 IPv6 source routing protection'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Description 'CIS 18.5.3 IPv4 source routing protection'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Value 0 -Description 'CIS 18.5.5 disable ICMP redirects'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NoNameReleaseOnDemand' -Value 1 -Description 'CIS 18.5.7 ignore untrusted NetBIOS name releases'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Value 1 -Description 'CIS 18.5.9 safe DLL search mode'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMDNS' -Value 0 -Description 'CIS 18.6.4.1 disable mDNS by policy'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'EnableAuthRateLimiter' -Value 1 -Description 'CIS 18.6.7.4 SMB server authentication rate limiter'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bowser' -Name 'EnableMailslots' -Value 0 -Description 'CIS 18.6.7.5 disable SMB server remote mailslots'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'MinSmb2Dialect' -Value 785 -Description 'CIS 18.6.7.6 SMB server minimum dialect'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' -Name 'InvalidAuthenticationDelayTimeInMs' -Value 2000 -Description 'CIS 18.6.7.7 SMB server authentication rate limit delay' -Accept { param($v) $v -ge 2000 }
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 -Description 'CIS 18.6.8.4 disable insecure SMB guest logons'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider' -Name 'EnableMailslots' -Value 0 -Description 'CIS 18.6.8.5 disable SMB client remote mailslots'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'MinSmb2Dialect' -Value 785 -Description 'CIS 18.6.8.6 SMB client minimum dialect'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'RequireEncryption' -Value 1 -Description 'CIS 18.6.8.7 require SMB client encryption'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_AllowNetBridge_NLA' -Value 0 -Description 'CIS 18.6.11.2 prohibit network bridge on domain networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value 0 -Description 'CIS 18.6.11.3 prohibit Internet Connection Sharing on domain networks'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Value 3 -Description 'CIS 18.6.21.1 prevent Wi-Fi when connected by Ethernet'

# More CIS Level 1 settings covered by Audit.ps1. Each entry is one registry DWORD:
# Value is written, and an existing value listed in AlsoAccepted is left unchanged.
# Restart marks settings that take effect only after Windows restarts.
# Keep this list identical to $cisAdditionalRegistrySettings in Audit.ps1, except for
# CIS 18.10.80.1 (Enhanced Sign-in Security) and CIS 18.9.29.1 (Block User from Showing Account
# Details on Sign-in), which the audit only reports as information and this script never sets.
$cisAdditionalRegistrySettings = @(
    @{ Id='2.3.17.1'; Title='UAC Admin Approval Mode for the Built-in Administrator Account'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Value=1 }
    @{ Id='2.3.17.3'; Title='UAC Automatically Deny Elevation Requests for Standard Users'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Value=0 }
    @{ Id='2.3.17.4'; Title='UAC Detect Application Installations and Prompt for Elevation'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Value=1 }
    @{ Id='2.3.17.5'; Title='UAC Only Elevate UIAccess Applications in Secure Locations'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableSecureUIAPaths'; Value=1 }
    @{ Id='2.3.17.8'; Title='UAC Virtualize File and Registry Write Failures'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableVirtualization'; Value=1 }
    @{ Id='18.9.20.1.2'; Title='Turn Off Downloading of Print Drivers over HTTP'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableWebPnPDownload'; Value=1 }
    @{ Id='18.9.27.1'; Title='Block Custom SSPs and APs in LSASS'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowCustomSSPsAPs'; Value=0; Restart=$true }
    @{ Id='18.9.29.2'; Title='Do Not Display Network Selection UI on the Sign-in Screen'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontDisplayNetworkSelectionUI'; Value=1 }
    @{ Id='18.9.29.3'; Title='Turn Off App Notifications on the Lock Screen'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DisableLockScreenAppNotifications'; Value=1 }
    @{ Id='18.9.35.6.5'; Title='Require a Password When the Computer Wakes (On Battery)'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='DCSettingIndex'; Value=1 }
    @{ Id='18.9.35.6.6'; Title='Require a Password When the Computer Wakes (Plugged In)'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='ACSettingIndex'; Value=1 }
    @{ Id='18.9.37.1'; Title='Offer Remote Assistance Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowUnsolicited'; Value=0 }
    @{ Id='18.9.37.2'; Title='Solicited Remote Assistance Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Value=0 }
    @{ Id='18.9.38.1'; Title='RPC Endpoint Mapper Client Authentication'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name='EnableAuthEpResolution'; Value=1; Restart=$true }
    @{ Id='18.9.38.2'; Title='Restrict Unauthenticated RPC Clients'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name='RestrictRemoteClients'; Value=1; Restart=$true }
    @{ Id='18.9.54'; Title='Sudo Command Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo'; Name='Enabled'; Value=0 }
    @{ Id='18.10.4.2'; Title='Block Unsigned Per-User Packages by Default'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx'; Name='DisablePerUserUnsignedPackagesByDefault'; Value=1 }
    @{ Id='18.10.4.3'; Title='Prevent Non-Admin Users from Installing Packaged Windows Apps'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx'; Name='BlockNonAdminUserInstall'; Value=1 }
    @{ Id='18.10.5.1'; Title='Block Voice Activation of Apps While Locked'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name='LetAppsActivateWithVoiceAboveLock'; Value=2 }
    @{ Id='18.10.8.1'; Title='Disallow Autoplay for Non-Volume Devices'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Value=1 }
    @{ Id='18.10.8.2'; Title='AutoRun Default Behavior'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Value=1 }
    @{ Id='18.10.15.1'; Title='Hide the Password Reveal Button'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI'; Name='DisablePasswordReveal'; Value=1 }
    @{ Id='18.10.15.2'; Title='Do Not Enumerate Administrator Accounts on Elevation'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name='EnumerateAdministrators'; Value=0 }
    @{ Id='18.10.18.2'; Title='App Installer Experimental Features Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableExperimentalFeatures'; Value=0 }
    @{ Id='18.10.18.3'; Title='App Installer Hash Override Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableHashOverride'; Value=0 }
    @{ Id='18.10.18.4'; Title='App Installer Local Archive Malware Scan Override Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableLocalArchiveMalwareScanOverride'; Value=0 }
    @{ Id='18.10.18.5'; Title='App Installer Microsoft Store Certificate Validation Bypass Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableBypassCertificatePinningForMicrosoftStore'; Value=0 }
    @{ Id='18.10.18.6'; Title='App Installer ms-appinstaller Protocol Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableMSAppInstallerProtocol'; Value=0 }
    @{ Id='18.10.29.3'; Title='Explorer Data Execution Prevention'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoDataExecutionPrevention'; Value=0 }
    @{ Id='18.10.29.4'; Title='Mark of the Web on Files Copied from Insecure Sources'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='DisableMotWOnInsecurePathCopy'; Value=0 }
    @{ Id='18.10.29.5'; Title='Explorer Heap Termination on Corruption'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoHeapTerminationOnCorruption'; Value=0 }
    @{ Id='18.10.29.6'; Title='Shell Protocol Protected Mode'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='PreXPSP2ShellProtocolBehavior'; Value=0 }
    @{ Id='18.10.57.2.3'; Title='Remote Desktop Client Password Saving Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DisablePasswordSaving'; Value=1 }
    @{ Id='18.10.59.5'; Title='Indexing of Encrypted Files Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowIndexingEncryptedStoresOrItems'; Value=0 }
    @{ Id='18.10.73.1'; Title='Recall Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name='AllowRecallEnablement'; Value=0 }
    @{ Id='18.10.81.2'; Title='Windows Ink Workspace Not Allowed Above the Lock Screen'; Path='HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name='AllowWindowsInkWorkspace'; Value=1; AlsoAccepted=@(0) }
    @{ Id='18.10.82.1'; Title='Windows Installer User Control Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='EnableUserControl'; Value=0 }
    @{ Id='18.10.82.2'; Title='Always Install with Elevated Privileges Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Value=0 }
    @{ Id='18.10.83.1'; Title='Password in MPR Notifications Disabled'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableMPR'; Value=0 }
    @{ Id='18.10.83.2'; Title='Automatic Restart Sign-On Disabled'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableAutomaticRestartSignOn'; Value=1 }
    @{ Id='18.10.93.2.1'; Title='Prevent Users from Modifying Exploit Protection Settings'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'; Name='DisallowExploitProtectionOverride'; Value=1 }
    @{ Id='2.3.15.1'; Title='System Objects Require Case Insensitivity for Non-Windows Subsystems'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'; Name='ObCaseInsensitive'; Value=1; Restart=$true }
    @{ Id='2.3.15.2'; Title='System Objects Strengthen Default Permissions of Internal Objects'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name='ProtectionMode'; Value=1; Restart=$true }
    @{ Id='18.1.1.1'; Title='Prevent Enabling Lock Screen Camera'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenCamera'; Value=1 }
    @{ Id='18.1.1.2'; Title='Prevent Enabling Lock Screen Slide Show'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenSlideshow'; Value=1 }
    @{ Id='18.1.2.2'; Title='Online Speech Recognition Services Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'; Name='AllowInputPersonalization'; Value=0 }
    @{ Id='18.4.3'; Title='Certificate Padding Check (64-bit)'; Path='HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config'; Name='EnableCertPaddingCheck'; Value=1 }
    @{ Id='18.4.3'; Title='Certificate Padding Check (32-bit)'; Path='HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'; Name='EnableCertPaddingCheck'; Value=1 }
    @{ Id='18.4.5'; Title='NetBT NodeType P-node'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NodeType'; Value=2; Restart=$true }
    @{ Id='18.9.4.2'; Title='Remote Host Allows Delegation of Non-Exportable Credentials'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name='AllowProtectedCreds'; Value=1 }
    @{ Id='18.9.17.1'; Title='CLFS Log File Authentication'; Path='HKLM:\SYSTEM\CurrentControlSet\Policies'; Name='ClfsAuthenticationChecking'; Value=1; Restart=$true }
    @{ Id='18.9.19.2'; Title='Continue Experiences on This Device Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableCdp'; Value=0 }
    @{ Id='18.9.20.1.6'; Title='Turn Off Internet Download for Web Publishing and Online Ordering Wizards'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoWebServices'; Value=1 }
    @{ Id='18.9.29.4'; Title='Convenience PIN Sign-in Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowDomainPINLogon'; Value=0 }
    @{ Id='18.9.35.6.1'; Title='Network Connectivity During Connected Standby Disabled (On Battery)'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; Name='DCSettingIndex'; Value=0 }
    @{ Id='18.9.35.6.2'; Title='Network Connectivity During Connected Standby Disabled (Plugged In)'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; Name='ACSettingIndex'; Value=0 }
    @{ Id='18.9.53.1.1'; Title='Windows NTP Client Enabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'; Name='Enabled'; Value=1 }
    @{ Id='18.10.6.1'; Title='Microsoft Accounts Optional'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='MSAOptional'; Value=1 }
    @{ Id='18.10.9.1.1'; Title='Enhanced Anti-Spoofing for Facial Features'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name='EnhancedAntiSpoofing'; Value=1 }
    @{ Id='18.10.13.1'; Title='Cloud Consumer Account State Content Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableConsumerAccountStateContent'; Value=1 }
    @{ Id='18.10.14.1'; Title='Require PIN for Wireless Display Pairing'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'; Name='RequirePinForPairing'; Value=2; AlsoAccepted=@(1) }
    @{ Id='18.10.15.3'; Title='Security Questions for Local Accounts Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='NoLocalPasswordResetQuestions'; Value=1 }
    @{ Id='18.10.16.3'; Title='Feedback Notifications Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DoNotShowFeedbackNotifications'; Value=1 }
    @{ Id='18.10.17.1'; Title='Delivery Optimization Without Internet Peering'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name='DODownloadMode'; Value=0; AlsoAccepted=@(1,2) }
    @{ Id='18.10.58.1'; Title='RSS Enclosure Downloads Blocked'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name='DisableEnclosureDownload'; Value=1 }
    @{ Id='18.10.79.1'; Title='Windows Game Recording and Broadcasting Disabled'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='AllowGameDVR'; Value=0 }
    @{ Id='18.11.2'; Title='HTTP Proxy Authentication over Loopback Disabled'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'; Name='DisableProxyAuthenticationSchemes'; Value=256; AlsoAccepted=@(287) }
    @{ Id='18.5.6'; Title='MSS KeepAliveTime 5 Minutes'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='KeepAliveTime'; Value=300000; Restart=$true }
    @{ Id='18.5.10'; Title='MSS TcpMaxDataRetransmissions (IPv6) 3'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'; Name='TcpMaxDataRetransmissions'; Value=3; Restart=$true }
    @{ Id='18.5.11'; Title='MSS TcpMaxDataRetransmissions (IPv4) 3'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='TcpMaxDataRetransmissions'; Value=3; Restart=$true }
    @{ Id='18.6.4.2'; Title='Default IPv6 DNS Servers Turned Off'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='DisableIPv6DefaultDnsServers'; Value=1 }
)
# CIS 18.10.73.1: turning Recall off deletes the snapshots it has saved, and rollback
# cannot restore them. The policy is therefore set only when the Recall optional
# feature is not enabled (or does not exist on this PC).
$recallPolicyCanBeSet = $false
try {
    $recallFeature = @(Get-OptionalFeatureByName -Name 'Recall' | Where-Object { $_ })
    if ($recallFeature.Count -gt 0 -and $recallFeature[0].State -eq 'Enabled') {
        Write-Warning 'CIS 18.10.73.1 Recall is not remediated: the Recall feature is enabled, and turning it off deletes its saved snapshots, which rollback cannot restore. Turn Recall off yourself in Settings > Privacy & security > Recall & snapshots, then run Remediations.ps1 again.'
    } else {
        $recallPolicyCanBeSet = $true
    }
}
catch {
    Write-Error "CIS 18.10.73.1 Recall is not remediated, because the state of the Recall feature could not be read: $_"
}
Write-Host 'CIS 18.10.80.1 Enhanced Sign-in Security (EnableESSwithSupportedPeripherals) is not remediated: with it on, Windows blocks face cameras and fingerprint readers that do not support Enhanced Sign-in Security and deletes the saved enrollments, which rollback cannot bring back. Audit.ps1 still checks it; turn it on yourself only if your hardware supports it.' -ForegroundColor Cyan
# CIS 18.9.29.1 Block User from Showing Account Details on Sign-in is an exception to CIS, for
# usability: it hides the account name and e-mail address on the sign-in screen and turns the
# Windows setting "Show account details such as my email address on the sign-in screen" off,
# which confuses regular users. It is not set, and a value that is already there is not changed.
$accountDetailsNow = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'BlockUserFromShowingAccountDetailsOnSignin' -ErrorAction SilentlyContinue
$accountDetailsState = if ($null -ne $accountDetailsNow) { "currently set to $($accountDetailsNow.BlockUserFromShowingAccountDetailsOnSignin), and left unchanged" } else { 'currently not set' }
Write-Host "CIS 18.9.29.1 Block User from Showing Account Details on Sign-in is not set by this script (an intended exception to CIS, because hiding the account details on the sign-in screen can confuse regular users); $accountDetailsState." -ForegroundColor Cyan
foreach ($setting in $cisAdditionalRegistrySettings) {
    if ($setting.Id -eq '18.10.73.1' -and -not $recallPolicyCanBeSet) { continue }
    $settingDescription = "CIS $($setting.Id) $($setting.Title)"
    $settingParameters = @{ Path = $setting.Path; Name = $setting.Name; Value = $setting.Value; Description = $settingDescription }
    if ($setting.ContainsKey('AlsoAccepted')) {
        $alsoAccepted = @($setting.AlsoAccepted)
        $settingParameters.Accept = { param($v) $v -in $alsoAccepted }.GetNewClosure()
    }
    $changesBefore = $script:RunChangeCount
    Set-IdempotentDword @settingParameters
    if ($setting.Restart) {
        Register-PendingRestart -ChangeCountBefore $changesBefore -Reason $settingDescription
    }
}


# CIS section 19 (user configuration) policies live in each user's own registry hive,
# HKEY_USERS\<SID>. They are set for every user profile that is loaded now (signed in);
# other users get them when Remediations.ps1 runs again while they are signed in. A user
# can change their own policy values, so the audit reports such drift.
# Rollback restores these values while the same profiles are loaded.
# Keep this list identical to $cisUserRegistrySettings in Audit.ps1.
$cisUserRegistrySettings = @(
    @{ Id='19.5.1.1'; Title='Turn Off Toast Notifications on the Lock Screen'; SubKey='Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name='NoToastApplicationNotificationOnLockScreen'; Value=1 }
    @{ Id='19.7.5.1'; Title='Preserve Zone Information in File Attachments'; SubKey='Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='SaveZoneInformation'; Value=2 }
    @{ Id='19.7.5.2'; Title='Notify Antivirus Programs When Opening Attachments'; SubKey='Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='ScanWithAntiVirus'; Value=3 }
    @{ Id='19.7.8.1'; Title='Windows Spotlight on Lock Screen Disabled'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='ConfigureWindowsSpotlight'; Value=2 }
    @{ Id='19.7.8.2'; Title='Third-party Content in Windows Spotlight Disabled'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableThirdPartySuggestions'; Value=1 }
    @{ Id='19.7.8.5'; Title='Spotlight Collection on Desktop Disabled'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableSpotlightCollectionOnDesktop'; Value=1 }
    @{ Id='19.7.26.1'; Title='Prevent Users from Sharing Files Within Their Profile'; SubKey='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoInplaceSharing'; Value=1 }
)
$loadedUserSids = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } | Sort-Object)
if ($loadedUserSids.Count -eq 0) {
    Write-Host 'No user profile is loaded, so the CIS 19 user policies were not configured. Run Remediations.ps1 again while the user is signed in.' -ForegroundColor Yellow
} else {
    $changesBefore = $script:RunChangeCount
    foreach ($userSid in $loadedUserSids) {
        foreach ($setting in $cisUserRegistrySettings) {
            Set-IdempotentDword -Path "Registry::HKEY_USERS\$userSid\$($setting.SubKey)" -Name $setting.Name -Value $setting.Value -Description "CIS $($setting.Id) $($setting.Title) (user $userSid)"
        }
    }
    Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'User policies (CIS 19)' -SignOutOnly
}
# Reputation-based protection (Windows Security > App & browser control).
# "Block" means SmartScreen warns about unrecognized downloaded apps and does not
# offer "Run anyway". To run a trusted unrecognized file, use its Properties > Unblock.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Value 1 -Description 'CIS 18.10.77.2.1 SmartScreen check apps and files'
Set-IdempotentString -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Block' -Description 'CIS 18.10.77.2.1 SmartScreen warn and prevent bypass'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' -Name 'EnableWebContentEvaluation' -Value 1 -Description 'SmartScreen for Microsoft Store apps'
# Enhanced Phishing Protection exists on Windows 11 22H2 (build 22621) and later.
if ([int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber -ge 22621) {
    $phishingProtectionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'
    Set-IdempotentDword -Path $phishingProtectionPath -Name 'CaptureThreatWindow' -Value 1 -Description 'CIS 18.10.77.1.1 Enhanced Phishing Protection automatic data collection'
    Set-IdempotentDword -Path $phishingProtectionPath -Name 'NotifyMalicious' -Value 1 -Description 'CIS 18.10.77.1.2 Enhanced Phishing Protection notify malicious'
    Set-IdempotentDword -Path $phishingProtectionPath -Name 'NotifyPasswordReuse' -Value 1 -Description 'CIS 18.10.77.1.3 Enhanced Phishing Protection notify password reuse'
    Set-IdempotentDword -Path $phishingProtectionPath -Name 'NotifyUnsafeApp' -Value 1 -Description 'CIS 18.10.77.1.4 Enhanced Phishing Protection notify unsafe app'
    Set-IdempotentDword -Path $phishingProtectionPath -Name 'ServiceEnabled' -Value 1 -Description 'CIS 18.10.77.1.5 Enhanced Phishing Protection service enabled'
} else {
    Write-Host 'Enhanced Phishing Protection is not available on this Windows version; skipping CIS 18.10.77.1.1-18.10.77.1.5.' -ForegroundColor DarkGray
}

$deviceGuardPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
$changesBefore = $script:RunChangeCount
Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Description 'CIS 18.9.5.1 virtualization-based security policy'
Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'RequirePlatformSecurityFeatures' -Value 1 -Description 'CIS 18.9.5.2 VBS platform security level' -Accept { param($v) $v -eq 3 }
# CIS 18.9.5.3 and 18.9.5.5 recommend value 1 ("Enabled with UEFI lock"). A UEFI lock is
# stored in the firmware, so a registry rollback cannot turn it off. Value 2 ("Enabled
# without lock") gives the same protection and stays reversible. An existing 1 or 2 is
# compliant and left unchanged.
try {
    $deviceGuardPolicy = Get-ItemProperty -LiteralPath $deviceGuardPolicyPath -ErrorAction SilentlyContinue
    if ($deviceGuardPolicy.HypervisorEnforcedCodeIntegrity -in @(1, 2)) {
        Write-Host "CIS 18.9.5.3 Memory Integrity policy is already enabled (HypervisorEnforcedCodeIntegrity = $($deviceGuardPolicy.HypervisorEnforcedCodeIntegrity))." -ForegroundColor Green
        Save-AlreadyCompliantValue -Path $deviceGuardPolicyPath -Name 'HypervisorEnforcedCodeIntegrity'
    } else {
        # Memory Integrity blocks incompatible kernel drivers, and a blocked boot driver can
        # stop Windows from starting. Only enforce it by policy when it already runs, which
        # proves the current drivers are compatible. Otherwise the Windows Security app must
        # turn it on first, because it checks the drivers and refuses if any are incompatible.
        $deviceGuardStatus = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
        if (@($deviceGuardStatus.SecurityServicesRunning) -contains 2) {
            Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'HypervisorEnforcedCodeIntegrity' -Value 2 -Description 'CIS 18.9.5.3 Memory Integrity (HVCI) without UEFI lock'
        } else {
            Write-Warning 'CIS 18.9.5.3 Memory Integrity policy was not set, because Memory Integrity is not running yet and an incompatible driver could stop Windows from starting. Turn on Windows Security > Device security > Core isolation > Memory integrity (it checks the drivers first), restart, and run Remediations.ps1 again.'
        }
    }
}
catch {
    Write-Error "Failed to configure CIS 18.9.5.3 Memory Integrity policy: $_"
}
Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'HVCIMATRequired' -Value 1 -Description 'CIS 18.9.5.4 require UEFI memory attributes table'
if ((Get-ItemProperty -LiteralPath $deviceGuardPolicyPath -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue).LsaCfgFlags -in @(1, 2)) {
    Write-Host 'CIS 18.9.5.5 Credential Guard policy is already enabled.' -ForegroundColor Green
    Save-AlreadyCompliantValue -Path $deviceGuardPolicyPath -Name 'LsaCfgFlags'
} else {
    Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'LsaCfgFlags' -Value 2 -Description 'CIS 18.9.5.5 Credential Guard without UEFI lock'
}
Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'ConfigureSystemGuardLaunch' -Value 1 -Description 'CIS 18.9.5.6 secure launch'
Set-IdempotentDword -Path $deviceGuardPolicyPath -Name 'ConfigureKernelShadowStacksLaunch' -Value 1 -Description 'CIS 18.9.5.7 kernel-mode hardware-enforced stack protection'
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'Virtualization-based security (Memory Integrity, Credential Guard, Secure Launch, kernel stack protection)'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Value 0 -Description 'CIS 18.9.4.1 CredSSP encryption oracle protection'
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Value 1 -Description 'CIS 18.9.7.2 disable automatic device metadata downloads'
$deviceInstallRestrictionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
Set-IdempotentDword -Path $deviceInstallRestrictionPath -Name 'DenyDeviceClasses' -Value 1 -Description 'CIS 18.9.7.1.1 prevent unapproved IEEE 1394 device classes'
$deviceClassPolicyPath = Join-Path $deviceInstallRestrictionPath 'DenyDeviceClasses'
Set-IdempotentString -Path $deviceClassPolicyPath -Name '1' -Value '{d48179be-ec20-11d1-b6b8-00c04fa372a7}' -Description 'CIS 18.9.7.1.2 block IEEE 1394 device class 1'
Set-IdempotentString -Path $deviceClassPolicyPath -Name '2' -Value '{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}' -Description 'CIS 18.9.7.1.2 block IEEE 1394 device class 2'
Set-IdempotentString -Path $deviceClassPolicyPath -Name '3' -Value '{c06ff265-ae09-48f0-812c-16753d7cba83}' -Description 'CIS 18.9.7.1.2 block IEEE 1394 device class 3'
Set-IdempotentString -Path $deviceClassPolicyPath -Name '4' -Value '{6bdd1fc1-810f-11d0-bec7-08002be2092f}' -Description 'CIS 18.9.7.1.2 block IEEE 1394 device class 4'
Set-IdempotentDword -Path $deviceInstallRestrictionPath -Name 'DenyDeviceClassesRetroactive' -Value 1 -Description 'CIS 18.9.7.1.3 apply IEEE 1394 restriction to existing devices'
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Value 3 -Description 'CIS 18.9.13.1 early launch antimalware driver policy'
# CIS 18.7 keeps local printing and the Print Spooler enabled but disables remote client
# connections and printer sharing. Network printers must use TCP-based RPC and, for IPP,
# IPPS with trusted, valid certificates; Point and Print driver operations require admin
# elevation. Windows Protected Print may affect older non-Mopria printer drivers. The
# client-connection policy requires a Print Spooler restart to take effect; no automatic
# restart is performed to avoid interrupting print jobs.

# Require UAC and a secure-desktop consent prompt for administrator elevation.
$uacPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-IdempotentDword -Path $uacPolicyPath -Name 'EnableLUA' -Value 1 -Description 'User Account Control'
Set-IdempotentDword -Path $uacPolicyPath -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Description 'Administrator elevation consent prompt (secure desktop)'
Set-IdempotentDword -Path $uacPolicyPath -Name 'PromptOnSecureDesktop' -Value 1 -Description 'Secure desktop for elevation prompts'

# Disable inbound Remote Desktop connections.
Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Description 'Remote Desktop connections disabled'

# Require the computer to lock after six minutes of inactivity.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 360 -Description 'Automatic screen lock timeout in seconds (InactivityTimeoutSecs)'

function Get-LocalPasswordPolicy {
    $policyFile = Join-Path $script:UndoStateDirectory ("SecurityPolicy-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        $exportOutput = (& $script:SeceditPath /export /cfg $policyFile /areas SECURITYPOLICY 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "secedit policy export failed: $exportOutput"
        }
        $policyText = Get-Content -LiteralPath $policyFile -Raw -ErrorAction Stop
        $systemAccess = [regex]::Match($policyText, '(?ims)^\[System Access\]\s*(.*?)(?=^\[|\z)')
        if (-not $systemAccess.Success) {
            throw 'Could not find the System Access section in the exported security policy.'
        }

        $settings = @{}
        foreach ($line in ($systemAccess.Groups[1].Value -split '\r?\n')) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(-?\d+)\s*$') {
                $settings[$Matches[1]] = [int]$Matches[2]
            }
        }
        # LockoutDuration and ResetLockoutCount are omitted from the export while
        # account lockout is disabled (LockoutBadCount = 0, the Windows 10 default),
        # and AllowAdministratorLockout is absent on Windows builds that predate it.
        # Missing optional settings are reported as $null (not configured), so they
        # are applied rather than aborting the remediation.
        $requiredSettings = @(
            'PasswordHistorySize'
            'MaximumPasswordAge'
            'MinimumPasswordAge'
            'MinimumPasswordLength'
            'PasswordComplexity'
            'ClearTextPassword'
            'LockoutBadCount'
            'LSAAnonymousNameLookup'
            'ForceLogoffWhenHourExpire'
        )
        $missingSettings = @($requiredSettings | Where-Object { -not $settings.ContainsKey($_) })
        if ($missingSettings.Count -gt 0) {
            throw "Could not parse these settings from the exported security policy: $($missingSettings -join ', ')."
        }
        foreach ($optionalSetting in @('LockoutDuration', 'ResetLockoutCount', 'AllowAdministratorLockout')) {
            if (-not $settings.ContainsKey($optionalSetting)) { $settings[$optionalSetting] = $null }
        }

        $samPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM'
        $relaxedLengthLimits = if (Test-Path -LiteralPath $samPath) {
            (Get-ItemProperty -LiteralPath $samPath -Name 'RelaxMinimumPasswordLengthLimits' -ErrorAction SilentlyContinue).RelaxMinimumPasswordLengthLimits
        }

        [pscustomobject]@{
            PasswordHistorySize = $settings.PasswordHistorySize
            MaximumPasswordAge = $settings.MaximumPasswordAge
            MinimumPasswordAge = $settings.MinimumPasswordAge
            MinimumPasswordLength = $settings.MinimumPasswordLength
            PasswordComplexity = $settings.PasswordComplexity
            PasswordReversibleEncryption = $settings.ClearTextPassword
            LockoutDuration = $settings.LockoutDuration
            LockoutBadCount = $settings.LockoutBadCount
            ResetLockoutCount = $settings.ResetLockoutCount
            AllowAdministratorLockout = $settings.AllowAdministratorLockout
            LSAAnonymousNameLookup = $settings.LSAAnonymousNameLookup
            ForceLogoffWhenHourExpire = $settings.ForceLogoffWhenHourExpire
            RelaxMinimumPasswordLengthLimits = $relaxedLengthLimits
        }
    }
    finally {
        if (Test-Path -LiteralPath $policyFile) {
            Remove-Item -LiteralPath $policyFile -Force -ErrorAction Stop
        }
    }
}

function Get-DesiredLocalPasswordPolicy {
    param(
        [Parameter(Mandatory)][psobject]$CurrentPolicy,
        [Parameter(Mandatory)][System.Collections.IDictionary]$TargetPolicy
    )

    [ordered]@{
        PasswordHistorySize = if ($CurrentPolicy.PasswordHistorySize -ge $TargetPolicy.PasswordHistorySize) { $CurrentPolicy.PasswordHistorySize } else { $TargetPolicy.PasswordHistorySize }
        MaximumPasswordAge = if ($CurrentPolicy.MaximumPasswordAge -ge 1 -and $CurrentPolicy.MaximumPasswordAge -le $TargetPolicy.MaximumPasswordAge) { $CurrentPolicy.MaximumPasswordAge } else { $TargetPolicy.MaximumPasswordAge }
        MinimumPasswordAge = if ($CurrentPolicy.MinimumPasswordAge -ge $TargetPolicy.MinimumPasswordAge) { $CurrentPolicy.MinimumPasswordAge } else { $TargetPolicy.MinimumPasswordAge }
        MinimumPasswordLength = if ($CurrentPolicy.MinimumPasswordLength -ge $TargetPolicy.MinimumPasswordLength) { $CurrentPolicy.MinimumPasswordLength } else { $TargetPolicy.MinimumPasswordLength }
        PasswordComplexity = $TargetPolicy.PasswordComplexity
        ClearTextPassword = $TargetPolicy.ClearTextPassword
        LockoutDuration = if ($CurrentPolicy.LockoutDuration -ge $TargetPolicy.LockoutDuration) { $CurrentPolicy.LockoutDuration } else { $TargetPolicy.LockoutDuration }
        LockoutBadCount = if ($CurrentPolicy.LockoutBadCount -ge 1 -and $CurrentPolicy.LockoutBadCount -le $TargetPolicy.LockoutBadCount) { $CurrentPolicy.LockoutBadCount } else { $TargetPolicy.LockoutBadCount }
        ResetLockoutCount = if ($CurrentPolicy.ResetLockoutCount -ge $TargetPolicy.ResetLockoutCount -and $CurrentPolicy.ResetLockoutCount -le $CurrentPolicy.LockoutDuration) { $CurrentPolicy.ResetLockoutCount } else { $TargetPolicy.ResetLockoutCount }
        AllowAdministratorLockout = $TargetPolicy.AllowAdministratorLockout
        LSAAnonymousNameLookup = $TargetPolicy.LSAAnonymousNameLookup
        ForceLogoffWhenHourExpire = $TargetPolicy.ForceLogoffWhenHourExpire
    }
}

# CIS account policies expire local passwords after 365 days, temporarily lock local
# accounts after repeated failed sign-ins, and disconnect SMB sessions when logon hours
# expire. On a standalone PC this risk is accepted, so no warning is shown.
try {
    $targetPolicy = [ordered]@{
        PasswordHistorySize = 24
        MaximumPasswordAge = 365
        MinimumPasswordAge = 1
        MinimumPasswordLength = 14
        PasswordComplexity = 1
        ClearTextPassword = 0
        LockoutDuration = 15
        LockoutBadCount = 5
        ResetLockoutCount = 15
        AllowAdministratorLockout = 1
        LSAAnonymousNameLookup = 0
        ForceLogoffWhenHourExpire = 1
    }
    $currentPasswordPolicy = Get-LocalPasswordPolicy

    # The policy is recorded for rollback even when it needs no change.
    Save-SecurityPolicyState -BaselineOnly
    $desiredPolicy = Get-DesiredLocalPasswordPolicy -CurrentPolicy $currentPasswordPolicy -TargetPolicy $targetPolicy
    $policyNeedsUpdate = $false
    foreach ($setting in $desiredPolicy.GetEnumerator()) {
        $currentValue = switch ($setting.Key) {
            'ClearTextPassword' { $currentPasswordPolicy.PasswordReversibleEncryption }
            default { $currentPasswordPolicy.($setting.Key) }
        }
        if ($currentValue -ne $setting.Value) {
            $policyNeedsUpdate = $true
            break
        }
    }
    if ($policyNeedsUpdate) {
        Save-SecurityPolicyState
        $policyFile = Join-Path $script:UndoStateDirectory ("SecurityPolicy-{0}.inf" -f [guid]::NewGuid().ToString('N'))
        $databaseFile = Join-Path $script:UndoStateDirectory ("SecurityPolicy-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
        try {
            $policyLines = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
'@
            foreach ($setting in $desiredPolicy.GetEnumerator()) {
                $policyLines += "`r`n$($setting.Key) = $($setting.Value)"
            }
            $policyLines | Set-Content -LiteralPath $policyFile -Encoding Unicode -ErrorAction Stop

            $configureOutput = (& $script:SeceditPath /configure /db $databaseFile /cfg $policyFile /areas SECURITYPOLICY /quiet 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "secedit policy configuration failed: $configureOutput"
            }
            Write-Host 'Updated local CIS account and security option policies.' -ForegroundColor Yellow
            Set-SettingOutcome -Key 'Local security policy' -Outcome Corrected
        }
        finally {
            foreach ($temporaryFile in @($policyFile, $databaseFile)) {
                if (Test-Path -LiteralPath $temporaryFile) {
                    Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction Stop
                }
            }
        }
    } else {
        Write-Host 'Local CIS account and security option policies are already configured.' -ForegroundColor Green
        Set-SettingOutcome -Key 'Local security policy' -Outcome AlreadyInExpectedState
    }

    Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' -Name 'RelaxMinimumPasswordLengthLimits' -Value 1 -Description 'CIS relaxed minimum password length limit'

    $updatedPasswordPolicy = Get-LocalPasswordPolicy
    $policyFailures = [System.Collections.Generic.List[string]]::new()
    if ($updatedPasswordPolicy.PasswordHistorySize -lt 24) { $policyFailures.Add('password history is below 24') }
    if ($updatedPasswordPolicy.MaximumPasswordAge -lt 1 -or $updatedPasswordPolicy.MaximumPasswordAge -gt 365) { $policyFailures.Add('maximum password age is not between 1 and 365 days') }
    if ($updatedPasswordPolicy.MinimumPasswordAge -lt 1) { $policyFailures.Add('minimum password age is below 1 day') }
    if ($updatedPasswordPolicy.MinimumPasswordLength -lt 14) { $policyFailures.Add('minimum password length is below 14 characters') }
    if ($updatedPasswordPolicy.PasswordComplexity -ne 1) { $policyFailures.Add('password complexity is not enabled') }
    if ($updatedPasswordPolicy.PasswordReversibleEncryption -ne 0) { $policyFailures.Add('reversible password encryption is enabled') }
    if ($updatedPasswordPolicy.RelaxMinimumPasswordLengthLimits -ne 1) { $policyFailures.Add('relaxed minimum password length limit is not enabled') }
    if ($null -eq $updatedPasswordPolicy.LockoutDuration -or $updatedPasswordPolicy.LockoutDuration -lt 15) { $policyFailures.Add('account lockout duration is not set or is below 15 minutes') }
    if ($updatedPasswordPolicy.LockoutBadCount -lt 1 -or $updatedPasswordPolicy.LockoutBadCount -gt 5) { $policyFailures.Add('account lockout threshold is not between 1 and 5 attempts') }
    if ($null -eq $updatedPasswordPolicy.ResetLockoutCount -or $updatedPasswordPolicy.ResetLockoutCount -lt 15 -or $updatedPasswordPolicy.ResetLockoutCount -gt $updatedPasswordPolicy.LockoutDuration) { $policyFailures.Add('reset lockout counter is not set, below 15 minutes, or exceeds lockout duration') }
    if ($null -eq $updatedPasswordPolicy.AllowAdministratorLockout) {
        $policyFailures.Add('built-in Administrator account lockout (AllowAdministratorLockout) is not available on this Windows build; install the latest Windows updates and re-run')
    } elseif ($updatedPasswordPolicy.AllowAdministratorLockout -ne 1) {
        $policyFailures.Add('built-in Administrator account lockout is not enabled')
    }
    if ($updatedPasswordPolicy.LSAAnonymousNameLookup -ne 0) { $policyFailures.Add('anonymous SID/name translation is enabled') }
    if ($updatedPasswordPolicy.ForceLogoffWhenHourExpire -ne 1) { $policyFailures.Add('force logoff when logon hours expire is disabled') }
    if ($policyFailures.Count -gt 0) {
        throw "Local CIS security policy verification failed: $($policyFailures -join '; ')."
    }
}
catch {
    # Report and continue, so one failed step does not skip all later remediations.
    Write-Error "Failed to configure local CIS account policies: $($_.Exception.Message)"
}

# Require SMB signing. Only the first recorded original value is kept for rollback.
try {
    $serverService = Get-CimInstance Win32_Service -Filter "Name='LanmanServer'" -ErrorAction Stop
    if ($serverService.StartMode -ne 'Disabled') {
        $serverConfig = Get-SmbServerConfiguration -ErrorAction Stop
        if ($null -eq $script:UndoState.SmbServerRequireSecuritySignature) {
            $script:UndoState.SmbServerRequireSecuritySignature = [bool]$serverConfig.RequireSecuritySignature
            $script:UndoStateDirty = $true
        }
        if ($serverConfig.RequireSecuritySignature -ne $true) {
            Add-UndoChange -Description "SMB Server RequireSecuritySignature: restore $($script:UndoState.SmbServerRequireSecuritySignature)"
            Save-UndoState
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
            Write-Host "Enabled SMB Server RequireSecuritySignature." -ForegroundColor Yellow
            Set-SettingOutcome -Key 'SMB server signing' -Outcome Corrected
        } else {
            Write-Host "SMB Server RequireSecuritySignature is already enabled." -ForegroundColor Green
            Set-SettingOutcome -Key 'SMB server signing' -Outcome AlreadyInExpectedState
        }
    } else {
        # The SMB cmdlets cannot read or change the server configuration while the Server
        # service is disabled, but CIS 2.3.9.2 still requires the policy value, which takes
        # effect as soon as the service is ever enabled again. So the registry value that
        # Set-SmbServerConfiguration would write is set directly (with rollback).
        Set-IdempotentDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Description 'CIS 2.3.9.2 SMB server signing required (LanmanServer disabled)'
    }
}
catch {
    Set-SettingOutcome -Key 'SMB server signing' -Outcome NotCorrected
    Write-Error "Failed to configure SMB server signing: $_"
}

try {
    $clientConfig = Get-SmbClientConfiguration -ErrorAction Stop
    if ($null -eq $script:UndoState.SmbClientRequireSecuritySignature) {
        $script:UndoState.SmbClientRequireSecuritySignature = [bool]$clientConfig.RequireSecuritySignature
        $script:UndoStateDirty = $true
    }
    if ($clientConfig.RequireSecuritySignature -ne $true) {
        Add-UndoChange -Description "SMB Client RequireSecuritySignature: restore $($script:UndoState.SmbClientRequireSecuritySignature)"
        Save-UndoState
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
        Write-Host "Enabled SMB Client RequireSecuritySignature." -ForegroundColor Yellow
        Set-SettingOutcome -Key 'SMB client signing' -Outcome Corrected
    } else {
        Write-Host "SMB Client RequireSecuritySignature is already enabled." -ForegroundColor Green
        Set-SettingOutcome -Key 'SMB client signing' -Outcome AlreadyInExpectedState
    }
}
catch {
    Set-SettingOutcome -Key 'SMB client signing' -Outcome NotCorrected
    Write-Error "Failed to configure SMB client signing: $_"
}

# Get all active (IPEnabled) network adapters
$InterfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"

$changesBefore = $script:RunChangeCount
if (Test-Path $InterfacesPath) {
    $adapterKeys = Get-ChildItem -Path $InterfacesPath
    foreach ($key in $adapterKeys) {
        $subKeyPath = $key.PSPath
        Set-IdempotentDword -Path $subKeyPath -Name 'NetbiosOptions' -Value 2 -Description "NetBIOS disablement on interface $($key.PSChildName)"
    }
}
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'NetBIOS over TCP/IP disablement'

# Microsoft Defender settings with a Disabled (0) / Enabled (1) / AuditMode (2) style
# mode are set to Enabled. The mode is recorded the first time it is seen, even when it
# needs no change, so later runs cannot replace it, and only after Defender has returned
# the current mode. If the change itself fails (for example because another antivirus
# product is active), the entry that announced the change is removed again.
function Set-DefenderModeEnabled {
    param(
        # Get-MpPreference property name, which is also the Set-MpPreference parameter name.
        [Parameter(Mandatory)][string]$PreferenceName,
        [Parameter(Mandatory)][string]$UndoKey,
        [Parameter(Mandatory)][string]$Description
    )

    try {
        $currentSetting = (Get-MpPreference -ErrorAction Stop).$PreferenceName
        if ($null -eq $currentSetting) {
            throw "Get-MpPreference did not return $PreferenceName."
        }
        if ($null -eq $script:UndoState[$UndoKey]) {
            $script:UndoState[$UndoKey] = [int]$currentSetting
            $script:UndoStateDirty = $true
        }
        if ([int]$currentSetting -eq 1) {
            Write-Host "$Description is already enabled." -ForegroundColor Green
            Set-SettingOutcome -Key "Defender|$UndoKey" -Outcome AlreadyInExpectedState
            return
        }

        $undoDescription = "${Description}: restore mode $([int]$script:UndoState[$UndoKey])"
        $listedNow = $undoDescription -notin @($script:UndoState['Changes'])
        Add-UndoChange -Description $undoDescription
        Save-UndoState
        try {
            $setParameters = @{ $PreferenceName = 'Enabled' }
            Set-MpPreference @setParameters -ErrorAction Stop
        }
        catch {
            if ($listedNow) {
                $script:UndoState['Changes'] = @($script:UndoState['Changes'] | Where-Object { $_ -ne $undoDescription })
                Save-UndoState
            }
            throw
        }
        if ([int](Get-MpPreference -ErrorAction Stop).$PreferenceName -ne 1) {
            throw "Verification failed: $PreferenceName is not Enabled after the change."
        }
        Write-Host "Enabled $Description." -ForegroundColor Yellow
        Set-SettingOutcome -Key "Defender|$UndoKey" -Outcome Corrected
    }
    catch {
        Set-SettingOutcome -Key "Defender|$UndoKey" -Outcome NotCorrected
        Write-Error "Failed to enable ${Description}: $($_.Exception.Message)"
    }
}

# Controlled Folder Access: 0 = Disabled, 1 = Enabled, 2 = Audit mode,
# 3 = Block disk modification only, 4 = Audit disk modification only.
Set-DefenderModeEnabled -PreferenceName 'EnableControlledFolderAccess' -UndoKey 'DefenderControlledFolderAccess' -Description 'Defender Controlled Folder Access'
# Network Protection: 0 = Disabled, 1 = Enabled, 2 = Audit mode.
Set-DefenderModeEnabled -PreferenceName 'EnableNetworkProtection' -UndoKey 'DefenderNetworkProtection' -Description 'Defender Network Protection'
# Potentially Unwanted App (PUA) Protection: 0 = Disabled, 1 = Enabled, 2 = Audit mode.
# Tamper Protection does not cover this setting, so rollback can restore the original mode.
Set-DefenderModeEnabled -PreferenceName 'PUAProtection' -UndoKey 'DefenderPuaProtection' -Description 'Defender Potentially Unwanted App (PUA) Protection'

# Microsoft Defender engine settings that are a plain value, not an Enabled / Disabled mode
# (cloud block level, extended cloud check time, removable drive scanning). The original value
# is recorded the first time it is seen, even when it needs no change, and only once Defender
# has returned the current value; if the change itself fails (for example because another
# antivirus product is active), the entry that announced the change is removed again.
function Set-DefenderPreferenceValue {
    param(
        # Get-MpPreference property name, which is also the Set-MpPreference parameter name.
        [Parameter(Mandatory)][string]$PreferenceName,
        [Parameter(Mandatory)]$TargetValue,
        # Receives the current value; $true when it already meets the baseline (a stricter value too).
        [Parameter(Mandatory)][scriptblock]$IsCompliant,
        [Parameter(Mandatory)][string]$UndoKey,
        [Parameter(Mandatory)][string]$Description,
        # Reads the current value; by default the Get-MpPreference property $PreferenceName.
        [scriptblock]$GetValue
    )

    if (-not $GetValue) { $GetValue = { (Get-MpPreference -ErrorAction Stop).$PreferenceName } }
    try {
        $currentValue = & $GetValue
        if ($null -eq $currentValue) {
            throw "Get-MpPreference did not return $PreferenceName."
        }
        if ($null -eq $script:UndoState[$UndoKey]) {
            $script:UndoState[$UndoKey] = $currentValue
            $script:UndoStateDirty = $true
        }
        if (& $IsCompliant $currentValue) {
            Write-Host "$Description is already configured ($currentValue)." -ForegroundColor Green
            Set-SettingOutcome -Key "Defender|$UndoKey" -Outcome AlreadyInExpectedState
            return
        }

        $undoDescription = "${Description}: restore value $($script:UndoState[$UndoKey])"
        $listedNow = $undoDescription -notin @($script:UndoState['Changes'])
        Add-UndoChange -Description $undoDescription
        Save-UndoState
        try {
            $setParameters = @{ $PreferenceName = $TargetValue }
            Set-MpPreference @setParameters -ErrorAction Stop
        }
        catch {
            if ($listedNow) {
                $script:UndoState['Changes'] = @($script:UndoState['Changes'] | Where-Object { $_ -ne $undoDescription })
                Save-UndoState
            }
            throw
        }
        $newValue = & $GetValue
        if (-not (& $IsCompliant $newValue)) {
            throw "Verification failed: $PreferenceName is $newValue after the change."
        }
        Write-Host "Set $Description to $newValue." -ForegroundColor Yellow
        Set-SettingOutcome -Key "Defender|$UndoKey" -Outcome Corrected
    }
    catch {
        Set-SettingOutcome -Key "Defender|$UndoKey" -Outcome NotCorrected
        Write-Error "Failed to configure ${Description}: $($_.Exception.Message)"
    }
}

# Microsoft security baseline for Windows 11 26H2 (not a CIS recommendation). The cloud block
# level High (2) and the extended cloud check of 50 seconds make Defender wait for a cloud
# verdict on unknown files and block more of them; a stricter level (4 or 6) is kept.
# Removable drives are scanned in full scans. The "send all samples" setting of the Microsoft
# baseline is not set: sending files to Microsoft is a privacy choice.
Set-DefenderPreferenceValue -PreferenceName 'CloudBlockLevel' -TargetValue 'High' -IsCompliant { param($v) [int]$v -in @(2, 4, 6) } -UndoKey 'DefenderCloudBlockLevel' -Description 'Defender cloud protection level (High)'
Set-DefenderPreferenceValue -PreferenceName 'CloudExtendedTimeout' -TargetValue 50 -IsCompliant { param($v) [int]$v -ge 50 } -UndoKey 'DefenderCloudExtendedTimeout' -Description 'Defender extended cloud check (50 seconds)' -GetValue { Get-DefenderCloudExtendedTimeout }
Set-DefenderPreferenceValue -PreferenceName 'DisableRemovableDriveScanning' -TargetValue $false -IsCompliant { param($v) $v -eq $false } -UndoKey 'DefenderRemovableDriveScanningDisabled' -Description 'Defender removable drive scanning'

# Tamper Protection cannot be configured through PowerShell during normal operation.
try {
    $tamperProtectionStatus = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected
    if ($tamperProtectionStatus -eq $true) {
        Write-Host "Microsoft Defender Tamper Protection is enabled." -ForegroundColor Green
    } elseif ($tamperProtectionStatus -eq $false) {
        Write-Warning "Microsoft Defender Tamper Protection is disabled. Turn it on in Windows Security > Virus & threat protection > Manage settings; PowerShell cannot enable it during normal operation."
    } else {
        throw 'Get-MpComputerStatus did not return an IsTamperProtected status.'
    }
}
catch {
    Write-Error "Failed to verify Microsoft Defender Tamper Protection: $_"
}

# Re-enable core system exploit mitigations only when explicitly disabled.
$changesBefore = $script:RunChangeCount
try {
    $requiredMitigations = @(
        @{ Name = 'DEP'; Section = 'Dep'; Property = 'Enable'; CmdletName = 'DEP' }
        @{ Name = 'CFG'; Section = 'Cfg'; Property = 'Enable'; CmdletName = 'CFG' }
        @{ Name = 'Bottom-Up ASLR'; Section = 'Aslr'; Property = 'BottomUp'; CmdletName = 'BottomUp' }
        @{ Name = 'SEHOP'; Section = 'Sehop'; Property = 'Enable'; CmdletName = 'SEHOP' }
    )
    $systemMitigations = Get-ProcessMitigation -System -ErrorAction Stop
    foreach ($mitigation in $requiredMitigations) {
        $section = $systemMitigations.PSObject.Properties[$mitigation.Section]
        if ($null -eq $section) {
            throw "Get-ProcessMitigation did not return the $($mitigation.Section) section."
        }
        $setting = $section.Value.PSObject.Properties[$mitigation.Property]
        if ($null -eq $setting) {
            throw "Get-ProcessMitigation did not return $($mitigation.Section).$($mitigation.Property)."
        }

        $state = [string]$setting.Value
        if ($state -eq 'OFF') {
            $script:UndoState.ExploitMitigations[$mitigation.CmdletName] = $state
            Add-UndoChange -Description "System exploit mitigation $($mitigation.Name): restore state $state"
            Save-UndoState
            Set-ProcessMitigation -System -Enable $mitigation.CmdletName -ErrorAction Stop
            Write-Host "Enabled system exploit mitigation: $($mitigation.Name)." -ForegroundColor Yellow
            Set-SettingOutcome -Key "Exploit mitigation|$($mitigation.Name)" -Outcome Corrected
        } elseif ($state -eq 'ON' -or $state -eq 'NOTSET') {
            Write-Host "System exploit mitigation $($mitigation.Name) is enabled or using the Windows default ($state)." -ForegroundColor Green
            Set-SettingOutcome -Key "Exploit mitigation|$($mitigation.Name)" -Outcome AlreadyInExpectedState
        } else {
            throw "Unexpected state '$state' for system exploit mitigation $($mitigation.Name)."
        }
    }

    $updatedMitigations = Get-ProcessMitigation -System -ErrorAction Stop
    foreach ($mitigation in $requiredMitigations) {
        $section = $updatedMitigations.PSObject.Properties[$mitigation.Section]
        $setting = if ($null -ne $section) { $section.Value.PSObject.Properties[$mitigation.Property] } else { $null }
        if ($null -eq $setting -or [string]$setting.Value -notin @('ON', 'NOTSET')) {
            $state = if ($null -ne $setting) { [string]$setting.Value } else { 'missing' }
            throw "Verification failed for system exploit mitigation $($mitigation.Name): $state."
        }
    }
}
catch {
    Write-Error "Failed to configure Windows Exploit Protection system mitigations: $_"
}
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'System exploit protection (DEP, CFG, ASLR, SEHOP)'

$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-IdempotentDword -Path $Path -Name 'RestrictNullSessAccess' -Value 1 -Description 'Anonymous SMB share access restriction'

# Baseline ASR rules. Action is what this script sets (1 = Block, 2 = Audit) and
# Accepted lists the actions that already meet the baseline and are left unchanged
# (6 = Warn). The ransomware and obfuscated-script rules can block self-built programs
# and scripts, so they start in Audit mode; an existing Warn or Block is kept. The
# PsExec and WMI process creation rule starts in Audit mode as in the Microsoft baseline,
# because it can block remote administration tools; an existing Warn or Block is kept.
# Keep this list identical to $asrBaselineRules in Audit.ps1.
$asrBaselineRules = @(
    @{ Id='56a863a9-875e-4185-98a7-b882c64b5ce5'; Name='Block abuse of exploited vulnerable signed drivers'; Action=1; Accepted=@(1) }
    @{ Id='9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Name='Block credential stealing from LSASS'; Action=1; Accepted=@(1) }
    @{ Id='e6db77e5-3df2-4cf1-b95a-636979351e5b'; Name='Block persistence through WMI event subscription'; Action=1; Accepted=@(1) }
    @{ Id='d4f940ab-401b-4efc-aadc-ad5f3c50688a'; Name='Block all Office applications from creating child processes'; Action=1; Accepted=@(1) }
    @{ Id='3b576869-a4ec-4529-8536-b80a7769e899'; Name='Block Office applications from creating executable content'; Action=1; Accepted=@(1) }
    @{ Id='be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Name='Block executable content from email client and webmail'; Action=1; Accepted=@(1) }
    @{ Id='75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Name='Block Office applications from injecting code into other processes'; Action=1; Accepted=@(1) }
    @{ Id='92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; Name='Block Win32 API calls from Office macros'; Action=1; Accepted=@(1) }
    @{ Id='d3e037e1-3eb8-44c8-a917-57927947596d'; Name='Block JavaScript or VBScript from launching downloaded executable content'; Action=1; Accepted=@(1) }
    @{ Id='b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Name='Block untrusted and unsigned processes that run from USB'; Action=1; Accepted=@(1) }
    @{ Id='7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Name='Block Adobe Reader from creating child processes'; Action=1; Accepted=@(1) }
    @{ Id='26190899-1602-49e8-8b27-eb1d0a1ce869'; Name='Block Office communication application from creating child processes'; Action=1; Accepted=@(1) }
    @{ Id='c1db55ab-c21a-4637-bb3f-a12568109d35'; Name='Use advanced protection against ransomware'; Action=2; Accepted=@(1,2,6) }
    @{ Id='5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Name='Block execution of potentially obfuscated scripts'; Action=2; Accepted=@(1,2,6) }
    @{ Id='d1e49aac-8f56-4280-b9ba-993a6d77406c'; Name='Block process creations originating from PSExec and WMI commands'; Action=2; Accepted=@(1,2,6) }
)

try {
    $asrPreference = Get-MpPreference -ErrorAction Stop
    # With no ASR rules configured, Defender returns $null, and @($null) would be a
    # one-element list containing $null. Filter it out so an empty list stays empty.
    $currentRuleIds = @($asrPreference.AttackSurfaceReductionRules_Ids | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
    $currentRuleActions = @($asrPreference.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    if ($currentRuleIds.Count -ne $currentRuleActions.Count) {
        throw 'Defender returned mismatched ASR rule ID and action lists.'
    }
    # Hashtable keys are case-insensitive, so the case Defender returns does not matter.
    $currentAsrActions = @{}
    for ($index = 0; $index -lt $currentRuleIds.Count; $index++) {
        $currentAsrActions[[string]$currentRuleIds[$index]] = [int]$currentRuleActions[$index]
    }
    # Only rules that are missing or have an action outside Accepted are changed.
    $asrRulesToSet = @($asrBaselineRules | Where-Object {
        -not $currentAsrActions.ContainsKey($_.Id) -or $currentAsrActions[$_.Id] -notin $_.Accepted
    })

    # Keep the first recorded original, so later runs cannot overwrite it. It is recorded
    # even when no rule needs a change.
    if ($null -eq $script:UndoState.DefenderAsrRuleIds) {
        $script:UndoState.DefenderAsrRuleIds = @($currentRuleIds)
        $script:UndoState.DefenderAsrRuleActions = @($currentRuleActions | ForEach-Object { [int]$_ })
        $script:UndoStateDirty = $true
    }
    if ($asrRulesToSet.Count -gt 0) {
        Add-UndoChange -Description 'Defender ASR rules: restore the original IDs and action list'
        Save-UndoState
        $asrTargetActions = @{}
        foreach ($rule in $asrRulesToSet) { $asrTargetActions[$rule.Id] = [int]$rule.Action }
        # Set-MpPreference replaces the whole list, so every existing rule is passed
        # again: with its new action when it is changed, otherwise with its current one.
        $mergedRuleIds = [System.Collections.Generic.List[string]]::new()
        $mergedRuleActions = [System.Collections.Generic.List[int]]::new()
        $includedRuleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        for ($index = 0; $index -lt $currentRuleIds.Count; $index++) {
            $ruleId = [string]$currentRuleIds[$index]
            if ($includedRuleIds.Add($ruleId)) {
                $mergedRuleIds.Add($ruleId)
                if ($asrTargetActions.ContainsKey($ruleId)) {
                    $mergedRuleActions.Add([int]$asrTargetActions[$ruleId])
                } else {
                    $mergedRuleActions.Add([int]$currentAsrActions[$ruleId])
                }
            }
        }
        foreach ($rule in $asrRulesToSet) {
            if ($includedRuleIds.Add($rule.Id)) {
                $mergedRuleIds.Add($rule.Id)
                $mergedRuleActions.Add([int]$rule.Action)
            }
        }
        Set-MpPreference -AttackSurfaceReductionRules_Ids $mergedRuleIds.ToArray() -AttackSurfaceReductionRules_Actions $mergedRuleActions.ToArray() -ErrorAction Stop
        $verifiedAsrPreference = Get-MpPreference -ErrorAction Stop
        $verifiedAsrActions = @{}
        $verifiedIds = @($verifiedAsrPreference.AttackSurfaceReductionRules_Ids | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
        $verifiedActions = @($verifiedAsrPreference.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
        if ($verifiedIds.Count -ne $verifiedActions.Count) {
            throw 'Defender returned mismatched ASR rule ID and action lists after update.'
        }
        for ($index = 0; $index -lt $verifiedIds.Count; $index++) {
            $verifiedAsrActions[[string]$verifiedIds[$index]] = [int]$verifiedActions[$index]
        }
        foreach ($rule in $asrBaselineRules) {
            if (-not $verifiedAsrActions.ContainsKey($rule.Id) -or $verifiedAsrActions[$rule.Id] -notin $rule.Accepted) {
                throw "ASR rule verification failed for '$($rule.Name)' ($($rule.Id))."
            }
        }
        Set-SettingOutcome -Key 'Defender|ASR rules' -Outcome Corrected
        foreach ($rule in $asrRulesToSet) {
            $modeName = if ($rule.Action -eq 1) { 'Block' } else { 'Audit' }
            Write-Host "Set ASR rule '$($rule.Name)' to $modeName mode." -ForegroundColor Yellow
        }
        if (@($asrRulesToSet | Where-Object { $_.Action -eq 2 }).Count -gt 0) {
            Write-Host "ASR rules in Audit mode only log what they would block (event 1122 in the 'Microsoft-Windows-Windows Defender/Operational' log). After reviewing those events, switch a rule to Block with: Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Enabled" -ForegroundColor Cyan
        }
    } else {
        Write-Host "All baseline ASR rules already meet the baseline." -ForegroundColor Green
        Set-SettingOutcome -Key 'Defender|ASR rules' -Outcome AlreadyInExpectedState
    }
}
catch {
    Set-SettingOutcome -Key 'Defender|ASR rules' -Outcome NotCorrected
    Write-Error "Failed to configure ASR rules: $_"
}

# Smart App Control (SAC) state from the code integrity policy: 0 Off, 1 On, 2 Evaluation.
# Windows versions without SAC have no such value, which counts as Off. Returns $null
# when the value cannot be read.
function Get-SmartAppControlState {
    $ciPolicyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    try {
        if (-not (Test-Path -LiteralPath $ciPolicyPath -PathType Container)) { return 0 }
        $ciPolicy = Get-ItemProperty -LiteralPath $ciPolicyPath -ErrorAction Stop
        if ($null -eq $ciPolicy.PSObject.Properties['VerifiedAndReputablePolicyState']) { return 0 }
        return [int]$ciPolicy.VerifiedAndReputablePolicyState
    } catch {
        return $null
    }
}

# Configure the Windows diagnostic data policy.
# AllowTelemetry = 0 requests Diagnostic data off on supported editions.
# Smart App Control can only be turned on while optional diagnostic data is allowed.
# Whether turning that data off later disables an active Smart App Control is not
# documented. If it did, rollback.ps1 could not undo it: restoring the policy does not
# turn Smart App Control on again (that may need a reset of Windows), and Evaluation
# mode exists only after a fresh installation. So the policy is set only while Smart App
# Control is Off; when it is On, in Evaluation or its state cannot be read, this step is
# skipped (see Design.md, section 11).
$smartAppControlState = Get-SmartAppControlState

if ($smartAppControlState -ne 0) {
    $smartAppControlDescription = switch ($smartAppControlState) {
        1 { 'On' }
        2 { 'in Evaluation mode' }
        default { 'in an unknown state (its setting could not be read)' }
    }
    Write-Host ("Skipped the diagnostic data policy (AllowTelemetry = 0, CIS 18.10.16.1): Smart App Control is $smartAppControlDescription. " +
        "Smart App Control requires optional diagnostic data, and turning that off could disable it, which rollback.ps1 cannot undo. " +
        "To apply this setting anyway, turn Smart App Control off in Windows Security first.") -ForegroundColor Yellow
} else {
    Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Description 'CIS 18.10.16.1 diagnostic data policy (AllowTelemetry)'
}

# Disable Tailored Experiences based on diagnostic data.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1 -Description 'Tailored Experiences policy (DisableTailoredExperiencesWithDiagnosticData)'

# Disable consumer features and app suggestions.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1 -Description 'Consumer features and app suggestions policy (DisableWindowsConsumerFeatures)'

# Disable the Advertising ID through policy.
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Value 1 -Description 'Advertising ID policy (DisabledByGroupPolicy)'

# Configure explicit firewall defaults for all profiles: block unsolicited inbound
# traffic and allow outbound connections unless a deliberate policy overrides this.
try {
    $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $expectedFirewallProfiles = @('Domain', 'Private', 'Public')
    if ($firewallProfiles.Count -ne $expectedFirewallProfiles.Count -or
        @($firewallProfiles.Name | Where-Object { $_ -notin $expectedFirewallProfiles }).Count -gt 0 -or
        @($expectedFirewallProfiles | Where-Object { $_ -notin $firewallProfiles.Name }).Count -gt 0) {
        throw "Expected Domain, Private, and Public firewall profiles; found: $(@($firewallProfiles.Name) -join ', ')."
    }

    # The original settings of every profile are recorded the first time, even when no
    # profile needs a change.
    foreach ($firewallProfile in $firewallProfiles) {
        if (-not $script:UndoState.FirewallProfiles.ContainsKey($firewallProfile.Name)) {
            $script:UndoState.FirewallProfiles[$firewallProfile.Name] = [pscustomobject]@{
                Enabled = [string]$firewallProfile.Enabled
                DefaultInboundAction = [string]$firewallProfile.DefaultInboundAction
                DefaultOutboundAction = [string]$firewallProfile.DefaultOutboundAction
            }
            $script:UndoStateDirty = $true
        }
    }
    $firewallProfileNames = @($firewallProfiles | ForEach-Object { [string]$_.Name })
    $profilesNeedingUpdate = @($firewallProfiles | Where-Object {
        $_.Enabled -ne $true -or $_.DefaultInboundAction -ne 'Block' -or $_.DefaultOutboundAction -ne 'Allow'
    })
    if ($profilesNeedingUpdate.Count -gt 0) {
        foreach ($firewallProfile in $profilesNeedingUpdate) {
            # Keep the first recorded original, so later runs cannot overwrite it
            # (or drop the notification setting saved with it).
            if (-not $script:UndoState.FirewallProfiles.ContainsKey($firewallProfile.Name)) {
                $script:UndoState.FirewallProfiles[$firewallProfile.Name] = [pscustomobject]@{
                    Enabled = [string]$firewallProfile.Enabled
                    DefaultInboundAction = [string]$firewallProfile.DefaultInboundAction
                    DefaultOutboundAction = [string]$firewallProfile.DefaultOutboundAction
                }
            }
            Add-UndoChange -Description "Windows Firewall $($firewallProfile.Name) profile: restore enabled and inbound/outbound defaults"
        }
        Save-UndoState
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
        $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $mismatchedProfiles = @($firewallProfiles | Where-Object {
            $_.Enabled -ne $true -or $_.DefaultInboundAction -ne 'Block' -or $_.DefaultOutboundAction -ne 'Allow'
        })
        if ($mismatchedProfiles.Count -gt 0) {
            throw "Firewall profile verification failed: $(@($mismatchedProfiles | ForEach-Object { "$($_.Name): enabled=$($_.Enabled), inbound=$($_.DefaultInboundAction), outbound=$($_.DefaultOutboundAction)" }) -join '; ')."
        }
        Write-Host "Updated Windows Firewall profiles: enabled, inbound Block, outbound Allow." -ForegroundColor Yellow
        foreach ($profileName in @($firewallProfileNames)) {
            Set-SettingOutcome -Key "Firewall profile|$profileName" -Outcome $(if ($profileName -in @($profilesNeedingUpdate.Name)) { 'Corrected' } else { 'AlreadyInExpectedState' })
        }
    } else {
        Write-Host "All Windows Firewall profiles are enabled and already use inbound Block, outbound Allow." -ForegroundColor Green
        foreach ($profileName in @($firewallProfileNames)) { Set-SettingOutcome -Key "Firewall profile|$profileName" -Outcome AlreadyInExpectedState }
    }
}
catch {
    foreach ($profileName in @($firewallProfileNames)) { Set-SettingOutcome -Key "Firewall profile|$profileName" -Outcome NotCorrected }
    Write-Error "Failed to configure Windows Firewall profile defaults: $_"
}

# CIS 9.2.3 and 9.3.3: disable Windows Firewall app-block notifications on
# Private and Public profiles while preserving the original values for rollback.
try {
    $notificationProfiles = @(Get-NetFirewallProfile -Name Private,Public -ErrorAction Stop)
    # The notification setting of the Private and Public profiles is recorded as well, even
    # when it needs no change.
    foreach ($notificationProfile in $notificationProfiles) {
        if ($script:UndoState.FirewallProfiles.ContainsKey($notificationProfile.Name)) {
            $savedProfile = $script:UndoState.FirewallProfiles[$notificationProfile.Name]
            if (-not $savedProfile.PSObject.Properties['NotifyOnListen']) {
                $savedProfile | Add-Member -MemberType NoteProperty -Name NotifyOnListen -Value ([string]$notificationProfile.NotifyOnListen)
                $script:UndoStateDirty = $true
            }
        } else {
            $script:UndoState.FirewallProfiles[$notificationProfile.Name] = [pscustomobject]@{
                Enabled = [string]$notificationProfile.Enabled
                DefaultInboundAction = [string]$notificationProfile.DefaultInboundAction
                DefaultOutboundAction = [string]$notificationProfile.DefaultOutboundAction
                NotifyOnListen = [string]$notificationProfile.NotifyOnListen
            }
            $script:UndoStateDirty = $true
        }
    }
    $profilesNeedingNotificationUpdate = @($notificationProfiles | Where-Object { [string]$_.NotifyOnListen -ne 'False' })
    if ($profilesNeedingNotificationUpdate.Count -gt 0) {
        foreach ($notificationProfile in $profilesNeedingNotificationUpdate) {
            if ($script:UndoState.FirewallProfiles.ContainsKey($notificationProfile.Name)) {
                $savedProfile = $script:UndoState.FirewallProfiles[$notificationProfile.Name]
                if (-not $savedProfile.PSObject.Properties['NotifyOnListen']) {
                    $savedProfile | Add-Member -MemberType NoteProperty -Name NotifyOnListen -Value ([string]$notificationProfile.NotifyOnListen)
                }
            } else {
                $script:UndoState.FirewallProfiles[$notificationProfile.Name] = [pscustomobject]@{
                    Enabled = [string]$notificationProfile.Enabled
                    DefaultInboundAction = [string]$notificationProfile.DefaultInboundAction
                    DefaultOutboundAction = [string]$notificationProfile.DefaultOutboundAction
                    NotifyOnListen = [string]$notificationProfile.NotifyOnListen
                }
            }
            Add-UndoChange -Description "Windows Firewall $($notificationProfile.Name) profile: restore app-block notifications"
        }
        Save-UndoState
        Set-NetFirewallProfile -Profile Private,Public -NotifyOnListen 'False' -ErrorAction Stop
        $verifiedNotificationProfiles = @(Get-NetFirewallProfile -Name Private,Public -ErrorAction Stop)
        $notificationFailures = @($verifiedNotificationProfiles | Where-Object { [string]$_.NotifyOnListen -ne 'False' })
        if ($notificationFailures.Count -gt 0) {
            throw "Firewall notification verification failed for: $(@($notificationFailures.Name) -join ', ')."
        }
        Write-Host 'Disabled Windows Firewall notifications for Private and Public profiles.' -ForegroundColor Yellow
        foreach ($notificationProfile in $notificationProfiles) {
            Set-SettingOutcome -Key "Firewall notifications|$($notificationProfile.Name)" -Outcome $(if ($notificationProfile.Name -in @($profilesNeedingNotificationUpdate.Name)) { 'Corrected' } else { 'AlreadyInExpectedState' })
        }
    } else {
        Write-Host 'Windows Firewall notifications are already disabled for Private and Public profiles.' -ForegroundColor Green
        foreach ($notificationProfile in $notificationProfiles) { Set-SettingOutcome -Key "Firewall notifications|$($notificationProfile.Name)" -Outcome AlreadyInExpectedState }
    }
}
catch {
    Write-Error "Failed to configure Windows Firewall notifications: $_"
}

# Disable AutoRun for all drive types.
$changesBefore = $script:RunChangeCount
Set-IdempotentDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Description 'AutoRun restriction for all drive types (NoDriveTypeAutoRun)'
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'AutoRun restriction' -SignOutOnly

# Define target subcategories and their required Success/Failure auditing states
$auditSettings = @(
    @{ Subcategory = "Logon"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Logoff"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Special Logon"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable" }
)

foreach ($setting in $auditSettings) {
    $subcat = $setting.Subcategory
    $success = $setting.Success
    $failure = $setting.Failure

    try {
        $expectedSetting = if ($success -eq 'enable' -and $failure -eq 'enable') {
            'Success and Failure'
        } elseif ($success -eq 'enable') {
            'Success'
        } elseif ($failure -eq 'enable') {
            'Failure'
        } else {
            'No Auditing'
        }
        $currentAuditOutput = (& $script:AuditpolPath /get /subcategory:"$subcat" 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol.exe query exited with code $LASTEXITCODE. $currentAuditOutput"
        }
        $auditSettingMatch = [regex]::Match($currentAuditOutput, "(?im)^\s*$([regex]::Escape($subcat))\s+(No Auditing|Success(?: and Failure)?|Failure)\s*$")
        if (-not $auditSettingMatch.Success) {
            throw "Could not parse the current audit state for subcategory '$subcat'. Output: $currentAuditOutput"
        }

        # Keep the first recorded original, so later runs cannot overwrite it. It is recorded
        # even when the subcategory already has the required setting.
        if (-not $script:UndoState.AuditPolicy.ContainsKey($subcat)) {
            $currentAuditState = $auditSettingMatch.Groups[1].Value
            $script:UndoState.AuditPolicy[$subcat] = [pscustomobject]@{
                Success = ($currentAuditState -in @('Success', 'Success and Failure'))
                Failure = ($currentAuditState -in @('Failure', 'Success and Failure'))
            }
            $script:UndoStateDirty = $true
        }
        if ($auditSettingMatch.Groups[1].Value -ne $expectedSetting) {
            $recordedAudit = $script:UndoState.AuditPolicy[$subcat]
            $originalState = if ($recordedAudit.Success -and $recordedAudit.Failure) { 'Success and Failure' } elseif ($recordedAudit.Success) { 'Success' } elseif ($recordedAudit.Failure) { 'Failure' } else { 'No Auditing' }
            Add-UndoChange -Description "Advanced Audit Policy ${subcat}: restore '$originalState'"
            Save-UndoState
            $auditPolOutput = (& $script:AuditpolPath /set /subcategory:"$subcat" /success:$success /failure:$failure 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "auditpol.exe set exited with code $LASTEXITCODE. $auditPolOutput"
            }
            $verifiedAuditOutput = (& $script:AuditpolPath /get /subcategory:"$subcat" 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "auditpol.exe verification query exited with code $LASTEXITCODE. $verifiedAuditOutput"
            }
            $verifiedAuditMatch = [regex]::Match($verifiedAuditOutput, "(?im)^\s*$([regex]::Escape($subcat))\s+(No Auditing|Success(?: and Failure)?|Failure)\s*$")
            if (-not $verifiedAuditMatch.Success -or $verifiedAuditMatch.Groups[1].Value -ne $expectedSetting) {
                throw "Verification failed for '$subcat'; expected '$expectedSetting'. Output: $verifiedAuditOutput"
            }
            Write-Host "Updated Advanced Audit Policy subcategory: $subcat." -ForegroundColor Yellow
            Set-SettingOutcome -Key "Audit policy|$subcat" -Outcome Corrected
        } else {
            Write-Host "Advanced Audit Policy subcategory $subcat is already configured." -ForegroundColor Green
            Set-SettingOutcome -Key "Audit policy|$subcat" -Outcome AlreadyInExpectedState
        }
    }
    catch {
        Set-SettingOutcome -Key "Audit policy|$subcat" -Outcome NotCorrected
        Write-Warning "Failed to configure subcategory '$subcat': $_"
    }
}

# CIS 18.10.26.1-18.10.26.4: maximum size and "when full" behavior of the Application,
# Security, Setup and System event logs. For each log, all with rollback:
# 1. The size the log uses is raised with wevtutil when it is smaller than the CIS
#    minimum, so the larger size applies at once. A larger size is never lowered.
# 2. The CIS policy value MaxSize (in KB) is set. The policy takes precedence over the
#    size in the log properties, so the value written is the larger of the CIS minimum
#    and the size the log uses now; a larger size configured earlier is therefore kept.
#    An existing policy value at or above the CIS minimum is left unchanged.
# 3. Retention = REG_SZ "0" (CIS: "Disabled"): when the log is full, the oldest events
#    are overwritten, so logging does not stop.
# Rollback first removes or restores the policy values (registry step), then restores
# the original log sizes with wevtutil.
# Keep this list identical to $eventLogBaselines in Audit.ps1.
$eventLogBaselines = @(
    @{ Name = 'Application'; MinimumSizeKB = 32768;  SizeId = '18.10.26.1.2'; RetentionId = '18.10.26.1.1' }
    @{ Name = 'Security';    MinimumSizeKB = 196608; SizeId = '18.10.26.2.2'; RetentionId = '18.10.26.2.1' }
    @{ Name = 'Setup';       MinimumSizeKB = 32768;  SizeId = '18.10.26.3.2'; RetentionId = '18.10.26.3.1' }
    @{ Name = 'System';      MinimumSizeKB = 32768;  SizeId = '18.10.26.4.2'; RetentionId = '18.10.26.4.1' }
)
foreach ($eventLogBaseline in $eventLogBaselines) {
    $eventLogName = $eventLogBaseline.Name
    $minimumSizeKB = [int]$eventLogBaseline.MinimumSizeKB
    $minimumSizeBytes = [long]$minimumSizeKB * 1KB
    $minimumSizeMB = $minimumSizeKB / 1024
    $eventLogPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$eventLogName"

    # 1. The size the log uses.
    $currentSizeBytes = $null
    try {
        $currentSizeBytes = [long](Get-WinEvent -ListLog $eventLogName -ErrorAction Stop).MaximumSizeInBytes
        # Keep the first recorded original, so later runs cannot overwrite it. It is recorded
        # even when the log is already large enough. Older versions of this script recorded
        # the Security log in SecurityLogMaximumSize.
        $alreadyRecorded = $script:UndoState.EventLogMaximumSizes.Contains($eventLogName) -or
            ($eventLogName -eq 'Security' -and $null -ne $script:UndoState.SecurityLogMaximumSize)
        if (-not $alreadyRecorded) {
            $script:UndoState.EventLogMaximumSizes[$eventLogName] = $currentSizeBytes
            $script:UndoStateDirty = $true
        }
        if ($currentSizeBytes -lt $minimumSizeBytes) {
            $recordedSizeBytes = if ($script:UndoState.EventLogMaximumSizes.Contains($eventLogName)) { $script:UndoState.EventLogMaximumSizes[$eventLogName] } else { $script:UndoState.SecurityLogMaximumSize }
            Add-UndoChange -Description "$eventLogName event log: restore maximum size to $recordedSizeBytes bytes"
            Save-UndoState
            $wevtutilOutput = (& $script:WevtutilPath sl $eventLogName "/ms:$minimumSizeBytes" 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "wevtutil failed to increase the $eventLogName log size: $wevtutilOutput"
            }
            $currentSizeBytes = [long](Get-WinEvent -ListLog $eventLogName -ErrorAction Stop).MaximumSizeInBytes
            if ($currentSizeBytes -lt $minimumSizeBytes) {
                throw "Verification failed: $eventLogName log maximum size is $currentSizeBytes bytes; expected at least $minimumSizeBytes bytes."
            }
            Write-Host "Increased the $eventLogName event log maximum size to $minimumSizeMB MB." -ForegroundColor Yellow
            Set-SettingOutcome -Key "Event log size|$eventLogName" -Outcome Corrected
        } else {
            Write-Host "$eventLogName event log maximum size is already at least $minimumSizeMB MB; leaving it unchanged." -ForegroundColor Green
            Set-SettingOutcome -Key "Event log size|$eventLogName" -Outcome AlreadyInExpectedState
        }
    }
    catch {
        Set-SettingOutcome -Key "Event log size|$eventLogName" -Outcome NotCorrected
        Write-Error "Failed to configure the $eventLogName event log size: $_"
    }

    # 2. The CIS policy value. It is written only when the current size is known,
    # because a policy value below the current size would shrink the log.
    if ($null -eq $currentSizeBytes) {
        Write-Error "CIS $($eventLogBaseline.SizeId) $eventLogName event log maximum size policy was not set, because the current size of the log could not be read."
    } else {
        $policySizeKB = [int][math]::Max([long]$minimumSizeKB, [long][math]::Ceiling($currentSizeBytes / 1KB))
        Set-IdempotentDword -Path $eventLogPolicyPath -Name 'MaxSize' -Value $policySizeKB `
            -Description "CIS $($eventLogBaseline.SizeId) $eventLogName event log maximum size policy (KB)" `
            -Accept { param($v) $v -ge $minimumSizeKB }.GetNewClosure()
    }

    # 3. Overwrite the oldest events when the log is full.
    Set-IdempotentString -Path $eventLogPolicyPath -Name 'Retention' -Value '0' `
        -Description "CIS $($eventLogBaseline.RetentionId) $eventLogName event log overwrites old events when full (Retention)"
}

$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Save-RegistryKeyExistence -Path $Path
if (!(Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# Disable administrative shares.
$changesBefore = $script:RunChangeCount
Set-IdempotentDword -Path $Path -Name 'AutoShareServer' -Value 0 -Description 'Administrative server shares'
Set-IdempotentDword -Path $Path -Name 'AutoShareWks' -Value 0 -Description 'Administrative workstation shares'
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'Administrative shares disablement'

$changesBefore = $script:RunChangeCount
try { Set-CisUserRights } catch { Write-Error "Failed to configure CIS user-right assignments: $_" }
Register-PendingRestart -ChangeCountBefore $changesBefore -Reason 'User rights assignments' -SignOutOnly

}
# ---- end of OS settings, part 3

# Settings were recorded even when they needed no change; write those records now.
if ($script:UndoStateDirty) {
    try { Save-UndoState } catch { Write-Error "Could not save the rollback snapshot: $_" }
}
$recordedSettingCount = $script:UndoState.RegistryValues.Count + $script:UndoState.Services.Count +
    $script:UndoState.FirewallProfiles.Count + $script:UndoState.AuditPolicy.Count +
    $script:UndoState.EventLogMaximumSizes.Count + $script:UndoState.OptionalFeatures.Count +
    @($script:UndoState.GetEnumerator() | Where-Object {
        $_.Key -match '^(Defender|Smb|SecurityPolicyFile|UserRightsPolicyFile|GuestAccount|SecurityLogMaximumSize)' -and $null -ne $_.Value
    }).Count
if ($recordedSettingCount -gt 0) {
    Write-Host ''
    Write-Host "The original state of $recordedSettingCount settings is recorded for rollback: $script:UndoStatePath" -ForegroundColor Cyan
    $outcomeValues = @($script:UndoState['SettingOutcomes'].Values)
    $alreadyCount = @($outcomeValues | Where-Object { $_.FirstOutcome -eq 'AlreadyInExpectedState' }).Count
    $correctedCount = @($outcomeValues | Where-Object { $_.FirstOutcome -eq 'Corrected' }).Count
    $notCorrectedCount = @($outcomeValues | Where-Object { $_.FirstOutcome -eq 'NotCorrected' }).Count
    Write-Host "Of the $($outcomeValues.Count) settings checked since the snapshot was created ($($script:UndoState['Created']) on $($script:UndoState['ComputerName'])): $alreadyCount were already in the expected state, $correctedCount were corrected, $notCorrectedCount could not be corrected." -ForegroundColor Cyan
}
if (@($script:UndoState['Changes']).Count -gt 0) {
    Write-Host ''
    # The snapshot's change list covers every run since the snapshot was created, so say
    # whether this run itself changed anything.
    if (@($script:RunCorrectedKeys).Count -gt 0) {
        Write-Host "This run changed $(@($script:RunCorrectedKeys).Count) settings. Rollback files (for the changes of all runs since the snapshot was created):" -ForegroundColor Cyan
    } else {
        Write-Host 'This run changed no settings; all checked settings already had the expected value. Rollback files (for the changes of earlier runs):' -ForegroundColor Cyan
    }
    Write-Host "Rollback script: $script:RollbackScriptPath"
    Write-Host "Rollback state:  $script:UndoStatePath"
    Write-Host "To undo the applied changes, open an elevated PowerShell prompt and run $script:RollbackScriptPath."
}
try {
    $reportPath = Write-RemediationReport
    Write-Host ''
    if ($reportPath) {
        Write-Host "Report of the applied changes: $reportPath" -ForegroundColor Cyan
    } else {
        Write-Host 'No change report was written, because this run changed no settings. Remediations.cmd Analyze lists the changes of all runs.'
    }
} catch {
    Write-Warning "Could not write the change report: $_"
}

# Restart / sign-out summary for settings changed during this run. A restart
# also covers sign-out changes, so they are listed together in that case.
if ($script:RestartReasons.Count -gt 0) {
    Write-Host ''
    Write-Host 'A restart is required to complete these changes:' -ForegroundColor Magenta
    foreach ($reason in @($script:RestartReasons) + @($script:SignOutReasons)) {
        Write-Host "  - $reason" -ForegroundColor Magenta
    }
    Write-Host 'Before restarting, make sure that you can still sign in: the Microsoft account user name, password and PIN must be known and working. If you sign in without a password (two-factor approval in the Microsoft Authenticator app, or a hardware security key), make sure that app or key is at hand and works. Some of these changes (for example Memory Integrity, Credential Guard and LSA protection) can change how sign-in works after the restart.' -ForegroundColor Magenta
} elseif ($script:SignOutReasons.Count -gt 0) {
    Write-Host ''
    Write-Host 'Sign out and back in (or restart) for these changes to apply:' -ForegroundColor Magenta
    foreach ($reason in $script:SignOutReasons) {
        Write-Host "  - $reason" -ForegroundColor Magenta
    }
}
}
finally {
    if ($null -ne $script:RunLock) { $script:RunLock.Dispose() }
}
