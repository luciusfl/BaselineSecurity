#requires -Version 5.1
<#
.SYNOPSIS
    Read-only Windows security configuration audit. No settings are changed;
    the only files it writes or deletes are its own logs and temporary files.
    It runs with or without elevation. Without elevation, checks that need
    administrator rights (for example Secure Boot, TPM, BitLocker and the
    local security policy) are reported as [ELEVATION REQUIRED] and skipped,
    all other checks run normally, and no log files are written.
    Pre-requisites: PowerShell 5.1 (powershell.exe) and Windows 11 or later.
.DESCRIPTION
    Checks the automated settings listed in SecurityBaselineSettings.html plus
    selected automated Level 1 recommendations from the CIS Windows 11
    Stand-alone Benchmark v5.0.0. Manual recommendations, audit and logging
    settings are not treated as compliance failures. Checks requiring Bluetooth,
    Print Spooler, and Windows Push Notifications to be disabled are omitted.
    A failed check or a setting
    that cannot be verified is reported in red and makes the final result
    "Computer is insecure". It verifies that Edge blocks extensions except
    those explicitly approved by policy.
    Run elevated for the complete results. Exit codes: 0 = all checks passed,
    1 = at least one check failed, 2 = nothing failed but some checks were not
    run because elevation is required, 3 = stopped before any check because
    another audit is already running and writing the logs (or a program has
    SecurityAudit.log open without allowing writers). An hourly SYSTEM task/service
    should be configured only after reviewing the output and log handling.

    After each failed check it always prints what the setting does
    (description), why it matters for security (rationale) and the source.
    The text comes from AuditCheckDetails.json, which must be next to this
    script; for CIS recommendations it holds a copy of the CIS benchmark text.
    The details are also written to SecurityAudit.log (under each failure
    line) and to SecurityAuditErrors.log (in a section after all failure
    lines, so the WatchDog toast still lists the failures). If the file is
    missing or unreadable, a warning is shown and the audit runs without the
    details; the result and exit code do not depend on them.
.PARAMETER RestrictTo
    Audits only the listed systems, separated by commas: OS (Windows itself),
    Edge (the Microsoft Edge policies) and Chrome (the Google Chrome policies).
    Not case sensitive; both -RestrictTo Edge,OS and RestrictTo=Edge,OS work.
    Unknown or misspelled names are ignored with a warning, and the supported
    ones still run. Without it, everything is audited. A restricted run writes
    no log files, so the
    result of the scheduled full audit that WatchDog shows is not replaced by
    a partial one.
.PARAMETER ApprovedAdministratorsFile
    UTF-8 text file listing approved local administrator account names, one
    per line (DOMAIN\name or COMPUTER\name). Without it the membership check
    is reported as not configured.
.PARAMETER Help
    Shows the usage and stops. Audit.cmd also shows it for ?, -?, /?, help and
    -help, and so does this script when one of these is given in place of
    RestrictTo. Nothing is checked and no log file is written.
.PARAMETER RunAuditElevated
    The checks that need administrator rights must run. Without elevation they
    are then reported as failures instead of [ELEVATION REQUIRED]. Install.cmd
    -RunAuditElevated registers the scheduled task as SYSTEM with this switch;
    without it the task runs as LocalService and skips those checks.
#>
[CmdletBinding()]
param(
    # Position 0, so that "RestrictTo=Edge,OS" (one argument, as a .cmd file passes it) is
    # bound here. Giving one parameter a position makes the others named only.
    [Parameter(Position = 0)][string[]]$RestrictTo,
    [string]$ApprovedAdministratorsFile,
    [int]$MaximumSignatureAgeDays = 3,
    [switch]$RunAuditElevated,
    [switch]$Help
)

# Security hardening; it must stay the first code in the script, before any command
# that could load a module, and uses no cmdlets itself.
# 1. Load PowerShell modules only from Windows and Program Files. An elevated session
#    otherwise also searches the Documents folder of the signed-in user first, where a
#    non-elevated process can plant a module named like a command this script uses and
#    so run code as an administrator.
# 2. Start secedit by full path from the system directory, never through the current
#    folder or PATH, and take system folders from Windows, not from environment
#    variables, which the signed-in user can override.
$env:PSModulePath = @(
    [System.IO.Path]::Combine($PSHOME, 'Modules')
    [System.IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'WindowsPowerShell\Modules')
    [System.IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\Modules')
) -join ';'
$script:SeceditPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'secedit.exe')

# Help. "?" or "help" given without a parameter name lands in RestrictTo (position 0), so
# those count as a request for help too. It runs before anything is checked or written.
if ($Help -or @(@($RestrictTo) | Where-Object { $_ -in @('?', '-?', '/?', 'help', '-help', '/help') }).Count -gt 0) {
    Write-Host @'
Audit.cmd checks the security settings of this Windows 11 PC against the baseline and
changes nothing.

Usage:
  Audit.cmd                       Audit everything
  Audit.cmd -RestrictTo Edge,OS   Audit only the listed systems, separated by commas: OS
                                  (Windows itself), Edge and Chrome (their browser policies).
                                  RestrictTo=Edge,OS works too. Unknown names are ignored
                                  with a warning. A restricted run writes no log files.
  Audit.cmd -RunAuditElevated     The checks that need administrator rights must run; without
                                  elevation they are reported as failures
  Audit.cmd -ApprovedAdministratorsFile <path>
                                  Text file of approved local administrator accounts
  Audit.cmd -MaximumSignatureAgeDays <days>
                                  Maximum age of the Defender signatures (default 3)
  Audit.cmd ?                     Show this help (-?, /?, help and -help work too)

Run it from an elevated prompt for the complete audit; without elevation the checks that
need administrator rights are skipped. Options are not case sensitive. Exit codes:
0 = all checks passed, 1 = at least one check failed, 2 = nothing failed but some checks
were not run, 3 = another audit is running. See Design.md for details.
'@
    exit 0
}

$ErrorActionPreference = 'Stop'
$script:Failures = 0
# Checks whose result could not be determined (an error while reading the setting, or a check
# that must run but cannot without elevation). They count against the result like a failure.
$script:Unverified = 0
$script:Checks = 0
$script:LogDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SecurityAudit'
$script:ErrorFilePath = Join-Path $script:LogDirectory 'SecurityAuditErrors.log'
$script:AuditFilePath = Join-Path $script:LogDirectory 'SecurityAudit.log'
# The log of the run before, kept for troubleshooting (for example a run that the task's time
# limit stopped while the PC was in standby).
$script:PreviousAuditFilePath = Join-Path $script:LogDirectory 'SecurityAudit.previous.log'
$script:PreviousLogProblem = $null
# When this PowerShell process started, for the header (startup can take a minute or more,
# for example right after the PC woke from standby) and for the duration in the summary.
$script:ProcessStart = try { (Get-Process -Id $PID -ErrorAction Stop).StartTime } catch { $null }
$script:LogOpenedAt = $null
# "1 second", "44 seconds".
function Format-SecondCount([double]$Seconds) {
    $count = [Math]::Round($Seconds)
    if ($count -eq 1) { '1 second' } else { '{0:N0} seconds' -f $count }
}
$script:ErrorLines = [System.Collections.Generic.List[string]]::new()

# The audit also runs without elevation. Checks that need administrator rights are
# then reported as [ELEVATION REQUIRED] instead of being run, and every other check
# runs normally. SYSTEM counts as elevated. With -RunAuditElevated those checks must
# run, so without elevation they are failures instead of being skipped.
$script:CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$script:IsElevated = ([System.Security.Principal.WindowsPrincipal]$script:CurrentIdentity).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
# The default scheduled task runs as LocalService (S-1-5-19), never elevated.
$script:IsLocalService = $script:CurrentIdentity.User.Value -eq 'S-1-5-19'
$script:SkipElevationRequired = -not $script:IsElevated -and -not $RunAuditElevated
$script:ElevationRequired = 0
# Check names (regular expressions) that cannot be evaluated without elevation:
# they either fail with "access denied" or return hidden or incomplete data, which
# would look like a failed check. Other checks that hit an access-denied error
# without elevation are reported the same way (see Test-Setting).
$script:ElevationRequiredChecks = @(
    '^Secure Boot$'                  # reading UEFI variables
    '^TPM 2\.0 Status$'              # TPM WMI provider
    '^BitLocker '                    # Get-BitLockerVolume
    '^Security Event Log Size$'      # Security event log properties
    '^SMBv1 Protocol'                # Get-WindowsOptionalFeature (DISM)
    '^Windows PowerShell 2\.0$'      # Get-WindowsOptionalFeature (DISM)
    '^CIS 1\.1\.[1-57] '             # secedit export: password policy (1.1.6 is a registry value)
    '^CIS 1\.2\.\d+ '                # secedit export: account lockout policy
    '^CIS 2\.2\.\d+ '                # secedit export: user rights
    '^CIS 2\.3\.10\.1 '              # secedit export: anonymous SID/name translation
    '^CIS 2\.3\.11\.5 '              # secedit export: force logoff when logon hours expire
    '^CIS 2\.3\.10\.[78] '           # registry keys readable only by administrators
)

# RestrictTo: the systems to audit. $script:SelectedSystems is $null when everything is
# audited. Names are matched without regard to case; unknown names are ignored with a
# warning, and the run stops only if no supported name is left.
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
        Write-Host "Error: RestrictTo names no supported system ($($script:SupportedSystems -join ', ')), so there is nothing to audit." -ForegroundColor Red
        exit 1
    }
    $script:SelectedSystems = $selectedSystems.ToArray()
}
function Test-SystemSelected {
    param([Parameter(Mandatory)][string]$System)
    $null -eq $script:SelectedSystems -or $script:SelectedSystems -contains $System
}

# The log files are written by the scheduled task, which runs as LocalService (the
# default) or as SYSTEM (Install.cmd -RunAuditElevated), and by elevated runs.
# InstallTasks.ps1 lets only SYSTEM, Administrators and the audit task's own SID write
# the log folder. An unelevated interactive run writes no logs: it cannot replace the
# task's logs, and its result must not be shown by WatchDog as the state of the computer.
# For the same reason a run restricted with RestrictTo writes no logs either.
$script:LoggingEnabled = ($script:IsElevated -or $script:IsLocalService) -and $null -eq $script:SelectedSystems
# The log folder is used only if it is a real folder that SYSTEM or Administrators own.
# Any user can create a folder, junction or symbolic link with this name in ProgramData
# before the first run: a link would redirect the logs to another place, and the
# creator of a folder could replace the logs that WatchDog shows. A missing folder is
# created by an elevated run together with a protective access list (SYSTEM and
# Administrators full control, Users read), so the permissions inherited from
# ProgramData never apply to it; InstallTasks.ps1 sets the final access list.
$script:LogDirectoryProblem = $null
if ($script:LoggingEnabled) {
    $trustedLogOwners = @('S-1-5-18', 'S-1-5-32-544')
    $existingLogDirectory = Get-Item -LiteralPath $script:LogDirectory -Force -ErrorAction SilentlyContinue
    if ($null -eq $existingLogDirectory) {
        if ($script:IsElevated) {
            $logInheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $logAcl = [System.Security.AccessControl.DirectorySecurity]::new()
            $logAcl.SetAccessRuleProtection($true, $false)
            foreach ($sid in $trustedLogOwners) {
                $logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                    [System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', $logInheritance, 'None', 'Allow'))
            }
            $logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', $logInheritance, 'None', 'Allow'))
            [void][System.IO.Directory]::CreateDirectory($script:LogDirectory, $logAcl)
        } else {
            $script:LogDirectoryProblem = 'it does not exist. Run Install.cmd to create it.'
        }
    } elseif (-not $existingLogDirectory.PSIsContainer -or ($existingLogDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        $script:LogDirectoryProblem = 'it is not a normal folder (it is a file, a junction or a symbolic link) and could redirect the logs to another place. Check it, delete it, and run Install.cmd again.'
    } else {
        $logDirectoryOwner = (Get-Acl -LiteralPath $script:LogDirectory -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($logDirectoryOwner -notin $trustedLogOwners) {
            $script:LogDirectoryProblem = "it is owned by $logDirectoryOwner, not by SYSTEM or Administrators, so another account created it and may be able to change the logs. Check its contents, delete the folder, and run Install.cmd again."
        }
    }
    if ($script:LogDirectoryProblem) {
        # Counted as a failure: without a trustworthy log folder WatchDog cannot report.
        $script:LoggingEnabled = $false
        $script:Failures++
        Write-Host "[FAIL] Audit log folder '$script:LogDirectory' is not used and no log files are written: $script:LogDirectoryProblem" -ForegroundColor Red
    }
}
# Temporary secedit exports of an elevated run go to the log folder, which only SYSTEM
# and Administrators can write. The temp folder of an elevated administrator is the
# user's own, where a non-elevated process could replace an export before it is read.
$script:WorkDirectory = if ($script:IsElevated -and $script:LoggingEnabled) { $script:LogDirectory } else { [System.IO.Path]::GetTempPath() }

# Only one audit at a time may write the logs. A run that writes logs opens SecurityAudit.log
# for writing, lets others only read it (FileShare.Read) and keeps it open until it ends. A
# second run cannot open the file for writing and stops at once, before it deletes or writes
# anything, so it cannot mix its lines into the logs of the first or delete the error log that
# the first one wrote. Windows checks this when the file is opened, also when the file does not
# exist yet (two runs that create it at the same moment cannot both succeed), and closes the
# file when the process ends, also after a crash, so no stale lock can remain.
# A program that has SecurityAudit.log open without allowing writers (for example a script
# that reads it with the default FileShare.Read) stops the audit in the same way: that cannot
# be told apart from a second audit.
# Runs that write no logs (unelevated interactive runs) take no lock.
$script:AuditLogWriter = $null
# Problems with the log files found before the logging functions exist. They are
# reported as failures after the header (see "Log file problems" below).
$script:LogFileProblems = [System.Collections.Generic.List[string]]::new()
function Close-AuditLog {
    if ($script:AuditLogWriter) {
        try { $script:AuditLogWriter.Dispose() } catch { }
        $script:AuditLogWriter = $null
    }
}
# Releases the files when the script stops with an error inside a PowerShell session
# that stays open (the process, and with it the open files, would otherwise live on).
trap { Close-AuditLog; break }
if ($script:LoggingEnabled) {
    try {
        # Opened without emptying it, with the same sharing rule as before (others may only
        # read), so a second audit is refused here exactly as before and nothing is touched.
        $auditLogStream = [System.IO.FileStream]::new(
            $script:AuditFilePath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::Read)
        $script:LogOpenedAt = Get-Date
        # This run holds the log now: keep the previous run's log as SecurityAudit.previous.log,
        # then empty the log for this run. A failure to keep it is only noted in the log.
        if ($auditLogStream.Length -gt 0) {
            try {
                $previousContent = [byte[]]::new($auditLogStream.Length)
                $offset = 0
                while ($offset -lt $previousContent.Length) {
                    $read = $auditLogStream.Read($previousContent, $offset, $previousContent.Length - $offset)
                    if ($read -le 0) { break }
                    $offset += $read
                }
                [System.IO.File]::WriteAllBytes($script:PreviousAuditFilePath, $previousContent)
            } catch {
                $script:PreviousLogProblem = "The log of the previous run could not be kept as SecurityAudit.previous.log: $($_.Exception.Message)"
            }
        }
        $auditLogStream.SetLength(0)
        $auditLogStream.Position = 0
        # UTF-8 with a byte order mark, as before. AutoFlush: readers see each line at once.
        $script:AuditLogWriter = [System.IO.StreamWriter]::new($auditLogStream, [System.Text.UTF8Encoding]::new($true))
        $script:AuditLogWriter.AutoFlush = $true
    } catch {
        $openError = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        # 0x80070020 = sharing violation: another audit, or a program that does not allow
        # writers, has the log open. Nothing has been deleted or written yet.
        if ($openError -is [System.IO.IOException] -and $openError.HResult -eq -2147024864) {
            Write-Host 'Another security audit is already running. Wait a minute until the other audit has finished, then run Audit.cmd again.' -ForegroundColor Red
            exit 3
        }
        # Any other reason (for example no write permission): the checks still run, and the
        # problem is reported as a failure in SecurityAuditErrors.log, so WatchDog shows a
        # toast instead of the audit silently writing nothing.
        $script:LogFileProblems.Add("SecurityAudit.log could not be written, so this run has no full log: $($openError.Message) If a program has the file open, close it. The failures are still written to SecurityAuditErrors.log.")
    }
    # The error log of the previous run is deleted only now, when this run holds the log.
    try {
        Remove-Item -LiteralPath $script:ErrorFilePath -Force -ErrorAction Stop
    } catch {
        if (Test-Path -LiteralPath $script:ErrorFilePath) {
            # Usually a program holds the file open. WatchDog then still shows the old
            # failures, so a toast appears, but they may not match this run.
            $script:LogFileProblems.Add("SecurityAuditErrors.log of the previous audit could not be deleted, so it may still show earlier results: $($_.Exception.Message) Close the program that has the file open.")
        }
    }
}
function Write-AuditLog {
    param([string]$Message)
    if (-not $script:AuditLogWriter) { return }
    try {
        $script:AuditLogWriter.WriteLine("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff K') $Message")
    } catch {
        Write-Warning "Unable to write audit log to '$script:AuditFilePath': $($_.Exception.Message)"
    }
}

function Write-AuditError {
    param([string]$Message)
    $script:ErrorLines.Add($Message)
    if (-not $script:LoggingEnabled) { return }
    try {
        if ($script:ErrorLines.Count -eq 1) {
            New-Item -ItemType File -Path $script:ErrorFilePath -Force -ErrorAction Stop | Out-Null
            Set-Content -LiteralPath $script:ErrorFilePath -Value $Message -Encoding UTF8 -ErrorAction Stop
        } else {
            Add-Content -LiteralPath $script:ErrorFilePath -Value $Message -Encoding UTF8 -ErrorAction Stop
        }
    } catch {
        Write-Warning "Unable to write audit error to '$script:ErrorFilePath': $($_.Exception.Message)"
    }
}

# Description and security rationale, shown under every failed check, all from
# AuditCheckDetails.json. Checks named "CIS <id> ..." use its cisRecommendations (a copy
# of the CIS benchmark text, written by Update-AuditCheckDetails.ps1); the other checks use
# its checks list, which either points to cisRecommendations (cisIds) or has its own text
# and sources. The file is only read, and a missing or unreadable file only turns the
# details off.
$script:CheckDetails = $null
function Import-CheckDetails {
    $detailsPath = Join-Path $PSScriptRoot 'AuditCheckDetails.json'
    try {
        $details = [System.IO.File]::ReadAllText($detailsPath) | ConvertFrom-Json
        $cisById = @{}
        foreach ($recommendation in $details.cisRecommendations) { $cisById[$recommendation.id] = $recommendation }
        $byName = @{}
        foreach ($check in $details.checks) { $byName[$check.name] = $check }
        $script:CheckDetails = @{ CisById = $cisById; ByName = $byName; CisSource = [string]$details.cisBenchmark }
    } catch {
        Write-Warning "Check details: descriptions are not available, because '$detailsPath' could not be read: $($_.Exception.Message)"
    }
}

# The details go to the console and, right under the failure line, to SecurityAudit.log.
# SecurityAuditErrors.log gets them in a separate section after all failure lines (see
# Write-AuditErrorDetailsSection): WatchDog shows the start of that file in its toast,
# which must keep listing the failures, and its "Open log" button opens the full file.
$script:ErrorDetailLines = [System.Collections.Generic.List[string]]::new()

# Called from inside Test-Setting's try block, so it must never throw: an error here
# would otherwise be counted as a second failure of the check.
function Write-CheckDetails {
    param([string]$Name)
    if (-not $script:CheckDetails) { return }
    try {
        $lines = @(Get-CheckDetailLines $Name)
        foreach ($line in $lines) {
            Write-Host $line -ForegroundColor $(if ($line -match '^    (Source:|No description)') { 'DarkGray' } else { 'Gray' })
            Write-AuditLog $line
        }
        $script:ErrorDetailLines.Add("[FAIL] $Name")
        foreach ($line in $lines) { $script:ErrorDetailLines.Add($line) }
    }
    catch { Write-Warning "Check details: could not show the description of '$Name': $($_.Exception.Message)" }
}

function Write-AuditErrorDetailsSection {
    if (-not $script:LoggingEnabled -or $script:ErrorLines.Count -eq 0 -or $script:ErrorDetailLines.Count -eq 0) { return }
    try {
        $section = @('', 'Details of the failed checks (what the setting does, why it matters for security, and the source):') + @($script:ErrorDetailLines)
        Add-Content -LiteralPath $script:ErrorFilePath -Value $section -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "Unable to write the failure details to '$script:ErrorFilePath': $($_.Exception.Message)"
    }
}

# The CIS texts keep their paragraphs and list items, one per line. The first line follows
# the label; the others are indented under it.
function Format-DetailText {
    param([string]$Label, [string]$Text)
    $paragraphs = @($Text -split "`r?`n" | Where-Object { $_ })
    if ($paragraphs.Count -eq 0) { return }
    $Label + $paragraphs[0]
    foreach ($paragraph in @($paragraphs | Select-Object -Skip 1)) { '      ' + $paragraph }
}

function Get-CheckDetailLines {
    param([string]$Name)
    $entries = [System.Collections.Generic.List[object]]::new()
    $cisIds = @()
    $custom = $script:CheckDetails.ByName[$Name]
    # @() around a missing property gives one $null element, so filter empty values.
    $customCisIds = @(if ($custom) { $custom.cisIds | Where-Object { $_ } })
    if ($customCisIds.Count -gt 0) { $cisIds = $customCisIds }
    elseif ($custom) {
        $entries.Add([pscustomobject]@{ Label = ''; Description = $custom.description; Rationale = $custom.rationale; Sources = @($custom.sources | ForEach-Object { "$($_.title) <$($_.url)>" }) })
    }
    elseif ($Name -match '^CIS (\d+(?:\.\d+)+) ') { $cisIds = @($Matches[1]) }
    foreach ($id in $cisIds) {
        $control = $script:CheckDetails.CisById[$id]
        if (-not $control) { continue }
        $label = if ($cisIds.Count -gt 1) { " (CIS $id)" } else { '' }
        $entries.Add([pscustomobject]@{ Label = $label; Description = $control.description; Rationale = $control.rationale; Sources = @("$($script:CheckDetails.CisSource), recommendation $id, page $($control.page): $($control.title)") })
    }
    if ($entries.Count -eq 0) { return '    No description or rationale is available for this check.' }
    foreach ($entry in $entries) {
        if ($entry.Description) { Format-DetailText "    Description$($entry.Label): " $entry.Description }
        if ($entry.Rationale) { Format-DetailText "    Why it matters$($entry.Label): " $entry.Rationale }
        foreach ($source in $entry.Sources) { "    Source: $source" }
    }
}
Import-CheckDetails

function Write-ElevationRequired {
    param([string]$Name,[string]$Expected)
    $script:ElevationRequired++
    $message = "[ELEVATION REQUIRED] $Name — not checked (expected: $Expected). Run Audit.cmd from an elevated (administrator) prompt to check this setting."
    Write-AuditLog $message
    Write-Host $message -ForegroundColor Yellow
}

function Write-CheckFailure {
    # -Unverified: the check could not be evaluated, as opposed to the setting not meeting the expectation.
    param([string]$Name,[string]$Message,[switch]$Unverified)
    if ($Unverified) { $script:Unverified++ } else { $script:Failures++ }
    Write-AuditLog $Message
    Write-AuditError $Message
    Write-Host $Message -ForegroundColor Red
    Write-CheckDetails $Name
}

# True when an error means "this needs administrator rights".
function Test-AccessDeniedError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    for ($exception = $ErrorRecord.Exception; $null -ne $exception; $exception = $exception.InnerException) {
        if ($exception -is [System.UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) { return $true }
        # 0x80070005 = E_ACCESSDENIED, 0x80070522 = a required privilege is not held, 0x80041003 = WMI access denied.
        # 0x800702E4 = the requested operation requires elevation.
        if ($exception.HResult -in @(-2147024891, -2147023582, -2147217405, -2147024156)) { return $true }
    }
    # Some tools (secedit, WMI providers) only report this as text.
    [string]$ErrorRecord.Exception.Message -match '(?i)access (is )?denied|requires elevation|sufficient permissions|run as administrator'
}

# Windows servicing (DISM) answers a query only when no installation or update holds its
# lock, so Get-WindowsOptionalFeature can wait for many minutes (7 minutes were seen
# while Windows was installing an update). Every DISM query therefore runs with a time
# limit shared by the whole run: 10 minutes in total. A query that does not finish in
# time fails its check ("could not verify", fail closed), and every later DISM query
# fails at once, so DISM never delays the audit by more than 10 minutes. The scheduled
# task also stops after 45 minutes (InstallTasks.ps1), which covers hangs elsewhere.
$script:DismTimeLimit = [TimeSpan]::FromMinutes(10)
$script:DismTimeUsed = [TimeSpan]::Zero
$script:DismTimedOut = $false
function Invoke-DismQuery {
    param([Parameter(Mandatory)][scriptblock]$Query, [switch]$IgnoreErrors)
    $notAnswered = "Windows servicing (DISM) did not answer within $([int]$script:DismTimeLimit.TotalMinutes) minutes, probably because Windows Update or an installation is in progress. Run the audit again later, or restart the PC if an update is waiting for a restart."
    $remainingMilliseconds = [int][Math]::Max(0, ($script:DismTimeLimit - $script:DismTimeUsed).TotalMilliseconds)
    if ($script:DismTimedOut -or $remainingMilliseconds -eq 0) {
        $script:DismTimedOut = $true
        throw $notAnswered
    }
    # The query runs in a separate runspace of this process, so the wait can be limited.
    # A separate runspace reports cmdlet errors only in its error stream, even with
    # -ErrorAction Stop, so the first one is thrown here, as a direct call would; a check
    # that ignored the errors of its direct call passes -IgnoreErrors.
    $queryShell = [powershell]::Create()
    [void]$queryShell.AddScript($Query.ToString())
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $queryResult = $queryShell.BeginInvoke()
    $finished = $queryResult.AsyncWaitHandle.WaitOne($remainingMilliseconds)
    $script:DismTimeUsed += $stopwatch.Elapsed
    if (-not $finished) {
        $script:DismTimedOut = $true
        # A waiting DISM call cannot be interrupted; its thread ends with this process.
        [void]$queryShell.BeginStop($null, $null)
        throw $notAnswered
    }
    try {
        $queryOutput = @($queryShell.EndInvoke($queryResult))
        if (-not $IgnoreErrors -and $queryShell.Streams.Error.Count -gt 0) {
            throw $queryShell.Streams.Error[0].Exception
        }
        $queryOutput
    } finally {
        $queryShell.Dispose()
    }
}

function Test-Setting {
    param([string]$Name,[string]$Expected,[scriptblock]$Check)
    $script:Checks++
    # For checks Remediations.ps1 does not fix, failures explain why and what to do.
    $notRemediated = ''
    if ($script:NotRemediatedReasons -and $script:NotRemediatedReasons[$Name]) {
        $notRemediated = " Not fixed by Remediations.ps1: $($script:NotRemediatedReasons[$Name])"
    }
    if (-not $script:IsElevated -and @($script:ElevationRequiredChecks | Where-Object { $Name -match $_ }).Count -gt 0) {
        if ($script:SkipElevationRequired) {
            Write-ElevationRequired $Name $Expected
        } else {
            # -RunAuditElevated: the check must run, and running it without elevation
            # would give access-denied errors or incomplete data.
            Write-CheckFailure $Name "[FAIL] $Name — expected: $Expected; not checked: this check needs administrator rights, and -RunAuditElevated requires it to run, but the audit is not running elevated.$notRemediated" -Unverified
        }
        return
    }
    try {
        $result = & $Check
        if ($result -is [bool] -and $result) {
            $message = "[PASS] $Name — $Expected"
            Write-AuditLog $message
            Write-Host $message -ForegroundColor Green
        } else {
            if ($null -eq $result -or $result -is [bool]) { $detail = 'Observed state does not meet expectation.' }
            else { $detail = [string]$result }
            Write-CheckFailure $Name "[FAIL] $Name — expected: $Expected; observed: $detail$notRemediated"
        }
    } catch {
        if ($script:SkipElevationRequired -and (Test-AccessDeniedError $_)) {
            Write-ElevationRequired $Name $Expected
            return
        }
        Write-CheckFailure $Name "[FAIL] $Name — expected: $Expected; could not verify: $($_.Exception.Message)$notRemediated" -Unverified
    }
}
function Get-RegValue($Path,$Name) {
    if (Test-Path -LiteralPath $Path) { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } else { $null }
}
function Test-RegDword($Path,$Name,$Expected) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $Name) { return $false }
    $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::DWord -and $key.GetValue($Name) -eq $Expected
}
function Test-RegString($Path,$Name,$Expected) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $Name) { return $false }
    $key.GetValueKind($Name) -eq [Microsoft.Win32.RegistryValueKind]::String -and $key.GetValue($Name) -ceq $Expected
}
function Test-RegMultiString($Path,$Name,[string[]]$Expected) {
    if (-not (Test-Path -LiteralPath $Path)) { return @($Expected).Count -eq 0 }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains $Name) { return @($Expected).Count -eq 0 }
    if ($key.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::MultiString) { return $false }
    $actual = @($key.GetValue($Name) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $expectedValues = @($Expected | Sort-Object)
    $actualValues = @($actual | Sort-Object)
    return @(Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues).Count -eq 0
}
function Get-LocalSecurityPolicy {
    $policyFile = Join-Path $script:WorkDirectory ("SecurityAudit-AccountPolicy-{0}.inf" -f [guid]::NewGuid().ToString('N'))
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
        # Missing optional settings are reported as $null (not configured), so only
        # the affected checks fail instead of every account-policy check.
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
        }
    }
    finally {
        if (Test-Path -LiteralPath $policyFile) {
            Remove-Item -LiteralPath $policyFile -Force -ErrorAction Stop
        }
    }
}
# The state of all services, read with one WMI query on first use and kept for the run.
# A filtered query per service takes about half a second, which added up to about 20
# seconds for the 40 service checks. If the query fails, nothing is kept, so every
# service check tries again and fails on its own (fail closed).
$script:ServiceStates = $null
function Get-ServiceState {
    param([Parameter(Mandatory)][string]$Name)

    if ($null -eq $script:ServiceStates) {
        $states = @{}
        foreach ($entry in @(Get-CimInstance -ClassName Win32_Service -Property Name, State, StartMode -ErrorAction Stop)) {
            $states[$entry.Name] = $entry
        }
        # Windows always has services; an empty answer would make every check pass as "not installed".
        if ($states.Count -eq 0) { throw 'The list of Windows services (Win32_Service) is empty.' }
        $script:ServiceStates = $states
    }
    # Service names are not case-sensitive, and neither are the keys of this table.
    $script:ServiceStates[$Name]
}
function Test-CisServiceDisabled {
    param([Parameter(Mandatory)][string]$Name)

    $service = Get-ServiceState -Name $Name
    if ($null -eq $service) {
        return $true
    }
    if ($service.State -eq 'Stopped' -and $service.StartMode -eq 'Disabled') {
        return $true
    }
    "Service $Name is installed with State=$($service.State), StartMode=$($service.StartMode)."
}
function Get-DeviceGuard {
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
}
function Get-ApprovedLines([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { throw 'Approved-list file was not provided or does not exist.' }
    @(Get-Content -LiteralPath $Path | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}
function Test-BrowserInstalled {
    param(
        [Parameter(Mandatory)][ValidateSet('Edge','Chrome')][string]$Browser
    )

    $browserDetails = @{
        Edge = @{
            RelativePath = 'Microsoft\Edge\Application\msedge.exe'
        }
        Chrome = @{
            RelativePath = 'Google\Chrome\Application\chrome.exe'
        }
    }[$Browser]
    $candidatePaths = [System.Collections.Generic.List[string]]::new()

    foreach ($programFiles in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($programFiles) {
            $candidatePaths.Add((Join-Path $programFiles $browserDetails.RelativePath))
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
                $candidatePaths.Add((Join-Path $expandedProfilePath "AppData\Local\$($browserDetails.RelativePath)"))
            }
        }
    }

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) { return $true }
    }
    return $false
}

# BrowsingDataLifetime is a REG_SZ JSON list of {data_types, time_to_live_in_hours}.
# Compliant when every required data type is listed with a lifetime of at most
# $MaximumHours. Returns $true, or a string that explains the failure.
function Test-BrowsingDataLifetimePolicy {
    param(
        [Parameter(Mandatory)][string]$PolicyRoot,
        [Parameter(Mandatory)][string[]]$RequiredDataTypes,
        [Parameter(Mandatory)][int]$MaximumHours
    )
    if (-not (Test-Path -LiteralPath $PolicyRoot -PathType Container)) { return 'BrowsingDataLifetime policy is not configured.' }
    $key = Get-Item -LiteralPath $PolicyRoot -ErrorAction Stop
    if ($key.GetValueNames() -notcontains 'BrowsingDataLifetime') { return 'BrowsingDataLifetime policy is not configured.' }
    if ($key.GetValueKind('BrowsingDataLifetime') -ne [Microsoft.Win32.RegistryValueKind]::String) { return 'BrowsingDataLifetime is not a REG_SZ value.' }
    $rawLifetime = [string]$key.GetValue('BrowsingDataLifetime')
    # The browsers accept only a JSON list, not a single object.
    if (-not $rawLifetime.TrimStart().StartsWith('[')) { return 'BrowsingDataLifetime is not a JSON list.' }
    try {
        # Windows PowerShell 5.1 returns a JSON array as one object; piping it unrolls the entries.
        $parsed = ConvertFrom-Json -InputObject $rawLifetime -ErrorAction Stop
        $entries = @($parsed | ForEach-Object { $_ })
    } catch {
        return 'BrowsingDataLifetime does not contain valid JSON.'
    }
    $missing = foreach ($dataType in $RequiredDataTypes) {
        $covered = $entries | Where-Object {
            @($_.data_types) -contains $dataType -and
                $_.time_to_live_in_hours -is [ValueType] -and
                $_.time_to_live_in_hours -ge 1 -and
                $_.time_to_live_in_hours -le $MaximumHours
        }
        if (-not $covered) { $dataType }
    }
    if (@($missing).Count -gt 0) {
        return "Data types not deleted within $MaximumHours hours: $(@($missing) -join ', ')."
    }
    $true
}

# Returns the display name of an installed extension from <Extensions>\<id>\<version>\manifest.json,
# or $null if it cannot be read. Localized names ("__MSG_key__") are resolved from
# _locales\<default_locale>\messages.json, as the browser does.
function Get-InstalledExtensionName {
    param([Parameter(Mandatory)][string]$ExtensionPath)
    try {
        $versionFolder = @(Get-ChildItem -LiteralPath $ExtensionPath -Directory -Force -ErrorAction Stop |
            Where-Object { [System.IO.File]::Exists((Join-Path $_.FullName 'manifest.json')) } |
            Sort-Object LastWriteTimeUtc -Descending) | Select-Object -First 1
        if (-not $versionFolder) { return $null }
        $manifest = [System.IO.File]::ReadAllText((Join-Path $versionFolder.FullName 'manifest.json')) | ConvertFrom-Json -ErrorAction Stop
        $name = [string]$manifest.name
        if ($name -match '^__MSG_(.+)__$') {
            $messageKey = $Matches[1]
            $locales = @([string]$manifest.default_locale, 'en', 'en_US') | Where-Object { $_ } | Select-Object -Unique
            foreach ($locale in $locales) {
                $messagesPath = Join-Path $versionFolder.FullName "_locales\$locale\messages.json"
                if (-not [System.IO.File]::Exists($messagesPath)) { continue }
                $messages = [System.IO.File]::ReadAllText($messagesPath) | ConvertFrom-Json -ErrorAction Stop
                # Message keys are case-insensitive in the extension format.
                $entry = $messages.PSObject.Properties | Where-Object { $_.Name -ieq $messageKey } | Select-Object -First 1
                if ($entry -and $entry.Value.message) { return [string]$entry.Value.message }
            }
            return $null
        }
        if ($name) { return $name }
    }
    catch { }
    return $null
}

# Returns a hashtable of extension ID -> $true (enabled) or $false (disabled) for one
# Edge or Chrome browser profile folder. Both browsers (Chromium) record this in
# "Secure Preferences" and "Preferences" under extensions.settings.<id>:
# a non-zero disable_reasons (a number, or a list in newer versions) means disabled,
# as does the older state = 0. IDs without an entry are not in the result; callers
# treat them as enabled (fail closed). The .NET JavaScriptSerializer is used because
# ConvertFrom-Json in Windows PowerShell 5.1 rejects keys that differ only in case.
function Get-BrowserExtensionEnabledStates {
    param([Parameter(Mandatory)][string]$BrowserProfilePath)
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $serializer.RecursionLimit = 1000
    $states = @{}
    foreach ($fileName in 'Secure Preferences', 'Preferences') {
        $preferencesPath = Join-Path $BrowserProfilePath $fileName
        if (-not [System.IO.File]::Exists($preferencesPath)) { continue }
        $preferences = $serializer.DeserializeObject([System.IO.File]::ReadAllText($preferencesPath))
        if ($preferences -isnot [System.Collections.IDictionary] -or -not $preferences.ContainsKey('extensions')) { continue }
        $extensionsNode = $preferences['extensions']
        if ($extensionsNode -isnot [System.Collections.IDictionary] -or -not $extensionsNode.ContainsKey('settings')) { continue }
        foreach ($extensionId in @($extensionsNode['settings'].Keys)) {
            $entry = $extensionsNode['settings'][$extensionId]
            if ($entry -isnot [System.Collections.IDictionary]) { continue }
            $disabled = $null
            if ($entry.ContainsKey('disable_reasons')) {
                $disabled = @($entry['disable_reasons'] | Where-Object { $null -ne $_ -and [long]$_ -ne 0 }).Count -gt 0
            } elseif ($entry.ContainsKey('state')) {
                $disabled = [long]$entry['state'] -eq 0
            }
            # Secure Preferences is read first; Preferences only fills in IDs without a decision yet.
            if ($null -ne $disabled -and -not $states.ContainsKey($extensionId)) {
                $states[$extensionId] = -not $disabled
            }
        }
    }
    $states
}

function Test-BrowserExtensionPolicy {
    param(
        [Parameter(Mandatory)][string]$Browser,
        [Parameter(Mandatory)][string]$PolicyRoot,
        [Parameter(Mandatory)][string[]]$ApprovedIds
    )

    # Passes when (1) the browser blocks all extensions by default and (2) no extension
    # outside $ApprovedIds can run in any browser profile of any local user.
    # An installed extension is not reported when any of these is true:
    #   - its folder has no manifest.json (a leftover the browser cannot load);
    #   - the browser saved it as disabled;
    #   - the machine policy blocks it: ExtensionInstallBlocklist contains *, the machine
    #     ExtensionInstallAllowlist exists (so per-user policy cannot widen it), no
    #     ExtensionSettings policy overrides these lists, and its ID is neither on the
    #     registry allow-list nor force-installed. The browser checks this policy before
    #     loading extensions, so such an extension cannot run even if a user's saved
    #     state still says enabled (for example, until that user starts the browser again).
    # Approved extensions do not have to be installed, and the registry allow-list is not
    # compared with $ApprovedIds: an approved ID that Remediations.ps1 has not written yet
    # only means the extension cannot be installed yet.
    $problems = [System.Collections.Generic.List[string]]::new()

    function Get-PolicyListValues([string]$KeyPath) {
        if (-not (Test-Path -LiteralPath $KeyPath -PathType Container)) { return $null }
        $listKey = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
        @($listKey.GetValueNames() | Where-Object { $listKey.GetValueKind($_) -eq [Microsoft.Win32.RegistryValueKind]::String } | ForEach-Object { [string]$listKey.GetValue($_) })
    }
    $blocklistValues = Get-PolicyListValues (Join-Path $PolicyRoot 'ExtensionInstallBlocklist')
    $blocksAll = $null -ne $blocklistValues -and @($blocklistValues | Where-Object { $_ -ceq '*' }).Count -gt 0
    if (-not $blocksAll) {
        $problems.Add('ExtensionInstallBlocklist does not contain * (extensions are not blocked by default; Remediations.ps1 sets it)')
    }
    $allowlistValues = Get-PolicyListValues (Join-Path $PolicyRoot 'ExtensionInstallAllowlist')
    # Force-installed entries have the form "<id>;<update URL>".
    $forcelistValues = @(Get-PolicyListValues (Join-Path $PolicyRoot 'ExtensionInstallForcelist') | ForEach-Object { ($_ -split ';')[0].Trim() })
    $hasExtensionSettings = (Test-Path -LiteralPath (Join-Path $PolicyRoot 'ExtensionSettings')) -or
        ($null -ne (Get-ItemProperty -LiteralPath $PolicyRoot -Name 'ExtensionSettings' -ErrorAction SilentlyContinue))
    $policyDecides = $blocksAll -and $null -ne $allowlistValues -and -not $hasExtensionSettings
    $policyAllowed = [System.Collections.Generic.HashSet[string]]::new([string[]]@(@($allowlistValues) + $forcelistValues | Where-Object { $_ }), [System.StringComparer]::OrdinalIgnoreCase)

    # Installed extensions: one folder per extension ID under <User Data>\<profile>\Extensions.
    # Built-in browser components are not stored there, so they are not reported.
    $userDataRelativePath = @{ Edge = 'Microsoft\Edge\User Data'; Chrome = 'Google\Chrome\User Data' }[$Browser]
    $approved = [System.Collections.Generic.HashSet[string]]::new([string[]]$ApprovedIds, [System.StringComparer]::OrdinalIgnoreCase)
    $unapproved = [System.Collections.Generic.List[string]]::new()
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($profileKey in @(Get-ChildItem -LiteralPath $profileListPath -ErrorAction Stop)) {
        $profileImagePath = (Get-ItemProperty -LiteralPath $profileKey.PSPath -ErrorAction Stop).ProfileImagePath
        if (-not $profileImagePath) { continue }
        $userDataPath = Join-Path ([Environment]::ExpandEnvironmentVariables([string]$profileImagePath)) "AppData\Local\$userDataRelativePath"
        if (-not [System.IO.Directory]::Exists($userDataPath)) { continue }
        foreach ($browserProfile in @(Get-ChildItem -LiteralPath $userDataPath -Directory -Force -ErrorAction Stop)) {
            $extensionsPath = Join-Path $browserProfile.FullName 'Extensions'
            if (-not [System.IO.Directory]::Exists($extensionsPath)) { continue }
            # Installed but disabled extensions are allowed; only enabled ones are reported.
            $enabledStates = Get-BrowserExtensionEnabledStates -BrowserProfilePath $browserProfile.FullName
            foreach ($extension in @(Get-ChildItem -LiteralPath $extensionsPath -Directory -Force -ErrorAction Stop)) {
                if ($extension.Name -notmatch '^[a-p]{32}$' -or $approved.Contains($extension.Name)) { continue }
                # Not installed: no version folder with a manifest.json, so the browser cannot load it.
                $hasManifest = @(Get-ChildItem -LiteralPath $extension.FullName -Directory -Force -ErrorAction Stop |
                    Where-Object { [System.IO.File]::Exists((Join-Path $_.FullName 'manifest.json')) }).Count -gt 0
                if (-not $hasManifest) { continue }
                # Saved as disabled by the browser.
                if ($enabledStates.ContainsKey($extension.Name) -and -not $enabledStates[$extension.Name]) { continue }
                # Blocked by machine policy, so the browser will not load it.
                if ($policyDecides -and -not $policyAllowed.Contains($extension.Name)) { continue }
                # Friendly name first, then the ID and where it is installed (Windows user\browser profile).
                $displayName = Get-InstalledExtensionName -ExtensionPath $extension.FullName
                if (-not $displayName) { $displayName = 'Unknown extension' }
                $windowsUser = Split-Path -Leaf ([Environment]::ExpandEnvironmentVariables([string]$profileImagePath))
                $unapproved.Add("$displayName ($($extension.Name), $windowsUser\$($browserProfile.Name))")
            }
        }
    }
    if ($unapproved.Count -gt 0) {
        $problems.Add("enabled extensions that are not on the approved list and not blocked by policy: $($unapproved -join ', '). Run Remediations.ps1 so the browser blocks them, remove them in the browser's extensions page, or add their IDs to the approved lists in Audit.ps1 and Remediations.ps1")
    }

    if ($problems.Count -gt 0) {
        "${Browser}: $($problems -join '; ')."
    } else {
        $true
    }
}

# Operating system, e.g. "Microsoft Windows 10 Pro, version 22H2 (build 19045.5011)".
try {
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption.Trim()
    $osVersionKey = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $osVersionName = if ($osVersionKey.PSObject.Properties['DisplayVersion']) { $osVersionKey.DisplayVersion }
        elseif ($osVersionKey.PSObject.Properties['ReleaseId']) { $osVersionKey.ReleaseId }
    $osBuild = $osVersionKey.CurrentBuild
    $script:OsBuildNumber = [int]$osVersionKey.CurrentBuild
    if ($osVersionKey.PSObject.Properties['UBR']) { $osBuild = "$osBuild.$($osVersionKey.UBR)" }
    $osDescription = if ($osVersionName) { "$osCaption, version $osVersionName (build $osBuild)" } else { "$osCaption (build $osBuild)" }
} catch {
    $osDescription = "unknown ($($_.Exception.Message))"
}

$auditHeader = @(
    "Windows security audit (read-only): $env:COMPUTERNAME"
    "Operating system: $osDescription"
    "Run time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
    $(if ($script:ProcessStart) { "Process started: {0:yyyy-MM-dd HH:mm:ss K} ({1} before the log was opened)" -f $script:ProcessStart, (Format-SecondCount ((@($script:LogOpenedAt, (Get-Date)) | Where-Object { $_ } | Select-Object -First 1) - $script:ProcessStart).TotalSeconds) } else { 'Process started: unknown' })
    "Account: $($script:CurrentIdentity.Name) ($(if ($script:IsElevated) { 'elevated' } else { 'not elevated' }))$(if ($RunAuditElevated) { '; -RunAuditElevated' })"
)
Write-Host $auditHeader[0] -ForegroundColor Cyan
for ($i = 1; $i -lt $auditHeader.Count - 1; $i++) { Write-Host $auditHeader[$i] }
Write-Host "$($auditHeader[-1])`n"
foreach ($headerLine in $auditHeader) { Write-AuditLog $headerLine }
if ($script:PreviousLogProblem) { Write-AuditLog "[INFO] $script:PreviousLogProblem" }
if ($null -ne $script:SelectedSystems) {
    Write-Host "Restricted to: $($script:SelectedSystems -join ', '). The other systems are not audited, and no log files are written.`n" -ForegroundColor Yellow
}
if (-not $script:IsElevated) {
    $elevationNote = if ($script:SkipElevationRequired) {
        'Not running elevated: checks that need administrator rights are reported as [ELEVATION REQUIRED] and are not run. Run Audit.cmd from an elevated prompt, or install the scheduled task with Install.cmd -RunAuditElevated, for the complete audit.'
    } else {
        'Not running elevated, but -RunAuditElevated was given: checks that need administrator rights are reported as failures.'
    }
    if (-not $script:LoggingEnabled) { $elevationNote += ' No log files are written.' }
    Write-AuditLog $elevationNote
    Write-Host "$elevationNote`n" -ForegroundColor Yellow
}
# Log file problems found when the logs were opened (see the lock above). They count
# as failures and go to SecurityAuditErrors.log, so WatchDog raises a toast.
foreach ($logFileProblem in $script:LogFileProblems) {
    $script:Failures++
    $logFileMessage = "[FAIL] Audit log — $logFileProblem"
    Write-AuditLog $logFileMessage
    Write-AuditError $logFileMessage
    Write-Host $logFileMessage -ForegroundColor Red
}
# Checks that Remediations.ps1 does not fix, keyed by check name, with the reason
# and what to do instead. Test-Setting appends the reason to a failure message.
# Keep this list aligned with the audit-only notes in SecurityBaselineSettings.html.
if ($null -eq $script:OsBuildNumber) { $script:OsBuildNumber = 0 }
$isWindows11Version22H2OrLater = $script:OsBuildNumber -ge 22621
$windowsDefaultReason = 'the Windows default already meets the baseline, so a failure means a person or program changed it on purpose; review why before reverting it.'
$script:NotRemediatedReasons = @{
    'Secure Boot' = 'Secure Boot is a firmware (UEFI) setting that Windows cannot change. Turn it on in the firmware setup; Windows must boot in UEFI mode from a GPT disk.'
    'TPM 2.0 Status' = 'the TPM is switched on in the firmware (Intel PTT or AMD fTPM) or is missing from the hardware, and Windows cannot turn it on. Check the firmware setup; tpm.msc shows whether Windows can see a TPM.'
    'Memory Integrity (HVCI)' = 'Remediations.ps1 does not turn Memory Integrity on, because an incompatible driver could stop Windows from starting. Turn on Windows Security > Device security > Core isolation > Memory integrity, which checks the drivers first and lists incompatible ones; it also needs CPU virtualization (Intel VT-x or AMD-V with SLAT) on in the firmware. Restart, then run Remediations.ps1 again to set the matching policy (CIS 18.9.5.3).'
    'CIS 18.9.5.3 HVCI Enabled' = 'Remediations.ps1 sets this policy only when Memory Integrity is already running, which proves the drivers are compatible. Turn on Windows Security > Device security > Core isolation > Memory integrity, restart, then run Remediations.ps1 again.'
    'Built-in Administrator Account' = 'disabling it automatically could lock you out if it is the only administrator account. Make sure another administrator account exists, then run: net user Administrator /active:no'
    'Defender Real-Time Protection' = 'Tamper Protection blocks scripted changes to this Defender setting, and another antivirus product may have turned Defender off. Turn it on in Windows Security > Virus & threat protection > Manage settings.'
    'Defender Cloud-Delivered Protection (MAPS)' = 'Tamper Protection blocks scripted changes to this Defender setting, and another antivirus product may have turned Defender off. Turn it on in Windows Security > Virus & threat protection > Manage settings.'
    'Defender Sample Submission' = 'Tamper Protection blocks scripted changes to this Defender setting, and sending samples is a privacy choice. Turn on Automatic sample submission in Windows Security > Virus & threat protection > Manage settings.'
    'Defender Tamper Protection' = 'Windows only allows Tamper Protection to be turned on in the Windows Security app, so malware cannot script it. Turn it on in Windows Security > Virus & threat protection > Manage settings.'
    'Defender Antivirus Service' = 'Windows protects the Defender service from scripted changes, and it stops when another antivirus product is active. Remove the other product or restart Windows.'
    'Defender Signature Age' = 'signatures arrive through Windows Update, not through a configuration setting. Check Windows Update, or run Update-MpSignature.'
    'Vulnerable Driver Blocklist' = $(if ($isWindows11Version22H2OrLater) {
        'it is on by default on this Windows version, so something turned it off. Turn on Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist.'
    } else {
        'on Windows 10 the blocklist is enforced only while Memory Integrity runs; this check passes once Memory Integrity runs.'
    })
    'Windows Ready Print Driver Ranking' = 'Windows creates the DriverRanking policy key so that only SYSTEM can change it (administrators may only read it), so Remediations.ps1 cannot set it, and changing the permissions of a key that Windows protects would weaken that protection. The feature is on by default; if it was turned off, turn it on again where it was turned off, or remove the value that turned it off as SYSTEM.'
    'Remote Desktop NLA' = "$windowsDefaultReason Turn it back on in System Properties > Remote > 'Allow connections only from computers running Remote Desktop with Network Level Authentication'."
    'Public Network Profile Safety' = 'Remediations.ps1 sets the firewall defaults and disables Teredo, but does not change network categories or Network Discovery / File and Printer Sharing rules, because that can break sharing on a home network. Set the network to Public in Settings > Network & Internet, or turn off Network Discovery and File and Printer Sharing for Public networks.'
    'SMBv1 Protocol Client/Server' = "$windowsDefaultReason Something may still need SMBv1 (for example an old NAS); if not, run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
    'Automatic Updates Policy' = "$windowsDefaultReason Remove the NoAutoUpdate value under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU."
    'Windows Update Pause Duration' = 'pausing updates is a deliberate choice, so it is not undone automatically. Resume updates in Settings > Windows Update.'
    'BitLocker OS Drive' = 'turning on BitLocker needs a TPM (or a startup password or USB key) and a safe place for the recovery key, so it is a manual step. Turn it on in Control Panel > BitLocker Drive Encryption (Windows Pro, Enterprise or Education).'
    'BitLocker Recovery Key Present' = 'storing the recovery key safely is a manual step. Add one when you turn on BitLocker, or run: manage-bde -protectors -add C: -RecoveryPassword, and store the key somewhere safe.'
    'CIS 2.3.1.2 Blank Password Network Restriction' = $windowsDefaultReason
    'CIS 2.3.7.6 Password Expiry Warning' = $windowsDefaultReason
    'CIS 2.3.8.2 Unencrypted Passwords to SMB Servers' = $windowsDefaultReason
    'DNS over HTTPS (DoH)' = 'Remediations.ps1 does not configure DNS over HTTPS, because that means choosing a DNS provider and changing the DNS servers of the network adapters, which can break name resolution on some networks. Turn it on in Settings > Network & internet > Wi-Fi or Ethernet > DNS server assignment > Edit.'
    'CIS 18.5.1 Automatic Logon Disabled' = "$windowsDefaultReason Automatic sign-in stores the password in the registry; turn it off by setting AutoAdminLogon to 0 under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon."
    'CIS 18.10.73.1 Recall Disabled' = 'Remediations.ps1 sets this policy only when the Recall feature is not enabled, because turning Recall off deletes its saved snapshots, which rollback cannot restore. If Recall is enabled, turn it off yourself in Settings > Privacy & security > Recall & snapshots, then run Remediations.ps1 again.'
}
if (-not $isWindows11Version22H2OrLater) {
    $script:NotRemediatedReasons['LSASS Protected Process (RunAsPPL)'] = 'on Windows 10 only RunAsPPL = 1 exists, and on Secure Boot PCs it is stored in a UEFI variable that rollback cannot remove. Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = DWORD 1 manually if you accept that, then restart.'
}

# ---- OS (Windows) checks, part 1. Skipped when RestrictTo does not include OS. The block is
# not indented, to keep the checks readable; it ends before the browser checks.
if (Test-SystemSelected 'OS') {

# Boot integrity: firmware security capabilities should be active and ready.
Test-Setting 'Secure Boot' 'Enabled (True)' { (Confirm-SecureBootUEFI) -eq $true }
Test-Setting 'TPM 2.0 Status' 'Present, ready, enabled, specification 2.0' {
    $t=Get-Tpm; $v=Get-CimInstance -Namespace root\CIMv2\Security\MicrosoftTpm -ClassName Win32_Tpm
    $spec=($v.SpecVersion -split ',')[0].Trim()
    [bool]($t.TpmPresent -and $t.TpmReady -and $t.TpmEnabled -and $spec -eq '2.0')
}
# Kernel / credential protection: both configured and active where applicable.
Test-Setting 'Memory Integrity (HVCI)' 'Enabled and running' {
    $d=Get-DeviceGuard; ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled') -eq 1) -and ($d.SecurityServicesRunning -contains 2)
}
Test-Setting 'LSASS Protected Process (RunAsPPL)' 'Enabled (1 or 2)' { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -in @(1,2) }
Test-Setting 'Cached Logon Credentials' 'Minimal (1-2)' { (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount') -in @('1','2',1,2) }
Test-Setting 'Built-in Administrator Account' 'Disabled' { -not (Get-LocalUser -ErrorAction Stop | Where-Object { ([string]$_.SID) -match '-500$' -and $_.Enabled }) }
Test-Setting 'Built-in Guest Account' 'Disabled' {
    $guestAccounts=@(Get-LocalUser -ErrorAction Stop | Where-Object { ([string]$_.SID) -match '-501$' })
    if ($guestAccounts.Count -ne 1) {
        "Expected to find exactly one built-in Guest account (SID ending in -501); found $($guestAccounts.Count)."
    } else {
        -not $guestAccounts[0].Enabled
    }
}

# Microsoft Defender: verify status through Defender cmdlets and policy values.
# Real-time protection, cloud reporting and sample submission are separate checks, so a
# failure names the setting that is wrong. Sample submission only has to be something other
# than "never send" (2): "send safe samples" (1) and "always prompt" (0) both pass, because
# sending all samples is a privacy choice this baseline does not require.
Test-Setting 'Defender Real-Time Protection' 'Enabled (RealTimeProtectionEnabled = True)' { (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled -eq $true }
Test-Setting 'Defender Cloud-Delivered Protection (MAPS)' 'Basic or Advanced (MAPSReporting = 1 or 2)' { (Get-MpPreference -ErrorAction Stop).MAPSReporting -in @(1, 2) }
Test-Setting 'Defender Sample Submission' 'Not turned off (SubmitSamplesConsent is not 2 = Never send)' { (Get-MpPreference -ErrorAction Stop).SubmitSamplesConsent -ne 2 }
# Microsoft security baseline for Windows 11 26H2 (not CIS): the stronger cloud verdict
# and the longer cloud check make Defender wait up to 50 seconds for a cloud verdict on an
# unknown file before it runs, and block more unknown files. CloudBlockLevel: 0 default,
# 1 moderate, 2 high, 4 high plus, 6 zero tolerance; 2 or more passes.
Test-Setting 'Defender Cloud Protection Level' 'High or higher (CloudBlockLevel = 2, 4 or 6)' { (Get-MpPreference -ErrorAction Stop).CloudBlockLevel -in @(2, 4, 6) }
# Windows 10 22H2 (seen with Defender platform 4.18.26100.4): Get-MpPreference reports
# CloudExtendedTimeout as 0 although Defender has stored 50 (MpBafsExtendedTimeout under
# HKLM\SOFTWARE\Microsoft\Windows Defender\MpEngine); Windows 11 with the same platform reports
# 50. So when the cmdlet reports less than 50, the stored value decides: the policy value if
# there is one (it overrides the local value), otherwise the local value. Both keys are readable
# without elevation. Keep identical in Remediations.ps1.
function Get-DefenderCloudExtendedTimeout {
    $reported = (Get-MpPreference -ErrorAction Stop).CloudExtendedTimeout
    if ($null -ne $reported -and [int]$reported -ge 50) { return [int]$reported }
    foreach ($keyPath in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine', 'HKLM:\SOFTWARE\Microsoft\Windows Defender\MpEngine') {
        $stored = (Get-ItemProperty -LiteralPath $keyPath -Name 'MpBafsExtendedTimeout' -ErrorAction SilentlyContinue).MpBafsExtendedTimeout
        if ($null -ne $stored) { return [int]$stored }
    }
    return $reported
}
Test-Setting 'Defender Extended Cloud Check' 'CloudExtendedTimeout = 50 seconds' { [int](Get-DefenderCloudExtendedTimeout) -ge 50 }
# Microsoft security baseline for Windows 11 26H2 (not CIS): full scans also scan removable drives.
Test-Setting 'Defender Removable Drive Scanning' 'Enabled (DisableRemovableDriveScanning = False)' { (Get-MpPreference -ErrorAction Stop).DisableRemovableDriveScanning -eq $false }
Test-Setting 'Defender Tamper Protection' 'Enabled (IsTamperProtected = True)' { (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected -eq $true }
Test-Setting 'Defender Antivirus Service' 'Running' { (Get-Service WinDefend).Status -eq 'Running' }
Test-Setting 'Defender Signature Age' "Updated within $MaximumSignatureAgeDays days" { (Get-MpComputerStatus).AntivirusSignatureAge -le $MaximumSignatureAgeDays }
Test-Setting 'Windows Exploit Protection' 'DEP, CFG, Bottom-Up ASLR, and SEHOP are enabled or use Windows defaults' {
    $systemMitigations = Get-ProcessMitigation -System -ErrorAction Stop
    $requiredMitigations = @(
        @{ Name = 'DEP'; Section = 'Dep'; Property = 'Enable' }
        @{ Name = 'CFG'; Section = 'Cfg'; Property = 'Enable' }
        @{ Name = 'Bottom-Up ASLR'; Section = 'Aslr'; Property = 'BottomUp' }
        @{ Name = 'SEHOP'; Section = 'Sehop'; Property = 'Enable' }
    )
    $nonSecureMitigations = foreach ($mitigation in $requiredMitigations) {
        $section = $systemMitigations.PSObject.Properties[$mitigation.Section]
        if ($null -eq $section) {
            throw "Get-ProcessMitigation did not return the $($mitigation.Section) section."
        }
        $setting = $section.Value.PSObject.Properties[$mitigation.Property]
        if ($null -eq $setting) {
            throw "Get-ProcessMitigation did not return $($mitigation.Section).$($mitigation.Property)."
        }
        $state = [string]$setting.Value
        if ($state -notin @('ON', 'NOTSET')) {
            "$($mitigation.Name)=$state"
        }
    }
    if (@($nonSecureMitigations).Count -gt 0) {
        "Mitigations are disabled or have an unexpected state: $(@($nonSecureMitigations) -join ', ')."
    } else {
        $true
    }
}
Test-Setting 'Potentially Unwanted App (PUA) Protection' 'Enabled (1)' { (Get-MpPreference).PUAProtection -eq 1 }
Test-Setting 'Defender Network Protection' 'Enabled (1)' { (Get-MpPreference).EnableNetworkProtection -eq 1 }
# Baseline ASR rules. Action is what Remediations.ps1 sets (1 = Block, 2 = Audit) and
# Accepted lists the actions that pass (6 = Warn). The ransomware and obfuscated-script
# rules can block self-built programs and scripts, so they start in Audit mode, as does
# the PsExec and WMI process creation rule (Audit mode in the Microsoft baseline); Warn or
# Block also pass.
# Keep this list identical to $asrBaselineRules in Remediations.ps1.
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
Test-Setting 'Defender Attack Surface Reduction (ASR) Rules' 'Twelve baseline rules in Block mode; the ransomware, obfuscated-script and PsExec/WMI process-creation rules in Audit, Warn or Block mode' {
    $p = Get-MpPreference -ErrorAction Stop
    $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions)
    # Hashtable keys are case-insensitive, so the case Defender returns does not matter.
    $configured = @{}
    for ($i = 0; $i -lt $ids.Count -and $i -lt $acts.Count; $i++) {
        if (-not [string]::IsNullOrEmpty([string]$ids[$i])) { $configured[[string]$ids[$i]] = [int]$acts[$i] }
    }
    $actionNames = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }
    $findings = foreach ($rule in $asrBaselineRules) {
        if (-not $configured.ContainsKey($rule.Id)) {
            "'$($rule.Name)' is not configured"
        } elseif ($configured[$rule.Id] -notin $rule.Accepted) {
            $action = $configured[$rule.Id]
            $actionName = if ($actionNames.ContainsKey($action)) { $actionNames[$action] } else { "action $action" }
            "'$($rule.Name)' is in $actionName mode"
        }
    }
    if (@($findings).Count -gt 0) { "$(@($findings) -join '; ')." } else { $true }
}
# Event 1122 in the Defender operational log means an ASR rule in Audit mode matched
# something that Block mode would have stopped. This is information, not a check: it is not
# counted and never fails the audit. It only reads the event log. The rule names come from
# $asrBaselineRules above.
function Get-AsrAuditEvent {
    param([Parameter(Mandatory)][string]$EventXml)
    $xml = [xml]$EventXml
    # Hashtables are case-insensitive, so the capitalization of the field names does not matter.
    $data = @{}
    foreach ($item in @($xml.Event.EventData.Data)) {
        if ($item.Name) { $data[[string]$item.Name] = [string]$item.'#text' }
    }
    [pscustomobject]@{
        Time    = [string]$xml.Event.System.TimeCreated.SystemTime
        RuleId  = [string]$data['ID']
        Fields  = $data
    }
}

# Shown with the advice to switch the PsExec and WMI rule from Audit to Block. It changes only
# this one rule: Add-MpPreference leaves the other ASR rules as they are (Set-MpPreference would
# replace the whole list). Remediations.ps1 keeps an existing Block, so a later run does not undo it.
$asrBlockCommandHelp = @(
    '    To switch it to Block, run this in an elevated (administrator) PowerShell:'
    '      Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled'
    '    To check the result:'
    '      (Get-MpPreference).AttackSurfaceReductionRules_Ids, (Get-MpPreference).AttackSurfaceReductionRules_Actions'
    '    To go back to Audit mode:'
    '      Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode'
) -join "`n"
function Write-AsrAuditEventReport {
    # Events: the 1122 events found (an empty list when there are none), or $null when the
    # log could not be read, in which case ReadError says why. PsExecRuleBlocked: the PsExec
    # and WMI rule is already in Block mode, so advising to block it would be wrong.
    param($Events, [string]$ReadError, [bool]$PsExecRuleBlocked, [hashtable]$RuleNames, [int]$MaximumShown = 10)
    $lines = New-Object System.Collections.Generic.List[string]
    $color = 'Gray'
    if ($null -eq $Events) {
        $lines.Add("[INFO] ASR audit events (event 1122) — could not read the Microsoft-Windows-Windows Defender/Operational log: $ReadError")
        $color = 'Yellow'
    } elseif (@($Events).Count -eq 0) {
        if ($PsExecRuleBlocked) {
            $lines.Add("[INFO] No event 1122 found. The ASR rule 'Block process creations originating from PSExec and WMI commands' is already in Block mode.")
        } else {
            $lines.Add("[INFO] No event 1122 found. Consider setting ASR rule: 'Block process creations originating from PSExec and WMI commands' from audit to block.")
            $lines.Add($asrBlockCommandHelp)
        }
    } else {
        $parsed = @(foreach ($asrEvent in @($Events)) { try { Get-AsrAuditEvent -EventXml $asrEvent.ToXml() } catch { } })
        $lines.Add("[INFO] Event 1122 found: $(@($Events).Count) event(s) in the Microsoft-Windows-Windows Defender/Operational log, where an ASR rule in Audit mode matched. Newest $([Math]::Min($MaximumShown, $parsed.Count)) shown:")
        $field = {
            param($e, [string]$name, [string]$label)
            $v = [string]$e.Fields[$name]
            if ([string]::IsNullOrWhiteSpace($v)) { return }
            if ($v.Length -gt 200) { $v = $v.Substring(0, 200) + '...' }
            "      ${label}: $v"
        }
        foreach ($e in @($parsed | Select-Object -First $MaximumShown)) {
            $ruleName = if ($e.RuleId -and $RuleNames -and $RuleNames.ContainsKey($e.RuleId)) { "$($RuleNames[$e.RuleId]) ($($e.RuleId))" } elseif ($e.RuleId) { $e.RuleId } else { 'unknown rule' }
            $when = $e.Time
            try { $when = ([datetime]$e.Time).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch { }
            $lines.Add("    $when  $ruleName")
            $fieldLines = @(foreach ($pair in @(@('User', 'User'), @('Process Name', 'Process'), @('Path', 'Path'), @('Target Commandline', 'Target command line'), @('Parent Commandline', 'Parent command line'))) {
                & $field $e $pair[0] $pair[1]
            })
            if ($fieldLines.Count -eq 0) {
                # None of the expected field names are present, so show every field the event has.
                $fieldLines = @(foreach ($name in @($e.Fields.Keys | Sort-Object)) { & $field $e $name $name })
            }
            foreach ($fieldLine in $fieldLines) { $lines.Add($fieldLine) }
        }
        $perRule = @($parsed | Group-Object RuleId | Sort-Object Count -Descending | ForEach-Object {
            $name = if ($_.Name -and $RuleNames -and $RuleNames.ContainsKey($_.Name)) { $RuleNames[$_.Name] } elseif ($_.Name) { $_.Name } else { 'unknown rule' }
            "$name`: $($_.Count)"
        })
        $lines.Add("    Events per rule: $($perRule -join '; ')")
        $lines.Add('    If these are legitimate, keep the rule in Audit mode. If not, switch the rule to Block (see SecurityBaselineSettings.html, Defender Attack Surface Reduction (ASR) Rules).')
        $lines.Add($asrBlockCommandHelp)
    }
    foreach ($line in $lines) {
        Write-AuditLog $line
        Write-Host $line -ForegroundColor $color
    }
}

$asrRuleNames = @{}
foreach ($rule in $asrBaselineRules) { $asrRuleNames[$rule.Id] = $rule.Name }
$asrEvents = $null
$asrEventReadError = ''
try {
    $asrEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1122 } -MaxEvents 200 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $asrEvents = @() } else { $asrEventReadError = $_.Exception.Message }
}
$psExecRuleBlocked = $false
if ($null -ne $asrEvents -and $asrEvents.Count -eq 0) {
    try {
        $asrPreferenceForEvents = Get-MpPreference -ErrorAction Stop
        $asrIdsForEvents = @($asrPreferenceForEvents.AttackSurfaceReductionRules_Ids)
        $asrActionsForEvents = @($asrPreferenceForEvents.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $asrIdsForEvents.Count -and $i -lt $asrActionsForEvents.Count; $i++) {
            if ([string]$asrIdsForEvents[$i] -eq 'd1e49aac-8f56-4280-b9ba-993a6d77406c' -and [int]$asrActionsForEvents[$i] -eq 1) { $psExecRuleBlocked = $true }
        }
    } catch { }
}
Write-AsrAuditEventReport -Events $asrEvents -ReadError $asrEventReadError -PsExecRuleBlocked $psExecRuleBlocked -RuleNames $asrRuleNames
Test-Setting 'Controlled Folder Access (Ransomware)' 'Enabled (1)' { (Get-MpPreference).EnableControlledFolderAccess -eq 1 }
Test-Setting 'Vulnerable Driver Blocklist' 'Enabled (HVCI or blocklist policy)' {
    $d=Get-DeviceGuard; $hvci=$d.SecurityServicesRunning -contains 2
    $block=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
    $hvci -or $block -eq 1
}

# Reputation-based protection (Windows Security > App & browser control).
# PUA blocking for apps is checked above; Edge SmartScreen and its PUA download
# blocking are checked with the browser policies below.
Test-Setting 'CIS 18.10.77.2.1 SmartScreen Check Apps and Files' 'EnableSmartScreen = DWORD 1 and ShellSmartScreenLevel = Block (warn and prevent bypass)' {
    (Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1) -and
        (Test-RegString 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block')
}
Test-Setting 'SmartScreen for Microsoft Store Apps' 'EnableWebContentEvaluation = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' 1
}
if ($isWindows11Version22H2OrLater) {
    $phishingProtectionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'
    Test-Setting 'CIS 18.10.77.1.1 Enhanced Phishing Protection Automatic Data Collection' 'CaptureThreatWindow = DWORD 1' { Test-RegDword $phishingProtectionPath 'CaptureThreatWindow' 1 }
    Test-Setting 'CIS 18.10.77.1.2 Enhanced Phishing Protection Notify Malicious' 'NotifyMalicious = DWORD 1' { Test-RegDword $phishingProtectionPath 'NotifyMalicious' 1 }
    Test-Setting 'CIS 18.10.77.1.3 Enhanced Phishing Protection Notify Password Reuse' 'NotifyPasswordReuse = DWORD 1' { Test-RegDword $phishingProtectionPath 'NotifyPasswordReuse' 1 }
    Test-Setting 'CIS 18.10.77.1.4 Enhanced Phishing Protection Notify Unsafe App' 'NotifyUnsafeApp = DWORD 1' { Test-RegDword $phishingProtectionPath 'NotifyUnsafeApp' 1 }
    Test-Setting 'CIS 18.10.77.1.5 Enhanced Phishing Protection Service Enabled' 'ServiceEnabled = DWORD 1' { Test-RegDword $phishingProtectionPath 'ServiceEnabled' 1 }
} else {
    $message = '[SKIP] CIS 18.10.77.1.1-18.10.77.1.5 Enhanced Phishing Protection — not available on this Windows version (requires Windows 11 22H2 or later).'
    Write-AuditLog $message
    Write-Host $message -ForegroundColor DarkGray
}

}
# ---- end of OS checks, part 1

# Browser security policies. Each installed browser is audited independently;
# machine and per-user installations are detected even when this task runs as SYSTEM.
# Each browser has its own allow-list, because the same extension has a different
# ID in the Microsoft Edge Add-ons store and in the Chrome Web Store. When both
# browsers are installed, each one is checked against its own list.
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
$browserConfigurations = @(
    @{
        Name = 'Edge'
        PolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        ApprovedExtensionIds = $edgeApprovedExtensionIds
    }
    @{
        Name = 'Chrome'
        PolicyRoot = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        ApprovedExtensionIds = $chromeApprovedExtensionIds
    }
)
foreach ($browser in $browserConfigurations) {
    # RestrictTo can select Edge and Chrome by name.
    if (-not (Test-SystemSelected $browser.Name)) { continue }
    $browserName = $browser.Name
    $script:DetectedBrowserInstallation = $null
    Test-Setting "$browserName Installation Detection" 'installation state can be determined' {
        $script:DetectedBrowserInstallation = Test-BrowserInstalled -Browser $browserName
        $true
    }
    $installed = $script:DetectedBrowserInstallation
    if ($null -eq $installed) { continue }
    if (-not $installed) {
        $message = "[SKIP] $browserName browser policies — browser is not installed."
        Write-AuditLog $message
        Write-Host $message -ForegroundColor DarkGray
        continue
    }

    if ($browserName -eq 'Edge') {
        Test-Setting 'Microsoft Defender SmartScreen (Edge)' 'Enabled by Edge policy' {
            (Get-RegValue $browser.PolicyRoot 'SmartScreenEnabled') -eq 1
        }
        Test-Setting 'Edge SmartScreen Potentially Unwanted App Blocking' 'Enabled by Edge policy (SmartScreenPuaEnabled = DWORD 1)' {
            Test-RegDword $browser.PolicyRoot 'SmartScreenPuaEnabled' 1
        }
        Test-Setting 'Edge Password Export' 'password export disabled by Edge policy' {
            (Get-RegValue $browser.PolicyRoot 'PasswordExportEnabled') -eq 0
        }        # Internet Explorer mode is the one way the old Internet Explorer engine still runs, inside
        # Edge. Both policies must be 0: no IE mode by site list or setting (InternetExplorerIntegrationLevel
        # = None), and users may not reload a site in IE mode themselves.
        Test-Setting 'Edge Internet Explorer Mode' 'IE mode off by Edge policy (InternetExplorerIntegrationLevel = DWORD 0 and InternetExplorerIntegrationReloadInIEModeAllowed = DWORD 0)' {
            (Test-RegDword $browser.PolicyRoot 'InternetExplorerIntegrationLevel' 0) -and (Test-RegDword $browser.PolicyRoot 'InternetExplorerIntegrationReloadInIEModeAllowed' 0)
        }
    }
    if ($browserName -eq 'Chrome') {
        foreach ($setting in $chromePolicySettings) {
            $acceptedValues = @(@($setting.Value) + @($setting.AlsoAccepted) | Where-Object { $null -ne $_ })
            Test-Setting $setting.Check $setting.Expected {
                if (@($acceptedValues | Where-Object { Test-RegDword $setting.Path $setting.Name $_ }).Count -gt 0) { return $true }
                $observed = 'not set'
                if (Test-Path -LiteralPath $setting.Path) {
                    $settingKey = Get-Item -LiteralPath $setting.Path -ErrorAction Stop
                    if ($settingKey.GetValueNames() -contains $setting.Name) {
                        $observed = "$($settingKey.GetValueKind($setting.Name)) $($settingKey.GetValue($setting.Name))"
                    }
                }
                "$($setting.Name) is $observed."
            }
        }
    }
    # Edge ignores this policy while sync is on; Chrome 115+ turns off sync for these data types.
    Test-Setting "$browserName Browsing Data Lifetime" 'browsing history, download history and cached images and files deleted after 30 days (720 hours) at most' {
        Test-BrowsingDataLifetimePolicy -PolicyRoot $browser.PolicyRoot -RequiredDataTypes @('browsing_history', 'download_history', 'cached_images_and_files') -MaximumHours 720
    }
    Test-Setting "$browserName Extension Install Policy" 'extensions blocked by default (ExtensionInstallBlocklist = *) and no installed extension outside the approved list' {
        Test-BrowserExtensionPolicy -Browser $browserName -PolicyRoot $browser.PolicyRoot -ApprovedIds $browser.ApprovedExtensionIds
    }
}

# ---- OS (Windows) checks, part 2. Skipped when RestrictTo does not include OS (not indented).
if (Test-SystemSelected 'OS') {

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

# Privacy and data minimization.
# Security setting: Diagnostic Data Level. When configured, expect diagnostic data off (AllowTelemetry = 0).
# Remediations.ps1 does not set the policy while Smart App Control is On, in Evaluation
# or in an unknown state, because Smart App Control requires optional diagnostic data
# and losing it could not be rolled back (see Design.md, section 11). The check is then
# skipped with that reason, unless the policy already has the expected value.
$smartAppControlState = Get-SmartAppControlState
$diagnosticDataPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$diagnosticDataPolicyKey = if (Test-Path -LiteralPath $diagnosticDataPolicyPath -PathType Container) {
    Get-Item -LiteralPath $diagnosticDataPolicyPath -ErrorAction Stop
}
$diagnosticDataPolicyConfigured = $null -ne $diagnosticDataPolicyKey -and $diagnosticDataPolicyKey.GetValueNames() -contains 'AllowTelemetry'
if ($smartAppControlState -ne 0 -and -not ($diagnosticDataPolicyConfigured -and (Get-RegValue $diagnosticDataPolicyPath 'AllowTelemetry') -eq 0)) {
    $smartAppControlDescription = switch ($smartAppControlState) {
        1 { 'On' }
        2 { 'in Evaluation mode' }
        default { 'in an unknown state (its setting could not be read)' }
    }
    $message = "[SKIP] Diagnostic Data Level — skipped: Smart App Control is $smartAppControlDescription and requires optional diagnostic data, so Remediations.ps1 leaves this setting alone (see Design.md, section 11)."
    Write-AuditLog $message
    Write-Host $message -ForegroundColor Yellow
} elseif (-not $diagnosticDataPolicyConfigured) {
    $message = '[SKIP] Diagnostic Data Level — AllowTelemetry policy is not configured; check skipped.'
    Write-AuditLog $message
    Write-Host $message -ForegroundColor Yellow
} else {
    Test-Setting 'Diagnostic Data Level' 'Diagnostic data off where supported (AllowTelemetry = 0)' {
        (Get-RegValue $diagnosticDataPolicyPath 'AllowTelemetry') -eq 0
    }
}
Test-Setting 'Tailored Experiences' 'Disabled (DisableTailoredExperiencesWithDiagnosticData = 1)' { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableTailoredExperiencesWithDiagnosticData') -eq 1 }
Test-Setting 'Consumer Features and App Suggestions' 'Disabled (DisableWindowsConsumerFeatures = 1)' { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures') -eq 1 }
Test-Setting 'Advertising ID Tracking' 'Disabled by policy (DisabledByGroupPolicy = 1)' { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy') -eq 1 }

# Account and remote-access controls.
Test-Setting 'User Account Control (UAC)' 'EnableLUA = DWORD 1' { Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1 }
Test-Setting 'Administrative Elevation Prompt' 'ConsentPromptBehaviorAdmin = DWORD 2 (prompt for consent on secure desktop)' { Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2 }
Test-Setting 'Secure Desktop for Elevation Prompts' 'PromptOnSecureDesktop = DWORD 1' { Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1 }
# Administrator protection (TypeOfAdminApprovalMode = 2, in the Microsoft security
# baseline for Windows 11 26H2) is deliberately not checked yet: the feature is new and
# still rolling out. Revisit by the end of January 2027.
Test-Setting 'Automatic Screen Lock' 'Lock after 360 seconds of inactivity (InactivityTimeoutSecs = 360)' { (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs') -eq 360 }
Test-Setting 'Autorun / Autoplay Restrictions' 'NoDriveTypeAutoRun = 255 (disabled for all drive types)' { (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -eq 255 }
Test-Setting 'CIS 2.3.4.1 Prevent Non-Administrators from Installing Printer Drivers' 'Enabled (AddPrinterDrivers = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers' 1 }
$script:LocalSecurityPolicy = $null
$script:UserRights = $null
function Get-CachedLocalSecurityPolicy {
    if ($null -eq $script:LocalSecurityPolicy) {
        $script:LocalSecurityPolicy = Get-LocalSecurityPolicy
    }
    $script:LocalSecurityPolicy
}

function Get-CachedUserRights {
    if ($null -eq $script:UserRights) {
        $policyFile = Join-Path $script:WorkDirectory ("SecurityAudit-UserRights-{0}.inf" -f [guid]::NewGuid().ToString('N'))
        try {
            $exportOutput = (& $script:SeceditPath /export /cfg $policyFile /areas USER_RIGHTS 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                throw "secedit user-rights export failed: $exportOutput"
            }

            $policyText = Get-Content -LiteralPath $policyFile -Raw -ErrorAction Stop
            $privilegeRights = [regex]::Match($policyText, '(?ims)^\[Privilege Rights\]\s*(.*?)(?=^\[|\z)')
            if (-not $privilegeRights.Success) {
                throw 'Could not find the Privilege Rights section in the exported security policy.'
            }

            $rights = @{}
            foreach ($line in ($privilegeRights.Groups[1].Value -split '\r?\n')) {
                if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$') {
                    $rightName = $Matches[1]
                    $rights[$rightName] = @($Matches[2] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
                }
            }
            $script:UserRights = $rights
        }
        finally {
            if (Test-Path -LiteralPath $policyFile) {
                Remove-Item -LiteralPath $policyFile -Force -ErrorAction Stop
            }
        }
    }
    $script:UserRights
}

# Accounts that only exist on some Windows versions. PrintSpoolerService is a
# virtual account introduced in Windows 11 22H2 and does not exist on Windows 10.
$script:CisOptionalUserRightAccounts = @('RESTRICTED SERVICES\PrintSpoolerService')

function ConvertTo-CisAccountSid {
    param([Parameter(Mandatory)][string]$Account)
    if ($Account -match '^S-1-') { return $Account }
    try {
        $accountNames = if ($Account.Contains('\')) { @($Account) } else { @("$env:COMPUTERNAME\$Account", $Account) }
        foreach ($accountName in $accountNames) {
            try { return ([System.Security.Principal.NTAccount]::new($accountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        }
        throw "Account name could not be translated."
    }
    catch {
        throw "Could not resolve CIS user-right account '$Account' to a SID: $($_.Exception.Message)"
    }
}

function Test-CisUserRight {
    param(
        [Parameter(Mandatory)][string]$Right,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedAccounts,
        [ValidateSet('Exact','Include')][string]$MatchMode = 'Exact'
    )
    $rights = Get-CachedUserRights
    if (-not $rights.ContainsKey($Right)) {
        if ($ExpectedAccounts.Count -eq 0) { return $true }
        # A right missing from the export has no accounts assigned.
        return "Expected accounts: $($ExpectedAccounts -join ', '); observed: no accounts assigned."
    }
    $expectedSids = @($ExpectedAccounts | ForEach-Object {
        if ($_ -in $script:CisOptionalUserRightAccounts) {
            # Skip accounts that do not exist on this Windows version (for example Windows 10).
            try { ConvertTo-CisAccountSid $_ } catch { }
        } else {
            ConvertTo-CisAccountSid $_
        }
    } | Sort-Object -Unique)
    $actualSids = @($rights[$Right] | ForEach-Object { ConvertTo-CisAccountSid $_ } | Sort-Object -Unique)
    $matchesExpected = if ($MatchMode -eq 'Include') {
        @($expectedSids | Where-Object { $_ -notin $actualSids }).Count -eq 0
    } else {
        $expectedSids.Count -eq $actualSids.Count -and
            @($expectedSids | Where-Object { $_ -notin $actualSids }).Count -eq 0
    }
    if (-not $matchesExpected) {
        return "Expected accounts: $($ExpectedAccounts -join ', '); observed SIDs: $($actualSids -join ', ')."
    }
    $true
}

# CIS 1.1.1-1.1.7 and 1.2.1-1.2.4 apply to local accounts on this standalone PC.
Test-Setting 'CIS 1.1.1 Password History' 'At least 24 remembered passwords' { (Get-CachedLocalSecurityPolicy).PasswordHistorySize -ge 24 }
Test-Setting 'CIS 1.1.2 Maximum Password Age' 'Between 1 and 365 days' { (Get-CachedLocalSecurityPolicy).MaximumPasswordAge -ge 1 -and (Get-CachedLocalSecurityPolicy).MaximumPasswordAge -le 365 }
Test-Setting 'CIS 1.1.3 Minimum Password Age' 'At least 1 day' { (Get-CachedLocalSecurityPolicy).MinimumPasswordAge -ge 1 }
Test-Setting 'CIS 1.1.4 Minimum Password Length' 'At least 14 characters' { (Get-CachedLocalSecurityPolicy).MinimumPasswordLength -ge 14 }
Test-Setting 'CIS 1.1.5 Password Complexity' 'Enabled' { (Get-CachedLocalSecurityPolicy).PasswordComplexity -eq 1 }
Test-Setting 'CIS 1.1.6 Relax Minimum Password Length Limit' 'Enabled (RelaxMinimumPasswordLengthLimits = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' 'RelaxMinimumPasswordLengthLimits' 1 }
Test-Setting 'CIS 1.1.7 Reversible Password Encryption' 'Disabled' { (Get-CachedLocalSecurityPolicy).PasswordReversibleEncryption -eq 0 }
Test-Setting 'CIS 1.2.1 Account Lockout Duration' 'At least 15 minutes' {
    $policy = Get-CachedLocalSecurityPolicy
    if ($null -eq $policy.LockoutDuration) { 'Not set (account lockout is disabled).' } else { $policy.LockoutDuration -ge 15 }
}
Test-Setting 'CIS 1.2.2 Account Lockout Threshold' 'Between 1 and 5 invalid sign-in attempts' { (Get-CachedLocalSecurityPolicy).LockoutBadCount -ge 1 -and (Get-CachedLocalSecurityPolicy).LockoutBadCount -le 5 }
Test-Setting 'CIS 1.2.3 Built-in Administrator Account Lockout' 'Enabled (AllowAdministratorLockout = 1)' {
    $policy = Get-CachedLocalSecurityPolicy
    if ($null -eq $policy.AllowAdministratorLockout) {
        'AllowAdministratorLockout is not present in the exported policy; this Windows build may not support it. Install the latest Windows updates and run Remediations.'
    } else {
        $policy.AllowAdministratorLockout -eq 1
    }
}
Test-Setting 'CIS 1.2.4 Reset Lockout Counter' 'At least 15 minutes and no longer than the lockout duration' {
    $policy = Get-CachedLocalSecurityPolicy
    if ($null -eq $policy.ResetLockoutCount) { 'Not set (account lockout is disabled).' }
    else { $policy.ResetLockoutCount -ge 15 -and $null -ne $policy.LockoutDuration -and $policy.ResetLockoutCount -le $policy.LockoutDuration }
}

Test-Setting 'Remote Desktop NLA' 'UserAuthentication = 1' { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1 }
Test-Setting 'Remote Desktop Service' 'Disabled (fDenyTSConnections = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 }
$cisSystemServices = @(
    @{ Recommendation = '5.3'; Name = 'Browser'; DisplayName = 'Computer Browser' }
    @{ Recommendation = '5.4'; Name = 'MapsBroker'; DisplayName = 'Downloaded Maps Manager' }
    @{ Recommendation = '5.5'; Name = 'GameInputSvc'; DisplayName = 'GameInput Service' }
    @{ Recommendation = '5.6'; Name = 'lfsvc'; DisplayName = 'Geolocation Service' }
    @{ Recommendation = '5.7'; Name = 'IISADMIN'; DisplayName = 'IIS Admin Service' }
    @{ Recommendation = '5.8'; Name = 'irmon'; DisplayName = 'Infrared Monitor Service' }
    @{ Recommendation = '5.9'; Name = 'lltdsvc'; DisplayName = 'Link-Layer Topology Discovery Mapper' }
    @{ Recommendation = '5.10'; Name = 'FTPSVC'; DisplayName = 'Microsoft FTP Service' }
    @{ Recommendation = '5.11'; Name = 'MSiSCSI'; DisplayName = 'Microsoft iSCSI Initiator Service' }
    @{ Recommendation = '5.12'; Name = 'sshd'; DisplayName = 'OpenSSH SSH Server' }
    @{ Recommendation = '5.13'; Name = 'PNRPsvc'; DisplayName = 'Peer Name Resolution Protocol' }
    @{ Recommendation = '5.14'; Name = 'p2psvc'; DisplayName = 'Peer Networking Grouping' }
    @{ Recommendation = '5.15'; Name = 'p2pimsvc'; DisplayName = 'Peer Networking Identity Manager' }
    @{ Recommendation = '5.16'; Name = 'PNRPAutoReg'; DisplayName = 'PNRP Machine Name Publication Service' }
    @{ Recommendation = '5.18'; Name = 'wercplsupport'; DisplayName = 'Problem Reports and Solutions Control Panel Support' }
    @{ Recommendation = '5.19'; Name = 'RasAuto'; DisplayName = 'Remote Access Auto Connection Manager' }
    @{ Recommendation = '5.20'; Name = 'SessionEnv'; DisplayName = 'Remote Desktop Configuration' }
    @{ Recommendation = '5.21'; Name = 'TermService'; DisplayName = 'Remote Desktop Services' }
    @{ Recommendation = '5.22'; Name = 'UmRdpService'; DisplayName = 'Remote Desktop Services UserMode Port Redirector' }
    @{ Recommendation = '5.23'; Name = 'RpcLocator'; DisplayName = 'Remote Procedure Call Locator' }
    @{ Recommendation = '5.24'; Name = 'RemoteRegistry'; DisplayName = 'Remote Registry' }
    @{ Recommendation = '5.25'; Name = 'RemoteAccess'; DisplayName = 'Routing and Remote Access' }
    @{ Recommendation = '5.26'; Name = 'LanmanServer'; DisplayName = 'Server' }
    @{ Recommendation = '5.27'; Name = 'simptcp'; DisplayName = 'Simple TCP/IP Services' }
    @{ Recommendation = '5.28'; Name = 'SNMP'; DisplayName = 'SNMP Service' }
    @{ Recommendation = '5.29'; Name = 'sacsvr'; DisplayName = 'Special Administration Console Helper' }
    @{ Recommendation = '5.30'; Name = 'SSDPSRV'; DisplayName = 'SSDP Discovery' }
    @{ Recommendation = '5.31'; Name = 'upnphost'; DisplayName = 'UPnP Device Host' }
    @{ Recommendation = '5.32'; Name = 'WMSvc'; DisplayName = 'Web Management Service' }
    @{ Recommendation = '5.33'; Name = 'WerSvc'; DisplayName = 'Windows Error Reporting Service' }
    @{ Recommendation = '5.34'; Name = 'Wecsvc'; DisplayName = 'Windows Event Collector' }
    @{ Recommendation = '5.35'; Name = 'WMPNetworkSvc'; DisplayName = 'Windows Media Player Network Sharing Service' }
    @{ Recommendation = '5.36'; Name = 'icssvc'; DisplayName = 'Windows Mobile Hotspot Service' }
    @{ Recommendation = '5.38'; Name = 'PushToInstall'; DisplayName = 'Windows PushToInstall Service' }
    @{ Recommendation = '5.39'; Name = 'WinRM'; DisplayName = 'Windows Remote Management' }
    @{ Recommendation = '5.40'; Name = 'W3SVC'; DisplayName = 'World Wide Web Publishing Service' }
    @{ Recommendation = '5.41'; Name = 'XboxGipSvc'; DisplayName = 'Xbox Accessory Management Service' }
    @{ Recommendation = '5.42'; Name = 'XblAuthManager'; DisplayName = 'Xbox Live Auth Manager' }
    @{ Recommendation = '5.43'; Name = 'XblGameSave'; DisplayName = 'Xbox Live Game Save' }
    @{ Recommendation = '5.44'; Name = 'XboxNetApiSvc'; DisplayName = 'Xbox Live Networking Service' }
)
foreach ($servicePolicy in $cisSystemServices) {
    Test-Setting "CIS $($servicePolicy.Recommendation) $($servicePolicy.DisplayName)" 'Stopped and disabled, or not installed' {
        Test-CisServiceDisabled -Name $servicePolicy.Name
    }
}

# Network protections and protocol exposure.
Test-Setting 'Windows Firewall Profiles' 'Domain, Private, and Public profiles enabled' { @(Get-NetFirewallProfile | Where-Object Enabled -ne $true).Count -eq 0 -and @(Get-NetFirewallProfile).Count -eq 3 }
Test-Setting 'Windows Firewall Effective Profile Settings' 'All profiles enabled; DefaultInboundAction = Block; DefaultOutboundAction = Allow' {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $expectedNames = @('Domain', 'Private', 'Public')
    $mismatches = @()
    if ($profiles.Count -ne $expectedNames.Count -or @($profiles.Name | Where-Object { $_ -notin $expectedNames }).Count -gt 0 -or
        @($expectedNames | Where-Object { $_ -notin $profiles.Name }).Count -gt 0) {
        $mismatches += "Expected exactly the Domain, Private, and Public profiles; observed: $(@($profiles.Name) -join ', ')."
    }
    foreach ($firewallProfile in $profiles) {
        if ($firewallProfile.Enabled -ne $true -or
            [string]$firewallProfile.DefaultInboundAction -ne 'Block' -or
            [string]$firewallProfile.DefaultOutboundAction -ne 'Allow') {
            $mismatches += "$($firewallProfile.Name): Enabled=$($firewallProfile.Enabled), DefaultInboundAction=$($firewallProfile.DefaultInboundAction), DefaultOutboundAction=$($firewallProfile.DefaultOutboundAction)."
        }
    }
    if ($mismatches.Count -gt 0) {
        "Firewall effective profile settings do not match the baseline: $($mismatches -join '; ')"
    } else {
        $true
    }
}
Test-Setting 'Public Network Profile Safety' 'Active unidentified networks use Public; Public profile is enabled with inbound Block; Network Discovery / File and Printer Sharing allow rules are disabled' {
    $profiles = @(Get-NetConnectionProfile -ErrorAction Stop)
    $unidentifiedProfiles = @($profiles | Where-Object { $_.Name -match '(?i)unidentified' })
    $nonPublicUnidentifiedProfiles = @($unidentifiedProfiles | Where-Object { $_.NetworkCategory -ne 'Public' })
    if ($nonPublicUnidentifiedProfiles.Count -gt 0) {
        "Active unidentified network profiles are not Public: $($nonPublicUnidentifiedProfiles.Name -join ', ')."
    } else {
        $publicFirewallProfile = @(Get-NetFirewallProfile -Name Public -ErrorAction Stop)
        if ($publicFirewallProfile.Count -ne 1 -or $publicFirewallProfile[0].Enabled -ne $true) {
            'The Public firewall profile is missing or disabled.'
        } else {
            $inboundActionProperty = $publicFirewallProfile[0].PSObject.Properties['DefaultInboundAction']
            $inboundAction = if ($null -ne $inboundActionProperty) { [string]$inboundActionProperty.Value } else { $null }
            if ($inboundAction -ne 'Block') {
                "Public firewall default inbound action is '$inboundAction' instead of Block."
            } else {
                # Only the rules of the two groups are read, by group, which takes a few
                # seconds; reading every rule of the Public profile first took about 30.
                # A rule applies to the Public profile when its profile is Any (0) or
                # includes Public (4).
                $sharingRuleGroups = @('@FirewallAPI.dll,-32752', '@FirewallAPI.dll,-28502')
                $sharingRules = @(foreach ($ruleGroup in $sharingRuleGroups) {
                    try {
                        Get-NetFirewallRule -Group $ruleGroup -ErrorAction Stop
                    } catch {
                        # A group that has no rule at all is reported as "not found"; any other error fails the check.
                        if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound) { throw }
                    }
                })
                $publicFirewallRules = @($sharingRules | Where-Object { [int]$_.Profile -eq 0 -or ([int]$_.Profile -band 4) })
                # Teredo-only rules (internal names ending in -Teredo, independent of the
                # display language) cannot receive traffic while Teredo is disabled by policy.
                $teredoDisabled = Test-RegString 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' 'Teredo_State' 'Disabled'
                $exposedPublicRules = @($publicFirewallRules | Where-Object {
                    $_.Enabled -eq 'True' -and
                    $_.Direction -eq 'Inbound' -and
                    $_.Action -eq 'Allow' -and
                    $_.Group -in $sharingRuleGroups -and
                    -not ($teredoDisabled -and $_.Name -like '*-Teredo')
                })
                if ($exposedPublicRules.Count -gt 0) {
                    "Public-profile Network Discovery or File and Printer Sharing inbound allow rules are enabled: $($exposedPublicRules.DisplayName -join ', ')."
                } else {
                    $true
                }
            }
        }
    }
}
Test-Setting 'SMBv1 Protocol Client/Server' 'Client feature disabled and server protocol absent' {
    $client=@(Invoke-DismQuery -IgnoreErrors { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue })[0]
    $serverService=Get-CimInstance Win32_Service -Filter "Name='LanmanServer'" -ErrorAction Stop
    $serverSmb1Enabled=$false
    if ($serverService.StartMode -ne 'Disabled') {
        $serverSmb1Enabled=(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    }
    ($null -eq $client -or $client.State -ne 'Enabled') -and -not $serverSmb1Enabled
}
Test-Setting 'Windows PowerShell 2.0' 'Optional features absent or disabled' {
    $powerShell2FeatureNames = @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')
    # The two features are queried by name, which takes about a second each; listing all
    # optional features took about 10 seconds. A feature that does not exist (PowerShell
    # 2.0 was removed from newer Windows versions) returns nothing and no error, the same
    # result as not finding it in the full list. The names are repeated inside the query
    # because it runs in a separate runspace, which cannot see the variables of this script.
    $powerShell2Features = @(Invoke-DismQuery {
            foreach ($featureName in 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2') {
                Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
            }
        } | Where-Object { $_.FeatureName -in $powerShell2FeatureNames })
    $enabledFeatures = @($powerShell2Features | Where-Object { $_.State -eq 'Enabled' })
    $unexpectedStates = @($powerShell2Features | Where-Object { $_.State -notin @('Enabled', 'Disabled', 'DisabledWithPayloadRemoved') })
    if ($enabledFeatures.Count -gt 0 -or $unexpectedStates.Count -gt 0) {
        $observed = @($powerShell2Features | ForEach-Object { "$($_.FeatureName)=$($_.State)" }) -join ', '
        "PowerShell 2.0 optional features are enabled or not verifiably disabled: $observed."
    } else {
        $true
    }
}
Test-Setting 'LLMNR Name Resolution' 'EnableMulticast = 0' { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0 }
Test-Setting 'Teredo Tunneling' 'Disabled by policy (Teredo_State = REG_SZ Disabled)' { Test-RegString 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' 'Teredo_State' 'Disabled' }
Test-Setting 'TLS/SSL Protocol Versions (Schannel)' 'SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 disabled for Client and Server (Enabled = DWORD 0, DisabledByDefault = DWORD 1); TLS 1.2 enabled (Enabled = DWORD 1, DisabledByDefault = DWORD 0); TLS 1.3 enabled on Windows 11 (Enabled = DWORD 1, DisabledByDefault = DWORD 0), not disabled on Windows 10' {
    $protocolsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    # Reads a DWORD without throwing when the key or value is missing; returns $null then.
    $readDword = {
        param($Path, $Name)
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains $Name) { return $null }
        if ($key.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { return "non-DWORD:$($key.GetValue($Name))" }
        [int]$key.GetValue($Name)
    }
    $formatValue = { param($Value) if ($null -eq $Value) { 'not set' } else { "$Value" } }
    $problems = foreach ($protocol in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')) {
        foreach ($role in @('Client', 'Server')) {
            $path = "$protocolsPath\$protocol\$role"
            $enabled = & $readDword $path 'Enabled'
            $disabledByDefault = & $readDword $path 'DisabledByDefault'
            $observed = "Enabled=$(& $formatValue $enabled), DisabledByDefault=$(& $formatValue $disabledByDefault)"
            $mustBeEnabled = $protocol -eq 'TLS 1.2' -or ($protocol -eq 'TLS 1.3' -and $script:OsBuildNumber -ge 22000)
            switch ($protocol) {
                { $mustBeEnabled } {
                    # Any nonzero Enabled value (1 or 0xFFFFFFFF) enables the protocol.
                    if (-not ($enabled -is [int] -and $enabled -ne 0 -and $disabledByDefault -is [int] -and $disabledByDefault -eq 0)) {
                        "$protocol $role is not explicitly enabled ($observed)"
                    }
                    break
                }
                'TLS 1.3' {
                    # Windows 10 only (Windows 11 is handled above): not configured by
                    # Remediations.ps1, so only flag an explicit disablement.
                    if (($enabled -is [int] -and $enabled -eq 0) -or ($disabledByDefault -is [int] -and $disabledByDefault -ne 0)) {
                        "$protocol $role is disabled ($observed); remove these values manually, Remediations.ps1 does not change TLS 1.3 on Windows 10"
                    }
                }
                default {
                    if (-not ($enabled -is [int] -and $enabled -eq 0 -and $disabledByDefault -is [int] -and $disabledByDefault -eq 1)) {
                        "$protocol $role is not explicitly disabled ($observed)"
                    }
                }
            }
        }
    }
    if (@($problems).Count -gt 0) { "Noncompliant Schannel protocol settings: $(@($problems) -join '; ')." } else { $true }
}
Test-Setting 'CIS 2.3.11.6 LAN Manager Authentication Level and Legacy Authentication Hardening' 'LmCompatibilityLevel=5; NoLMHash=1; WDigest UseLogonCredential=0' {
    $settings = @(
        @{ Name='LmCompatibilityLevel'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected=5 }
        @{ Name='NoLMHash'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected=1 }
        @{ Name='WDigest UseLogonCredential'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; ValueName='UseLogonCredential'; Expected=0 }
    )
    $mismatches = foreach ($setting in $settings) {
        $valueName = if ($setting.ValueName) { $setting.ValueName } else { $setting.Name }
        $value = Get-RegValue $setting.Path $valueName
        if (-not (Test-RegDword $setting.Path $valueName $setting.Expected)) {
            "$valueName=$value (expected $($setting.Expected))"
        }
    }
    if (@($mismatches).Count -gt 0) { "Noncompliant registry values: $(@($mismatches) -join ', ')." } else { $true }
}
Test-Setting 'CIS 2.3.11.1 Local System Computer Identity for NTLM' 'Enabled (UseMachineId = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'UseMachineId' 1 }
Test-Setting 'CIS 2.3.11.2 LocalSystem NULL Session Fallback' 'Disabled (AllowNullSessionFallback = DWORD 0)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AllowNullSessionFallback' 0 }
Test-Setting 'CIS 2.3.11.3 PKU2U Online Identity Authentication' 'Disabled (AllowOnlineID = DWORD 0)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' 'AllowOnlineID' 0 }
Test-Setting 'CIS 2.3.11.4 Kerberos Encryption Types' 'AES128, AES256, and future encryption types (SupportedEncryptionTypes = DWORD 2147483640)' { Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 2147483640 }
Test-Setting 'CIS 2.3.11.5 Force Logoff When Logon Hours Expire' 'Enabled (ForceLogoffWhenHourExpire = 1)' { (Get-CachedLocalSecurityPolicy).ForceLogoffWhenHourExpire -eq 1 }
Test-Setting 'CIS 2.3.11.7 LDAP Client Encryption Requirements' 'Negotiate sealing or require sealing (LDAPClientConfidentiality = DWORD 1 or 2)' {
    (Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientConfidentiality' 1) -or
    (Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientConfidentiality' 2)
}
Test-Setting 'CIS 2.3.11.8 LDAP Client Signing Requirements' 'Negotiate signing or require signing (LDAPClientIntegrity = DWORD 1 or 2)' {
    (Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1) -or
    (Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 2)
}
Test-Setting 'CIS 2.3.11.9 Minimum NTLM Client Session Security' 'NTLMv2 and 128-bit encryption (NTLMMinClientSec = DWORD 537395200)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' 537395200 }
Test-Setting 'CIS 2.3.11.10 Minimum NTLM Server Session Security' 'NTLMv2 and 128-bit encryption (NTLMMinServerSec = DWORD 537395200)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec' 537395200 }
Test-Setting 'CIS 2.3.11.11 Audit Incoming NTLM Traffic' 'Audit all accounts (AuditReceivingNTLMTraffic = DWORD 2)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic' 2 }
Test-Setting 'CIS 2.3.11.12 Audit Outgoing NTLM Traffic' 'Audit all (RestrictSendingNTLMTraffic = DWORD 1) or Deny all (DWORD 2)' {
    (Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictSendingNTLMTraffic' 1) -or
    (Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictSendingNTLMTraffic' 2)
}
Test-Setting 'CIS 18.6.9.1 Link-Layer Topology Discovery Mapper I/O Driver' 'Disabled (all LLTDIO policy values = DWORD 0)' {
    $lltdPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD'
    @('AllowLLTDIOOnDomain','AllowLLTDIOOnPublicNet','EnableLLTDIO','ProhibitLLTDIOOnPrivateNet') |
        ForEach-Object { Test-RegDword $lltdPath $_ 0 } |
        Where-Object { -not $_ } |
        Measure-Object |
        ForEach-Object { $_.Count -eq 0 }
}
Test-Setting 'CIS 18.6.9.2 Link-Layer Topology Discovery Responder Driver' 'Disabled (all RSPNDR policy values = DWORD 0)' {
    $lltdPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD'
    @('AllowRspndrOnDomain','AllowRspndrOnPublicNet','EnableRspndr','ProhibitRspndrOnPrivateNet') |
        ForEach-Object { Test-RegDword $lltdPath $_ 0 } |
        Where-Object { -not $_ } |
        Measure-Object |
        ForEach-Object { $_.Count -eq 0 }
}
Test-Setting 'CIS 18.6.10.2 Turn Off Microsoft Peer-to-Peer Networking Services' 'Enabled (Disabled = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' 'Disabled' 1 }
Test-Setting 'CIS 18.6.14.1 Hardened UNC Paths' 'NETLOGON and SYSVOL require mutual authentication, integrity, and privacy' {
    $hardenedPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
    $expectedPathPolicy = 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'
    (Test-RegString $hardenedPath '\\*\NETLOGON' $expectedPathPolicy) -and
        (Test-RegString $hardenedPath '\\*\SYSVOL' $expectedPathPolicy)
}
Test-Setting 'CIS 18.6.20.1 Windows Connect Now Configuration' 'Disabled (all five Registrar policy values = DWORD 0)' {
    $wcnPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
    @('EnableRegistrars','DisableUPnPRegistrar','DisableInBand802DOT11Registrar','DisableFlashConfigRegistrar','DisableWPDRegistrar') |
        ForEach-Object { Test-RegDword $wcnPath $_ 0 } |
        Where-Object { -not $_ } |
        Measure-Object |
        ForEach-Object { $_.Count -eq 0 }
}
Test-Setting 'CIS 18.6.20.2 Windows Connect Now Wizards' 'Prohibited (DisableWcnUi = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' 'DisableWcnUi' 1 }
Test-Setting 'CIS 18.6.23.2.1 Automatic Wi-Fi Sense Connections' 'Disabled (AutoConnectAllowedOEM = DWORD 0)' { Test-RegDword 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' 'AutoConnectAllowedOEM' 0 }
Test-Setting 'mDNS and WPAD' 'EnableMDNS=0; WpadOverride=1' {
    $mdns=Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'
    $wpad=Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' 'WpadOverride'
    if ($mdns -ne 0 -or $wpad -ne 1) {
        "EnableMDNS=$mdns (expected 0); WpadOverride=$wpad (expected 1)"
    } else { $true }
}
Test-Setting 'CIS 2.3.10.1 Allow Anonymous SID/Name Translation' 'Disabled (LSAAnonymousNameLookup = 0)' { (Get-CachedLocalSecurityPolicy).LSAAnonymousNameLookup -eq 0 }
Test-Setting 'CIS 2.3.10.2 Anonymous SAM Account Enumeration' 'Disabled (RestrictAnonymousSAM = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1 }
Test-Setting 'CIS 2.3.10.3 Anonymous SAM Account and Share Enumeration' 'Disabled (RestrictAnonymous = DWORD 2)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 2 }
Test-Setting 'CIS 2.3.10.4 Network Credential Storage' 'Disabled (DisableDomainCreds = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableDomainCreds' 1 }
Test-Setting 'CIS 2.3.10.5 Everyone Permissions for Anonymous Users' 'Disabled (EveryoneIncludesAnonymous = DWORD 0)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0 }
Test-Setting 'CIS 2.3.10.6 Anonymous Named Pipes' 'No anonymously accessible named pipes (NullSessionPipes empty)' { Test-RegMultiString 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'NullSessionPipes' @() }
Test-Setting 'CIS 2.3.10.7 Remotely Accessible Registry Paths' 'Required paths only (AllowedExactPaths\Machine)' {
    Test-RegMultiString 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' 'Machine' @(
        'System\CurrentControlSet\Control\ProductOptions'
        'System\CurrentControlSet\Control\Server Applications'
        'Software\Microsoft\Windows NT\CurrentVersion'
    )
}
Test-Setting 'CIS 2.3.10.8 Remotely Accessible Registry Paths and Sub-Paths' 'Required paths only (AllowedPaths\Machine)' {
    Test-RegMultiString 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' 'Machine' @(
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
    )
}
Test-Setting 'CIS 2.3.10.9 Restrict Anonymous Access to Named Pipes and Shares' 'Enabled (RestrictNullSessAccess = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'RestrictNullSessAccess' 1 }
Test-Setting 'CIS 2.3.10.10 Restrict Remote SAM RPC Access' 'Administrators: Remote Access: Allow (restrictremotesam REG_SZ)' { Test-RegString 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictremotesam' 'O:BAG:BAD:(A;;RC;;;BA)' }
Test-Setting 'CIS 2.3.10.11 Anonymous Shares' 'No anonymously accessible shares (NullSessionShares empty)' { Test-RegMultiString 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' 'NullSessionShares' @() }
Test-Setting 'CIS 2.3.10.12 Local Account Network Authentication' 'Classic (ForceGuest = DWORD 0)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'ForceGuest' 0 }
Test-Setting 'CIS 18.7.1 Print Spooler Client Connections' 'Disabled (RegisterSpoolerRemoteRpcEndPoint = DWORD 2)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'RegisterSpoolerRemoteRpcEndPoint' 2 }
Test-Setting 'CIS 18.7.2 Print Spooler Redirection Guard' 'Enabled (RedirectionguardPolicy = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'RedirectionguardPolicy' 1 }
Test-Setting 'CIS 18.7.3 Outgoing Print RPC Protocol' 'RPC over TCP (RpcUseNamedPipeProtocol = DWORD 0)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcUseNamedPipeProtocol' 0 }
Test-Setting 'CIS 18.7.4 Outgoing Print RPC Authentication' 'Default (RpcAuthentication = DWORD 0)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcAuthentication' 0 }
Test-Setting 'CIS 18.7.5 Incoming Print RPC Protocols' 'RPC over TCP (RpcProtocols = DWORD 5)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcProtocols' 5 }
Test-Setting 'CIS 18.7.6 Incoming Print RPC Authentication' 'Negotiate or Kerberos (ForceKerberosForRpc = DWORD 0 or 1)' {
    (Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' 'ForceKerberosForRpc' 0) -or
        (Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' 'ForceKerberosForRpc' 1)
}
Test-Setting 'CIS 18.7.7 Print RPC TCP Port' 'Dynamic TCP port (RpcTcpPort = DWORD 0)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcTcpPort' 0 }
Test-Setting 'CIS 18.7.8 Print RPC Packet Privacy' 'Enabled (RpcAuthnLevelPrivacyEnabled = DWORD 1)' { Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'RpcAuthnLevelPrivacyEnabled' 1 }
Test-Setting 'CIS 18.7.9 Windows Protected Print' 'Enabled (WindowsProtectedPrintGroupPolicyState = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\WPP' 'WindowsProtectedPrintGroupPolicyState' 1 }
Test-Setting 'CIS 18.7.10 Administrator-Only Print Driver Installation' 'Enabled (RestrictDriverInstallationToAdministrators = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators' 1 }
Test-Setting 'CIS 18.7.11 Queue-Specific Print File Processing' 'Color profiles only (CopyFilesPolicy = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'CopyFilesPolicy' 1 }
Test-Setting 'CIS 18.7.12 Point and Print New-Connection Prompt' 'Show warning and elevation prompt (NoWarningNoElevationOnInstall = DWORD 0)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall' 0 }
Test-Setting 'CIS 18.7.13 Point and Print Existing-Connection Prompt' 'Show warning and elevation prompt (UpdatePromptSettings = DWORD 0)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'UpdatePromptSettings' 0 }
Test-Setting 'CIS 18.7.14 IPP Printer Transport Security' 'Require IPPS (RequireIpps = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' 'RequireIpps' 1 }
Test-Setting 'CIS 18.7.15 IPP Invalid Certificate Authority' 'Reject invalid certificate authorities (SecurityFlagsBlockUnknownCA = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' 'SecurityFlagsBlockUnknownCA' 1 }
Test-Setting 'CIS 18.7.16 IPP Non-Server Certificates' 'Reject non-server certificates (SecurityFlagsBlockCertWrongUsage = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' 'SecurityFlagsBlockCertWrongUsage' 1 }
Test-Setting 'CIS 18.7.17 IPP Invalid Certificate Common Name' 'Reject invalid certificate names (SecurityFlagsBlockCertCNInvalid = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' 'SecurityFlagsBlockCertCNInvalid' 1 }
Test-Setting 'CIS 18.7.18 IPP Invalid Certificate Date' 'Reject invalid certificate dates (SecurityFlagsBlockCertDateInvalid = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP' 'SecurityFlagsBlockCertDateInvalid' 1 }

# Microsoft security baseline for Windows 11 26H2 (not a CIS recommendation): programs cannot
# start Internet Explorer 11 through COM automation. iexplore.exe is still on Windows 11 as a
# stub that opens Edge; this policy closes the COM route that malware has used to start it.
Test-Setting 'Internet Explorer Launch via COM Automation' 'Disabled (DisableInternetExplorerLaunchViaCOM = DWORD 1)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' 'DisableInternetExplorerLaunchViaCOM' 1 }
# Microsoft security baseline for Windows 11 26H2 (not a CIS recommendation): Windows prefers
# the Microsoft IPP Class Driver for printers that support IPP, instead of a vendor driver.
# Windows decides in this order: the policy value UseWindowsReadyPrintDriverRankingGroupPolicy,
# else the local setting UseWindowsReadyPrintDriverRanking, else on (the default). Both are in
# a key that Windows creates so that only SYSTEM can change it, so the check reads the
# effective state. Windows 11 versions before 24H2 do not have the feature.
Test-Setting 'Windows Ready Print Driver Ranking' 'Enabled (by policy, by the local setting, or by default)' {
    $driverRankingPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'
    $driverRankingValues = @{}
    if (Test-Path -LiteralPath $driverRankingPath) {
        $driverRankingKey = Get-Item -LiteralPath $driverRankingPath -ErrorAction Stop
        foreach ($valueName in $driverRankingKey.GetValueNames()) { $driverRankingValues[$valueName] = $driverRankingKey.GetValue($valueName) }
    }
    foreach ($valueName in @('UseWindowsReadyPrintDriverRankingGroupPolicy', 'UseWindowsReadyPrintDriverRanking')) {
        if ($driverRankingValues.ContainsKey($valueName)) {
            if ([string]$driverRankingValues[$valueName] -eq '0') { return "Turned off: $valueName = $($driverRankingValues[$valueName])." }
            return $true
        }
    }
    $true
}

# Not a CIS or Microsoft baseline recommendation: the lock screen widgets ("Weather and more")
# show content fetched from the internet on the lock screen, before anyone has signed in.
# The policy value DisableWidgetsOnLockScreen = 0 hides the widgets and 1 shows them (tested on
# Windows 11 build 10.0.26300; a web guide, majorgeeks.com, also says to set 0). That matches the
# values table of the Policy CSP page for NewsAndInterests (https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests),
# "0 (Default) Enabled, 1 Disabled", when "Enabled" is read as the state of the policy "Disable
# Widgets On Lock Screen" (on = widgets hidden). So the behavior is as documented; only the
# name of the value is misleading, because it suggests the opposite. It is per machine and
# applies to all users; without
# it, each user decides in Settings > Personalization > Lock screen.
Test-Setting 'Lock Screen Widgets Disabled' 'DisableWidgetsOnLockScreen = DWORD 0 (turns the lock screen widgets off, despite the name)' { Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'DisableWidgetsOnLockScreen' 0 }

# Additional CIS Windows 11 v5.0.0 Level 1 checks. Manual recommendations,
# audit/logging controls, Level 2-only controls, and services explicitly kept
# enabled for this computer are intentionally omitted.
$cisAdminsSid = 'S-1-5-32-544'
$cisUsersSid = 'S-1-5-32-545'
$cisGuestsSid = 'S-1-5-32-546'
$cisRdpUsersSid = 'S-1-5-32-555'
$cisLocalServiceSid = 'S-1-5-19'
$cisNetworkServiceSid = 'S-1-5-20'
$cisServiceSid = 'S-1-5-6'
$cisVirtualMachinesSid = 'S-1-5-83-0'  # NT VIRTUAL MACHINE\Virtual Machines
# CIS 2.2.13 adds NT VIRTUAL MACHINE\Virtual Machines when Hyper-V is installed; without it,
# new virtual machines cannot be created. The Hyper-V Virtual Machine Management service
# (vmms) exists only when the Hyper-V role is installed, not with Virtual Machine Platform alone.
$cisHyperVInstalled = $null -ne (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue)
$cisSymbolicLinkAccounts = if ($cisHyperVInstalled) { @($cisAdminsSid, $cisVirtualMachinesSid) } else { @($cisAdminsSid) }

$cisUserRightChecks = @(
    @{ Id='2.2.1'; Name='Access Credential Manager as a trusted caller'; Right='SeTrustedCredManAccessPrivilege'; Expected=@() }
    @{ Id='2.2.2'; Name='Access this computer from the network'; Right='SeNetworkLogonRight'; Expected=@($cisAdminsSid,$cisRdpUsersSid) }
    @{ Id='2.2.3'; Name='Act as part of the operating system'; Right='SeTcbPrivilege'; Expected=@() }
    @{ Id='2.2.4'; Name='Adjust memory quotas for a process'; Right='SeIncreaseQuotaPrivilege'; Expected=@($cisAdminsSid,$cisLocalServiceSid,$cisNetworkServiceSid) }
    @{ Id='2.2.5'; Name='Allow log on locally'; Right='SeInteractiveLogonRight'; Expected=@($cisAdminsSid,$cisUsersSid) }
    @{ Id='2.2.6'; Name='Allow log on through Remote Desktop Services'; Right='SeRemoteInteractiveLogonRight'; Expected=@($cisAdminsSid,$cisRdpUsersSid) }
    @{ Id='2.2.7'; Name='Back up files and directories'; Right='SeBackupPrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.8'; Name='Change the system time'; Right='SeSystemtimePrivilege'; Expected=@($cisAdminsSid,$cisLocalServiceSid) }
    @{ Id='2.2.9'; Name='Create a pagefile'; Right='SeCreatePagefilePrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.10'; Name='Create a token object'; Right='SeCreateTokenPrivilege'; Expected=@() }
    @{ Id='2.2.11'; Name='Create global objects'; Right='SeCreateGlobalPrivilege'; Expected=@($cisAdminsSid,$cisLocalServiceSid,$cisNetworkServiceSid,$cisServiceSid) }
    @{ Id='2.2.12'; Name='Create permanent shared objects'; Right='SeCreatePermanentPrivilege'; Expected=@() }
    @{ Id='2.2.13'; Name='Create symbolic links'; Right='SeCreateSymbolicLinkPrivilege'; Expected=$cisSymbolicLinkAccounts }
    @{ Id='2.2.14'; Name='Debug programs'; Right='SeDebugPrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.15'; Name='Deny access to this computer from the network'; Right='SeDenyNetworkLogonRight'; Expected=@($cisGuestsSid); MatchMode='Include' }
    @{ Id='2.2.16'; Name='Deny log on as a batch job'; Right='SeDenyBatchLogonRight'; Expected=@($cisGuestsSid); MatchMode='Include' }
    @{ Id='2.2.17'; Name='Deny log on as a service'; Right='SeDenyServiceLogonRight'; Expected=@($cisGuestsSid); MatchMode='Include' }
    @{ Id='2.2.18'; Name='Deny log on locally'; Right='SeDenyInteractiveLogonRight'; Expected=@($cisGuestsSid); MatchMode='Include' }
    @{ Id='2.2.19'; Name='Deny log on through Remote Desktop Services'; Right='SeDenyRemoteInteractiveLogonRight'; Expected=@($cisGuestsSid); MatchMode='Include' }
    @{ Id='2.2.20'; Name='Enable computer and user accounts to be trusted for delegation'; Right='SeEnableDelegationPrivilege'; Expected=@() }
    @{ Id='2.2.21'; Name='Force shutdown from a remote system'; Right='SeRemoteShutdownPrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.23'; Name='Impersonate a client after authentication'; Right='SeImpersonatePrivilege'; Expected=@($cisAdminsSid,$cisLocalServiceSid,$cisNetworkServiceSid,$cisServiceSid,'RESTRICTED SERVICES\PrintSpoolerService') }
    @{ Id='2.2.24'; Name='Increase scheduling priority'; Right='SeIncreaseBasePriorityPrivilege'; Expected=@($cisAdminsSid,'S-1-5-90-0') }
    @{ Id='2.2.25'; Name='Load and unload device drivers'; Right='SeLoadDriverPrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.26'; Name='Lock pages in memory'; Right='SeLockMemoryPrivilege'; Expected=@() }
    @{ Id='2.2.30'; Name='Modify an object label'; Right='SeRelabelPrivilege'; Expected=@() }
    @{ Id='2.2.31'; Name='Modify firmware environment values'; Right='SeSystemEnvironmentPrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.32'; Name='Perform volume maintenance tasks'; Right='SeManageVolumePrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.33'; Name='Profile single process'; Right='SeProfileSingleProcessPrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.34'; Name='Profile system performance'; Right='SeSystemProfilePrivilege'; Expected=@($cisAdminsSid,'NT SERVICE\WdiServiceHost') }
    @{ Id='2.2.35'; Name='Replace a process level token'; Right='SeAssignPrimaryTokenPrivilege'; Expected=@($cisLocalServiceSid,$cisNetworkServiceSid) }
    @{ Id='2.2.36'; Name='Restore files and directories'; Right='SeRestorePrivilege'; Expected=@($cisAdminsSid) }
    @{ Id='2.2.37'; Name='Shut down the system'; Right='SeShutdownPrivilege'; Expected=@($cisAdminsSid,$cisUsersSid) }
    @{ Id='2.2.38'; Name='Take ownership of files or other objects'; Right='SeTakeOwnershipPrivilege'; Expected=@($cisAdminsSid) }
)
foreach ($userRightCheck in $cisUserRightChecks) {
    $userRightMatchMode = if ($userRightCheck.MatchMode) { $userRightCheck.MatchMode } else { 'Exact' }
    Test-Setting "CIS $($userRightCheck.Id) $($userRightCheck.Name)" "Assigned accounts match CIS Level 1" {
        Test-CisUserRight -Right $userRightCheck.Right -ExpectedAccounts $userRightCheck.Expected -MatchMode $userRightMatchMode
    }
}

# CIS 2.3 security options not already covered by the baseline.
Test-Setting 'CIS 2.3.1.2 Blank Password Network Restriction' 'LimitBlankPasswordUse = DWORD 1' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1
}
Test-Setting 'CIS 2.3.7.2 Hide Last Signed-in User' 'DontDisplayLastUserName = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName' 1
}
Test-Setting 'CIS 2.3.7.6 Password Expiry Warning' 'PasswordExpiryWarning between 5 and 14 days' {
    $warningDays = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'PasswordExpiryWarning'
    $null -ne $warningDays -and [int]$warningDays -ge 5 -and [int]$warningDays -le 14
}
Test-Setting 'CIS 2.3.7.7 Smart Card Removal Behavior' 'ScRemoveOption is Lock, Force Logoff, or Disconnect (1, 2, or 3)' {
    $smartCardRemoval = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScRemoveOption'
    $null -ne $smartCardRemoval -and [string]$smartCardRemoval -in @('1','2','3')
}
Test-Setting 'CIS 2.3.8.2 Unencrypted Passwords to SMB Servers' 'EnablePlainTextPassword = DWORD 0' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnablePlainTextPassword' 0
}
Test-Setting 'CIS 2.3.9.1 SMB Server Idle Session Timeout' 'AutoDisconnect is between 1 and 15 minutes' {
    $autoDisconnect = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoDisconnect'
    $null -ne $autoDisconnect -and [int]$autoDisconnect -ge 1 -and [int]$autoDisconnect -le 15
}
Test-Setting 'CIS 2.3.9.3 Disconnect SMB Clients When Logon Hours Expire' 'EnableForcedLogOff = DWORD 1' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableForcedLogOff' 1
}
Test-Setting 'CIS 2.3.9.4 SMB Server SPN Target Name Validation' 'SmbServerNameHardeningLevel is 1 or 2' {
    $hardeningLevel = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SmbServerNameHardeningLevel'
    $null -ne $hardeningLevel -and [int]$hardeningLevel -in @(1,2)
}

# CIS 18.5 MSS network and host hardening settings at Level 1.
Test-Setting 'CIS 18.5.1 Automatic Logon Disabled' 'AutoAdminLogon is absent or REG_SZ 0' {
    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not (Test-Path -LiteralPath $winlogonPath)) { return $true }
    $winlogonKey = Get-Item -LiteralPath $winlogonPath -ErrorAction Stop
    if ($winlogonKey.GetValueNames() -notcontains 'AutoAdminLogon') { return $true }
    $winlogonKey.GetValueKind('AutoAdminLogon') -eq [Microsoft.Win32.RegistryValueKind]::String -and
        [string]$winlogonKey.GetValue('AutoAdminLogon') -eq '0'
}
Test-Setting 'CIS 18.5.2 IPv6 Source Routing Protection' 'DisableIPSourceRouting = DWORD 2' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2
}
Test-Setting 'CIS 18.5.3 IPv4 Source Routing Protection' 'DisableIPSourceRouting = DWORD 2' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2
}
Test-Setting 'CIS 18.5.5 Disable ICMP Redirects' 'EnableICMPRedirect = DWORD 0' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0
}
Test-Setting 'CIS 18.5.7 Ignore Untrusted NetBIOS Name Releases' 'NoNameReleaseOnDemand = DWORD 1' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand' 1
}
Test-Setting 'CIS 18.5.9 Safe DLL Search Mode' 'SafeDllSearchMode = DWORD 1' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1
}

# CIS 18.6 network controls; the mDNS check here verifies the benchmark policy
# value in addition to the existing host-level mDNS/WPAD check.
Test-Setting 'CIS 18.6.4.1 Disable mDNS by Policy' 'EnableMDNS = DWORD 0' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 0
}
Test-Setting 'CIS 18.6.7.4 SMB Server Authentication Rate Limiter' 'EnableAuthRateLimiter = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' 'EnableAuthRateLimiter' 1
}
Test-Setting 'CIS 18.6.7.5 Disable SMB Server Remote Mailslots' 'EnableMailslots = DWORD 0' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bowser' 'EnableMailslots' 0
}
Test-Setting 'CIS 18.6.7.6 SMB Server Minimum Dialect' 'MinSmb2Dialect = DWORD 785 (SMB 3.1.1)' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' 'MinSmb2Dialect' 785
}
Test-Setting 'CIS 18.6.7.7 SMB Server Authentication Rate Limit Delay' 'InvalidAuthenticationDelayTimeInMs is at least 2000' {
    $delay = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer' 'InvalidAuthenticationDelayTimeInMs'
    $null -ne $delay -and [int]$delay -ge 2000
}
Test-Setting 'CIS 18.6.8.4 Disable Insecure SMB Guest Logons' 'AllowInsecureGuestAuth = DWORD 0' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0
}
Test-Setting 'CIS 18.6.8.5 Disable SMB Client Remote Mailslots' 'EnableMailslots = DWORD 0' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider' 'EnableMailslots' 0
}
Test-Setting 'CIS 18.6.8.6 SMB Client Minimum Dialect' 'MinSmb2Dialect = DWORD 785 (SMB 3.1.1)' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'MinSmb2Dialect' 785
}
Test-Setting 'CIS 18.6.8.7 Require SMB Client Encryption' 'RequireEncryption = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'RequireEncryption' 1
}
Test-Setting 'CIS 18.6.11.2 Prohibit Network Bridge on Domain Networks' 'NC_AllowNetBridge_NLA = DWORD 0' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_AllowNetBridge_NLA' 0
}
Test-Setting 'CIS 18.6.11.3 Prohibit Internet Connection Sharing on Domain Networks' 'NC_ShowSharedAccessUI = DWORD 0' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_ShowSharedAccessUI' 0
}
Test-Setting 'CIS 18.6.21.1 Prevent Wi-Fi When Connected by Ethernet' 'fMinimizeConnections = DWORD 3' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'fMinimizeConnections' 3
}

# CIS 18.9 VBS settings. The existing HVCI check validates active runtime
# protection; these checks also verify the corresponding Level 1 policy options.
$deviceGuardPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Test-Setting 'CIS 18.9.5.1 Virtualization Based Security Policy' 'EnableVirtualizationBasedSecurity = DWORD 1' {
    Test-RegDword $deviceGuardPolicyPath 'EnableVirtualizationBasedSecurity' 1
}
Test-Setting 'CIS 18.9.5.2 VBS Platform Security Level' 'RequirePlatformSecurityFeatures is DWORD 1 or 3' {
    (Test-RegDword $deviceGuardPolicyPath 'RequirePlatformSecurityFeatures' 1) -or
        (Test-RegDword $deviceGuardPolicyPath 'RequirePlatformSecurityFeatures' 3)
}
# 18.9.5.3 and 18.9.5.5: CIS recommends 1 (with UEFI lock). The baseline also accepts
# 2 (without lock), which Remediations.ps1 sets so that rollback can undo it.
Test-Setting 'CIS 18.9.5.3 HVCI Enabled' 'HypervisorEnforcedCodeIntegrity = DWORD 1 (with UEFI lock) or 2 (without lock)' {
    (Test-RegDword $deviceGuardPolicyPath 'HypervisorEnforcedCodeIntegrity' 1) -or
        (Test-RegDword $deviceGuardPolicyPath 'HypervisorEnforcedCodeIntegrity' 2)
}
Test-Setting 'CIS 18.9.5.4 Require UEFI Memory Attributes Table' 'HVCIMATRequired = DWORD 1' {
    Test-RegDword $deviceGuardPolicyPath 'HVCIMATRequired' 1
}
Test-Setting 'CIS 18.9.5.5 Credential Guard Enabled' 'LsaCfgFlags = DWORD 1 (with UEFI lock) or 2 (without lock)' {
    (Test-RegDword $deviceGuardPolicyPath 'LsaCfgFlags' 1) -or
        (Test-RegDword $deviceGuardPolicyPath 'LsaCfgFlags' 2)
}
Test-Setting 'CIS 18.9.5.6 Secure Launch' 'ConfigureSystemGuardLaunch = DWORD 1' {
    Test-RegDword $deviceGuardPolicyPath 'ConfigureSystemGuardLaunch' 1
}
Test-Setting 'CIS 18.9.5.7 Kernel-mode Hardware-enforced Stack Protection' 'ConfigureKernelShadowStacksLaunch = DWORD 1' {
    Test-RegDword $deviceGuardPolicyPath 'ConfigureKernelShadowStacksLaunch' 1
}
# CIS 9.2.3 and 9.3.3: suppress firewall app-block notifications on private
# and public networks. Logging recommendations are intentionally excluded.
Test-Setting 'CIS 9.2.3 and 9.3.3 Firewall Notifications' 'Private and Public NotifyOnListen are disabled' {
    $firewallProfilesForNotifications = @(Get-NetFirewallProfile -Name Private,Public -ErrorAction Stop)
    $firewallProfilesForNotifications.Count -eq 2 -and
        @($firewallProfilesForNotifications | Where-Object { [string]$_.NotifyOnListen -ne 'False' }).Count -eq 0
}

Test-Setting 'CIS 18.9.4.1 CredSSP Encryption Oracle Protection' 'AllowEncryptionOracle = DWORD 0 (Force Updated Clients)' {
    Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' 'AllowEncryptionOracle' 0
}
Test-Setting 'CIS 18.9.7.2 Disable Automatic Device Metadata App Downloads' 'PreventDeviceMetadataFromNetwork = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' 'PreventDeviceMetadataFromNetwork' 1
}
Test-Setting 'CIS 18.9.7.1.1 Prevent Unapproved IEEE 1394 Device Classes' 'DenyDeviceClasses = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' 'DenyDeviceClasses' 1
}
Test-Setting 'CIS 18.9.7.1.2 Block IEEE 1394 Device Classes' 'DenyDeviceClasses list contains all four benchmark GUIDs' {
    $deviceClassPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
    $expectedDeviceClasses = @(
        '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
        '{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}'
        '{c06ff265-ae09-48f0-812c-16753d7cba83}'
        '{6bdd1fc1-810f-11d0-bec7-08002be2092f}'
    )
    if (-not (Test-Path -LiteralPath $deviceClassPath -PathType Container)) { return $false }
    $deviceClassKey = Get-Item -LiteralPath $deviceClassPath -ErrorAction Stop
    $actualDeviceClasses = @($deviceClassKey.GetValueNames() | ForEach-Object { [string]$deviceClassKey.GetValue($_) } | Sort-Object)
    $expectedDeviceClasses = @($expectedDeviceClasses | Sort-Object)
    @(Compare-Object -ReferenceObject $expectedDeviceClasses -DifferenceObject $actualDeviceClasses).Count -eq 0
}
Test-Setting 'CIS 18.9.7.1.3 Apply IEEE 1394 Device Restriction to Existing Devices' 'DenyDeviceClassesRetroactive = DWORD 1' {
    Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' 'DenyDeviceClassesRetroactive' 1
}
Test-Setting 'CIS 18.9.13.1 Early Launch Antimalware Driver Policy' 'DriverLoadPolicy = DWORD 3' {
    Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' 'DriverLoadPolicy' 3
}

# More CIS Level 1 settings. Each entry is one registry DWORD: Value is what
# Remediations.ps1 writes, and AlsoAccepted lists other values that also pass.
# Keep this list identical to $cisAdditionalRegistrySettings in Remediations.ps1, except for
# CIS 18.10.80.1 (Enhanced Sign-in Security) and CIS 18.9.29.1 (Block User from Showing Account
# Details on Sign-in): see the messages after this loop.
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
foreach ($setting in $cisAdditionalRegistrySettings) {
    $acceptedValues = @(@($setting.Value) + @($setting.AlsoAccepted) | Where-Object { $null -ne $_ })
    Test-Setting "CIS $($setting.Id) $($setting.Title)" "$($setting.Name) = DWORD $($acceptedValues -join ' or ')" {
        if (@($acceptedValues | Where-Object { Test-RegDword $setting.Path $setting.Name $_ }).Count -gt 0) { return $true }
        $observed = 'not set'
        if (Test-Path -LiteralPath $setting.Path) {
            $settingKey = Get-Item -LiteralPath $setting.Path -ErrorAction Stop
            if ($settingKey.GetValueNames() -contains $setting.Name) {
                $observed = "$($settingKey.GetValueKind($setting.Name)) $($settingKey.GetValue($setting.Name))"
            }
        }
        "$($setting.Name) is $observed."
    }
}

# CIS 18.10.80.1 Enhanced Sign-in Security is recommended, but it is not a pass/fail check:
# a face camera or fingerprint reader without Enhanced Sign-in Security support (older laptops)
# stops working with Windows Hello when the policy is on, and nothing can be done about missing
# hardware support, so a permanent failure and its toast would only be noise. Remediations.ps1
# does not set the policy either. The state is reported as information only.
$essMessage = $null
$essColor = 'Gray'
try {
    if (Test-RegDword 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics' 'EnableESSwithSupportedPeripherals' 1) {
        $essMessage = '[INFO] CIS 18.10.80.1 Enhanced Sign-in Security with Supported Peripherals is turned on (EnableESSwithSupportedPeripherals = 1).'
    } else {
        $essMessage = '[INFO] CIS 18.10.80.1 Enhanced Sign-in Security with Supported Peripherals (EnableESSwithSupportedPeripherals = DWORD 1) is not turned on. Turning it on is recommended, but on older laptops whose camera or fingerprint reader does not support Enhanced Sign-in Security it blocks Windows Hello and deletes the saved face and fingerprint enrollments. Remediations.ps1 therefore does not set it, and this is not counted as a failure. Turn it on yourself only if your hardware supports it, and keep your PIN or password at hand.'
    }
} catch {
    $essMessage = "[INFO] CIS 18.10.80.1 Enhanced Sign-in Security could not be read: $($_.Exception.Message)"
    $essColor = 'Yellow'
}
Write-AuditLog $essMessage
Write-Host $essMessage -ForegroundColor $essColor

# CIS 18.9.29.1 Block User from Showing Account Details on Sign-in is an exception to CIS, for
# usability: with the policy on, the sign-in screen no longer shows the account name or e-mail
# address and the Windows setting "Show account details such as my email address on the sign-in
# screen" is turned off, which confuses regular users. It is therefore not a pass/fail check
# and Remediations.ps1 does not set it. A value of 1 that is already there is left as it is.
$accountDetailsMessage = $null
$accountDetailsColor = 'Gray'
try {
    if (Test-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'BlockUserFromShowingAccountDetailsOnSignin' 1) {
        $accountDetailsMessage = '[INFO] CIS 18.9.29.1 Block User from Showing Account Details on Sign-in is turned on (BlockUserFromShowingAccountDetailsOnSignin = 1), as CIS recommends. This baseline does not require it and Remediations.ps1 does not set it, because hiding the account details on the sign-in screen can confuse regular users. It is not counted as a failure either way.'
    } else {
        $accountDetailsMessage = '[INFO] CIS 18.9.29.1 Block User from Showing Account Details on Sign-in (BlockUserFromShowingAccountDetailsOnSignin = DWORD 1) is not turned on. CIS recommends it, but this baseline deviates on purpose: Remediations.ps1 does not set it and it is not counted as a failure, because hiding the account name and e-mail address on the sign-in screen can confuse regular users.'
    }
} catch {
    $accountDetailsMessage = "[INFO] CIS 18.9.29.1 Block User from Showing Account Details on Sign-in could not be read: $($_.Exception.Message)"
    $accountDetailsColor = 'Yellow'
}
Write-AuditLog $accountDetailsMessage
Write-Host $accountDetailsMessage -ForegroundColor $accountDetailsColor


# CIS section 19 (user configuration) policies live in each user's own registry hive,
# HKEY_USERS\<SID>, so they are checked for every loaded profile of a local or domain
# account. An elevated run reads all loaded hives. A run without elevation can only read
# its own account's hive; when that account is not a loaded user (for example LocalService),
# the checks are reported as needing elevation. Users who are not signed in are not checked.
# Keep this list identical to $cisUserRegistrySettings in Remediations.ps1.
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
$currentUserSid = [string]$script:CurrentIdentity.User.Value
if ($script:IsElevated -and $loadedUserSids.Count -eq 0) {
    $message = '[SKIP] CIS 19.5.1.1, 19.7.5.1, 19.7.5.2, 19.7.8.1, 19.7.8.2, 19.7.8.5 and 19.7.26.1 user policies — no user profile is loaded, so there is nothing to check.'
    Write-AuditLog $message
    Write-Host $message -ForegroundColor DarkGray
} else {
    foreach ($setting in $cisUserRegistrySettings) {
        Test-Setting "CIS $($setting.Id) $($setting.Title)" "$($setting.Name) = DWORD $($setting.Value) for every loaded user profile" {
            $sidsToCheck = if ($script:IsElevated) { $loadedUserSids } elseif ($loadedUserSids -contains $currentUserSid) { @($currentUserSid) } else { @() }
            if ($sidsToCheck.Count -eq 0) {
                throw [System.UnauthorizedAccessException]::new('Access is denied: the user registry hives of other accounts cannot be read without administrator rights.')
            }
            $profilesNotCompliant = @(foreach ($sid in $sidsToCheck) {
                if (-not (Test-RegDword "Registry::HKEY_USERS\$sid\$($setting.SubKey)" $setting.Name $setting.Value)) { $sid }
            })
            if ($profilesNotCompliant.Count -eq 0) { return $true }
            "$($setting.Name) is not DWORD $($setting.Value) for user profile(s): $($profilesNotCompliant -join ', ')."
        }
    }
}
Test-Setting 'SMB Signing (Server)' 'Required (RequireSecuritySignature = True), also while LanmanServer is disabled (CIS 2.3.9.2)' {
    $serverService=Get-CimInstance Win32_Service -Filter "Name='LanmanServer'" -ErrorAction Stop
    if ($serverService.StartMode -eq 'Disabled') {
        # The SMB cmdlets fail while the Server service is disabled, so the policy value
        # that Set-SmbServerConfiguration writes is read directly.
        Test-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
    }
    else { (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature -eq $true }
}
Test-Setting 'SMB Signing (Client)' 'RequireSecuritySignature = True' { (Get-SmbClientConfiguration).RequireSecuritySignature -eq $true }
if (Get-Command -Name Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
    Test-Setting 'DNS over HTTPS (DoH)' 'At least one DNS server address configured to use DoH' { @(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object { $_.DohTemplate -and $_.DohTemplate.Trim() }).Count -gt 0 }
} else {
    # Windows 10 has no native DoH client configuration cmdlets.
    $message = '[SKIP] DNS over HTTPS (DoH) — not available on this Windows version (requires Windows 11).'
    Write-AuditLog $message
    Write-Host $message -ForegroundColor DarkGray
}
Test-Setting 'NetBIOS over TCP/IP' 'Disabled on every active adapter' {
    $a=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'); $a.Count -gt 0 -and @($a | Where-Object TcpipNetbiosOptions -ne 2).Count -eq 0
}
# CIS 18.10.26.1-18.10.26.4: for each event log, the policy value MaxSize (in KB), the
# size the log actually uses, and the policy that overwrites old events when it is full.
# Keep this list identical to $eventLogBaselines in Remediations.ps1.
$eventLogBaselines = @(
    @{ Name = 'Application'; MinimumSizeKB = 32768;  SizeId = '18.10.26.1.2'; RetentionId = '18.10.26.1.1' }
    @{ Name = 'Security';    MinimumSizeKB = 196608; SizeId = '18.10.26.2.2'; RetentionId = '18.10.26.2.1' }
    @{ Name = 'Setup';       MinimumSizeKB = 32768;  SizeId = '18.10.26.3.2'; RetentionId = '18.10.26.3.1' }
    @{ Name = 'System';      MinimumSizeKB = 32768;  SizeId = '18.10.26.4.2'; RetentionId = '18.10.26.4.1' }
)
foreach ($eventLogBaseline in $eventLogBaselines) {
    $eventLogName = $eventLogBaseline.Name
    $minimumSizeKB = [int]$eventLogBaseline.MinimumSizeKB
    $minimumSizeText = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0} MB ({1:N0} KB)', $minimumSizeKB / 1024, $minimumSizeKB)
    $eventLogPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$eventLogName"
    Test-Setting "CIS $($eventLogBaseline.SizeId) $eventLogName Event Log Maximum Size Policy" "MaxSize = DWORD $minimumSizeKB (KB) or greater" {
        if (-not (Test-Path -LiteralPath $eventLogPolicyPath)) { return 'MaxSize is not set.' }
        $eventLogPolicyKey = Get-Item -LiteralPath $eventLogPolicyPath -ErrorAction Stop
        if ($eventLogPolicyKey.GetValueNames() -notcontains 'MaxSize') { return 'MaxSize is not set.' }
        if ($eventLogPolicyKey.GetValueKind('MaxSize') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { return "MaxSize is not a DWORD ($($eventLogPolicyKey.GetValueKind('MaxSize')))." }
        $maximumSizeKB = [uint32]$eventLogPolicyKey.GetValue('MaxSize')
        if ($maximumSizeKB -ge $minimumSizeKB) { $true } else { "MaxSize is $maximumSizeKB KB." }
    }
    Test-Setting "$eventLogName Event Log Size" "Maximum log size at least $minimumSizeText" {
        $maximumSizeBytes = (Get-WinEvent -ListLog $eventLogName -ErrorAction Stop).MaximumSizeInBytes
        if ($maximumSizeBytes -ge ([long]$minimumSizeKB * 1KB)) { $true } else { "Maximum log size is $([math]::Round($maximumSizeBytes / 1MB, 1)) MB." }
    }
    Test-Setting "CIS $($eventLogBaseline.RetentionId) $eventLogName Event Log Overwrites Old Events When Full" 'Retention = REG_SZ 0' {
        if (Test-RegString $eventLogPolicyPath 'Retention' '0') { return $true }
        if (-not (Test-Path -LiteralPath $eventLogPolicyPath)) { return 'Retention is not set.' }
        $eventLogPolicyKey = Get-Item -LiteralPath $eventLogPolicyPath -ErrorAction Stop
        if ($eventLogPolicyKey.GetValueNames() -notcontains 'Retention') { return 'Retention is not set.' }
        "Retention is $($eventLogPolicyKey.GetValueKind('Retention')) '$($eventLogPolicyKey.GetValue('Retention'))'."
    }
}
Test-Setting 'Automatic Updates Policy' 'NoAutoUpdate = 0 or policy not explicitly disabling updates' { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate') -ne 1 }
Test-Setting 'Windows Update Pause Duration' 'No active quality or feature update pause longer than 2 days' {
    $maximumPauseDuration = [TimeSpan]::FromDays(2)
    $maximumPauseWindow = [TimeSpan]::FromDays(35)
    $now = [DateTimeOffset]::Now
    $pauseDefinitions = @(
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            StartName = 'PauseUpdatesStartTime'
            ExpiryNames = @('PauseUpdatesExpiryTime')
            Description = 'Windows Update'
        }
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            StartName = 'PauseQualityUpdatesStartTime'
            ExpiryNames = @('PauseQualityUpdatesExpiryTime', 'PauseQualityUpdatesEndTime', 'PauseUpdatesExpiryTime')
            Description = 'Quality updates'
        }
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            StartName = 'PauseFeatureUpdatesStartTime'
            ExpiryNames = @('PauseFeatureUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseUpdatesExpiryTime')
            Description = 'Feature updates'
        }
        @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            StartName = 'PauseQualityUpdatesStartTime'
            ExpiryNames = @()
            Description = 'Policy quality updates'
        }
        @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            StartName = 'PauseFeatureUpdatesStartTime'
            ExpiryNames = @()
            Description = 'Policy feature updates'
        }
    )
    $pauseFindings = @()
    foreach ($definition in $pauseDefinitions) {
        if (-not (Test-Path -LiteralPath $definition.Path)) { continue }
        $pauseKey = Get-Item -LiteralPath $definition.Path -ErrorAction Stop
        if ($pauseKey.GetValueNames() -notcontains $definition.StartName) { continue }
        $rawStart = [string]$pauseKey.GetValue($definition.StartName)
        if ([string]::IsNullOrWhiteSpace($rawStart)) { continue }

        $startTime = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse($rawStart, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$startTime)) {
            $pauseFindings += "$($definition.Description) pause start time '$rawStart' cannot be parsed."
            continue
        }
        if ($startTime -gt $now) { continue }

        $expiryTime = $null
        $expiryName = @($definition.ExpiryNames | Where-Object { $pauseKey.GetValueNames() -contains $_ } | Select-Object -First 1)
        if ($expiryName.Count -gt 0) {
            $rawExpiry = [string]$pauseKey.GetValue($expiryName[0])
            if (-not [string]::IsNullOrWhiteSpace($rawExpiry)) {
                $parsedExpiry = [DateTimeOffset]::MinValue
                if (-not [DateTimeOffset]::TryParse($rawExpiry, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsedExpiry)) {
                    $pauseFindings += "$($definition.Description) pause expiry time '$rawExpiry' cannot be parsed."
                    continue
                }
                $expiryTime = $parsedExpiry
                if ($expiryTime -le $now) { continue }
            }
        }

        $duration = $now - $startTime
        if ($null -eq $expiryTime -and $duration -gt $maximumPauseWindow) { continue }
        if ($rawStart -match '^\d{4}-\d{2}-\d{2}$' -and $duration -gt $maximumPauseDuration) {
            $pauseFindings += "$($definition.Description) pause start has date-only precision, so compliance with the 2-day limit cannot be verified."
            continue
        }
        if ($duration -gt $maximumPauseDuration) {
            $pauseFindings += "$($definition.Description) have been paused for $([math]::Floor($duration.TotalMinutes)) minutes."
        }
    }
    if ($pauseFindings.Count -gt 0) {
        $pauseFindings -join '; '
    } else {
        $true
    }
}
Test-Setting 'BitLocker OS Drive' 'Protection on and conversion fully encrypted' { $b=Get-BitLockerVolume -MountPoint $env:SystemDrive; $b.ProtectionStatus -eq 'On' -and $b.VolumeStatus -eq 'FullyEncrypted' }
# Security setting: BitLocker Protector Type. Expected secure result: TPM plus startup PIN protector present.
# Test-Setting 'BitLocker Protector Type' 'TPM plus startup PIN protector present' { $b=Get-BitLockerVolume -MountPoint $env:SystemDrive; $types=@($b.KeyProtector | ForEach-Object KeyProtectorType); ($types -contains 'TpmPin') -or (($types -contains 'Tpm') -and ($types -contains 'Pin')) }
Test-Setting 'BitLocker Recovery Key Present' 'RecoveryPassword protector present' { (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector.KeyProtectorType -contains 'RecoveryPassword' }

}
# ---- end of OS checks, part 2

# After a failed audit: where the results are. SecurityAudit.log has every check of this run and
# SecurityAuditErrors.log only the failed and unverified ones, with their details. Without logging
# (an audit that is not elevated, or a log folder that cannot be trusted) nothing was written.
function Write-AuditLogLocation {
    if ($script:LoggingEnabled) {
        Write-Host "Log file: $script:AuditFilePath" -ForegroundColor Yellow
        if (Test-Path -LiteralPath $script:ErrorFilePath -PathType Leaf) { Write-Host "Failures and details: $script:ErrorFilePath" -ForegroundColor Yellow }
    } else {
        Write-Host 'No log file was written: logs are only written by an elevated audit or by the scheduled task. Run Audit.cmd from an elevated (administrator) prompt to get one.' -ForegroundColor Yellow
    }
}

Write-AuditErrorDetailsSection
$summary = "Checks run: {0}; failed: {1}; unverified: {2}; not run because elevation is required: {3}" -f ($script:Checks - $script:ElevationRequired), $script:Failures, $script:Unverified, $script:ElevationRequired
# The duration counts from the process start, so it includes a slow start of PowerShell.
if ($script:ProcessStart) { $summary += '; duration: ' + (Format-SecondCount ((Get-Date) - $script:ProcessStart).TotalSeconds) }
Write-AuditLog $summary
# All log lines are written: close SecurityAudit.log and release the lock for the next audit.
Close-AuditLog
Write-Host "`n$summary"
# A run restricted with RestrictTo says only something about the audited systems.
$restrictedScope = if ($null -ne $script:SelectedSystems) { " (only $($script:SelectedSystems -join ', ') audited)" } else { '' }
if (($script:Failures + $script:Unverified) -gt 0) {
    Write-Host "Computer is insecure$restrictedScope" -ForegroundColor Red
    Write-AuditLogLocation
    if ($script:ElevationRequired -gt 0) {
        Write-Host "$($script:ElevationRequired) more checks were not run. Run Audit.cmd from an elevated (administrator) prompt for the complete audit." -ForegroundColor Yellow
    }
    exit 1
}
if ($script:ElevationRequired -gt 0) {
    # Exit code 2: nothing failed, but the audit is incomplete.
    Write-Host "No problems found in the checks that ran, but $($script:ElevationRequired) checks were not run. Run Audit.cmd from an elevated (administrator) prompt for the complete audit." -ForegroundColor Yellow
    exit 2
}
if ($restrictedScope) {
    Write-Host "No problems found$restrictedScope. Run Audit.cmd without RestrictTo for the full audit." -ForegroundColor Green
} else {
    Write-Host 'Computer is secure' -ForegroundColor Green
}
exit 0
