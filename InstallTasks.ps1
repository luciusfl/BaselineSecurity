#requires -Version 5.1
<#
.SYNOPSIS
    Installs the hourly security audit and the WatchDog notifier as scheduled tasks,
    or removes everything it installed again (-Uninstall).
.DESCRIPTION
    Copies Audit.ps1, AuditCheckDetails.json and WatchDog.exe from this folder to
    %ProgramFiles%\SecurityAudit, which only SYSTEM and Administrators can change,
    and registers the tasks to run them from there. By default the audit task runs
    as LocalService, not elevated: the checks that need administrator rights are
    skipped and do not count as failures. Run it again after changing any of those
    files; it replaces the copies, the tasks and the toast shortcut. It installs on
    Windows 11 (build 22000 or later) only and refuses to run on Windows 10.
.PARAMETER RunAuditElevated
    Run the audit task as SYSTEM and pass -RunAuditElevated to Audit.ps1, so the
    checks that need administrator rights run too and fail when they are not met.
.PARAMETER Uninstall
    Remove the two scheduled tasks (stopping them first if they are running), the
    installation folder %ProgramFiles%\SecurityAudit, the log folder
    %ProgramData%\SecurityAudit and the toast shortcut 'Security Configuration
    Alert' from the Start Menu. The settings that Remediations.ps1 changed stay
    (Rollback.cmd reverts them). Running it again, or with nothing installed, is
    safe. It cannot be combined with -RunAuditElevated.
.PARAMETER Help
    Show the supported parameters, the installation folder and the log folder,
    then exit without changing anything. Install.cmd ?, -? and help use it.
#>
[CmdletBinding()]
param(
    [switch]$RunAuditElevated,
    [switch]$Uninstall,
    [switch]$Help
)

# Security hardening of this elevated session; it must stay the first code in the
# script and uses no cmdlets itself. Modules are loaded only from Windows and Program
# Files: an elevated session otherwise also searches the Documents folder of the
# signed-in user first, where a non-elevated process can plant a module. System
# folders below come from Windows, not from environment variables, which the signed-in
# user can override.
$env:PSModulePath = @(
    [System.IO.Path]::Combine($PSHOME, 'Modules')
    [System.IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'WindowsPowerShell\Modules')
    [System.IO.Path]::Combine([Environment]::SystemDirectory, 'WindowsPowerShell\v1.0\Modules')
) -join ';'

$AuditTaskName = 'Security Configuration Audit'
$WatchdogTaskName = 'Security Configuration Watchdog'
$SourceDirectory = $PSScriptRoot
# The tasks run the files from here, never from the folder the installer is started
# from: that folder may be writable by the signed-in user, and anyone who can change
# Audit.ps1 can run code as the task's account.
$InstallDirectory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SecurityAudit'
$RuntimeFiles = @('Audit.ps1', 'AuditCheckDetails.json', 'WatchDog.exe')
$AuditScriptPath = Join-Path $InstallDirectory 'Audit.ps1'
$WatchdogExecutablePath = Join-Path $InstallDirectory 'WatchDog.exe'
# Audit.ps1 writes its logs here (the same path is set in Audit.ps1).
$LogDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SecurityAudit'

if ($Help) {
    @"
Install.cmd installs the hourly security audit and the WatchDog notifier as
scheduled tasks. Run it from an elevated (administrator) prompt.

Usage:
  Install.cmd [-RunAuditElevated]
  Install.cmd -Uninstall
  Install.cmd ? | -? | help

Parameters:
  (none)             The audit task runs as LocalService, not elevated. Checks
                     that need administrator rights are skipped (listed as
                     [ELEVATION REQUIRED] in the log) and never count as failures.
  -RunAuditElevated  The audit task runs as SYSTEM and passes -RunAuditElevated
                     to Audit.ps1: every check runs, and a check that cannot run
                     counts as a failure.
  -Uninstall         Remove everything the installation created: the two scheduled
                     tasks, the installation folder, the log folder and the toast
                     shortcut (all listed below). The settings changed by
                     Remediations.cmd stay (use Rollback.cmd for those). Cannot be
                     combined with -RunAuditElevated.
  ?, -?, help        Show this help. Nothing is installed; no elevation needed.

Install.cmd works on Windows 11 only (build 22000 or later) and refuses to run on
Windows 10. -Uninstall works on any version.

Installation folder: $InstallDirectory
  Install.cmd copies Audit.ps1, AuditCheckDetails.json and WatchDog.exe there
  (only SYSTEM and Administrators can change them), and the tasks run them from
  there. Run Install.cmd again after a new build to replace them.

Log folder: $LogDirectory
  SecurityAudit.log        full result of the latest audit
  SecurityAuditErrors.log  failures of the latest audit with their details;
                           only present if a check failed (WatchDog shows it)
  SecurityAudit.previous.log  the log of the audit before, for troubleshooting

WatchDog log: %LOCALAPPDATA%\SecurityAudit\WatchDog.log of the signed-in user
  (one line per WatchDog run: what it found and whether it showed a toast)

Scheduled tasks: \$AuditTaskName (at installation, then every 60 minutes from that time),
                 \$WatchdogTaskName (after each audit, as the signed-in user)

Toast shortcut: 'Security Configuration Alert' in the Start Menu of the user who
ran the installation (Windows needs it to show the notification).
"@ | Write-Host
    exit 0
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-StepDone {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "  $Message" -ForegroundColor Green
}

# Removes the scheduled tasks, the watcher first so that stopping a running audit does not
# start it. A task that is not installed is not an error, so running this twice is safe.
# Returns $true when no task is left. Nothing else is touched.
function Remove-AuditTasks {
    param([Parameter(Mandatory)][string[]]$TaskName)
    $allRemoved = $true
    foreach ($name in $TaskName) {
        try {
            $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if (-not $task) { Write-StepDone "Scheduled task '$name' is not installed."; continue }
            if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $name -ErrorAction Stop }
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            Write-StepDone "Scheduled task '$name' removed."
        }
        catch {
            $allRemoved = $false
            Write-Host "  Could not remove the scheduled task '$name': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    $allRemoved
}

# Deletes one of the folders the installation created (the installation folder with the copies of Audit.ps1, AuditCheckDetails.json and
# WatchDog.exe, or the log folder). A WatchDog.exe that runs from this folder is stopped first, because Windows
# does not delete a program that is running. A junction or symbolic link inside it is removed
# as a link, never followed, so nothing outside the folder is deleted; if the folder itself is
# a link it is not touched. Returns $true when the folder is gone (also when it never existed).
function Remove-DirectoryTree {
    param([Parameter(Mandatory)][string]$Path)
    foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($Path)) {
        $attributes = [System.IO.File]::GetAttributes($entry)
        $isDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
        $isLink = ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        if (-not $isDirectory) { [System.IO.File]::Delete($entry) }
        elseif ($isLink) { [System.IO.Directory]::Delete($entry) }   # removes the link only (the folder is not recursed into)
        else { Remove-DirectoryTree -Path $entry }
    }
    [System.IO.Directory]::Delete($Path)
}

function Remove-AuditFolder {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Write-StepDone "The folder $Path does not exist."; return $true }
    try {
        $folder = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $folder.PSIsContainer -or ($folder.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Write-Host "  The folder $Path is not an ordinary folder (it is a file, junction or link), so it was not deleted." -ForegroundColor Red
            return $false
        }
        $prefix = $folder.FullName.TrimEnd('\') + '\'
        foreach ($process in @(Get-Process -Name 'WatchDog' -ErrorAction SilentlyContinue)) {
            $processPath = $null
            try { $processPath = $process.Path } catch { }
            if ($processPath -and $processPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-StepDone "Stopped the running WatchDog.exe (process $($process.Id))."
            }
        }
        Remove-DirectoryTree -Path $folder.FullName
        Write-StepDone "Folder $Path deleted."
        return $true
    }
    catch {
        Write-Host "  Could not delete the folder ${Path}: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Deletes the toast shortcut 'Security Configuration Alert' that the installation created in
# the Start Menu of the user who ran it. Only that one file is deleted, and only if it is an
# ordinary file. Returns $true when it is gone (also when it never existed).
function Remove-ToastShortcut {
    $appData = [Environment]::GetFolderPath('ApplicationData')
    if ([string]::IsNullOrWhiteSpace($appData)) { Write-Host '  Could not determine the AppData folder, so the toast shortcut was not removed.' -ForegroundColor Red; return $false }
    $shortcutPath = Join-Path $appData 'Microsoft\Windows\Start Menu\Programs\Security Configuration Alert.lnk'
    if (-not (Test-Path -LiteralPath $shortcutPath)) { Write-StepDone "The toast shortcut $shortcutPath does not exist."; return $true }
    try {
        $item = Get-Item -LiteralPath $shortcutPath -Force -ErrorAction Stop
        if ($item.PSIsContainer) { Write-Host "  $shortcutPath is a folder, not a shortcut, so it was not deleted." -ForegroundColor Red; return $false }
        [System.IO.File]::Delete($item.FullName)
        Write-StepDone "Toast shortcut $shortcutPath deleted."
        return $true
    }
    catch {
        Write-Host "  Could not delete the toast shortcut ${shortcutPath}: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

if ($Uninstall) {
    if ($RunAuditElevated) {
        Write-Host 'Error. -Uninstall cannot be combined with -RunAuditElevated.' -ForegroundColor Red
        exit 1
    }
    Write-Step 'Removing the scheduled tasks...'
    # The folder is deleted only after the tasks are gone: a task that still exists would
    # run files that are no longer there.
    if (-not (Remove-AuditTasks -TaskName @($WatchdogTaskName, $AuditTaskName))) { exit 1 }
    # The three steps run even if one fails, so as much as possible is removed; the exit
    # code says whether everything was.
    $removedAll = $true
    Write-Step "Deleting the installation folder $InstallDirectory..."
    if (-not (Remove-AuditFolder -Path $InstallDirectory)) { $removedAll = $false }
    Write-Step "Deleting the log folder $LogDirectory..."
    if (-not (Remove-AuditFolder -Path $LogDirectory)) { $removedAll = $false }
    Write-Step "Deleting the toast shortcut 'Security Configuration Alert'..."
    if (-not (Remove-ToastShortcut)) { $removedAll = $false }
    Write-Host ''
    if (-not $removedAll) { Write-Host 'Not everything could be removed; see the messages above.' -ForegroundColor Red; exit 1 }
    Write-Host 'Everything the installation created was removed. The settings that Remediations.cmd changed stay; Rollback.cmd reverts them.' -ForegroundColor Cyan
    exit 0
}

# Installation needs Windows 11 (build 22000 or later): the baseline and the checks are
# written for it, and the audit refuses to describe Windows 10 as compliant. The build
# number is read from the operating system; if it cannot be read, installation is refused.
function Get-WindowsBuildNumber {
    try { return [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber } catch { }
    try { return [int](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber' -ErrorAction Stop) } catch { }
    return 0
}
$windowsBuild = Get-WindowsBuildNumber
if ($windowsBuild -lt 22000) {
    $found = if ($windowsBuild -eq 0) { 'the Windows version could not be determined' } else { "this computer runs Windows build $windowsBuild (Windows 10 or older)" }
    Write-Host "Error. Install.cmd supports Windows 11 only (build 22000 or later); $found. Nothing was installed." -ForegroundColor Red
    exit 1
}

# The SID Task Scheduler adds to the token of a task registered with
# ProcessTokenSidType Unrestricted (NT TASK\<name>): S-1-5-87 followed by the SHA-1
# hash of the upper-case task name in UTF-16LE, as five 32-bit numbers. It gives
# the LocalService audit task access to its folders without giving it to every
# other LocalService process. The same value is shown by: schtasks /showsid /tn <name>
function Get-TaskSid {
    param([Parameter(Mandatory)][string]$TaskName)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha1.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($TaskName.ToUpperInvariant())) }
    finally { $sha1.Dispose() }
    $parts = foreach ($index in 0..4) { [System.BitConverter]::ToUInt32($hash, $index * 4) }
    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-87-' + ($parts -join '-'))
}
$AuditTaskSid = Get-TaskSid $AuditTaskName

Write-Step 'Checking that the required files are present...'
foreach ($file in $RuntimeFiles) {
    $sourcePath = Join-Path $SourceDirectory $file
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "File not found: $sourcePath"
    }
    Write-StepDone "Found $sourcePath"
}

$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$usersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'

# Creates a folder with the given access list, or applies the list to an existing one.
# A new folder is created together with its access list, so inherited permissions
# never apply to it (ProgramData lets every user create files in new subfolders).
# An existing folder is used only if it is a real folder that SYSTEM or Administrators
# own. Any user can create a folder, junction or symbolic link with this name in
# ProgramData before the first installation: a link would redirect the access list
# and the files to another place, and the creator of a folder could keep access to it.
function Set-ProtectedDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.AccessControl.DirectorySecurity]$AccessList
    )
    $existing = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        [void][System.IO.Directory]::CreateDirectory($Path, $AccessList)
        return
    }
    if (-not $existing.PSIsContainer -or ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "'$Path' is not a normal folder (it is a file, a junction or a symbolic link), so the installer did not create it and it could redirect files to another place. Nothing was installed. Check it, delete it, and run Install.cmd again."
    }
    $owner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($systemSid.Value, $administratorsSid.Value)) {
        throw "'$Path' is owned by $owner, not by SYSTEM or Administrators, so another account created it and may still have access to it. Nothing was installed. Check its contents, delete the folder, and run Install.cmd again."
    }
    # SetAccessControl writes only the changed parts (owner and permissions). Set-Acl can
    # also try to write the audit part (SACL), which fails without SeSecurityPrivilege.
    $existing.SetAccessControl($AccessList)
}

# A reinstall changes files that the scheduled tasks use: the audit holds SecurityAudit.log
# open for writing during its whole run (several minutes), and a running WatchDog.exe cannot
# be overwritten. Both tasks are therefore stopped first, and a WatchDog.exe that runs from
# the installation folder is ended. The tasks are registered again at the end of the
# installation, and their triggers start them as before.
function Stop-InstalledWatchDog {
    $prefix = [System.IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\') + '\'
    foreach ($process in @(Get-Process -Name 'WatchDog' -ErrorAction SilentlyContinue)) {
        $processPath = $null
        try { $processPath = $process.Path } catch { }
        if ($processPath -and $processPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-StepDone "Stopped the running WatchDog.exe (process $($process.Id))."
            } catch { }   # it may have ended by itself; the caller tries again
        }
    }
}

function Stop-RunningAuditActivity {
    foreach ($name in @($WatchdogTaskName, $AuditTaskName)) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $name -ErrorAction Stop
            Write-StepDone "Stopped the running scheduled task '$name'."
        }
    }
    Stop-InstalledWatchDog
    # Give the stopped tasks a moment to release their files.
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        $stillRunning = @(@($WatchdogTaskName, $AuditTaskName) | Where-Object {
            $runningTask = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue
            $runningTask -and $runningTask.State -eq 'Running'
        })
        if ($stillRunning.Count -eq 0) { return }
        Start-Sleep -Seconds 1
    }
    throw "The scheduled task(s) '$($stillRunning -join "', '")' did not stop within 30 seconds. Try again in a minute."
}

# Deletes a file, trying again for up to 15 seconds because a program that was just stopped
# may need a moment to close it. If it stays open, the message names the likely reason.
function Remove-FileWhenFree {
    param([Parameter(Mandatory)][string]$Path)
    for ($attempt = 1; $attempt -le 15; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            return
        }
        catch [System.IO.IOException] {
            if ($attempt -eq 15) {
                throw "$Path is still open in another program (for example an Audit.cmd window that is running, or a text editor that shows the log). Close it and run the installation again. $($_.Exception.Message)"
            }
            Start-Sleep -Seconds 1
        }
    }
}

# Copies a file over the installed one. The watchdog task can start WatchDog.exe again
# between the stop above and this copy, so a copy that fails because the file is in use
# ends WatchDog.exe again and retries for up to 15 seconds.
function Copy-FileWhenFree {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Destination)
    for ($attempt = 1; $attempt -le 15; $attempt++) {
        try {
            Copy-Item -LiteralPath $Path -Destination $Destination -Force -ErrorAction Stop
            return
        }
        catch [System.IO.IOException] {
            if ($attempt -eq 15) {
                throw "$Destination is still in use by another program. Close it (or sign out other users who run it) and run the installation again. $($_.Exception.Message)"
            }
            Stop-InstalledWatchDog
            Start-Sleep -Seconds 1
        }
    }
}

Write-Step 'Stopping the scheduled tasks that are running...'
Stop-RunningAuditActivity
Write-StepDone 'No audit or WatchDog is running now.'

# The install folder gets its own access list without inheritance: SYSTEM and
# Administrators full control, Users read and execute (WatchDog runs as the signed-in
# user). The LocalService audit task also gets read and execute through its task SID.
# Nobody else can change the files the tasks run.
Write-Step "Copying the audit files to $InstallDirectory..."
$installAcl = [System.Security.AccessControl.DirectorySecurity]::new()
$installAcl.SetAccessRuleProtection($true, $false)
$installAcl.SetOwner($administratorsSid)
$installAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($systemSid, 'FullControl', $inheritance, 'None', 'Allow'))
$installAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($administratorsSid, 'FullControl', $inheritance, 'None', 'Allow'))
$installAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($usersSid, 'ReadAndExecute', $inheritance, 'None', 'Allow'))
if (-not $RunAuditElevated) {
    $installAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($AuditTaskSid, 'ReadAndExecute', $inheritance, 'None', 'Allow'))
}
Set-ProtectedDirectory -Path $InstallDirectory -AccessList $installAcl
$sourceFullPath = [System.IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\')
$installFullPath = [System.IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$installingFromInstallDirectory = [string]::Equals($sourceFullPath, $installFullPath, [System.StringComparison]::OrdinalIgnoreCase)
foreach ($file in $RuntimeFiles) {
    $targetPath = Join-Path $InstallDirectory $file
    if (-not $installingFromInstallDirectory) {
        Copy-FileWhenFree -Path (Join-Path $SourceDirectory $file) -Destination $targetPath
    }
    # Copying over an existing file keeps that file's own access entries, so every
    # file is reset to the folder's inherited permissions only.
    $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($false, $false)
    (Get-Item -LiteralPath $targetPath -Force -ErrorAction Stop).SetAccessControl($fileAcl)
}
Write-StepDone 'Audit files copied; only SYSTEM and Administrators can change them.'

Write-Step "Creating the audit log directory $LogDirectory..."
# WatchDog shows whatever the error log contains, so only the audit task and
# administrators may write there. ProgramData lets ordinary users create files in new
# subfolders; the folder therefore gets its own access list without inheritance:
# SYSTEM and Administrators full control, Users read only (WatchDog runs as the
# signed-in user and reads the log). The LocalService audit task writes its logs
# through its task SID; no other LocalService process can.
# The files the LocalService task creates are owned by LocalService, and the owner of
# a file may always change its permissions. OWNER RIGHTS (S-1-3-4) replaces that
# implicit right with read only, so no other LocalService process can take over the
# logs; the task itself still writes them through its task SID.
$logAcl = [System.Security.AccessControl.DirectorySecurity]::new()
$logAcl.SetAccessRuleProtection($true, $false)
$logAcl.SetOwner($administratorsSid)
$logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($systemSid, 'FullControl', $inheritance, 'None', 'Allow'))
$logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($administratorsSid, 'FullControl', $inheritance, 'None', 'Allow'))
$logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($usersSid, 'ReadAndExecute', $inheritance, 'None', 'Allow'))
$logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-3-4'), 'ReadAndExecute', $inheritance, 'None', 'Allow'))
if (-not $RunAuditElevated) {
    $logAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($AuditTaskSid, 'Modify', $inheritance, 'None', 'Allow'))
}
Set-ProtectedDirectory -Path $LogDirectory -AccessList $logAcl
# A file that another account created there earlier (for example a fake error log)
# is removed. The logs of the previous audit are removed too: they may belong to the other
# task account (SYSTEM or LocalService), and the audit started at the end of the
# installation writes fresh ones. SecurityAudit.lock is a file of earlier versions, which
# the audit no longer uses (the open log file itself keeps a second audit out).
$previousAuditLogs = @('SecurityAudit.log', 'SecurityAuditErrors.log', 'SecurityAudit.previous.log', 'SecurityAudit.lock')
foreach ($logFile in @(Get-ChildItem -LiteralPath $LogDirectory -Force -File -ErrorAction Stop)) {
    $owner = (Get-Acl -LiteralPath $logFile.FullName -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($logFile.Name -in $previousAuditLogs) {
        Remove-FileWhenFree -Path $logFile.FullName
        Write-StepDone "Removed $($logFile.Name) of the previous audit."
    } elseif ($owner -notin @($systemSid.Value, $administratorsSid.Value)) {
        Remove-FileWhenFree -Path $logFile.FullName
        Write-StepDone "Removed $($logFile.Name), which was not created by SYSTEM or an administrator."
    }
}
if ($RunAuditElevated) {
    Write-StepDone 'Log directory is ready; only SYSTEM and Administrators can write to it.'
} else {
    Write-StepDone "Log directory is ready; only SYSTEM, Administrators and the audit task (NT TASK\$AuditTaskName, $($AuditTaskSid.Value)) can write to it."
}

$PowerShellPath = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'

function ConvertTo-XmlText {
    param([string]$Value)
    [System.Security.SecurityElement]::Escape($Value)
}

function Register-ToastApplication {
    if (-not ('WindowsToastShortcutRegistration' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct WindowsToastPropertyKey
{
    public Guid FormatId;
    public uint PropertyId;

    public WindowsToastPropertyKey(Guid formatId, uint propertyId)
    {
        FormatId = formatId;
        PropertyId = propertyId;
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct WindowsToastPropVariant
{
    [FieldOffset(0)] public ushort VariantType;
    [FieldOffset(8)] public IntPtr StringValue;
}

[ComImport]
[Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IWindowsToastPropertyStore
{
    [PreserveSig] int GetCount(out uint count);
    [PreserveSig] int GetAt(uint index, out WindowsToastPropertyKey key);
    [PreserveSig] int GetValue(ref WindowsToastPropertyKey key, out WindowsToastPropVariant value);
    [PreserveSig] int SetValue(ref WindowsToastPropertyKey key, ref WindowsToastPropVariant value);
    [PreserveSig] int Commit();
}

public static class WindowsToastShortcutRegistration
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHGetPropertyStoreFromParsingName(
        string path,
        IntPtr bindContext,
        uint flags,
        ref Guid interfaceId,
        out IWindowsToastPropertyStore propertyStore);

    [DllImport("ole32.dll", PreserveSig = true)]
    private static extern int PropVariantClear(ref WindowsToastPropVariant value);

    public static void SetAppUserModelId(string shortcutPath, string appUserModelId)
    {
        Guid interfaceId = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99");
        IWindowsToastPropertyStore propertyStore;
        int result = SHGetPropertyStoreFromParsingName(shortcutPath, IntPtr.Zero, 2, ref interfaceId, out propertyStore);
        Marshal.ThrowExceptionForHR(result);

        WindowsToastPropertyKey key = new WindowsToastPropertyKey(
            new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"),
            5);
        WindowsToastPropVariant value = new WindowsToastPropVariant();
        value.VariantType = 31;
        value.StringValue = Marshal.StringToCoTaskMemUni(appUserModelId);

        try
        {
            Marshal.ThrowExceptionForHR(propertyStore.SetValue(ref key, ref value));
            Marshal.ThrowExceptionForHR(propertyStore.Commit());
        }
        finally
        {
            PropVariantClear(ref value);
            Marshal.ReleaseComObject(propertyStore);
        }
    }
}
'@
    }

    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        throw 'Could not determine the current user''s AppData folder.'
    }

    $startMenuPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    $null = New-Item -ItemType Directory -Path $startMenuPath -Force
    $shortcutPath = Join-Path $startMenuPath 'Security Configuration Alert.lnk'

    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $WatchdogExecutablePath
    $shortcut.Arguments = ''
    $shortcut.Description = 'Security Configuration Alert'
    $shortcut.Save()
    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
        throw "Could not create the toast shortcut: $shortcutPath"
    }

    [WindowsToastShortcutRegistration]::SetAppUserModelId($shortcutPath, 'Security Configuration Alert')
}

function Register-ParameterizedTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$ActionPath,
        [string]$ActionArguments = '',
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][ValidateSet('ServiceAccount','InteractiveToken')][string]$LogonType,
        [Parameter(Mandatory)][ValidateSet('LeastPrivilege','HighestAvailable')][string]$RunLevel,
        [Parameter(Mandatory)][string]$TriggerXml,
        [Parameter(Mandatory)][string]$Description,
        [ValidateRange(0,10)][int]$Priority = 7,
        # Service accounts only: add the task SID to the token and keep only these privileges.
        [switch]$UseTaskSid,
        [string[]]$RequiredPrivileges = @()
    )
    $principalOptions = @(
        if ($UseTaskSid) { '      <ProcessTokenSidType>Unrestricted</ProcessTokenSidType>' }
        if ($RequiredPrivileges.Count -gt 0) {
            '      <RequiredPrivileges>'
            foreach ($privilege in $RequiredPrivileges) { "        <Privilege>$(ConvertTo-XmlText $privilege)</Privilege>" }
            '      </RequiredPrivileges>'
        }
    ) -join "`n"

    # ExecutionTimeLimit: Task Scheduler stops a run after 45 minutes (its default is 72
    # hours). The audit normally takes a few minutes; a run that hangs would otherwise
    # block every later hourly run (IgnoreNew) and never raise a toast. WatchDog finishes
    # in seconds, so the limit never affects it.
    Register-ScheduledTask -TaskName $TaskName -Force -ErrorAction Stop -Xml @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$(ConvertTo-XmlText $Description)</Description>
  </RegistrationInfo>
  <Triggers>
$TriggerXml
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$(ConvertTo-XmlText $UserId)</UserId>
$(if ($LogonType -ne 'ServiceAccount') { "      <LogonType>$LogonType</LogonType>" })
      <RunLevel>$RunLevel</RunLevel>
$principalOptions
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT45M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <Priority>$Priority</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$(ConvertTo-XmlText $ActionPath)</Command>
      <Arguments>$(ConvertTo-XmlText $ActionArguments)</Arguments>
    </Exec>
  </Actions>
</Task>
"@ | Out-Null
}

# Register the Start Menu shortcut identity before any audit run can send a toast.
Write-Step "Registering the toast notification shortcut 'Security Configuration Alert'..."
Register-ToastApplication
Write-StepDone 'Toast notification shortcut registered.'

# The audit runs every 60 minutes counted from the installation time, not on the full hour
# of the clock: one time trigger that starts now and repeats hourly, for example 9:35,
# 10:35, 11:35, across restarts too. StartWhenAvailable makes up a run that was missed
# while the PC was off or in standby, so the audit also runs soon after Windows starts when
# a slot was missed; the task's low priority keeps it from slowing the start of Windows.
# IgnoreNew drops a start while a run is still going.
$auditScheduleStart = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
$auditArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $AuditScriptPath
if ($RunAuditElevated) {
    # SYSTEM, elevated: every check runs, and one that cannot run is a failure.
    $auditAccount = 'SYSTEM'
    $auditPrincipal = @{ UserId = 'SYSTEM'; RunLevel = 'HighestAvailable' }
    $auditArguments += ' -RunAuditElevated'
} else {
    # LocalService (S-1-5-19), never elevated: the checks that need administrator rights
    # are skipped. The task SID gives it its folders, and only the privilege to traverse
    # folders is kept. Dropping SeImpersonatePrivilege in particular closes the usual
    # path from a LocalService process to SYSTEM.
    $auditAccount = 'LocalService'
    $auditPrincipal = @{ UserId = 'S-1-5-19'; RunLevel = 'LeastPrivilege'; UseTaskSid = $true; RequiredPrivileges = @('SeChangeNotifyPrivilege') }
}
Write-Step "Installing scheduled task '$AuditTaskName' (runs as $auditAccount now and every 60 minutes from now)..."
Register-ParameterizedTask @auditPrincipal `
    -TaskName $AuditTaskName `
    -ActionPath $PowerShellPath `
    -ActionArguments $auditArguments `
    -LogonType ServiceAccount `
    -Priority 8 `
    -Description 'Verifies that security configuration comply with baseline security standards. Outputs an error log file if a configuration does not comply.' `
    -TriggerXml @"
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>$auditScheduleStart</StartBoundary>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
"@
Write-StepDone "Scheduled task '$AuditTaskName' installed."

# The watchdog is event-triggered by audit completion, so it checks after the
# audit has written its log. Its interactive user principal allows the modal
# toast to appear in the installing user's desktop session.
Write-Step "Installing scheduled task '$WatchdogTaskName' (runs as the current user after each audit)..."
Register-ParameterizedTask `
    -TaskName $WatchdogTaskName `
    -ActionPath $WatchdogExecutablePath `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) `
    -LogonType InteractiveToken `
    -RunLevel LeastPrivilege `
    -Description 'Shows the audit error log after an audit run completes as a notification toast.' `
    -TriggerXml @"
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription><![CDATA[$('<QueryList><Query Id="0" Path="Microsoft-Windows-TaskScheduler/Operational"><Select Path="Microsoft-Windows-TaskScheduler/Operational">*[System[Provider[@Name=''Microsoft-Windows-TaskScheduler''] and EventID=102] and EventData[Data[@Name=''TaskName'']=''{0}'']]</Select></Query></QueryList>' -f "\$AuditTaskName")]]></Subscription>
    </EventTrigger>
"@
Write-StepDone "Scheduled task '$WatchdogTaskName' installed."

# The first audit runs now. The trigger's first slot (the installation time) has already
# passed when the task is registered, and Task Scheduler does not make up that slot, so this
# start is the first run; the trigger's next slot is 60 minutes from now. Each completed
# run triggers the watcher.
Write-Step "Starting the first run of '$AuditTaskName'..."
Start-ScheduledTask -TaskName $AuditTaskName -ErrorAction Stop
Write-StepDone "Task started. Results will be written to $LogDirectory."
if (-not $RunAuditElevated) {
    Write-Host "The audit runs as LocalService, so the checks that need administrator rights are skipped. Run Install.cmd -RunAuditElevated to run them as SYSTEM instead." -ForegroundColor Yellow
}
Write-Host 'Installation complete.' -ForegroundColor Green
