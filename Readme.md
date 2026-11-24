# Windows 11 Security Configuration Baseline Audit

## Overview

This suite checks a stand-alone Windows 11 PC against the security baseline in SecurityBaselineSettings.html. Once installed, it audits the PC every hour and at startup, and shows a Windows notification if a setting no longer matches the baseline. It never changes settings on its own.

For details on how it works, what it writes and where, why it must run elevated, and how rollback works, see Design.md.

## Prerequisites

- Windows 11 or later. Install.cmd refuses to install on Windows 10.
- Windows PowerShell 5.1 (powershell.exe). It comes with Windows, so nothing needs to be installed.
- A stand-alone PC: not joined to a domain and not managed by Intune or corporate Group Policy.
- An administrator account. Run Remediations.cmd, Rollback.cmd and Install.cmd from an elevated Command Prompt (right-click > **Run as administrator**). Audit.cmd also runs unelevated, but then skips the checks that need administrator rights.
- Run the .cmd files from a Command Prompt (the prompt looks like `C:\...>`). In PowerShell (`PS C:\...>`, the default in Windows Terminal) start them with `.\`, for example `.\Audit.cmd`, because PowerShell does not run commands from the current folder otherwise.
- Windows notifications turned on (**Settings > System > Notifications**).

Keep this folder where only you can change it, because its .cmd files run elevated. Install.cmd copies the files the scheduled tasks need to %ProgramFiles%\SecurityAudit, so the folder can be moved later; after changing files here, run Install.cmd again.

## Installation (recommended order)

1. Copy the folder to your local machine. Press Win + R, type cmd to open the command prompt, and navigate to the folder's root directory.
2. **Audit first.** Run Audit.cmd. It changes no security settings and lists every check that passes or fails, so you can see all violations before anything is changed. Some failures say "Not fixed by Remediations.ps1"; those you must fix by hand, as described in the message.
3. **Remediate.** Run Remediations.cmd. It fixes the settings that do not match the baseline and leaves correct settings alone. Restart or sign out if it asks you to. **Note:** In Edge and Chrome, all extensions are blocked except the approved ones listed in Audit.ps1 and Remediations.ps1. Review those lists before this step.
4. **Verify.** Run Audit.cmd again. Audit.cmd and Remediations.cmd can be limited to some systems with -RestrictTo, for example -RestrictTo Edge (supported: OS, Edge, Chrome). Repeat steps 2 and 3 until it reports "Computer is secure", or until the only failures left are ones you have reviewed and fixed by hand.
5. **Install.** Run Install.cmd. It creates two scheduled tasks ("Security Configuration Audit" and "Security Configuration Watchdog") and starts the first audit. By default the hourly audit runs without administrator rights and skips the checks that need them (Secure Boot, TPM, BitLocker, local security policy and a few others). To run every check, use **Install.cmd -RunAuditElevated**, or run Audit.cmd elevated from time to time. **Install.cmd ?** lists the options and folders. The -RunAuditElevated command line switch can only run from an elevated command prompt.

Results are written to %ProgramData%\SecurityAudit\SecurityAudit.log. The notification's **Open log** button opens the list of failures.

## Uninstall

Run **Install.cmd -Uninstall** from an elevated Command Prompt. It removes the two scheduled tasks, the folders %ProgramFiles%\SecurityAudit and %ProgramData%\SecurityAudit (including the logs) and the toast shortcut. The settings that Remediations.cmd changed stay; use Rollback.cmd for those. See Design.md, section 5.5.

## Undo remediations

Remediations.cmd saves the original state of every setting it checks, whether or not it changed it, with a rollback script in %ProgramData%\SecurityBaseline. After each run that changes something, Remediations.cmd prints the path of a Markdown report of that run's changes (old value, new value and the security reason). To see everything that was changed since the first run, run **Remediations.cmd Analyze** (elevated): one line per setting, original -> now. To restore the original settings, run Rollback.cmd. Remediations.cmd ? shows the options. See Design.md for details.

## Test the notification

1. Open regedit and go to **HKLM\SOFTWARE\Policies\Microsoft\Edge**.
2. Set (or create) the DWORD value **SmartScreenEnabled** to **0**.
3. Open Task Scheduler (taskschd.msc) and run the "Security Configuration Audit" task.
4. A notification should appear within a few minutes. Run Remediations.cmd afterwards to fix the setting again.
