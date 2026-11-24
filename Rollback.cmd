@echo off
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
    echo Error. Rollback.cmd must run elevated.
    exit /b 1
)

rem Remediations.ps1 writes rollback.ps1 next to its rollback snapshot, in a folder
rem that only SYSTEM and Administrators can change. PowerShell takes that folder from
rem Windows ([Environment]::GetFolderPath), not from %ProgramData%: a non-elevated
rem process can set a user environment variable named ProgramData, which would point
rem an elevated Rollback.cmd at a script of its choice. rollback.ps1 is then started
rem with -File in a new powershell.exe from the same folder ($PSHOME), so it runs and
rem returns its exit code exactly as before.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$rollbackScript = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SecurityBaseline\rollback.ps1'; if (-not (Test-Path -LiteralPath $rollbackScript -PathType Leaf)) { Write-Host 'Nothing to roll back. rollback.ps1 is created by Remediations.cmd only when it changes a setting.'; exit 0 }; & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $rollbackScript; exit $LASTEXITCODE"
exit /b %errorlevel%