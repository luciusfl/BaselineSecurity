@echo off
rem Usage: Install.cmd [-RunAuditElevated]
rem        Install.cmd -Uninstall   (removes the two tasks, %ProgramFiles%\SecurityAudit, %ProgramData%\SecurityAudit and the toast shortcut)
rem        Install.cmd ? ^| -? ^| help   (shows the help; no elevation needed)
rem Without -RunAuditElevated the audit task runs as LocalService and skips the
rem checks that need administrator rights; with it, the task runs as SYSTEM.
rem Installation is refused on Windows 10; the check is made in InstallTasks.ps1.
setlocal

rem The help is checked first, so it also works from an unelevated prompt.
rem A shift loop is used because a "for" loop would expand ? as a file wildcard.
rem SHIFT does not change %*, which still passes every argument on below.
:checkHelp
if "%~1"=="" goto install
if "%~1"=="?" goto help
if "%~1"=="-?" goto help
if "%~1"=="/?" goto help
if /i "%~1"=="help" goto help
shift
goto checkHelp

:help
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0InstallTasks.ps1" -Help
exit /b %errorlevel%

:install
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
    echo Error. Install.cmd must run elevated. Run "Install.cmd help" for the options.
    exit /b 1
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0InstallTasks.ps1" %*
exit /b %errorlevel%
