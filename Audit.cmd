@echo off
rem Runs with or without elevation. Without elevation, checks that need
rem administrator rights are reported as [ELEVATION REQUIRED] and are not run.
rem Audit.cmd ? ^| -? ^| /? ^| help ^| -help   shows the options.
setlocal

rem The help is checked first. A shift loop is used because a "for" loop would expand ? as
rem a file wildcard. SHIFT does not change %*, which still passes every argument on below.
rem PowerShell itself takes -? for its own help and prints nothing useful for this script,
rem so the help options are turned into -Help here.
:checkHelp
if "%~1"=="" goto run
if "%~1"=="?" goto help
if "%~1"=="-?" goto help
if "%~1"=="/?" goto help
if /i "%~1"=="help" goto help
if /i "%~1"=="-help" goto help
if /i "%~1"=="/help" goto help
shift
goto checkHelp

:help
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Audit.ps1" -Help
exit /b %errorlevel%

:run
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Audit.ps1" %*
exit /b %errorlevel%
