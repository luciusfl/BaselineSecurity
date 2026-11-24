@echo off
rem Usage: Remediations.cmd                 applies the security baseline
rem        Remediations.cmd -RestrictTo Edge,OS
rem                                         applies only the listed systems (OS, Edge, Chrome);
rem                                         RestrictTo=Edge,OS works too
rem        Remediations.cmd Analyze         lists every checked setting, one line each: "original -> now"
rem                                         (changed settings in yellow)
rem Options are not case sensitive.
rem        Remediations.cmd ? ^| -? ^| /? ^| help ^| -help   (shows the help; no elevation needed)
setlocal

rem The arguments are checked before the elevation check, so the help also works from an
rem unelevated prompt. A shift loop is used because a "for" loop would expand ? as a
rem file wildcard.
rem cmd.exe splits arguments at commas and equal signs as well as at spaces, so
rem "RestrictTo=Edge,OS" arrives as RestrictTo, Edge and OS. The names after RestrictTo are
rem therefore collected until the next option and passed on as one list; Remediations.ps1
rem checks them and ignores unknown names with a warning.
set "analyze="
set "restrictGiven="
set "restrict="
:checkArgs
if "%~1"=="" goto argsDone
if "%~1"=="?" goto help
if "%~1"=="-?" goto help
if "%~1"=="/?" goto help
if /i "%~1"=="help" goto help
if /i "%~1"=="-help" goto help
if /i "%~1"=="/help" goto help
if /i "%~1"=="analyze" set "analyze=1" & shift & goto checkArgs
if /i "%~1"=="-analyze" set "analyze=1" & shift & goto checkArgs
if /i "%~1"=="restrictto" goto restrictTo
if /i "%~1"=="-restrictto" goto restrictTo
if /i "%~1"=="/restrictto" goto restrictTo
echo Error. Unknown option "%~1". Run "Remediations.cmd help" for the options.
exit /b 1

:restrictTo
set "restrictGiven=1"
shift
:restrictToValue
if "%~1"=="" goto argsDone
set "next=%~1"
if "%next:~0,1%"=="-" goto checkArgs
if "%next:~0,1%"=="/" goto checkArgs
if "%next%"=="?" goto checkArgs
if /i "%next%"=="analyze" goto checkArgs
if /i "%next%"=="help" goto checkArgs
if defined restrict (set "restrict=%restrict%,%next%") else (set "restrict=%next%")
shift
goto restrictToValue

:argsDone
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
    echo Error. Remediations.cmd must run elevated. Run "Remediations.cmd help" for the options.
    exit /b 1
)

set "psOptions="
if defined analyze set "psOptions=-Analyze"
if defined restrictGiven set "psOptions=%psOptions% -RestrictTo "%restrict%""
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Remediations.ps1" %psOptions%
exit /b %errorlevel%

:help
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Remediations.ps1" -Help
exit /b %errorlevel%
