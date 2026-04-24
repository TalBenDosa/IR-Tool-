@echo off
setlocal enableextensions
title Forensic Master-Analyzer

rem -----------------------------------------------------------------
rem  Forensic Master-Analyzer - one-click launcher.
rem  Drops report on the user's Desktop and opens it in the browser.
rem -----------------------------------------------------------------

set "SCRIPT_DIR=%~dp0"

rem Resolve the REAL Desktop folder via the Windows shell API.
rem On systems where Desktop has been redirected to OneDrive,
rem "%USERPROFILE%\Desktop" does not exist.
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command ^
    "[Environment]::GetFolderPath('Desktop')"`) do set "DESKTOP=%%D"
if not defined DESKTOP set "DESKTOP=%USERPROFILE%\Desktop"
set "REPORT=%DESKTOP%\ForensicReport.html"

where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo  [X] Python was not found on PATH.
    echo      Install Python 3.9+ from https://www.python.org/downloads/
    echo      ^(make sure "Add Python to PATH" is ticked during install^).
    echo.
    pause
    exit /b 1
)

echo.
echo  Forensic Master-Analyzer
echo  ------------------------
echo  Working dir : %SCRIPT_DIR%
echo  Report path : %REPORT%
echo.
echo  This will collect live host artifacts and parse the Windows
echo  event logs. First run pip-installs ~5 Python packages; budget
echo  a few extra minutes.
echo.

python "%SCRIPT_DIR%forensic_master_analyzer.py" ^
    --output "%REPORT%" ^
    --workdir "%SCRIPT_DIR%workdir" ^
    --verbose

if errorlevel 1 (
    echo.
    echo  [X] Analysis failed. Review the error above.
    pause
    exit /b 1
)

echo.
echo  [OK] Report generated: %REPORT%
start "" "%REPORT%"
echo.
echo  A copy of the structured JSON was saved next to the HTML.
pause
