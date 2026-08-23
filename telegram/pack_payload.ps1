# ============================================================================
# pack_payload.ps1
#
# Just zips the agent + deploy script into a single file you can upload
# yourself from your own machine. Use this when:
#   - the build host can't reach public upload services
#   - you want full control over where the payload lives
#   - you're using Google Drive / MEGA / your own VPS / etc.
#
# Output: a single zip file you can then upload to wherever you want.
#
# Usage
# -----
#   .\pack_payload.ps1
#   .\pack_payload.ps1 -Output "C:\Users\me\Desktop\payload.zip"
# ============================================================================

param(
    [string]$Agent     = "build\agent_telegram_prod.exe",
    [string]$Deploy    = "deploy_telegram.sh",
    [string]$InstallCmd = "install.cmd",
    [string]$Output    = $null
)

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$WorkDir    = Join-Path $env:TEMP "sentinel_pack_$PID"

if (-not (Test-Path $Agent)) {
    throw "agent binary not found: $Agent"
}
if (-not $Output) {
    $Output = Join-Path $env:TEMP ("sentinel_payload_" +
        (Get-Date -Format "yyyyMMdd_HHmmss") + ".zip")
}

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

Copy-Item (Resolve-Path $Agent).Path (Join-Path $WorkDir "agent_telegram.exe")
if (Test-Path $Deploy) {
    Copy-Item (Resolve-Path $Deploy).Path (Join-Path $WorkDir "deploy_telegram.sh")
}
if ($InstallCmd -and (Test-Path $InstallCmd)) {
    Copy-Item (Resolve-Path $InstallCmd).Path (Join-Path $WorkDir "install.cmd")
}

Add-Type -AssemblyName System.IO.Compression.FileSystem 2>$null
Write-Host "[*] Packing $Output ..." -ForegroundColor Cyan
[System.IO.Compression.ZipFile]::CreateFromDirectory($WorkDir, $Output)

Remove-Item -Recurse -Force $WorkDir

$size = [math]::Round((Get-Item $Output).Length / 1024, 1)
Write-Host "[+] Done: $Output  ($size KB)" -ForegroundColor Green
Write-Host ""
Write-Host "Upload this zip anywhere that gives a direct download URL:" -ForegroundColor Cyan
Write-Host "  * Google Drive -> share -> 'Anyone with the link' -> copy direct link"
Write-Host "  * MEGA.nz     -> get link"
Write-Host "  * Dropbox     -> share -> 'Anyone with the link' -> change ?dl=0 to ?dl=1"
Write-Host "  * Your own VPS -> scp + 'python3 -m http.server 8000'"
Write-Host "  * GitHub gist  -> upload as release asset"
Write-Host "  * transfer.sh / 0x0.st / catbox.moe / file.io  (run upload_payload.ps1 from a network that can reach them)"
