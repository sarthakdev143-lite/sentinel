# SentinelC2 agent + c2_server build script.
#
# Compiles all 3 agent variants (silent / engagement / aggressive)
# and the c2_server. Run from this directory:
#
#   .\build.ps1
#
# Override nim binary with $env:NIM = "D:\path\nim.exe" if it's not
# on PATH.

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$BuildDir = Join-Path $ProjectDir "build"
$SrcDir = $ProjectDir
$Nim = if ($env:NIM) { $env:NIM } else { "nim" }

# Verify toolchain
if (-not (Get-Command $Nim -ErrorAction SilentlyContinue)) {
    if (-not (Test-Path $Nim)) {
        Write-Error "nim not found. Set `$env:NIM or add nim to PATH."
        exit 1
    }
}

# Clean build dir, then build all 3 variants
if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
}
New-Item -ItemType Directory -Path $BuildDir | Out-Null

# Build flags shared by all variants
$BaseFlags = @(
    "c",
    "-d:release",
    "-d:ssl",
    "--opt:size",
    "--app:gui",
    "--passL:-s"
)

# Build the c2_server first (no variants)
Write-Host "[*] Building c2_server..." -ForegroundColor Cyan
& $Nim @BaseFlags `
    --out:(Join-Path $BuildDir "c2_server.exe") `
    (Join-Path $SrcDir "c2_server.nim")
if ($LASTEXITCODE -ne 0) { throw "c2_server build failed" }

# Build each agent variant
$Variants = @{
    "agent_silent.exe"      = @()
    "agent_engagement.exe"  = @("-d:variant_engagement")
    "agent_aggressive.exe"  = @("-d:variant_aggressive")
}

foreach ($kv in $Variants.GetEnumerator()) {
    $name = $kv.Key
    $defines = $kv.Value
    Write-Host "[*] Building $name ..." -ForegroundColor Cyan
    $flags = @("c", "-d:release", "-d:ssl", "--opt:size", "--app:gui", "--passL:-s") + $defines
    & $Nim @flags `
        --out:(Join-Path $BuildDir $name) `
        (Join-Path $SrcDir "agent.nim")
    if ($LASTEXITCODE -ne 0) { throw "$name build failed" }
}

# Build the unit test (no variants)
Write-Host "[*] Building tests..." -ForegroundColor Cyan
$TestDir = Join-Path $ProjectDir "tests"
if (Test-Path (Join-Path $TestDir "test_crypto.nim")) {
    & $Nim @BaseFlags `
        --out:(Join-Path $BuildDir "test_crypto.exe") `
        (Join-Path $TestDir "test_crypto.nim")
    if ($LASTEXITCODE -ne 0) { Write-Warning "test_crypto build failed (non-fatal)" }
}

# Summary
Write-Host ""
Write-Host "[+] Build complete. Output in: $BuildDir" -ForegroundColor Green
Get-ChildItem $BuildDir -Filter "*.exe" | Format-Table Name,
    @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}} -AutoSize
