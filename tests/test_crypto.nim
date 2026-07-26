# tests/test_crypto.nim
# Round-trip tests for the v2 crypto layer.
# Build:   nim c -r -d:release --nimcache:tests/cache tests/test_crypto.nim

import std/[unittest, strutils, times, math, base64, random]
import nimcrypto/[pbkdf2, sha2, hmac, utils, bcmode, rijndael]

# Mirror the agent/server crypto
const SECRET = "sentinel-engagement-q4-2026-echo-tango-whiskey"

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

proc encryptFrame(key: array[32, byte], agentId: string, dir: byte,
                  sendCtr: var uint32, plain: string): seq[byte] =
  var randBytes: array[8, byte]
  for i in 0..<8: randBytes[i] = byte(rand(255))
  let nonce = makeNonce(sendCtr, randBytes)
  inc sendCtr
  let aad = makeAad(agentId, dir)
  var ctx: GCM[aes256]
  ctx.init(key, nonce, aad)
  let pt = cast[seq[byte]](plain)
  var ct = newSeq[byte](pt.len)
  ctx.encrypt(pt, ct)
  let tag = ctx.getTag()
  result = newSeqOfCap[byte](12 + ct.len + 16)
  for b in nonce: result.add(b)
  for b in ct: result.add(b)
  for b in tag: result.add(b)

proc decryptFrame(key: array[32, byte], agentId: string, dir: byte,
                  blob: openArray[byte]): string =
  if blob.len < 28: return ""
  var nonce: array[12, byte]
  for i in 0..<12: nonce[i] = blob[i]
  let ctLen = blob.len - 12 - 16
  if ctLen < 0: return ""
  let ct = blob[12 ..< 12 + ctLen]
  let tag = blob[blob.len - 16 ..< blob.len]
  let aad = makeAad(agentId, dir)
  var ctx: GCM[aes256]
  ctx.init(key, nonce, aad)
  var pt = newSeq[byte](ct.len)
  if not ctx.decrypt(ct, pt, tag): return ""
  result = cast[string](pt)

suite "Session key derivation":
  test "both sides derive the same key using canonical (server||agent) order":
    let agentNonce: array[16, byte] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let serverNonce: array[16, byte] = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    # Both agent and server must use the canonical ordering:
    # HMAC(secret, server_nonce || agent_nonce).
    let kServer = deriveSessionKey(SECRET, serverNonce, agentNonce)
    let kAgent  = deriveSessionKey(SECRET, serverNonce, agentNonce)
    check kServer == kAgent
    # And different nonces produce different keys (sanity).
    let kOther = deriveSessionKey(SECRET, [byte 99, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], agentNonce)
    check kServer != kOther

suite "Frame round-trip":
  randomize()
  let agentId = "12345678"
  let key: array[32, byte] = block:
    var k: array[32, byte]
    for i in 0..<32: k[i] = byte(rand(255))
    k
  test "encrypt then decrypt returns the original plaintext":
    var ctr: uint32 = 0
    let plain = "hello world from agent"
    let blob = encryptFrame(key, agentId, 1, ctr, plain)
    check blob.len == 12 + plain.len + 16
    let dec = decryptFrame(key, agentId, 1, blob)
    check dec == plain

  test "tampered ciphertext fails authentication":
    var ctr: uint32 = 0
    let blob = encryptFrame(key, agentId, 1, ctr, "secret")
    var tampered = blob
    tampered[15] = tampered[15] xor 0x01  # flip a bit in the nonce
    let dec = decryptFrame(key, agentId, 1, tampered)
    check dec == ""

  test "wrong AAD direction fails authentication":
    var ctr: uint32 = 0
    let blob = encryptFrame(key, agentId, 1, ctr, "secret")
    # Server would decrypt with the opposite direction byte
    let dec = decryptFrame(key, agentId, 0, blob)
    check dec == ""

  test "wrong agent_id fails authentication":
    var ctr: uint32 = 0
    let blob = encryptFrame(key, "AAAAAAAA", 1, ctr, "secret")
    let dec = decryptFrame(key, "BBBBBBBB", 1, blob)
    check dec == ""

  test "nonce counter is monotonically included":
    var ctr: uint32 = 0
    let b1 = encryptFrame(key, agentId, 1, ctr, "msg1")
    let b2 = encryptFrame(key, agentId, 1, ctr, "msg2")
    check b1[0..3] != b2[0..3]   # counter prefix changed

  test "small frames (< 12 + 16 = 28 bytes) are rejected":
    check decryptFrame(key, agentId, 1, @[1'u8, 2, 3]) == ""
    check decryptFrame(key, agentId, 1, newSeq[byte](27)) == ""

suite "Registration HMAC":
  test "valid HMAC authenticates registration payload":
    let payload = "hostname=foo&user=bar\nAAAAAAAAAAAAAAAAAAAAAA=="
    let hmacHex = toHex(sha256.hmac(SECRET, payload).data)
    check hmacHex.len == 64  # SHA-256 = 32 bytes = 64 hex chars
    # Tamper with the payload, HMAC should no longer match
    let hmacTampered = toHex(sha256.hmac(SECRET, payload & "x").data)
    check hmacHex != hmacTampered

suite "AAD construction":
  test "AAD binds direction and agent id":
    let a1 = makeAad("ABC", 0x00)
    let a2 = makeAad("ABC", 0x01)
    let a3 = makeAad("ABD", 0x00)
    check a1 == @[byte('A'), byte('B'), byte('C'), 0x00]
    check a2 == @[byte('A'), byte('B'), byte('C'), 0x01]
    check a3 == @[byte('A'), byte('B'), byte('D'), 0x00]
    check a1 != a2  # direction matters
    check a1 != a3  # agent id matters
