# common/proto.nim — single source of truth for the SentinelC2 wire
# protocol crypto. Imported by c2_server.nim, agent.nim and sentinel.nim
# so a format change can never drift between the sides again.
#
# Wire format (unchanged):
#   frame:  nonce(12) || ciphertext || tag(16)
#   nonce:  4-byte BE counter || 8 random bytes
#   AAD:    agent_id || direction (0x00 S->A, 0x01 A->S)
#   key:    HMAC-SHA256(secret, server_nonce || agent_nonce), 32 bytes
#   reg:    HMAC-SHA256(secret, payload) hex, once, pre-encryption

import nimcrypto/[sha2, hmac, bcmode, rijndael, utils]

const
  AAD_DIR_S2A* = 0x00'u8
  AAD_DIR_A2S* = 0x01'u8

proc deriveSessionKey*(secret: string,
                       ourNonce, peerNonce: openArray[byte]): array[32, byte] =
  # Single HMAC-SHA256 over (ourNonce || peerNonce), keyed with the
  # static secret. Both sides run the same computation with the roles
  # swapped so the derived keys match.
  var ctx: HMAC[sha256]
  ctx.init(secret)
  ctx.update(ourNonce)
  ctx.update(peerNonce)
  let d = ctx.finish()
  for i in 0..<32: result[i] = d.data[i]
  ctx.clear()

proc makeNonce*(ctr: uint32, randBytes: openArray[byte]): array[12, byte] =
  result[0] = byte((ctr shr 24) and 0xFF)
  result[1] = byte((ctr shr 16) and 0xFF)
  result[2] = byte((ctr shr 8) and 0xFF)
  result[3] = byte(ctr and 0xFF)
  for i in 0..<8: result[4 + i] = randBytes[i]

proc makeAad*(agentId: string, dir: byte): seq[byte] =
  result = newSeqOfCap[byte](agentId.len + 1)
  for c in agentId: result.add(byte(c))
  result.add(dir)

proc hmacHex*(secret, data: string): string =
  toHex(sha256.hmac(secret, data).data)

proc gcmSeal*(key: array[32, byte], nonce: array[12, byte],
              aad: seq[byte], plain: string): seq[byte] =
  ## Frame body: ciphertext || tag(16). Caller prepends the nonce.
  var ctx: GCM[aes256]
  ctx.init(key, nonce, aad)
  let pt = cast[seq[byte]](plain)
  var ct = newSeq[byte](pt.len)
  ctx.encrypt(pt, ct)
  let tag = ctx.getTag()
  result = newSeqOfCap[byte](ct.len + 16)
  for b in ct: result.add(b)
  for b in tag: result.add(b)

proc gcmOpen*(key: array[32, byte], nonce: array[12, byte],
              aad: seq[byte], blob: openArray[byte]): string =
  ## Inverse of gcmSeal. Returns "" on authentication failure.
  if blob.len < 16: return ""
  let ctLen = blob.len - 16
  let ct = blob[0 ..< ctLen]
  let tag = blob[blob.len - 16 ..< blob.len]
  var ctx: GCM[aes256]
  ctx.init(key, nonce, aad)
  var pt = newSeq[byte](ct.len)
  if not ctx.decrypt(ct, pt, tag): return ""
  result = cast[string](pt)
