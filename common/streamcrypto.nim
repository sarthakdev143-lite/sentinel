# common/streamcrypto.nim — single source of truth for the stream cipher
# and the encrypted agent log. Imported by sentinel.nim and by the test
# suite so a regression in either side is caught by the same round-trip.
#
# The stream cipher is used by:
#   * encodeObf / obfDec in sentinel.nim (compile-time obfuscated S_* consts)
#   * encryptLogLine / decryptLogLine (encrypted at-rest log on the target)
#
# Mirroring the algorithm in the test (the pattern used by test_crypto.nim)
# would only verify the *spec* works, not the agent's actual code. Importing
# the same module catches real regressions.

import std/[endians]

# -----------------------------------------------------------------------------
# 16-byte block mixer (SipHash-like add/rotate/xor)
# -----------------------------------------------------------------------------
proc mixBytes(input, key: openArray[byte]; rounds: int = 8): array[16, byte] =
  ## 16-byte block mixer. Treat the input as 4 little-endian uint32s and
  ## run a SipHash-like add/rotate/xor loop. Position-dependent (same input
  ## always produces the same output; different inputs produce different
  ## outputs at the same position).
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

# -----------------------------------------------------------------------------
# CBC-style chained stream cipher on top of mixBytes
# -----------------------------------------------------------------------------
proc streamCipher*(plaintext, key, nonce: openArray[byte]): seq[byte] =
  ## Each 16-byte block: build input [block_idx:4][nonce:4][0:8], mix with key,
  ## XOR with previous ciphertext (chaining), XOR with plaintext. `key` is
  ## passed by the caller (typically XorKey from xorkey.nim) so this module
  ## has no implicit dependency on per-build secrets.
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

# -----------------------------------------------------------------------------
# Encrypted at-rest log (the previous plaintext svc-X7K.log / %TEMP% timeline)
# -----------------------------------------------------------------------------
# Wire format: [nonce:4 BE uint32][len:2 BE uint16][ciphertext:N]
# Nonce is an atomic counter, incremented per call. Two adjacent lines never
# reuse keystream (CBC chaining handles that internally too).
proc encryptLogLine*(plain: string, key: openArray[byte],
                     nonceCtr: var uint32): seq[byte] =
  inc nonceCtr
  var nonce: array[4, byte]
  bigEndian32(addr nonce[0], addr nonceCtr)
  let ct = streamCipher(plain.toOpenArrayByte(0, plain.len - 1), key, nonce)
  # Allocate the result with the full header + ciphertext up front so
  # bigEndian16 can write directly into the seq without an IndexDefect.
  result = newSeq[byte](6 + ct.len)
  result[0] = nonce[0]; result[1] = nonce[1]
  result[2] = nonce[2]; result[3] = nonce[3]
  let len16: uint16 = uint16(ct.len)
  bigEndian16(addr result[4], addr len16)
  for i, b in ct: result[6 + i] = b

proc decryptLogLine*(blob: openArray[byte], key: openArray[byte]): string =
  ## Inverse of encryptLogLine. Returns empty string on malformed input.
  if blob.len < 6: return ""
  var nonce: array[4, byte]
  for i in 0..<4: nonce[i] = blob[i]
  let ctLen = (int(blob[4]) shl 8) or int(blob[5])
  if blob.len < 6 + ctLen: return ""
  let ct = blob[6 ..< 6 + ctLen]
  let pt = streamCipher(ct, key, nonce)
  result = newString(pt.len)
  for i in 0..<pt.len: result[i] = chr(int(pt[i]))
