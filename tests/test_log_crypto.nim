# tests/test_log_crypto.nim
# Round-trip tests for the encrypted at-rest agent log.
# Imports the SAME common/streamcrypto.nim that sentinel.nim uses,
# so a regression in either side is caught by this test.
#
# Build:  nim c -r -d:release --path:common --nimcache:tests/cache tests/test_log_crypto.nim
#
# The on-disk format (matches sentinel.nim's agentLog):
#   [nonce:4 BE uint32][len:2 BE uint16][ciphertext:N]
# The plaintext is XOR-streamed using common/streamcrypto.streamCipher
# with CBC-style block chaining over a 16-byte keyed mixer.

import std/[unittest, times, sugar, sequtils]
import ../common/streamcrypto

# Test key. Doesn't have to match any real XorKey - the test exercises
# the algorithm's round-trip, not interop with a specific binary.
let testKey: array[32, byte] = [
  byte 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
]

suite "Log line round-trip":
  test "single short line decrypts to plaintext":
    var nonceCtr: uint32 = 0
    let blob = encryptLogLine("hello world", testKey, nonceCtr)
    check decryptLogLine(blob, testKey) == "hello world"

  test "empty line decrypts to empty":
    var nonceCtr: uint32 = 0
    let blob = encryptLogLine("", testKey, nonceCtr)
    check decryptLogLine(blob, testKey) == ""

  test "long line (>16 bytes, crosses cipher block boundary)":
    var nonceCtr: uint32 = 0
    let plain = "this is a longer log line that crosses the 16-byte cipher block boundary"
    let blob = encryptLogLine(plain, testKey, nonceCtr)
    check decryptLogLine(blob, testKey) == plain

  test "binary / non-ASCII plaintext survives round-trip":
    var nonceCtr: uint32 = 0
    let plain = "\x00\xff\x7f\xe9" & "ascii tail" & "\x80\x81\x82"
    let blob = encryptLogLine(plain, testKey, nonceCtr)
    check decryptLogLine(blob, testKey) == plain

  test "format header is [nonce:4][len:2][cipher:N]":
    var nonceCtr: uint32 = 0
    let plain = "0123456789"   # 10 bytes
    let blob = encryptLogLine(plain, testKey, nonceCtr)
    check blob.len == 6 + plain.len
    # len bytes are at offset 4..5, big-endian
    let lenField = (int(blob[4]) shl 8) or int(blob[5])
    check lenField == plain.len

suite "Log line nonces":
  test "adjacent encryptions use different ciphertext (different nonces)":
    var nonceCtr: uint32 = 0
    let blob1 = encryptLogLine("same line", testKey, nonceCtr)
    let blob2 = encryptLogLine("same line", testKey, nonceCtr)
    check blob1 != blob2
    # But both still decrypt to the same plaintext
    check decryptLogLine(blob1, testKey) == "same line"
    check decryptLogLine(blob2, testKey) == "same line"

  test "counter increments per call":
    var nonceCtr: uint32 = 5
    discard encryptLogLine("a", testKey, nonceCtr)
    check nonceCtr == 6
    discard encryptLogLine("b", testKey, nonceCtr)
    check nonceCtr == 7

suite "Log line authentication / integrity":
  test "tampered ciphertext fails to decrypt (round-trip mismatch)":
    var nonceCtr: uint32 = 0
    let blob = encryptLogLine("secret payload", testKey, nonceCtr)
    var tampered = blob
    # Flip a bit somewhere in the ciphertext (past the 6-byte header)
    tampered[10] = tampered[10] xor 0x01
    let dec = decryptLogLine(tampered, testKey)
    check dec != "secret payload"

  test "wrong key fails to decrypt":
    var nonceCtr: uint32 = 0
    let blob = encryptLogLine("secret", testKey, nonceCtr)
    let wrongKey: array[32, byte] = [byte 0xAA, 0xBB, 0xCC, 0xDD, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    let dec = decryptLogLine(blob, wrongKey)
    check dec != "secret"

  test "truncated blob returns empty":
    var nonceCtr: uint32 = 0
    let blob = encryptLogLine("hello", testKey, nonceCtr)
    # Header claims len=5 but the blob is truncated to header-only
    check decryptLogLine(blob[0..<5], testKey) == ""

  test "length-field mismatch returns empty":
    var nonceCtr: uint32 = 0
    let blob = encryptLogLine("hello", testKey, nonceCtr)
    var bad = blob
    # Bump claimed length beyond the actual ciphertext
    bad[4] = 0xFF
    bad[5] = 0xFF
    check decryptLogLine(bad, testKey) == ""

suite "Log line length / wire format edge cases":
  test "exactly 16-byte plaintext (one cipher block)":
    var nonceCtr: uint32 = 0
    let plain = "0123456789abcdef"
    let blob = encryptLogLine(plain, testKey, nonceCtr)
    check decryptLogLine(blob, testKey) == plain
    check blob.len == 6 + 16

  test "17-byte plaintext (crosses block boundary)":
    var nonceCtr: uint32 = 0
    let plain = "0123456789abcdef!"
    let blob = encryptLogLine(plain, testKey, nonceCtr)
    check decryptLogLine(blob, testKey) == plain

  test "1000 sequential lines all round-trip":
    var nonceCtr: uint32 = 0
    var lines: seq[string] = @[]
    for n in 1..1000:
      lines.add("line " & $n & " with payload " & $n & $n & $n)
    var blobs: seq[seq[byte]] = @[]
    for line in lines:
      blobs.add(encryptLogLine(line, testKey, nonceCtr))
    # All blobs should differ (different nonces)
    check blobs.len == 1000
    var unique = 0
    for b in blobs:
      if blobs.count(b) == 1: inc unique
    check unique == 1000
    # All decrypt correctly
    for i, b in blobs:
      check decryptLogLine(b, testKey) == lines[i]
