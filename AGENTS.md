# AGENTS.md

SentinelC2: Nim red-team C2. Two single-file monoliths — `agent.nim` (~3300 lines, Windows implant) and `c2_server.nim` (~2300 lines, C2 server + web dashboard). Plus a hardened agent variant (`hardened/agent_hardened.nim` ~1100 lines, imports 9 evasion/resilience modules). Windows-only (both use winim). No `.nimble` project config; deps (`nimcrypto`, `winim`, `ws`) come from the Nimble global store.

## Build

```powershell
.\build.ps1            # builds 3 baseline agent variants + c2_server into build/
.\build_hardened.ps1   # builds 3 hardened agent variants into build/
```

- Nim 2.2.10 lives at `D:\appdata\nim-2.2.10\bin\nim.exe` and may not be on PATH — both build scripts honor `$env:NIM`.
- Baseline variants: silent (default), `-d:variant_engagement`, `-d:variant_aggressive`.
- Hardened variants: `agent_hardened_silent.exe`, `agent_hardened_engagement.exe`, `agent_hardened_aggressive.exe`.
- `build/` is gitignored. Root-level `agent_fixed.exe` / `c2_server.exe` are stale committed artifacts — ignore them.
- `xorkey.nim` is auto-generated: build.ps1 generates a 16-byte key per variant (baseline), build_hardened.ps1 generates a 32-byte key per variant (hardened, for the stream cipher). Deleted after each compile. Never commit it; don't hand-edit — if absent, both sources fall back to a fixed default key at compile time (`staticExec` check).
- `build_hardened.ps1` wipes `build/` on each run (Remove-Item -Recurse). Rebuild c2_server with `build.ps1` if you need it alongside hardened agents.
- Defender may quarantine freshly built agent exes — add an exclusion for `build\` if outputs vanish.

## Verify

```powershell
python tests/e2e_harness.py --start      # E2E: launches build\c2_server.exe, simulates agent, 26 assertions
nim c -r -d:release --nimcache:tests/cache tests/test_crypto.nim   # crypto round-trip unit tests
python tests/pe_imports.py build\agent_silent.exe  # baseline: must show only KERNEL32.dll + msvcrt.dll
python tests/pe_imports.py build\agent_hardened_silent.exe  # hardened: KERNEL32.dll + USER32.dll + msvcrt.dll
python tests/verify_hardened.py          # comprehensive IAT + secret + sensitive string scan for hardened variants
```

- Build first — the E2E harness requires `build\c2_server.exe` and pip deps `websockets requests cryptography`.
- The harness hardcodes `SECRET` and `WEB_AUTH` creds (tests/e2e_harness.py:40-41) mirroring the Nim sources — update it whenever you change those consts or the E2E goes red.
- Baseline IAT: KERNEL32.dll + msvcrt.dll only (winmm/avicap loaded dynamically).
- Hardened IAT: KERNEL32.dll + USER32.dll + msvcrt.dll (USER32 from winim used by anti_analysis/hollowing). No ntdll, amsi, or other suspicious DLLs.

## Config gotchas (compile-time, both files)

- `S_AGENT_SECRET` (agent.nim + agent_hardened.nim) must equal `S_SECRET` (c2_server.nim) — `encodeObf()`-obfuscated consts, plaintext `sentinel-engagement-q4-2026-echo-tango-whiskey`. Rotate per engagement.
- Dashboard creds `WEB_AUTH_USER` / `WEB_AUTH_PASSWORD` (c2_server.nim:58-59, defaults `operator` / `S3nt1n3l-C2-D3v-Only-CHANGEME`); the server emits a compile-time warning if unchanged.
- Agent C2 URLs resolve at runtime without rebuild: `--c2=` CLI flag(s) > `SENTINEL_C2_URLS` env var > `C2_URLS_DEFAULT` const.
- `BuildPrefix` const (default `X7K`) is baked into log filename `%TEMP%\svc-X7K.log` and prompt strings.
- Ports: 8443 agent WS, 8080 dashboard HTTP (basic auth), 8081 dashboard WS push (separate raw listener — asynchttpserver can't safely hijack sockets). Server creates `logs/`, `downloads/`, `uploads/` at runtime (gitignored).

## Conventions

- Every signatured literal (DLL names, API names, paths, secrets, WMI class names) is an obfuscated `S_*` const via `encodeObf()` — add new ones the same way, never as raw literals. The `reconEdrAv` EDR-name list is a known literal-string holdout in the baseline.
- Baseline uses 16-byte XOR key; hardened uses 32-byte key + pure-Nim stream cipher (`mixBytes` + `streamCipher` with CBC-style chaining) for stronger compile-time obfuscation.
- Server builds need `--threads:on`; agents use `--opt:size --app:gui --passL:-s`. Hardened agents add `--path:hardened` + linker flags for `-lws2_32 -lsecur32 -lcrypt32 -ladvapi32 -lshell32 -lole32 -lntdll`.
- Read `BUILD.md` (build/dev-loop reference) and `README.md` (protocol, wire format, command set) before touching either source. `DEPLOY.md` covers Tailscale Funnel deployment. `hardened/README.md` documents the 7 integration points, `hardened/DEPLOYMENT_CHECKLIST.md` covers verification procedures.
