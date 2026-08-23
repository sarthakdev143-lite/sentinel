# AGENTS.md

**PRIMARY VARIANT: Sentinel Telegram** (`sentinel.nim` built with `-d:c2_tg`). All new feature work, fixes, and testing focus here. The other agents (`agent.nim`, `hardened/`, `telegram/agent_telegram.nim`) and the WS/both transports are frozen — keep them compiling if touched, but don't extend them. `py_telegram_c2/` was removed intentionally.

SentinelC2: Nim red-team C2. Two single-file monoliths — `agent.nim` (~3300 lines, Windows implant) and `c2_server.nim` (~2300 lines, C2 server + web dashboard). Plus a hardened agent variant (`hardened/agent_hardened.nim` ~1100 lines, imports 9 evasion/resilience modules) and a Telegram-Bot-API variant (`telegram/agent_telegram.nim` ~900 lines, single-file implant that uses the public Telegram Bot API as its C2 channel — no custom server, no VPS). Windows-only (both use winim). No `.nimble` project config; deps (`nimcrypto`, `winim`, `ws`) come from the Nimble global store.

**Sentinel super-agent** — `sentinel.nim` combines the full feature set of `agent.nim` + `agent_hardened.nim` + `agent_telegram.nim` into one file. Transport is compile-time selectable via `-d:c2_ws` (default, WebSocket), `-d:c2_tg` (**primary**, Telegram Bot API), or `-d:c2_both` (WS primary + TG notify). Build variants: `-d:variant_silent|engagement|aggressive`. Build: `.\build_sentinel.ps1 -Tg ...`. TG transport reaches api.telegram.org through dynamically-resolved native WinHTTP — **no OpenSSL DLLs needed for pure -Tg builds** (OpenSSL is only linked by the WS transports via the `ws` package). IAT of a TG build: KERNEL32 + msvcrt + USER32 only.

## Build

```powershell
.\build.ps1            # builds 3 baseline agent variants + c2_server into build/
.\build_hardened.ps1   # builds 3 hardened agent variants into build/
.\telegram\build_telegram.ps1 -BotToken "..." -ChatId "..."   # builds telegram\agent_telegram.exe (Telegram Bot API C2)
```

- Nim 2.2.10 lives at `D:\appdata\nim-2.2.10\bin\nim.exe` and may not be on PATH — both build scripts honor `$env:NIM`.
- Baseline variants: silent (default), `-d:variant_engagement`, `-d:variant_aggressive`.
- Hardened variants: `agent_hardened_silent.exe`, `agent_hardened_engagement.exe`, `agent_hardened_aggressive.exe`.
- Telegram variant: single `agent_telegram.exe` (~440 KB) + two bundled OpenSSL DLLs (`libssl-1_1-x64.dll`, `libcrypto-1_1-x64.dll` — copied next to the exe by `build_telegram.ps1`). Without the OpenSSL pair the agent cannot reach `https://api.telegram.org` and silently fails on every poll. XOR-encodes the bot token, chat id, and a per-build randomized mutex name with a fresh 16-byte key (written to `xorkey.nim`, deleted after compile). Token fingerprint is printed so the operator can verify the right binary is going to the right target. See `telegram\README.md` for the full operator guide and the live-Linux-USB deploy script.
- `build/` is gitignored. Root-level `agent_fixed.exe` / `c2_server.exe` are stale committed artifacts — ignore them.
- `xorkey.nim` is auto-generated: build.ps1 generates a 16-byte key per variant (baseline), build_hardened.ps1 generates a 32-byte key per variant (hardened, for the stream cipher), build_telegram.ps1 generates a 16-byte key for the Telegram variant. Deleted after each compile. Never commit it; don't hand-edit. **The Telegram source `include`s `xorkey.nim` directly** (no `staticExec` gate) — the old `when staticExec("if exist xorkey.nim ...") == "yes\n"` pattern silently fell back to the hardcoded key on a non-trivial subset of PowerShell/cmd.exe CWD combinations, which produced an agent with garbage decoded secrets and an IndexDefect crash at startup. If xorkey.nim is missing at compile time, the build fails loudly — which is what we want.
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
- Server builds need `--threads:on`; agents use `--opt:size --app:gui --passL:-s --define:ssl`. Hardened agents add `--path:hardened` + linker flags for `-lws2_32 -lsecur32 -lcrypt32 -ladvapi32 -lshell32 -lole32 -lntdll`.
- Read `BUILD.md` (build/dev-loop reference) and `README.md` (protocol, wire format, command set) before touching either source. `DEPLOY.md` covers Tailscale Funnel deployment. `hardened/README.md` documents the 7 integration points, `hardened/DEPLOYMENT_CHECKLIST.md` covers verification procedures.
