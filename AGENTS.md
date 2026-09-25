# AGENTS.md

## Scope and entrypoints

- `sentinel.nim` is the primary implementation; the primary transport is Telegram (`-d:c2_tg`). `agent.nim`, `hardened/`, and `telegram/agent_telegram.nim` are separate legacy variants—keep them compiling when touched, but do not extend them without an explicit request.
- `c2_server.nim` is the WebSocket server and embeds `web/dashboard.html`. `common/proto.nim` and `common/streamcrypto.nim` are shared by the primary Sentinel/server path; the legacy agents contain duplicate protocol code.
- Trust the current Nim source and PowerShell scripts over `README.md`, `BUILD.md`, and deployment prose when they disagree.

## Build

- Windows-only; use Nim 2.2.x with MinGW. There is no `.nimble` project or lockfile; `nimcrypto`, `winim`, and `ws` come from the global Nimble store, and CI installs them unpinned.
- Run `build_sentinel.ps1` from the repository root: it uses relative output/include paths and honors `$env:NIM`, falling back to `D:\appdata\nim-2.2.10\bin\nim.exe`. `build.ps1`, `build_hardened.ps1`, and `telegram/build_telegram.ps1` also honor `$env:NIM`.
- Main commands:

```powershell
.\build_sentinel.ps1 -Tg -Variant aggressive
.\build_sentinel.ps1 -Both -Variant engagement
.\build.ps1                         # baseline agents + c2_server
.\build_hardened.ps1                # legacy hardened agents
.\telegram\build_telegram.ps1 -BotToken "<token>" -ChatId "<id>"
```

- `build.ps1` and `build_hardened.ps1` delete the entire `build/` directory; run `build.ps1` again if the server or baseline binaries are needed afterward. `build_sentinel.ps1` does not wipe the whole directory; it removes matching Sentinel outputs (and legacy Telegram artifacts for TG/Both builds).
- Generated includes are build inputs, not source: `xorkey.nim`, `prefix.nim`, `secret.nim`, `telegram_creds.nim`, `pin.nim`, `c2_override.nim`, and legacy `telegram/agent_telegram_built.nim`. Never hand-edit or commit them. The primary Sentinel and hardened builds use 32-byte keys; the baseline/server and legacy Telegram builders use 16-byte keys. The legacy Telegram wrapper reads `TG_BOT_TOKEN`/`TG_CHAT_ID` at build time, while its agent uses `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` at runtime. A failed legacy Telegram build intentionally leaves generated files for diagnosis.
- The server, baseline, Sentinel, and hardened builders generate `secret.nim`; set the same `C2_AGENT_PASSPHRASE` for interop. `-Passphrase` changes only the Sentinel build, and the legacy Telegram agent has a separate protocol/credential path.
- `build_sentinel.ps1` injects `-BotToken`/`-ChatId` into generated `telegram_creds.nim`; runtime `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` still override those defaults.
- `-PinCertPath` generates `pin.nim`, enables `-d:ssl` and `-d:tls_pin`, and `sentinel.nim` includes the generated PEM. The resulting SSL-capable build may require OpenSSL DLLs.

## Transport and runtime

- `build_sentinel.ps1` maps no transport switch to `c2_ws`, `-Tg` to `c2_tg`, and `-Both` to `c2_both` (WS primary + TG notifications); `-Both` wins if both switches are supplied. Variants are `variant_silent`, `variant_engagement`, and `variant_aggressive`.
- WebSocket URL precedence is repeatable/comma-separated `--c2=` arguments, then `SENTINEL_C2_URLS`, then the compile-time default. Environment/config values are resolved at startup and cached.
- The current Telegram path installs startup persistence regardless of `variant_silent`; only `C2_NO_PERSIST=1` suppresses it. Do not describe the Telegram silent build as persistence-free.
- `c2_server.nim` is currently a plain WebSocket listener, not a WSS/TLS server. It binds the agent listener on `0.0.0.0:8443`, the dashboard HTTP listener on `127.0.0.1:8080` by default, and the dashboard WebSocket listener on `0.0.0.0:8081`. Use an external TLS terminator for `wss://`; the server creates `logs/`, `downloads/`, and `uploads/` relative to its working directory.
- Dashboard credentials are runtime environment variables `C2_WEB_USER` and `C2_WEB_PASSWORD`; compiled defaults are empty. The old `WEB_AUTH_*` names and defaults in the docs are stale. Without credentials, the server starts but dashboard authentication cannot succeed.
- Sentinel's primary log is encrypted at `%TEMP%\csp-<BuildPrefix>.dat`; do not assume the old global `X7K` or `svc-X7K.log` values for Sentinel.

## Verification

- Build before integration tests. The normal WS check is:

```powershell
nim c -r -d:release --nimcache:tests/cache tests/test_crypto.nim
python tests/e2e_harness.py --start
```

- `e2e_harness.py` prefers `C2_AGENT_PASSPHRASE`, `C2_WEB_USER`, and `C2_WEB_PASSWORD` (with legacy `SENTINEL_*` fallbacks) and now fails fast when values are missing. It requires `build/c2_server.exe`, fixed ports 8443/8080, and `websockets`, `requests`, and `cryptography`.
- Strict audits are:

```powershell
python tests/audit_strings.py --strict build\sentinel_tg_silent.exe
python tests/audit_server.py --binary --strict
```

- `pe_imports.py`, `verify_hardened.py`, and `scan_strings.py` primarily report findings and are not reliable pass/fail gates. `test_tg_commands.py --build` is a focused Telegram-handler test and now generates/cleans all required includes. `test_dashboard_ui.py` additionally requires Playwright and a headless Chromium install.
- CI runs baseline build, crypto and log-crypto tests, E2E, import inspection, hardened build/verification, a full baseline/server rebuild, Sentinel TG/WS compile checks, then a report-only string scan.

## Working conventions

- Add new signature-sensitive strings using the neighboring `S_*`/`encodeObf` pattern and preserve the generated-key include contract; this is not a claim that every existing literal is encoded.
- Use the build scripts to generate Nim includes; the primary scripts now write UTF-8 without a BOM for PowerShell 5.1 compatibility. Do not hand-generate these files.
- `config.example.nim` is not currently referenced by the source or build scripts; copying it to `config.nim` has no effect.
- There is no repository lint or typecheck task. Validate Nim changes with the relevant build script plus the focused checks above, and run CI-equivalent checks before considering a change complete.
