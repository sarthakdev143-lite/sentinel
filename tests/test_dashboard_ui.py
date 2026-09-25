#!/usr/bin/env python3
"""Automated UI tests for the SentinelC2 dashboard (Playwright, headless).

Starts c2_server + a FakeAgent, then drives the real dashboard in
headless Chromium:

  1. Page loads, agents sidebar renders the fake agent
  2. Selecting the agent enables the command bar
  3. Quick-action button sends a command the agent actually receives
  4. Typed command with Enter dispatches through /api/cmd
  5. Ctrl+K palette opens and lists agents
  6. Files tab renders after a file exists in downloads/
  7. Full-page screenshot saved to build/dashboard_preview.png

Run:  python tests/test_dashboard_ui.py
"""

import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from e2e_harness import (  # noqa: E402
    FakeAgent, SERVER_EXE, HOST, HTTP_PORT, require_test_config,
)

import requests  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

BASE = f"http://{HOST}:{HTTP_PORT}"
AUTH = (os.environ.get("C2_WEB_USER") or os.environ.get("SENTINEL_WEB_USER", ""),
        os.environ.get("C2_WEB_PASSWORD") or os.environ.get("SENTINEL_WEB_PASS", ""))

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}"
          + (f"   -> {detail[:140]}" if not cond else ""))
    passed, failed = passed + (1 if cond else 0), failed + (0 if cond else 1)


def main():
    require_test_config()
    server = subprocess.Popen(
        [str(SERVER_EXE)], cwd=str(ROOT),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    try:
        run_ui_tests()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    print(f"\n  PASSED: {passed}   |   FAILED: {failed}")
    sys.exit(1 if failed else 0)


import subprocess  # noqa: E402
import queue  # noqa: E402


class AgentBridge:
    """Runs FakeAgent on a background thread with its own event loop
    (Playwright's sync API owns the main one). Received frames land in
    a thread-safe queue."""

    def __init__(self):
        import threading
        import threading as th
        self.q = queue.Queue()
        self.id_q = queue.Queue()
        self.agent = FakeAgent("UI-TESTBOX", "Windows 11 Enterprise",
                               "sarthak", True)
        self.loop = asyncio.new_event_loop()
        t = th.Thread(target=self._run, daemon=True)
        t.start()
        self.agent_id = self.id_q.get(timeout=15)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._main())

    async def _main(self):
        aid = await self.agent.connect()
        self.id_q.put(aid)
        # Beacon so the dashboard console has content immediately.
        await self.agent.send_output("[+] ui-test beacon online")
        while True:
            frame = await self.agent.recv_frame(timeout_s=3600)
            if frame is not None:
                self.q.put(frame)

    def next_frame(self, timeout=8):
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return None


def run_ui_tests():
    bridge = AgentBridge()
    aid = bridge.agent_id
    print(f"[+] Fake agent registered: {aid}")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1500, "height": 950},
                                  http_credentials={
                                      "username": AUTH[0],
                                      "password": AUTH[1]})
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        page.goto(BASE, wait_until="networkidle")
        check("dashboard loads (title)", page.title() == "Operator Console")

        # 1. sidebar shows the fake agent
        page.wait_for_selector(".agent-card", timeout=10000)
        cards = page.locator(".agent-card")
        check("agent card rendered", cards.count() >= 1)
        check("hostname shown", "UI-TESTBOX" in cards.first.inner_text())

        # 2. select it -> command bar enables
        cards.first.click()
        page.wait_for_timeout(600)
        check("cmd input enabled on selection",
              page.locator("#cmdInput").is_enabled())
        check("target label updated", "UI-TESTBOX" in
              page.locator("#cmdTarget").inner_text())

        # 3. quick-action: Screenshot -> agent receives `screenshot`
        page.locator('.qa[data-cmd="screenshot"]').click()
        got = bridge.next_frame(8)
        check("quick-action delivered to agent",
              got is not None and got.get("cmd") == "screenshot", str(got))

        # toast appeared
        check("toast feedback shown", page.locator(".toast").count() >= 1)

        # 4. typed command via Enter
        page.fill("#cmdInput", "ps")
        page.keyboard.press("Enter")
        got = bridge.next_frame(8)
        check("typed Enter dispatched cmd=ps",
              got is not None and got.get("cmd") == "ps", str(got))

        # 5. Ctrl+K palette lists commands + agents
        page.keyboard.press("Control+k")
        page.wait_for_selector("#palette.on", timeout=3000)
        items = page.locator(".pal-item")
        check("palette lists entries", items.count() >= 10,
              f"count={items.count()}")
        page.locator("#palInput").click()
        page.keyboard.press("Escape")
        page.wait_for_selector("#palette.on", state="detached", timeout=3000)
        check("palette closes on Escape", True)

        # 6. Files tab renders a card for an existing download
        dl_dir = ROOT / "downloads" / aid
        dl_dir.mkdir(parents=True, exist_ok=True)
        (dl_dir / "ui_test.txt").write_text("hello from ui test")
        page.locator("#tabFiles").click()
        page.wait_for_selector(".file-card", timeout=8000)
        check("file card rendered",
              "ui_test.txt" in page.locator(".file-card").first.inner_text())

        # preview modal opens
        page.locator(".file-card").first.click()
        page.wait_for_selector("#modal.on", timeout=5000)
        check("preview modal opened",
              "ui_test.txt" in page.locator("#modalTitle").inner_text())
        page.locator("#modalClose").click()

        # 7. log console received lines (beacon + command acks)
        page.locator("#tabLog").click()
        page.wait_for_timeout(1500)
        log_text = page.locator("#logView").inner_text()
        check("console has log content",
              "ui-test beacon" in log_text or len(log_text.strip()) > 20,
              log_text[:80])

        # JS console errors?
        check("no page JS errors", len(errors) == 0, "; ".join(errors[:3]))

        # screenshot for the operator
        shot = ROOT / "build" / "dashboard_preview.png"
        page.screenshot(path=str(shot), full_page=False)
        print(f"[+] Preview screenshot: {shot}")

        # keep agent alive briefly so WS pushes settle
        time.sleep(1)
        browser.close()


import subprocess  # noqa: E402

if __name__ == "__main__":
    main()
