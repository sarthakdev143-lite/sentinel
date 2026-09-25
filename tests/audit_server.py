#!/usr/bin/env python3
"""Audit c2_server.nim (source + binary) for the same kind of plaintext
leaks we just cleaned out of sentinel.nim.

The server isn't deployed to a target, but:
  * The compiled binary leaks if the operator's box is compromised.
  * Source-level plaintext becomes git history forever.
  * Some leaks (the shared secret) give an attacker the same material
    they would have extracted from a captured agent.

Two modes:
  default     - print findings, exit 0 (informational)
  --strict    - exit 1 if any MUST-NOT-APPEAR pattern is found
  --source    - audit c2_server.nim source (default)
  --binary    - audit build/c2_server.exe
  --both      - audit source AND binary

Usage:
  python tests/audit_server.py --source
  python tests/audit_server.py --binary --strict
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

MUST_NOT_APPEAR = [
    # Source-level: hardcoded passphrase / project roadmap.
    ("sentinel-engagement-q4-2026-echo-tango-whiskey",
     "S_SECRET plaintext in source (was shared with agent)"),
    ("sentinel-engagement",
     "S_SECRET fragment"),
    ("echo-tango-whiskey",
     "S_SECRET fragment"),

    # Source + binary: BuildPrefix hardcoded to X7K (same cluster key
    # the agent used to leak).
    ("X7K",
     "BuildPrefix literal (free cross-deployment clustering key)"),

    # Help text contiguous blob in helpText() - 26 lines of capabilities.
    ("run shell command\n",
     "helpText() blob (was 26-line contiguous capability list)"),
    ("uninstall and quit",
     "helpText() blob fragment"),
    ("emergency self-destruct",
     "helpText() blob fragment (panic command description)"),
    ("keylogger control",
     "helpText() blob fragment"),

    # Plaintext project name in HTTP basic auth realm + startup banner.
    ('"SentinelC2"',
     'HTTP basic auth realm + startup banner (project name in plaintext)'),

    # Hardcoded placeholder auth password.
    ("S3nt1n3l-C2-D3v-Only-CHANGEME",
     "hardcoded dashboard password (was placeholder)"),
]

INTENTIONAL = [
    # Each operator command name has to appear as a literal because the
    # if/elif dispatch chain compares strings. Eliminating them would
    # require indexed dispatch (same as the agent's 34 residual labels).
    # Documented here so the operator knows the limit.
    ('"list"', "operator dispatch label 'list'"),
    ('"shell"', "operator dispatch label 'shell'"),
    ('"download"', "operator dispatch label 'download'"),
    ('"upload"', "operator dispatch label 'upload'"),
    ('"screenshot"', "operator dispatch label 'screenshot'"),
    ('"help"', "operator dispatch label 'help'"),
    ('"panic"', "operator dispatch label 'panic'"),
    ('"kill"', "operator dispatch label 'kill'"),
]


def audit_file(path: Path, label: str):
    print(f"\n=== {label}: {path.name} ({path.stat().st_size if path.exists() else 0} bytes) ===")
    if not path.exists():
        print(f"  FILE NOT FOUND")
        return []

    data = path.read_bytes()
    leaks = []
    print(f"\n--- {len(MUST_NOT_APPEAR)} MUST-NOT-APPEAR patterns ---")
    for pattern, comment in MUST_NOT_APPEAR:
        hits = list(re.finditer(re.escape(pattern.encode('ascii', errors='ignore')),
                                data, re.IGNORECASE))
        if hits:
            leaks.append((pattern, comment, hits))
            print(f"  [LEAK]  {pattern!r}")
            print(f"          ({comment})")
            for h in hits[:2]:
                ctx = data[max(0, h.start()-12):h.end()+12]
                print(f"          @ 0x{h.start():x}: {ctx!r}")
        else:
            print(f"  [OK]    {pattern!r}")

    print(f"\n--- {len(INTENTIONAL)} INTENTIONAL plaintext (documented limit) ---")
    for pattern, comment in INTENTIONAL:
        hits = list(re.finditer(re.escape(pattern.encode('ascii', errors='ignore')),
                                data, re.IGNORECASE))
        status = "[INTENTIONAL]" if hits else "[ABSENT]"
        print(f"  {status:13s}  {pattern!r:50s} ({comment})")

    return leaks


def main():
    args = sys.argv[1:]
    strict = False
    if "--strict" in args:
        strict = True
        args.remove("--strict")

    mode = "source"
    if "--binary" in args:
        mode = "binary"
    if "--both" in args:
        mode = "both"
    if "--source" in args:
        mode = "source"

    source = REPO / "c2_server.nim"
    binary = REPO / "build" / "c2_server.exe"

    all_leaks = []
    if mode in ("source", "both"):
        all_leaks += audit_file(source, "SOURCE")
    if mode in ("binary", "both"):
        all_leaks += audit_file(binary, "BINARY")

    print()
    if all_leaks:
        print(f"=== {len(all_leaks)} MUST-NOT-APPEAR patterns leaked ===")
        if strict:
            print("STRICT mode: exiting with code 1")
            sys.exit(1)
        print("(informational mode: exiting with code 0)")
        sys.exit(0)

    print("=== Audit passed: no known plaintext leaks ===")
    sys.exit(0)


if __name__ == "__main__":
    main()
