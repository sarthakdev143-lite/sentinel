"""Report hardened agent binary verification findings."""

import os
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
EXES = [
    "agent_hardened_silent.exe",
    "agent_hardened_engagement.exe",
    "agent_hardened_aggressive.exe",
]
SENSITIVE = [
    b"sentinel-engagement",
    b"amsi.dll",
    b"AmsiScanBuffer",
    b"EtwEventWrite",
    b"__EventFilter",
    b"CommandLineEventConsumer",
    b"__FilterToConsumerBinding",
    b"Win32_LogonSession",
    b"__InstanceCreationEvent",
    b"ROOT\\subscription",
    b"S3nt1n3l",
    b"discord.com",
    b"hooks.slack.com",
]


def main() -> int:
    missing = False
    print("=== IAT CHECK ===")
    for name in EXES:
        path = BUILD / name
        if not path.exists():
            print(f"  {name}: NOT FOUND")
            missing = True
            continue
        pe = pefile.PE(str(path))
        dlls = sorted(entry.dll.decode("ascii", "replace")
                      for entry in pe.DIRECTORY_ENTRY_IMPORT)
        print(f"  {name}: {dlls}")

    print()
    print("=== SECRET CHECK ===")
    for name in EXES:
        path = BUILD / name
        if not path.exists():
            missing = True
            continue
        data = path.read_bytes()
        status = "FAIL - secret found" if b"sentinel-engagement" in data else "CLEAN - secret absent"
        print(f"  {name}: {status}")

    print()
    print("=== SENSITIVE STRING SCAN ===")
    for name in EXES:
        path = BUILD / name
        if not path.exists():
            missing = True
            continue
        data = path.read_bytes().lower()
        hits = []
        for needle in SENSITIVE:
            lower = needle.lower()
            index = data.find(lower)
            if index >= 0:
                context = data[max(0, index - 10):index + len(lower) + 20]
                hits.append((needle.decode("ascii", "replace"), context))
        if hits:
            print(f"  {name}:")
            for needle, context in hits:
                print(f"    [HIT]   {needle}: ...{context}...")
        else:
            print(f"  {name}: ALL CLEAN")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
