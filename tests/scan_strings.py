"""Scan agent binaries for sensitive plaintext strings."""

import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(BASE, "build")
DEFAULT_EXES = [
    "agent_hardened_silent.exe",
    "agent_hardened_engagement.exe",
    "agent_hardened_aggressive.exe",
]
SENSITIVE = [
    "sentinel-engagement",
    "amsi.dll",
    "AmsiScanBuffer",
    "EtwEventWrite",
    "ntdll",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "S3nt1n3l",
    "discord.com",
    "hooks.slack.com",
    "Win32_LogonSession",
    "__EventFilter",
    "CommandLineEventConsumer",
]


def scan(path: str) -> bool:
    if not os.path.exists(path):
        print(f"=== {path} === NOT FOUND")
        return False
    with open(path, "rb") as handle:
        data = handle.read()
    raw_strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    string_set = {value.decode("ascii", "replace").lower() for value in raw_strings}
    print(f"=== {path} ===")
    found = False
    for needle in SENSITIVE:
        lower = needle.lower()
        hit = next((value[:100] for value in string_set if lower in value), None)
        if hit:
            print(f"  [HIT]   {needle}: found in \"{hit}\"")
            found = True
        else:
            print(f"  [CLEAN] {needle}: not found")
    return found


def main() -> int:
    paths = sys.argv[1:] or [os.path.join(BUILD, name) for name in DEFAULT_EXES]
    any_hit = False
    for path in paths:
        any_hit = scan(path) or any_hit
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
