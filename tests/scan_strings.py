"""Scan hardened agent binaries for sensitive plaintext strings."""
import os, re, sys

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
build = os.path.join(base, "build")

exes = [
    "agent_hardened_silent.exe",
    "agent_hardened_engagement.exe",
    "agent_hardened_aggressive.exe",
]

sensitive = [
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

for exe in exes:
    path = os.path.join(build, exe)
    if not os.path.exists(path):
        print(f"=== {exe} === NOT FOUND\n")
        continue
    with open(path, "rb") as f:
        data = f.read()
    raw_strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    string_set = set(s.decode("ascii", "replace").lower() for s in raw_strings)
    print(f"=== {exe} ===")
    for needle in sensitive:
        nl = needle.lower()
        hit = None
        for s in string_set:
            if nl in s:
                hit = s[:100]
                break
        if hit:
            print(f"  [HIT]   {needle}: found in \"{hit}\"")
        else:
            print(f"  [CLEAN] {needle}: not found")
    print()
