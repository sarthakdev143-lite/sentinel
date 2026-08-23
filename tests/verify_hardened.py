"""Comprehensive hardened agent binary verification."""
import pefile, os, re

base = r"D:\Sarthak\Coding\My Codes\Cybersecurity\SentinelAgent\Nim"
build = os.path.join(base, "build")
exes = [
    "agent_hardened_silent.exe",
    "agent_hardened_engagement.exe",
    "agent_hardened_aggressive.exe",
]

# 1. IAT check
print("=== IAT CHECK ===")
for exe in exes:
    path = os.path.join(build, exe)
    pe = pefile.PE(path)
    dlls = sorted([e.dll.decode("ascii") for e in pe.DIRECTORY_ENTRY_IMPORT])
    print(f"  {exe}: {dlls}")

# 2. Plaintext secret check
print()
print("=== SECRET CHECK ===")
secret = b"sentinel-engagement"
for exe in exes:
    path = os.path.join(build, exe)
    with open(path, "rb") as f:
        data = f.read()
    status = "FAIL - secret found" if secret in data else "CLEAN - secret absent"
    print(f"  {exe}: {status}")

# 3. Sensitive string scan (case-insensitive)
print()
print("=== SENSITIVE STRING SCAN ===")
sensitive = [
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

for exe in exes:
    path = os.path.join(build, exe)
    with open(path, "rb") as f:
        data = f.read().lower()
    hits = []
    for s in sensitive:
        sl = s.lower()
        if sl in data:
            idx = data.find(sl)
            ctx = data[max(0, idx - 10) : idx + len(sl) + 20]
            hits.append((s.decode("ascii", "replace"), ctx))
    if hits:
        print(f"  {exe}:")
        for needle, ctx in hits:
            print(f"    [HIT]   {needle}: ...{ctx}...")
    else:
        print(f"  {exe}: ALL CLEAN")
