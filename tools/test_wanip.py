"""Diagnose the IPv6 enumeration path and exercise the WAN IP helpers."""
from __future__ import annotations

import json
import subprocess
import sys

sys.path.insert(0, ".")

import wanip  # noqa: E402

PS_CMD = (
    "Get-NetIPAddress -AddressFamily IPv6 | "
    "Where-Object { $_.IPAddress -notmatch '^(fe80|::1)' } | "
    "Select-Object IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin | "
    "ConvertTo-Json -Compress"
)

print("=== raw powershell stdout from python ===")
proc = subprocess.run(
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_CMD],
    capture_output=True,
    text=True,
    timeout=40,
)
print("returncode:", proc.returncode)
print("stdout repr[:500]:", repr(proc.stdout[:500]))
print("stdout length:", len(proc.stdout))
if proc.stderr.strip():
    print("stderr[:200]:", proc.stderr[:200])

print()
print("=== parsed via wanip.get_ipv6_candidates() ===")
cands = wanip.get_ipv6_candidates()
print("count:", len(cands))
for c in cands:
    print(
        f"  {c['address']:42} prefix={c['prefix']:26} "
        f"temp={str(c['is_temporary']):5} origin={c['suffix_origin']}"
    )

print()
print("=== distinct /64 prefixes ===")
for p in wanip.get_ipv6_prefixes():
    print("  ", p, "-> AAAA", wanip.build_aaaa(p))

print()
print("=== IPv4 observers (raw) ===")
for url, ans in wanip.get_ipv4_wan_detailed():
    print(f"  {url:34} -> {ans}")

print()
print("=== IPv4 consensus ===")
print("  result =", wanip.get_ipv4_wan())
