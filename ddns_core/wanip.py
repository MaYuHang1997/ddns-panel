"""
WAN IP observation - zero third-party dependencies.

Design notes
------------
IPv4: this host sits behind two layers of NAT, so the only way to learn the
      public address is to ask an external observer. We query several
      independent endpoints and take a majority vote, because a single
      observer can be wrong (or poisoned by a local proxy).

IPv6: no NAT, and the /64 prefix is delegated all the way to this host. We
      ask the kernel which source address it would use for a global
      destination, then keep ONLY the /64 prefix.

      Keeping just the prefix is the whole trick: Windows privacy extensions
      rotate the low 64 bits every few hours, but every one of those
      addresses (stable, temporary, DHCPv6) shares the SAME /64 prefix.
      Any suffix inside that prefix is routed to this LAN, so we are free to
      pick our own stable suffix instead of chasing a moving target.

Proxy handling: every request explicitly disables proxies. This machine runs
      an HTTP proxy (WorkBuddy's 127.0.0.1:50144 among others); leaving it
      enabled would make the observer report the proxy's egress IP, and we
      would then write a wrong address into DNS. This was verified to be a
      real failure mode earlier in this session.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import urllib.request
from typing import Iterable

__all__ = [
    "get_ipv6_prefixes",
    "get_ipv6_candidates",
    "get_ipv4_wan",
    "PRETTY_SUFFIX",
]

# Default suffix we append to a /64 prefix to build the AAAA record.
PRETTY_SUFFIX = "::1"

# Independent external observers used for the IPv4 majority vote.
IPV4_SOURCES: tuple[str, ...] = (
    "https://api-ipv4.ip.sb/ip",
    "https://ipv4.icanhazip.com",
    "http://whatismyip.akamai.com/",
    "https://4.ident.me",
)

# Address used purely to make the kernel pick a source address.
# 2400:3200::1 is AliDNS; nothing is actually sent.
_IPV6_PROBE_TARGET = ("2400:3200::1", 53)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _no_proxy_get(url: str, timeout: float = 8.0) -> str:
    """HTTP GET that never uses a proxy."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "curl/8.4.0", "Accept": "*/*"}
    )
    with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _is_temporary(suffix_origin: Any) -> bool:
    """Is this an RFC 4941 privacy (temporary) address?

    ``SuffixOrigin`` comes back as a numeric enum (5 == Random) through
    ConvertTo-Json, but as the literal string "Random" in Format-Table
    output. Both forms must be recognised, otherwise a rotating privacy
    address would be mistaken for a stable one and written into DNS.
    """
    if isinstance(suffix_origin, bool):
        return False
    if isinstance(suffix_origin, int):
        return suffix_origin == 5
    return str(suffix_origin).strip().lower() == "random"


def get_ipv6_candidates() -> list[dict[str, object]]:
    """Enumerate global unicast IPv6 addresses on this host.

    Returns a list of dicts with keys: address, prefix, is_temporary,
    source. ``is_temporary`` is True for RFC 4941 privacy addresses,
    which must never be written into DNS.
    """
    found: list[dict[str, object]] = []

    # ---- Windows: PowerShell gives us the richest metadata -------------
    try:
        ps = (
            "Get-NetIPAddress -AddressFamily IPv6 | "
            "Where-Object { $_.IPAddress -notmatch '^(fe80|::1)' } | "
            "Select-Object IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin | "
            "ConvertTo-Json -Compress"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=25,
        )
        if out.returncode == 0 and out.stdout.strip():
            data = json.loads(out.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                addr = str(item.get("IPAddress", "")).split("%")[0]
                try:
                    ip = ipaddress.IPv6Address(addr)
                except ValueError:
                    continue
                if not ip.is_global:
                    continue
                suffix_origin = item.get("SuffixOrigin", "")
                try:
                    plen = int(item.get("PrefixLength") or 128)
                except (TypeError, ValueError):
                    plen = 128
                # Any global address yields the delegated /64, whether it is
                # a stable EUI-64 address, a privacy address or DHCPv6.
                # Do not filter on plen here: privacy/DHCPv6 addresses are
                # /128 and would be dropped, hiding them from the panel.
                net = ipaddress.IPv6Network((addr, 64), strict=False)
                found.append({
                    "address": addr,
                    "prefix": str(net),
                    "is_temporary": _is_temporary(suffix_origin),
                    "source": "powershell",
                    "prefix_length": plen,
                    "prefix_origin": str(item.get("PrefixOrigin", "")),
                    "suffix_origin": str(suffix_origin),
                })
    except Exception:  # noqa: BLE001
        pass

    # ---- Linux / container: /proc/net/if_inet6 -------------------------
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 6:
                    continue
                hexaddr, _idx, plen = parts[0], parts[1], int(parts[2], 16)
                addr = ":".join(
                    hexaddr[i:i + 4].lstrip("0") or "0"
                    for i in range(0, 32, 4)
                )
                try:
                    ip = ipaddress.IPv6Address(addr)
                except ValueError:
                    continue
                if not ip.is_global:
                    continue
                net = ipaddress.IPv6Network((addr, 64), strict=False)
                found.append({
                    "address": addr,
                    "prefix": str(net),
                    "is_temporary": False,  # /proc does not expose the flag
                    "source": "procfs",
                    "prefix_origin": "",
                    "suffix_origin": "",
                })
    except OSError:
        pass

    return found


def get_ipv6_prefixes() -> list[str]:
    """Return the distinct /64 prefixes usable for AAAA records.

    Only global unicast addresses are considered; prefixes derived from
    privacy/temporary addresses are still usable because the prefix itself
    is what gets delegated.
    """
    prefixes: list[str] = []
    for item in get_ipv6_candidates():
        p = str(item["prefix"])
        if p not in prefixes:
            prefixes.append(p)
    return prefixes


def get_ipv4_wan(
    sources: Iterable[str] = IPV4_SOURCES,
    timeout: float = 8.0,
    min_agree: int = 2,
) -> str | None:
    """Determine the public IPv4 address by majority vote.

    Args:
        sources: External observer URLs.
        timeout: Per-request timeout in seconds.
        min_agree: How many observers must agree before we trust the result.

    Returns:
        The agreed IPv4 address, or None if no consensus was reached.
    """
    votes: dict[str, int] = {}
    raw: list[tuple[str, str]] = []

    for url in sources:
        try:
            body = _no_proxy_get(url, timeout=timeout)
        except Exception:  # noqa: BLE001
            continue
        match = _IPV4_RE.search(body)
        if not match:
            continue
        ip = match.group(0)
        raw.append((url, ip))
        votes[ip] = votes.get(ip, 0) + 1

    if not votes:
        return None

    best_ip, best_count = max(votes.items(), key=lambda kv: kv[1])
    if best_count < min_agree:
        return None
    return best_ip


def get_ipv4_wan_detailed(
    sources: Iterable[str] = IPV4_SOURCES,
    timeout: float = 8.0,
) -> list[tuple[str, str]]:
    """Return each observer's raw answer, for diagnostics."""
    results: list[tuple[str, str]] = []
    for url in sources:
        try:
            body = _no_proxy_get(url, timeout=timeout).strip()
        except Exception as exc:  # noqa: BLE001
            results.append((url, f"ERROR {type(exc).__name__}"))
            continue
        match = _IPV4_RE.search(body)
        results.append((url, match.group(0) if match else f"NO-MATCH: {body[:40]}"))
    return results


def build_aaaa(prefix: str, suffix: str = PRETTY_SUFFIX) -> str | None:
    """Combine a /64 prefix with a suffix into a full AAAA address.

    The delegated prefix is the stable part; the suffix is ours to choose,
    which sidesteps RFC 4941 privacy-address rotation entirely.
    """
    try:
        net = ipaddress.IPv6Network(prefix, strict=True)
        if net.prefixlen != 64:
            return None
        tail = int(ipaddress.IPv6Address(suffix)) & 0xFFFFFFFFFFFFFFFF
        return str(ipaddress.IPv6Address(int(net.network_address) | tail))
    except Exception:  # noqa: BLE001
        return None
