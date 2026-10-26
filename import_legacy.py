"""
One-shot migration: import an existing AliDDNS installation into this panel.

Reads D:\\AliDDNS_Release_v3.9.0.0_win\\aliddns_config.xml, decrypts the
AccessKey (AES-128-ECB with AliDDNS's hard-coded key), then registers the
account and the record it was guarding with the panel's own API.

Also creates the AAAA record that AliDDNS could never manage.

This script only writes to the panel's local database. It does NOT touch
AliDNS itself; run a dry-run sync afterwards to see what would change.

Usage:
    python import_legacy.py [--config PATH] [--api http://127.0.0.1:8300]
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

DEFAULT_CONFIG = r"D:\AliDDNS_Release_v3.9.0.0_win\aliddns_config.xml"
DEFAULT_API = "http://127.0.0.1:8300"
AES_KEY = b"[45/*YUIdse..e;]"

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def decrypt(b64_text: str) -> str:
    from Crypto.Cipher import AES

    raw = base64.b64decode(b64_text)
    out = AES.new(AES_KEY, AES.MODE_ECB).decrypt(raw)
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
    return out.decode("utf-8", errors="replace")


def api_call(base: str, method: str, path: str, payload: dict | None = None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=90) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"API {method} {path} -> HTTP {exc.code}: {detail[:300]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--api", default=DEFAULT_API)
    args = ap.parse_args()

    tree = ET.parse(args.config)
    cfg = {e.get("key"): (e.get("value") or "") for e in tree.getroot().iter("add")}

    full_domain = cfg.get("fullDomainName", "")   # e.g. "@.example.com"
    ttl = int(cfg.get("TTL") or 600)
    if "." not in full_domain:
        raise SystemExit(f"unexpected fullDomainName: {full_domain!r}")

    rr, domain = full_domain.split(".", 1)
    rr = rr or "@"

    ak_id = decrypt(cfg["AccessKeyID"])
    ak_secret = decrypt(cfg["AccessKeySecret"])

    print(f"legacy target : {rr}.{domain}  (ttl={ttl})")
    print(f"access key    : {ak_id[:3]}***{ak_id[-3:]}")

    # --- account (skip if an account with the same hint already exists) ----
    accounts = api_call(args.api, "GET", "/api/accounts") or []
    hint = ak_id[:3] + "*" * max(0, len(ak_id) - 6) + ak_id[-3:]
    existing = next((a for a in accounts if a["ak_id_hint"] == hint), None)
    if existing:
        account_id = existing["id"]
        print(f"account       : reusing #{account_id} ({existing['name']})")
    else:
        created = api_call(args.api, "POST", "/api/accounts", {
            "name": "主账号 (from AliDDNS)",
            "ak_id": ak_id,
            "ak_secret": ak_secret,
            "endpoint": "https://alidns.aliyuncs.com/",
        })
        account_id = created["id"]
        print(f"account       : created #{account_id}")

    # --- credentials sanity check (read-only) ------------------------------
    test = api_call(args.api, "POST", f"/api/accounts/{account_id}/test")
    if test and test.get("ok"):
        print(f"connectivity  : ok, domains = {test.get('domains')}")
    else:
        print(f"connectivity  : FAILED {test}")
        return 1

    # --- records: IPv4 (migrated) + IPv6 (new capability) ------------------
    records = api_call(args.api, "GET", "/api/records") or []
    have = {(r["account_id"], r["domain"], r["rr"], r["rtype"]) for r in records}

    wanted = [
        ("v4", "A", "IPv4 主记录（迁移自 AliDDNS）"),
        ("v6", "AAAA", "IPv6 前缀记录（新增能力）"),
    ]
    for source, rtype, label in wanted:
        if (account_id, domain, rr, rtype) in have:
            print(f"record        : {rtype} already present, skipped")
            continue
        res = api_call(args.api, "POST", "/api/records", {
            "account_id": account_id,
            "domain": domain,
            "rr": rr,
            "source": source,
            "ttl": ttl,
            "suffix": "::1",
        })
        print(f"record        : created {rtype} #{res['id']}  ({label})")

    print()
    print("done. nothing was written to AliDNS yet.")
    print(f"preview changes: curl -X POST '{args.api}/api/sync?dry_run=true'")
    print(f"apply changes  : curl -X POST '{args.api}/api/sync'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
