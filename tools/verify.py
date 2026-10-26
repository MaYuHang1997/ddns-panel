"""
Verify the self-implemented AliDNS client end-to-end.

Steps:
  1. Read AliDDNS's aliddns_config.xml
  2. Decrypt AccessKeyID / AccessKeySecret with the hard-coded AES key
     (AES-128-ECB / PKCS7, key = "[45/*YUIdse..e;]")
  3. Call DescribeDomains (read-only) using our own V2 signature
  4. Print the result with secrets masked

Run with the uv interpreter that has pycryptodome:
  C:/Users/myh/AppData/Roaming/uv/python/cpython-3.12.14-windows-x86_64-none/python.exe verify.py
"""
from __future__ import annotations

import base64
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from alidns import AliDnsClient, AliDnsError, ENDPOINT_PUBLIC, ENDPOINT_CN_HANGZHOU  # noqa: E402

CONFIG = r"D:\AliDDNS_Release_v3.9.0.0_win\aliddns_config.xml"
AES_KEY = b"[45/*YUIdse..e;]"


def decrypt(b64: str) -> str:
    """AES-128-ECB decrypt, matching EncryptHelper.AESDecrypt."""
    from Crypto.Cipher import AES

    raw = base64.b64decode(b64)
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    out = cipher.decrypt(raw)
    # PKCS7 unpad
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
    return out.decode("utf-8", errors="replace")


def mask(s: str) -> str:
    if len(s) <= 6:
        return "*" * len(s)
    return s[:3] + "*" * (len(s) - 6) + s[-3:]


def main() -> int:
    tree = ET.parse(CONFIG)
    cfg = {e.get("key"): (e.get("value") or "") for e in tree.getroot().iter("add")}

    print("=== config fields ===")
    for k in ("AccessKeyID", "AccessKeySecret", "fullDomainName", "RecordID", "TTL", "WaitingTime"):
        print(f"  {k:18} {mask(cfg.get(k, ''))}")

    ak_id = decrypt(cfg["AccessKeyID"])
    ak_sec = decrypt(cfg["AccessKeySecret"])
    print()
    print(f"decrypted AccessKeyID     len={len(ak_id)}  {mask(ak_id)}")
    print(f"decrypted AccessKeySecret len={len(ak_sec)} {mask(ak_sec)}")

    print()
    print("=== signing test: V2 (HMAC-SHA1) against DescribeDomains ===")
    for ep_name, ep in (("alidns.aliyuncs.com", ENDPOINT_PUBLIC),
                        ("alidns.cn-hangzhou.aliyuncs.com", ENDPOINT_CN_HANGZHOU)):
        print(f"--- endpoint: {ep_name} ---")
        cli = AliDnsClient(ak_id, ak_sec, endpoint=ep)
        try:
            res = cli.list_domains()
            total = res.get("TotalCount")
            print(f"  SUCCESS  total domains = {total}   requestId = {res.get('RequestId')}")
            doms = res.get("Domains", {}).get("Domain", [])
            for d in doms[:10]:
                print(f"    - {str(d.get('DomainName','')).strip():24} records={d.get('RecordCount')} "
                      f"version={d.get('VersionName')} aliDomain={d.get('AliDomain')}")
        except AliDnsError as exc:
            print(f"  V2 FAILED   {exc.code}: {exc.message}")
        except Exception as exc:  # noqa: BLE001
            print(f"  V2 ERROR    {type(exc).__name__}: {exc}")

        try:
            res3 = cli.call_v3("DescribeDomains", PageNumber=1, PageSize=100)
            print(f"  V3 SUCCESS  total={res3.get('TotalCount')} "
                  f"requestId={res3.get('RequestId')}")
        except AliDnsError as exc:
            print(f"  V3 FAILED   {exc.code}: {exc.message}")
        except Exception as exc:  # noqa: BLE001
            print(f"  V3 ERROR    {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
