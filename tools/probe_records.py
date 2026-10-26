"""
Probe the live AliDNS record state using only our own signed client.

Reads AliDDNS's existing config, then walks the API surface we would need
for a management panel. All secrets are masked in output.
"""
from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from alidns import AliDnsClient, AliDnsError  # noqa: E402
from verify import CONFIG, decrypt, mask  # noqa: E402


def main() -> int:
    tree = ET.parse(CONFIG)
    cfg = {e.get("key"): (e.get("value") or "") for e in tree.getroot().iter("add")}

    ak_id = decrypt(cfg["AccessKeyID"])
    ak_sec = decrypt(cfg["AccessKeySecret"])
    record_id = cfg.get("RecordID", "")
    full = cfg.get("fullDomainName", "")

    print(f"known RecordID from AliDDNS config : {mask(record_id)}")
    print(f"fullDomainName                     : {mask(full)}")
    print()

    cli = AliDnsClient(ak_id, ak_sec)

    # 1) What record does the existing RecordID point at?
    print("=== DescribeDomainRecordInfo (current DNS value) ===")
    try:
        info = cli.record_info(record_id)
        for k in ("RecordId", "RR", "Type", "Value", "TTL", "Status", "Line", "Locked"):
            v = info.get(k)
            print(f"  {k:10} {mask(str(v)) if k in ('RecordId',) else v}")
    except AliDnsError as exc:
        print(f"  FAILED {exc.code}: {exc.message}")

    # 2) Full record list for the domain
    print()
    print("=== DescribeDomainRecords (all records) ===")
    try:
        res = cli.list_records("example.com")
        recs = res.get("DomainRecords", {}).get("Record", [])
        print(f"  total = {res.get('TotalCount')}  returned = {len(recs)}")
        for r in recs:
            print(
                f"    {str(r.get('RR')):10} {str(r.get('Type')):6} "
                f"{str(r.get('Value')):42} ttl={r.get('TTL')} "
                f"line={r.get('Line')} id={mask(str(r.get('RecordId')))}"
            )
    except AliDnsError as exc:
        print(f"  FAILED {exc.code}: {exc.message}")

    # 3) Subdomain lookup (the cheap polling call)
    print()
    print("=== DescribeSubDomainRecords (polling call, type filtered) ===")
    for rtype in ("A", "AAAA", None):
        label = rtype or "(all)"
        try:
            sub = cli.describe_subdomain("example.com", rtype)
            recs = sub.get("DomainRecords", {}).get("Record", [])
            print(f"  Type={label:8} total={sub.get('TotalCount')}")
            for r in recs:
                print(f"    {str(r.get('RR')):10} {str(r.get('Type')):6} "
                      f"{str(r.get('Value')):42} id={mask(str(r.get('RecordId')))}")
        except AliDnsError as exc:
            print(f"  Type={label:8} FAILED {exc.code}: {exc.message}")

    # 4) What can this key actually do? (permission probe)
    print()
    print("=== permission probe: can this key WRITE? ===")
    print("  (we do NOT actually modify anything; we call with a bogus")
    print("   RecordId and read the error code to infer permission)")
    try:
        cli.update_record("0000000000000000", "nonexistent-probe", "A", "127.0.0.1")
        print("  update returned 200 -> key has write permission")
    except AliDnsError as exc:
        print(f"  error code: {exc.code}")
        print(f"  message   : {exc.message}")
        if exc.code in ("Forbidden", "Forbidden.RAM", "NoPermission",
                        "Forbidden.User", "Unauthorized"):
            print("  => key is READ-ONLY for DNS (good safety property)")
        elif exc.code in ("InvalidRecordId.NotFound", "DomainRecordNotFound",
                          "InvalidRecordId", "RecordNotFound"):
            print("  => key has WRITE permission (rejected only on bad id)")
        else:
            print("  => inconclusive, inspect code above")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
