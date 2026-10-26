"""
Delete a live DNS record at Aliyun, outside the panel.

Why this exists
---------------
The panel's delete button only removes a row from the local SQLite database;
it never touches Aliyun. That is deliberate (a panel bug should not be able
to destroy records you manage by hand), but it means cleaning up a record the
panel itself created needs an explicit one-off tool.

Default is a dry run: it prints what it would delete. Pass --apply to do it.

Usage
-----
    python tools/delete_remote_record.py --domain olbaid.asia --type AAAA
    python tools/delete_remote_record.py --domain olbaid.asia --type AAAA --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
for p in (str(_HERE), str(_HERE / "ddns_core")):
    if p not in sys.path:
        sys.path.insert(0, p)

import store  # noqa: E402
from alidns import AliDnsClient, AliDnsError  # noqa: E402


def subdomain_of(domain: str, rr: str) -> str:
    """Aliyun wants the full name, with '@' for the apex."""
    return domain if rr in ("@", "") else f"{rr}.{domain}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--rr", default="@")
    ap.add_argument("--type", dest="rtype", default="AAAA")
    ap.add_argument("--account", type=int, default=1)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    try:
        ak_id, ak_secret, endpoint = store.get_account_credentials(args.account)
    except KeyError:
        print(f"no account #{args.account} in {store.DB_PATH}")
        return 1

    cli = AliDnsClient(ak_id, ak_secret, endpoint=endpoint)
    name = subdomain_of(args.domain, args.rr)
    print(f"target : {name}  {args.rtype}")
    print(f"account: #{args.account}  ({ak_id[:4]}...)")

    try:
        res = cli.describe_subdomain(name, args.rtype)
    except AliDnsError as exc:
        print(f"query failed: {exc.code}: {exc.message}")
        return 1

    records = res.get("DomainRecords", {}).get("Record", []) or []
    if not records:
        print("no matching record on the live zone - nothing to do")
        return 0

    for rec in records:
        rid = str(rec.get("RecordId", ""))
        print(
            f"  found  RecordId={rid}  {rec.get('RR')}.{rec.get('DomainName')}"
            f"  {rec.get('Type')}  {rec.get('Value')}  ttl={rec.get('TTL')}"
        )
        if not args.apply:
            print("    (dry run, pass --apply to delete)")
            continue
        try:
            cli.delete_record(rid)
            print(f"    DELETED {rid}")
            store.log_change(
                None, args.domain, args.rr, args.rtype, "delete-remote",
                rec.get("Value"), None, True, "removed via delete_remote_record.py",
            )
        except AliDnsError as exc:
            print(f"    FAILED  {exc.code}: {exc.message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
