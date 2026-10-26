"""
Record synchronisation: observe the real IP, compare with DNS, write if needed.

Design rules
------------
1. Read before write. We always ask AliDNS for the current value first, so a
   sync is idempotent: running it twice in a row produces exactly one change.
2. Never write an unverified address. If IPv4 observers disagree, or no IPv6
   prefix can be found, we abort instead of pushing a guess.
3. Only touch the record we manage. The lookup is filtered by RR and type so
   sibling records on the same name are left alone.
4. Every attempt is logged, including no-ops and failures, because "why did
   my DNS change at 3am" needs an answer.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Reuse the verified, dependency-free core built earlier.
_HERE = Path(__file__).resolve().parent
_CORE = _HERE / "ddns_core"
if not _CORE.is_dir():
    _CORE = _HERE.parent / "ddns_core"
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import store  # noqa: E402
import wanip  # noqa: E402
from alidns import AliDnsClient, AliDnsError  # noqa: E402


class SyncError(RuntimeError):
    """Raised when we cannot determine a trustworthy desired value."""


def subdomain_of(domain: str, rr: str) -> str:
    """AliDNS wants the fully-qualified name; '@' means the apex."""
    return domain if rr in ("@", "") else f"{rr}.{domain}"


def observe_desired(rec: dict[str, Any]) -> tuple[str, str]:
    """Return ``(desired_value, record_type)`` for this record.

    Raises:
        SyncError: if the observation is not trustworthy.
    """
    if rec["source"] == "v4":
        value = wanip.get_ipv4_wan()
        if not value:
            raise SyncError(
                "IPv4 observers did not reach consensus; refusing to write a guess"
            )
        return value, "A"

    prefixes = wanip.get_ipv6_prefixes()
    if not prefixes:
        raise SyncError(
            "no global IPv6 /64 prefix found on this host "
            "(is IPv6 up? does the adapter have a delegated prefix?)"
        )
    # Prefer the first prefix; the delegated /64 is the stable part, the
    # suffix is ours to choose so privacy-address rotation cannot break us.
    value = wanip.build_aaaa(prefixes[0], rec.get("suffix") or "::1")
    if not value:
        raise SyncError(f"could not build AAAA from prefix {prefixes[0]}")
    return value, "AAAA"


def sync_record(rec: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """Bring one record in line with reality.

    Args:
        rec: A row from ``store.list_records()``.
        dry_run: When True, report what would happen without calling the API.

    Returns:
        A dict with keys: ok, action, old, new, message.
    """
    record_id = rec["id"]
    domain, rr = rec["domain"], rec["rr"]
    label = f"{rr}.{domain}" if rr not in ("@", "") else domain

    try:
        desired, rtype = observe_desired(rec)
    except SyncError as exc:
        store.log_change(record_id, domain, rr, rec["rtype"], "error", None, None,
                         False, str(exc))
        return {"ok": False, "action": "error", "old": None, "new": None,
                "message": str(exc)}

    try:
        ak_id, ak_secret, endpoint = store.get_account_credentials(rec["account_id"])
    except KeyError as exc:
        msg = f"credentials unavailable: {exc}"
        store.log_change(record_id, domain, rr, rtype, "error", None, desired, False, msg)
        return {"ok": False, "action": "error", "old": None, "new": desired, "message": msg}

    cli = AliDnsClient(ak_id, ak_secret, endpoint=endpoint)

    # --- read current state -------------------------------------------------
    try:
        res = cli.describe_subdomain(subdomain_of(domain, rr), rtype)
        existing = [
            r for r in res.get("DomainRecords", {}).get("Record", [])
            if str(r.get("RR", "")) == rr and str(r.get("Type", "")) == rtype
        ]
    except AliDnsError as exc:
        msg = f"query failed: {exc.code}: {exc.message}"
        store.log_change(record_id, domain, rr, rtype, "error", None, desired, False, msg)
        return {"ok": False, "action": "error", "old": None, "new": desired, "message": msg}

    current = str(existing[0]["Value"]) if existing else None

    # --- decide -------------------------------------------------------------
    if current == desired:
        store.update_record_state(record_id, last_value=current, checked=True)
        store.log_change(record_id, domain, rr, rtype, "noop", current, desired, True,
                         "already up to date")
        return {"ok": True, "action": "noop", "old": current, "new": desired,
                "message": "already up to date"}

    if dry_run:
        action = "would-update" if existing else "would-add"
        return {"ok": True, "action": action, "old": current, "new": desired,
                "message": f"{label} {rtype}: {current} -> {desired}"}

    # --- write --------------------------------------------------------------
    try:
        if existing:
            cli.update_record(str(existing[0]["RecordId"]), rr, rtype, desired,
                              int(rec.get("ttl") or 600))
            action = "update"
        else:
            cli.add_record(domain, rr, rtype, desired, int(rec.get("ttl") or 600))
            action = "add"
    except AliDnsError as exc:
        msg = f"write failed: {exc.code}: {exc.message}"
        store.update_record_state(record_id, checked=True)
        store.log_change(record_id, domain, rr, rtype, "error", current, desired, False, msg)
        return {"ok": False, "action": "error", "old": current, "new": desired, "message": msg}

    store.update_record_state(record_id, last_value=desired, checked=True, changed=True)
    store.log_change(record_id, domain, rr, rtype, action, current, desired, True,
                     f"{label} {rtype} set to {desired}")
    return {"ok": True, "action": action, "old": current, "new": desired,
            "message": f"{label} {rtype}: {current} -> {desired}"}


def sync_all(dry_run: bool = False) -> list[dict[str, Any]]:
    """Sync every enabled record. Returns one result dict per record."""
    results: list[dict[str, Any]] = []
    for rec in store.list_records():
        if not rec.get("enabled"):
            continue
        res = sync_record(rec, dry_run=dry_run)
        res["record_id"] = rec["id"]
        res["label"] = (
            rec["domain"] if rec["rr"] in ("@", "") else f"{rec['rr']}.{rec['domain']}"
        )
        results.append(res)
    return results


def observe_now() -> dict[str, Any]:
    """Report what the observer sees right now, without touching DNS."""
    v4 = wanip.get_ipv4_wan()
    v4_detail = wanip.get_ipv4_wan_detailed()
    prefixes = wanip.get_ipv6_prefixes()
    candidates = wanip.get_ipv6_candidates()
    return {
        "ipv4": v4,
        "ipv4_observers": [{"url": u, "answer": a} for u, a in v4_detail],
        "ipv6_prefixes": prefixes,
        "ipv6_aaaa_example": wanip.build_aaaa(prefixes[0]) if prefixes else None,
        "ipv6_addresses": [
            {
                "address": c["address"],
                "is_temporary": c["is_temporary"],
                "suffix_origin": c["suffix_origin"],
            }
            for c in candidates
        ],
    }
