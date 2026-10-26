"""
DDNS control panel - FastAPI backend.

Binds to 127.0.0.1 by default. This panel can read and rewrite DNS records
for the whole account, so it is deliberately not exposed to the LAN or the
internet; reach it through SSH/RDP or a tunnel if you need remote access.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

_HERE = Path(__file__).resolve().parent
# Core modules live in ddns_core/ inside this repo; fall back to a sibling
# directory so the old layout (panel + ddns_core side by side) still works.
_CORE = _HERE / "ddns_core"
if not _CORE.is_dir():
    _CORE = _HERE.parent / "ddns_core"
for p in (str(_HERE), str(_CORE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import scheduler  # noqa: E402
import store  # noqa: E402
import sync  # noqa: E402
from alidns import AliDnsClient, AliDnsError  # noqa: E402

STATIC = _HERE / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    store.load_or_create_master_key()
    scheduler.start()
    try:
        yield
    finally:
        scheduler.stop()


app = FastAPI(title="DDNS Panel", version="0.1.0", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class AccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    ak_id: str = Field(min_length=8, max_length=128)
    ak_secret: str = Field(min_length=8, max_length=128)
    endpoint: str = "https://alidns.aliyuncs.com/"


class RecordIn(BaseModel):
    account_id: int
    domain: str = Field(min_length=3, max_length=253)
    rr: str = Field(default="@", max_length=253)
    source: str = Field(pattern="^(v4|v6)$")
    ttl: int = Field(default=600, ge=1, le=86400)
    suffix: str = "::1"


class EnabledIn(BaseModel):
    enabled: bool


class SchedulerConfigIn(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    max_interval_seconds: int | None = Field(default=None, ge=300, le=86400)


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "data_dir": str(store.DATA_DIR),
        "db": str(store.DB_PATH),
        "master_key_present": store.KEY_PATH.exists(),
    }


# --------------------------------------------------------------------------- #
# Observation (read-only preview)
# --------------------------------------------------------------------------- #
@app.get("/api/observe")
def observe() -> dict[str, Any]:
    return sync.observe_now()


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
@app.get("/api/accounts")
def list_accounts() -> list[dict[str, Any]]:
    return store.list_accounts()


@app.post("/api/accounts")
def create_account(payload: AccountIn) -> dict[str, Any]:
    aid = store.add_account(payload.name, payload.ak_id, payload.ak_secret,
                            payload.endpoint)
    return {"id": aid}


@app.delete("/api/accounts/{account_id}")
def delete_account(account_id: int) -> dict[str, Any]:
    store.delete_account(account_id)
    return {"deleted": account_id}


@app.post("/api/accounts/{account_id}/test")
def test_account(account_id: int) -> dict[str, Any]:
    """Verify the stored credentials by listing domains."""
    try:
        ak_id, ak_secret, endpoint = store.get_account_credentials(account_id)
    except KeyError:
        raise HTTPException(404, "account not found")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"cannot decrypt credentials: {exc}")
    try:
        cli = AliDnsClient(ak_id, ak_secret, endpoint=endpoint)
        res = cli.list_domains()
        domains = [str(d.get("DomainName", "")).strip()
                   for d in res.get("Domains", {}).get("Domain", [])]
        return {"ok": True, "total": res.get("TotalCount"), "domains": domains}
    except AliDnsError as exc:
        return {"ok": False, "code": exc.code, "message": exc.message}


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
@app.get("/api/records")
def list_records() -> list[dict[str, Any]]:
    return store.list_records()


@app.post("/api/records")
def create_record(payload: RecordIn) -> dict[str, Any]:
    rtype = "A" if payload.source == "v4" else "AAAA"
    try:
        rid = store.add_record(
            payload.account_id, payload.domain, payload.rr, rtype,
            payload.source, payload.ttl, payload.suffix,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"cannot create record: {exc}")
    return {"id": rid, "rtype": rtype}


@app.patch("/api/records/{record_id}/enabled")
def set_enabled(record_id: int, payload: EnabledIn) -> dict[str, Any]:
    if not store.get_record(record_id):
        raise HTTPException(404, "record not found")
    store.set_record_enabled(record_id, payload.enabled)
    return {"id": record_id, "enabled": payload.enabled}


@app.delete("/api/records/{record_id}")
def delete_record(record_id: int) -> dict[str, Any]:
    store.delete_record(record_id)
    return {"deleted": record_id}


@app.post("/api/records/{record_id}/sync")
def sync_one(record_id: int, dry_run: bool = False) -> dict[str, Any]:
    rec = store.get_record(record_id)
    if not rec:
        raise HTTPException(404, "record not found")
    return sync.sync_record(rec, dry_run=dry_run)


@app.post("/api/sync")
def sync_everything(dry_run: bool = False) -> dict[str, Any]:
    results = sync.sync_all(dry_run=dry_run)
    return {
        "dry_run": dry_run,
        "count": len(results),
        "changed": sum(1 for r in results if r["action"] in ("update", "add")),
        "failed": sum(1 for r in results if not r["ok"]),
        "results": results,
    }


# --------------------------------------------------------------------------- #
# Scheduler
# --------------------------------------------------------------------------- #
@app.get("/api/scheduler")
def scheduler_status() -> dict[str, Any]:
    """Config plus live state: last run, next run, failure backoff."""
    return scheduler.status()


@app.post("/api/scheduler/config")
def scheduler_config(payload: SchedulerConfigIn) -> dict[str, Any]:
    if (
        payload.enabled is None
        and payload.interval_seconds is None
        and payload.max_interval_seconds is None
    ):
        raise HTTPException(400, "nothing to change")
    return scheduler.set_config(
        enabled=payload.enabled,
        interval_seconds=payload.interval_seconds,
        max_interval_seconds=payload.max_interval_seconds,
    )


@app.post("/api/scheduler/run")
def scheduler_run() -> dict[str, Any]:
    """Poll immediately, outside the schedule. Recording rules identical."""
    return scheduler.run_once()


# --------------------------------------------------------------------------- #
# Change log
# --------------------------------------------------------------------------- #
@app.get("/api/changes")
def list_changes(limit: int = 100) -> list[dict[str, Any]]:
    return store.list_changes(limit=min(max(limit, 1), 500))
