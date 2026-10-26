"""
Persistence layer: SQLite + AES-256-GCM secret encryption.

Why this exists
---------------
The original AliDDNS stores the AccessKey with a hard-coded AES key compiled
into the binary, so anyone holding the config file can recover the secret.
This module fixes that properly:

  * A random 32-byte master key is generated once into ``master.key`` and
    never leaves the machine.
  * Each secret is encrypted with AES-256-GCM under a fresh 12-byte nonce.
  * The GCM tag makes tampering detectable instead of silently decrypting
    to garbage.

The master key file is the single thing worth protecting. Back it up: if it
is lost, stored secrets become unrecoverable (they are not derivable).
"""

from __future__ import annotations

import base64
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

DATA_DIR = Path(os.environ.get("DDNS_DATA_DIR", r"D:\ddns-panel-data"))
DB_PATH = DATA_DIR / "ddns.db"
KEY_PATH = DATA_DIR / "master.key"

_KEY_BYTES = 32
_NONCE_BYTES = 12


# --------------------------------------------------------------------------- #
# Master key handling
# --------------------------------------------------------------------------- #
def load_or_create_master_key() -> bytes:
    """Load the 32-byte master key, generating it on first run."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        raw = KEY_PATH.read_bytes()
        if len(raw) != _KEY_BYTES:
            raise RuntimeError(
                f"{KEY_PATH} exists but is {len(raw)} bytes, expected {_KEY_BYTES}. "
                "Refusing to continue: overwriting it would make every stored "
                "secret permanently unrecoverable."
            )
        return raw

    key = get_random_bytes(_KEY_BYTES)
    KEY_PATH.write_bytes(key)
    # Best effort on Windows: restrict to the current user via icacls.
    # Failure here is not fatal, only a hardening step.
    try:
        import subprocess

        user = os.environ.get("USERNAME", "")
        if user:
            subprocess.run(
                ["icacls", str(KEY_PATH), "/inheritance:r",
                 "/grant:r", f"{user}:F"],
                capture_output=True, timeout=15,
            )
    except Exception:  # noqa: BLE001
        pass
    return key


def encrypt(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encrypt, returned as base64(nonce || tag || ciphertext)."""
    nonce = get_random_bytes(_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return base64.b64encode(nonce + tag + ct).decode("ascii")


def decrypt(blob: str, key: bytes) -> str:
    """Reverse of :func:`encrypt`. Raises ValueError if the tag fails."""
    raw = base64.b64decode(blob)
    nonce, tag, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:_NONCE_BYTES + 16], raw[_NONCE_BYTES + 16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode("utf-8")


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    ak_id_enc     TEXT    NOT NULL,
    ak_secret_enc TEXT    NOT NULL,
    endpoint      TEXT    NOT NULL DEFAULT 'https://alidns.aliyuncs.com/',
    ak_id_hint    TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain         TEXT    NOT NULL,
    rr             TEXT    NOT NULL,
    rtype          TEXT    NOT NULL,
    source         TEXT    NOT NULL,
    ttl            INTEGER NOT NULL DEFAULT 600,
    suffix         TEXT    NOT NULL DEFAULT '::1',
    enabled        INTEGER NOT NULL DEFAULT 1,
    last_value     TEXT,
    last_check_at  TEXT,
    last_change_at TEXT,
    UNIQUE(account_id, domain, rr, rtype)
);

CREATE TABLE IF NOT EXISTS changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id  INTEGER,
    domain     TEXT NOT NULL DEFAULT '',
    rr         TEXT NOT NULL DEFAULT '',
    rtype      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    ok         INTEGER NOT NULL DEFAULT 0,
    message    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_changes_created ON changes(created_at DESC);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(_SCHEMA)


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
def add_account(name: str, ak_id: str, ak_secret: str, endpoint: str) -> int:
    key = load_or_create_master_key()
    hint = ak_id[:3] + "*" * max(0, len(ak_id) - 6) + ak_id[-3:] if len(ak_id) > 6 else "***"
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO accounts (name, ak_id_enc, ak_secret_enc, endpoint, ak_id_hint, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (name, encrypt(ak_id, key), encrypt(ak_secret, key), endpoint, hint, now_iso()),
        )
        return int(cur.lastrowid)


def list_accounts() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, name, endpoint, ak_id_hint, created_at FROM accounts ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


def get_account_credentials(account_id: int) -> tuple[str, str, str]:
    """Return ``(access_key_id, access_key_secret, endpoint)`` decrypted."""
    key = load_or_create_master_key()
    with connect() as conn:
        row = conn.execute(
            "SELECT ak_id_enc, ak_secret_enc, endpoint FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
    if row is None:
        raise KeyError(f"account {account_id} not found")
    return decrypt(row["ak_id_enc"], key), decrypt(row["ak_secret_enc"], key), row["endpoint"]


def delete_account(account_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
def add_record(
    account_id: int,
    domain: str,
    rr: str,
    rtype: str,
    source: str,
    ttl: int = 600,
    suffix: str = "::1",
) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO records (account_id, domain, rr, rtype, source, ttl, suffix, enabled)"
            " VALUES (?,?,?,?,?,?,?,1)",
            (account_id, domain, rr, rtype, source, ttl, suffix),
        )
        return int(cur.lastrowid)


def list_records() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT r.*, a.name AS account_name FROM records r"
            " JOIN accounts a ON a.id = r.account_id ORDER BY r.id"
        ).fetchall()
        return [dict(r) for r in rows]


def get_record(record_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row) if row else None


def update_record_state(
    record_id: int,
    last_value: str | None = None,
    checked: bool = False,
    changed: bool = False,
) -> None:
    fields: list[str] = []
    params: list[Any] = []
    if last_value is not None:
        fields.append("last_value=?")
        params.append(last_value)
    if checked:
        fields.append("last_check_at=?")
        params.append(now_iso())
    if changed:
        fields.append("last_change_at=?")
        params.append(now_iso())
    if not fields:
        return
    params.append(record_id)
    with connect() as conn:
        conn.execute(f"UPDATE records SET {', '.join(fields)} WHERE id=?", params)


def set_record_enabled(record_id: int, enabled: bool) -> None:
    with connect() as conn:
        conn.execute("UPDATE records SET enabled=? WHERE id=?", (1 if enabled else 0, record_id))


def delete_record(record_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM records WHERE id=?", (record_id,))


# --------------------------------------------------------------------------- #
# Change log
# --------------------------------------------------------------------------- #
def log_change(
    record_id: int | None,
    domain: str,
    rr: str,
    rtype: str,
    action: str,
    old_value: str | None,
    new_value: str | None,
    ok: bool,
    message: str = "",
) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO changes (record_id, domain, rr, rtype, action, old_value,"
            " new_value, ok, message, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (record_id, domain, rr, rtype, action, old_value, new_value,
             1 if ok else 0, message[:500], now_iso()),
        )


def list_changes(limit: int = 100) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
