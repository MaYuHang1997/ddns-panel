"""
Background polling scheduler.

Why a thread and not a separate process
---------------------------------------
The panel is the only thing that owns the decrypted credentials, so polling
has to happen where the credentials live. A daemon thread inside the panel
process means: one scheduler per panel, no second copy of the key handling,
and no extra thing to install.

Behaviours
----------
*   **Backs off on failure.** Consecutive failures double the wait, capped at
    ``max_interval_seconds``. A single success resets it to the configured
    interval. A network outage therefore costs a handful of calls, not one
    every 5 minutes forever.
*   **Config is hot.** Changing the interval or pausing wakes the thread
    immediately instead of waiting out the old timer.
*   **Every unattended run is audited.** sync.py already writes to the
    ``changes`` table, so "why did my DNS change at 3am" is answerable from
    the panel's change log.
*   **Nothing is written on failure to observe.** If the observers disagree,
    sync.py refuses to push a guess; the scheduler just records the failure
    and backs off.
"""

from __future__ import annotations

import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_CORE = _HERE / "ddns_core"
if not _CORE.is_dir():
    _CORE = _HERE.parent / "ddns_core"
for p in (str(_HERE), str(_CORE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import store  # noqa: E402
import sync  # noqa: E402

K_ENABLED = "scheduler_enabled"
K_INTERVAL = "scheduler_interval_seconds"
K_MAX_INTERVAL = "scheduler_max_interval_seconds"
K_STARTUP_DELAY = "scheduler_startup_delay_seconds"

DEFAULT_INTERVAL = 300
DEFAULT_MAX_INTERVAL = 3600
DEFAULT_STARTUP_DELAY = 20
# Floor on the interval: this host's own outbound calls plus AliDNS rate
# limits make anything faster pointless, and a typo should not mean hammering
# the API 60 times a minute.
MIN_INTERVAL = 60

_lock = threading.RLock()
_wakeup = threading.Event()
_stop = threading.Event()
_thread: threading.Thread | None = None

_state: dict[str, Any] = {
    "running": False,
    "started_at": None,
    "last_run_at": None,
    "last_duration_ms": None,
    "last_summary": None,
    "last_error": None,
    "next_run_epoch": None,
    "consecutive_failures": 0,
    "effective_interval": DEFAULT_INTERVAL,
    "total_runs": 0,
    "total_changes": 0,
}


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def config() -> dict[str, Any]:
    """Current scheduler config, read from the settings table every time."""
    interval = max(MIN_INTERVAL, store.get_setting_int(K_INTERVAL, DEFAULT_INTERVAL))
    max_interval = max(interval, store.get_setting_int(K_MAX_INTERVAL, DEFAULT_MAX_INTERVAL))
    return {
        "enabled": store.get_setting_bool(K_ENABLED, True),
        "interval_seconds": interval,
        "max_interval_seconds": max_interval,
        "startup_delay_seconds": max(
            0, store.get_setting_int(K_STARTUP_DELAY, DEFAULT_STARTUP_DELAY)
        ),
    }


def set_config(
    enabled: bool | None = None,
    interval_seconds: int | None = None,
    max_interval_seconds: int | None = None,
) -> dict[str, Any]:
    """Persist config changes and wake the loop so they take effect at once."""
    if enabled is not None:
        store.set_setting(K_ENABLED, "1" if enabled else "0")
    if interval_seconds is not None:
        store.set_setting(K_INTERVAL, str(max(MIN_INTERVAL, int(interval_seconds))))
    if max_interval_seconds is not None:
        store.set_setting(K_MAX_INTERVAL, str(int(max_interval_seconds)))
    poke()
    return config()


# --------------------------------------------------------------------------- #
# One poll
# --------------------------------------------------------------------------- #
def run_once() -> dict[str, Any]:
    """Run a full poll right now and return a summary. Never raises."""
    t0 = time.time()
    try:
        results = sync.sync_all(dry_run=False)
    except Exception as exc:  # noqa: BLE001
        duration = int((time.time() - t0) * 1000)
        with _lock:
            _state["last_run_at"] = store.now_iso()
            _state["last_duration_ms"] = duration
            _state["last_error"] = f"{type(exc).__name__}: {exc}"
            _state["total_runs"] += 1
        store.log_change(
            None, "", "", "", "scheduler-error", None, None, False,
            f"{type(exc).__name__}: {exc}",
        )
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(limit=3),
            "duration_ms": duration,
        }

    duration = int((time.time() - t0) * 1000)
    changed = [r for r in results if r.get("action") in ("update", "add")]
    failed = [r for r in results if not r.get("ok")]
    summary = {
        "ok": not failed,
        "duration_ms": duration,
        "checked": len(results),
        "changed": len(changed),
        "failed": len(failed),
        "records": [
            {
                "record_id": r.get("record_id"),
                "label": r.get("label"),
                "action": r.get("action"),
                "old": r.get("old"),
                "new": r.get("new"),
                "ok": r.get("ok"),
                "message": r.get("message", ""),
            }
            for r in results
        ],
    }
    with _lock:
        _state["last_run_at"] = store.now_iso()
        _state["last_duration_ms"] = duration
        _state["last_summary"] = summary
        _state["last_error"] = None
        _state["total_runs"] += 1
        _state["total_changes"] += len(changed)
    return summary


def _tick() -> None:
    """One scheduled pass, plus the backoff bookkeeping."""
    cfg = config()
    if not cfg["enabled"]:
        with _lock:
            _state["next_run_epoch"] = None
        return

    summary = run_once()
    healthy = bool(summary.get("ok"))

    with _lock:
        if healthy:
            _state["consecutive_failures"] = 0
            _state["effective_interval"] = cfg["interval_seconds"]
        else:
            _state["consecutive_failures"] += 1
            failures = _state["consecutive_failures"]
            _state["effective_interval"] = min(
                cfg["max_interval_seconds"],
                cfg["interval_seconds"] * (2 ** min(failures, 6)),
            )


# --------------------------------------------------------------------------- #
# Loop
# --------------------------------------------------------------------------- #
def _loop() -> None:
    cfg = config()
    delay = cfg["startup_delay_seconds"]
    if delay:
        with _lock:
            _state["next_run_epoch"] = time.time() + delay
        _wakeup.wait(delay)
        _wakeup.clear()
        if _stop.is_set():
            return

    while not _stop.is_set():
        try:
            _tick()
        except Exception as exc:  # noqa: BLE001 - a scheduler must not die
            with _lock:
                _state["last_error"] = f"loop: {type(exc).__name__}: {exc}"

        with _lock:
            wait = int(_state.get("effective_interval") or DEFAULT_INTERVAL)
            _state["next_run_epoch"] = time.time() + wait

        # Sleep in slices so a config change or shutdown is picked up promptly.
        _wakeup.wait(wait)
        _wakeup.clear()


def poke() -> None:
    """Wake the loop early (used after config changes)."""
    _wakeup.set()


def start() -> None:
    """Start the scheduler thread. Idempotent."""
    global _thread
    with _lock:
        if _thread and _thread.is_alive():
            return
        _stop.clear()
        _wakeup.clear()
        _state["running"] = True
        _state["started_at"] = store.now_iso()
        _thread = threading.Thread(target=_loop, name="ddns-scheduler", daemon=True)
        _thread.start()


def stop() -> None:
    """Ask the loop to exit. It is a daemon thread, so this is best effort."""
    with _lock:
        _state["running"] = False
        _state["next_run_epoch"] = None
    _stop.set()
    _wakeup.set()


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #
def status() -> dict[str, Any]:
    """Everything the UI needs: config, last run, next run, failures."""
    cfg = config()
    with _lock:
        st = dict(_state)
    next_epoch = st.get("next_run_epoch")
    st["next_run_in_seconds"] = (
        max(0, int(next_epoch - time.time())) if next_epoch else None
    )
    st["next_run_epoch"] = next_epoch
    st.update(cfg)
    st["min_interval_seconds"] = MIN_INTERVAL
    return st
