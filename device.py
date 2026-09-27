"""Stable per-PC device identity for encryption provenance (offline, local only).

The first time it runs on a PC it mints a random stable id and persists it to
``data/device.json``. That id is recorded in the common encryption registry
every time a file is encrypted, so a later leak investigation can report
*which PC* encrypted the file and *when*.

No networking: hostname comes from ``platform.node()`` (no sockets).
"""
import os
import platform
import uuid

import store

DEVICE_FILE = os.path.join(store.DATA_DIR, "device.json")


def _hostname() -> str:
    try:
        name = platform.node() or ""
    except Exception:
        name = ""
    return name.strip()


def get_device(force_label: str | None = None) -> dict:
    """Return ``{pc_id, pc_label, hostname}``, minting and persisting pc_id once."""
    store.ensure_dirs()
    saved: dict = {}
    try:
        saved = store._load_json(DEVICE_FILE, {}) or {}
    except Exception:
        saved = {}
    if not isinstance(saved, dict):
        saved = {}
    pc_id = saved.get("pc_id")
    if not isinstance(pc_id, str) or len(pc_id) < 8:
        pc_id = f"PC-{uuid.uuid4().hex[:12].upper()}"
        saved["pc_id"] = pc_id
    hostname = _hostname()
    if hostname:
        saved["hostname"] = hostname
    if force_label is not None and isinstance(force_label, str) and force_label.strip():
        saved["pc_label"] = force_label.strip()[:64]
    saved.setdefault("pc_label", saved.get("hostname", ""))
    try:
        store._save_json(DEVICE_FILE, saved)
    except Exception:
        pass
    return {
        "pc_id": saved["pc_id"],
        "pc_label": saved.get("pc_label", ""),
        "hostname": saved.get("hostname", ""),
    }


def resolve_device(pc_id: str | None = None, pc_label: str | None = None) -> dict:
    """Device record for an encryption event.

    - ``pc_id``: caller-supplied id (e.g. another PC syncing to the common DB),
      otherwise this machine's stable id.
    - ``pc_label``: caller-supplied friendly name, otherwise stored label.
    """
    base = get_device()
    if isinstance(pc_id, str) and pc_id.strip():
        base["pc_id"] = pc_id.strip()[:64]
    if isinstance(pc_label, str) and pc_label.strip():
        base["pc_label"] = pc_label.strip()[:64]
        # Remember a friendly name set on this machine for next time.
        if pc_id is None or pc_id.strip() == "":
            try:
                saved = store._load_json(DEVICE_FILE, {}) or {}
                if isinstance(saved, dict):
                    saved["pc_label"] = base["pc_label"]
                    store._save_json(DEVICE_FILE, saved)
            except Exception:
                pass
    return base
