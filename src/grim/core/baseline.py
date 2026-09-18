"""Persistent scan baselines for drift detection (`watch`).

A baseline is the file manifest (path -> {size, hash}) of a target at a point in time,
stored outside the scanned tree. Comparing a later scan to a baseline is the highest-signal
"is this system compromised right now?" check.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

BASELINE_VERSION = 1
CACHE_DIR = Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim")) / "baselines"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_path(target: str) -> Path:
    resolved = str(Path(target).resolve())
    digest = hashlib.sha256(resolved.encode()).hexdigest()[:16]
    slug = Path(resolved).name or "root"
    return CACHE_DIR / f"{slug}-{digest}.json"


def save(
    target: str,
    manifest: dict,
    root: str | None,
    deep: bool = False,
    path: str | os.PathLike | None = None,
) -> Path:
    p = Path(path) if path else default_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": BASELINE_VERSION,
        "target": str(Path(target).resolve()),
        "created": _now(),
        "deep": deep,
        "root": root,
        "entries": len(manifest),
        "manifest": manifest,
    }
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, p)
    return p


def load(path: str | os.PathLike | None, target: str = "") -> dict:
    p = Path(path) if path else default_path(target or ".")
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def describe(baseline: dict) -> dict:
    if not baseline:
        return {"exists": False}
    return {
        "exists": True,
        "target": baseline.get("target"),
        "created": baseline.get("created"),
        "deep": baseline.get("deep", False),
        "root": baseline.get("root"),
        "entries": baseline.get("entries", len(baseline.get("manifest") or {})),
    }
