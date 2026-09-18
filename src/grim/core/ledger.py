"""Persistent findings ledger.

Tracks every finding across audits so GRIM can answer the questions that matter over
time: what is new, what is still open, what was fixed. Stored as JSON outside the
scanned tree (so scanning stays read-only). No dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .findings import Finding, SEVERITY_ORDER

LEDGER_VERSION = 1
CACHE_DIR = Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim")) / "ledgers"

OPEN = "open"
ACK = "acknowledged"
RESOLVED = "resolved"
VALID_STATUS = {OPEN, ACK, RESOLVED}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_path(target: str) -> Path:
    """Deterministic ledger path for a target, outside the scanned tree."""
    resolved = str(Path(target).resolve())
    digest = hashlib.sha256(resolved.encode()).hexdigest()[:16]
    slug = Path(resolved).name or "root"
    return CACHE_DIR / f"{slug}-{digest}.json"


def load(path: str | os.PathLike | None, target: str = "") -> dict:
    if path is None:
        path = default_path(target or ".")
    p = Path(path)
    if not p.exists():
        return {"version": LEDGER_VERSION, "target": target, "updated": "", "entries": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": LEDGER_VERSION, "target": target, "updated": "", "entries": {}}
    data.setdefault("version", LEDGER_VERSION)
    data.setdefault("entries", {})
    return data


def save(ledger: dict, path: str | os.PathLike | None) -> Path:
    p = Path(path) if path else default_path(ledger.get("target") or ".")
    p.parent.mkdir(parents=True, exist_ok=True)
    ledger["updated"] = _now()
    p.write_text(json.dumps(ledger, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _key(f: Finding) -> str:
    return f.id or f.fingerprint()


def _record(f: Finding, entry: dict | None) -> dict:
    rec = entry or {}
    rec.update(
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "engine": f.engine,
            "location": f.location,
            "first_seen": (entry or {}).get("first_seen") or _now(),
            "last_seen": _now(),
            "times_seen": int((entry or {}).get("times_seen", 0)) + 1,
        }
    )
    if not entry:
        rec["status"] = OPEN
    elif rec.get("status") == RESOLVED:
        rec["status"] = OPEN
    else:
        rec.setdefault("status", OPEN)
    return rec


def merge(ledger: dict, findings: Iterable[Finding], target: str = "") -> tuple[dict, dict]:
    """Merge current findings into the ledger. Returns (ledger, report)."""
    entries: dict[str, dict] = ledger.setdefault("entries", {})
    if target:
        ledger["target"] = target

    new: list[dict] = []
    known: list[dict] = []
    reopened: list[dict] = []
    seen: set[str] = set()

    for f in findings:
        k = _key(f)
        seen.add(k)
        prior = entries.get(k)
        was_resolved = bool(prior) and prior.get("status") == RESOLVED
        rec = _record(f, prior)
        entries[k] = rec
        if prior is None:
            new.append(rec)
        elif was_resolved:
            reopened.append(rec)
        else:
            known.append(rec)

    resolved: list[dict] = []
    for k, rec in entries.items():
        if k in seen:
            continue
        if rec.get("status") in (OPEN, ACK):
            rec["status"] = RESOLVED
            rec["resolved_at"] = _now()
            resolved.append(rec)

    ledger["updated"] = _now()
    report = {
        "target": target,
        "new": new,
        "known": known,
        "reopened": reopened,
        "resolved": resolved,
        "totals": {
            "new": len(new),
            "known": len(known),
            "reopened": len(reopened),
            "resolved": len(resolved),
            "tracked": len(entries),
            "open": sum(1 for r in entries.values() if r.get("status") in (OPEN, ACK)),
        },
    }
    return ledger, report


def set_status(ledger: dict, finding_id: str, status: str) -> bool:
    if status not in VALID_STATUS:
        return False
    rec = ledger.get("entries", {}).get(finding_id)
    if not rec:
        return False
    rec["status"] = status
    rec["status_updated"] = _now()
    if status == RESOLVED:
        rec["resolved_at"] = _now()
    return True


def sort_records(records: list[dict]) -> list[dict]:
    return sorted(
        records,
        key=lambda r: (-SEVERITY_ORDER.get(r.get("severity", "info"), 0), str(r.get("id", ""))),
    )
