"""Indicator-of-compromise (IoC) store, feed sync, and hash matching.

The store is a small JSON file (GRIM_CACHE/iocs.json by default) that can be seeded
from a local file or synced from a remote feed. Entries match by SHA-256, SHA-1, or
MD5. Also detects the EICAR antivirus test string as a built-in sanity indicator.

No third-party dependencies; network sync is opt-in.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import urllib.request
from pathlib import Path

from ..core.findings import Finding, make_id
from ..engines.exposure import READ_LIMIT, open_source

FEED_URL = os.environ.get("GRIM_IOC_FEED", "")
CACHE_FILE = Path(os.environ.get("GRIM_IOC_CACHE", Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim")) / "iocs.json"))
TIMEOUT = 25

# EICAR standard antivirus test file (harmless, industry standard)
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

HASH_FIELDS = ("sha256", "sha1", "md5")


def load(path: str | os.PathLike | None = None) -> list[dict]:
    p = Path(path) if path else CACHE_FILE
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("indicators") or data.get("iocs") or []
    out: list[dict] = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and any(item.get(f) for f in HASH_FIELDS):
            out.append(_normalize(item))
    return out


def save(entries: list[dict], path: str | os.PathLike | None = None) -> Path:
    p = Path(path) if path else CACHE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"indicators": entries}, indent=2), encoding="utf-8")
    return p


def add(entries: list[dict], path: str | os.PathLike | None = None) -> int:
    existing = {_key(e): e for e in load(path)}
    added = 0
    for e in entries:
        e = _normalize(e)
        k = _key(e)
        if k and k not in existing:
            existing[k] = e
            added += 1
    save(list(existing.values()), path)
    return added


def clear(path: str | os.PathLike | None = None) -> None:
    p = Path(path) if path else CACHE_FILE
    if p.exists():
        p.unlink()


def sync(url: str | None = None, path: str | os.PathLike | None = None) -> int:
    """Fetch a feed (JSON list, or {"indicators": [...]}) and merge it in."""
    url = url or FEED_URL
    if not url:
        raise ValueError("no IoC feed URL configured (set GRIM_IOC_FEED or pass url)")
    raw = _fetch(url)
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("indicators") or data.get("iocs") or []
    if not isinstance(data, list):
        raise ValueError("feed did not contain a list of indicators")
    return add([d for d in data if isinstance(d, dict)], path)


def _fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "grim-ioc/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", str(TIMEOUT), url],
            capture_output=True, text=True, check=True,
        )
        return proc.stdout


def _normalize(item: dict) -> dict:
    out = {
        "name": str(item.get("name") or item.get("description") or "unknown indicator"),
        "severity": item.get("severity") if item.get("severity") in {"critical", "high", "medium", "low", "info"} else "high",
        "source": str(item.get("source") or item.get("reference") or "feed"),
    }
    for f in HASH_FIELDS:
        val = item.get(f)
        if val:
            out[f] = str(val).strip().lower()
    return out


def _key(item: dict) -> str:
    for f in HASH_FIELDS:
        if item.get(f):
            return str(item[f])
    return ""


def _index(entries: list[dict]) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for e in entries:
        for f in HASH_FIELDS:
            if e.get(f):
                idx[e[f]] = e
    return idx


def _digests(data: bytes) -> list[str]:
    return [
        hashlib.sha256(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
    ]


def scan_iocs(
    path: str,
    ioc_path: str | os.PathLike | None = None,
    max_bytes: int = 64 * 1024 * 1024,
    deep: bool = False,
    max_findings: int = 500,
) -> list[Finding]:
    """Hash files under a directory/archive and match against the IoC store."""
    entries = load(ioc_path)
    idx = _index(entries)
    findings: list[Finding] = []

    source = open_source(path, nested=deep)
    try:
        for entry, reader in source.iter_items():
            if entry.is_dir or entry.is_link or entry.size <= 0:
                continue
            if len(findings) >= max_findings:
                break
            if entry.size > max_bytes:
                continue
            data = reader(entry.size + 1)
            if not data:
                continue
            matched = None
            for digest in _digests(data):
                if digest in idx:
                    matched = idx[digest]
                    break
            if matched is not None:
                findings.append(_ioc_finding(entry.path, matched, entry.size))
                continue
            if EICAR in data[:READ_LIMIT]:
                findings.append(_eicar_finding(entry.path))
    finally:
        source.close()
    return findings


def _ioc_finding(path: str, ioc: dict, size: int) -> Finding:
    name = ioc.get("name", "unknown")
    return Finding(
        id=make_id("IOC", name, path),
        severity=ioc.get("severity", "high"),
        confidence=0.99,
        category="CWE-506",
        owasp="A08:2021",
        title=f"Known malicious file hash matched: {name}",
        description=(
            "The file's cryptographic hash matches an indicator of compromise in the "
            "configured threat-intel store. Treat as known-bad."
        ),
        location={"file": path},
        evidence=f"{size} B; source: {ioc.get('source', 'feed')}",
        remediation="Quarantine the file, investigate its origin and accesses, and rotate any credentials it could reach.",
        engine="grim-ioc",
        tags=["ioc", "known-malware", "active-compromise"],
    )


def _eicar_finding(path: str) -> Finding:
    return Finding(
        id=make_id("IOC", "eicar", path),
        severity="high",
        confidence=1.0,
        category="CWE-506",
        owasp="A08:2021",
        title="EICAR antivirus test file",
        description="The EICAR test string is present. Harmless by design, but confirms malware scanning works end to end.",
        location={"file": path},
        evidence="EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        remediation="Delete the test file; no action needed beyond confirming detection.",
        engine="grim-ioc",
        tags=["ioc", "eicar"],
    )
