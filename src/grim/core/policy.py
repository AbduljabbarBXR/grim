"""Authorization policy for live checks.

Live network checks are off unless an explicit scope authorizes the target. The scope is
JSON (stdlib-friendly) stored in ``grim.scope.json`` or passed inline:

    {
      "authorization": {"declared_by": "owner", "reference": "contract-123"},
      "targets": [
        {"host": "example.com", "mode": "passive",
         "max_requests_per_minute": 30, "paths_allowlist": ["/", "/api/health"]}
      ],
      "deny": ["*/wp-admin/*"]
    }

Nothing here performs I/O; it only decides what is allowed.
"""

from __future__ import annotations

import fnmatch
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

SCOPE_NAMES = ("grim.scope.json",)
VALID_MODES = {"passive", "active"}


class PolicyError(Exception):
    pass


def find_scope(target: str | None = None) -> Path | None:
    candidates: list[Path] = []
    if target:
        p = Path(target)
        candidates.append((p if p.is_dir() else p.parent) / "grim.scope.json")
    candidates.append(Path.cwd() / "grim.scope.json")
    for c in candidates:
        if c.is_file():
            return c
    return None


def load(path: str | os.PathLike | None = None, target: str | None = None, inline: dict | None = None) -> dict:
    if inline:
        return inline
    if path is None:
        path = find_scope(target)
    if path is None:
        raise PolicyError("no scope found; pass a scope file or inline scope (live checks are opt-in)")
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"scope file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"invalid scope file {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("scope must be a JSON object")
    return data


def authorize(scope: dict, url: str) -> dict:
    """Return {allowed, mode, max_rpm, host, reason}. Deny rules win."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    port = parsed.port
    full_host = f"{host}:{port}" if port else host
    path = parsed.path or "/"
    if not host:
        return {"allowed": False, "reason": "could not determine host", "host": "", "mode": "", "max_rpm": 0}

    for pattern in scope.get("deny") or []:
        if _matches(full_host, path, pattern):
            return {"allowed": False, "reason": f"denied by rule: {pattern}", "host": host, "mode": "", "max_rpm": 0}

    for target in scope.get("targets") or []:
        thost = str(target.get("host", "")).lower()
        if thost not in (host, full_host):
            continue
        mode = str(target.get("mode", "passive")).lower()
        if mode not in VALID_MODES:
            mode = "passive"
        return {
            "allowed": True,
            "mode": mode,
            "max_rpm": int(target.get("max_requests_per_minute", 30) or 0),
            "host": host,
            "paths_allowlist": list(target.get("paths_allowlist") or []),
            "reason": "authorized",
        }
    return {"allowed": False, "reason": f"host not in scope: {host}", "host": host, "mode": "", "max_rpm": 0}


def path_allowed(path: str, allowlist: list[str]) -> bool:
    if not allowlist:
        return False
    return any(_matches_path(path, p) for p in allowlist)


def _matches(host: str, path: str, pattern: str) -> bool:
    return fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(host + path, pattern)


def _matches_path(path: str, pattern: str) -> bool:
    return fnmatch.fnmatch(path, pattern) or path.startswith(pattern.rstrip("*"))


class RateLimiter:
    def __init__(self, max_per_minute: int):
        self.interval = 60.0 / max_per_minute if max_per_minute > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        delta = time.monotonic() - self._last
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self._last = time.monotonic()
