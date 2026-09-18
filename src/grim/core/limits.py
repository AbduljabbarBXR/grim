"""Runtime limits, overridable via environment variables.

Every hard cap can be raised, lowered, or disabled without a code change. Engines
resolve limits at call time, so tests and operators can tune them per run.

Convention: a value of ``0`` (or negative) means **unlimited**.
"""

from __future__ import annotations

import os


def resolve(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def is_unlimited(value: int) -> bool:
    return value <= 0


def reached(count: int, limit: int) -> bool:
    """True when ``count`` has hit a finite ``limit``."""
    return (not is_unlimited(limit)) and count >= limit


def clamp(count: int, limit: int) -> int:
    """Return count, or the limit when finite and exceeded."""
    if is_unlimited(limit):
        return count
    return min(count, limit)
