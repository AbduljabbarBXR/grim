"""Remote rule feed: additional SAST regex rules synced from a URL or local file.

The feed is a JSON list of rule objects::

    {"id": "...", "pattern": "...", "severity": "high",
     "title": "...", "description": "...", "remediation": "...",
     "languages": ["python", "all"]}

Rules are validated (regex must compile, severity known) and stored in the cache. The
code scanner merges them with its built-in rules, so new coverage arrives by syncing a
feed rather than shipping a new GRIM release.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

MAX_RULES = 1000
SEVERITIES = {"critical", "high", "medium", "low", "info"}


def cache_path() -> Path:
    root = Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim"))
    return Path(os.environ.get("GRIM_RULES_CACHE", root / "rules.json"))


def feed_url() -> str:
    return os.environ.get("GRIM_FEEDS_URL") or os.environ.get("GRIM_RULES_FEED", "")


def _validate(rule: dict) -> dict | None:
    if not isinstance(rule, dict):
        return None
    rid = str(rule.get("id") or "").strip()
    pattern = str(rule.get("pattern") or "")
    if not rid or not pattern:
        return None
    try:
        re.compile(pattern)
    except re.error:
        return None
    sev = str(rule.get("severity") or "medium").lower()
    if sev not in SEVERITIES:
        sev = "medium"
    langs = rule.get("languages") or ["all"]
    if isinstance(langs, str):
        langs = [langs]
    langs = [str(x).lower() for x in langs] or ["all"]
    return {
        "id": rid,
        "pattern": pattern,
        "severity": sev,
        "title": str(rule.get("title") or rid),
        "description": str(rule.get("description") or "Custom rule from feed."),
        "remediation": str(rule.get("remediation") or "Review and fix per the rule description."),
        "languages": langs,
    }


def save(rules: list, source: str = "", version: str = "") -> int:
    """Replace the stored rule set. Returns the number of valid rules saved."""
    cleaned = [r for r in (_validate(x) for x in (rules or [])) if r][:MAX_RULES]
    p = cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": version or "", "source": source, "count": len(cleaned), "rules": cleaned}
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, p)
    return len(cleaned)


def load_raw() -> dict:
    p = cache_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def clear() -> None:
    p = cache_path()
    if p.exists():
        p.unlink()


def digest() -> str:
    p = cache_path()
    if not p.exists():
        return ""
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def overlay() -> list[tuple]:
    """Compiled overlay rules in the scanner's rule-tuple shape."""
    out: list[tuple] = []
    for r in load_raw().get("rules", []):
        try:
            out.append(
                (
                    f"feed-{r['id']}",
                    re.compile(r["pattern"]),
                    r["severity"],
                    r["title"],
                    r["description"],
                    r["remediation"],
                    set(r.get("languages") or ["all"]),
                )
            )
        except (re.error, KeyError, TypeError):
            continue
    return out


def install(rules: list, source: str = "local", version: str = "") -> int:
    return save(rules, source=source, version=version)
