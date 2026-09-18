"""Finding model, ranking, and dedupe for GRIM."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_EMOJI = {"critical": "!!", "high": "!", "medium": "+", "low": "-", "info": "."}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    id: str
    severity: str
    confidence: float
    category: str
    owasp: str
    title: str
    description: str = ""
    location: dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    engine: str = "grim"
    first_seen: str = field(default_factory=_now)
    tags: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity_rank"] = SEVERITY_ORDER.get(self.severity, 0)
        return d

    def fingerprint(self) -> str:
        key = json.dumps(
            [
                self.severity,
                self.category,
                self.location.get("file", self.location.get("url", "")),
                self.location.get("line", 0),
                self.title,
            ],
            sort_keys=True,
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]


SEVERITY_CVSS_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def cvss_to_severity(score: float) -> str:
    for threshold, sev in SEVERITY_CVSS_BANDS:
        if score >= threshold:
            return sev
    return "info"


def rank(findings: Iterable[Finding]) -> list[Finding]:
    """Dedupe and sort by severity x confidence, then by location."""
    seen: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint()
        if fp in seen:
            existing = seen[fp]
            # keep the higher-confidence version, merge tags
            if f.confidence > existing.confidence:
                existing.confidence = f.confidence
                existing.evidence = f.evidence or existing.evidence
            for t in f.tags:
                if t not in existing.tags:
                    existing.tags.append(t)
            continue
        seen[fp] = f
    ordered = sorted(
        seen.values(),
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            -f.confidence,
            str(f.location.get("file", f.location.get("url", ""))),
            int(f.location.get("line", 0) or 0),
        ),
    )
    return ordered


def summarize(findings: Iterable[Finding]) -> dict[str, Any]:
    counts: dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    total = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        total += 1
    return {"total": total, "by_severity": counts}


def make_id(prefix: str, title: str, location: str = "") -> str:
    digest = hashlib.sha1(f"{prefix}|{title}|{location}".encode()).hexdigest()[:6].upper()
    return f"GRIM-{prefix}-{digest}"
