"""`watch`: save a baseline and detect drift on later scans."""

from __future__ import annotations

from ..core import baseline
from ..core.findings import Finding
from .diffscan import diff_against_manifest, snapshot


def save_baseline(
    target: str,
    deep: bool = False,
    path: str | None = None,
) -> dict:
    manifest, root, stats = snapshot(target, deep=deep)
    saved = baseline.save(target, manifest, root, deep=deep, path=path)
    return {
        "baseline_path": str(saved),
        "entries": len(manifest),
        "root": root,
        "deep": deep,
        "truncated": stats.get("truncated", False),
        "error": stats.get("error"),
    }


def watch_diff(
    target: str,
    deep: bool = False,
    baseline_path: str | None = None,
) -> tuple[list[Finding], dict, dict]:
    saved = baseline.load(baseline_path, target)
    if not saved or not saved.get("manifest"):
        raise FileNotFoundError("no baseline found; run watch with action=save first")
    findings, stats = diff_against_manifest(saved, target, deep=deep)
    return findings, stats, saved
