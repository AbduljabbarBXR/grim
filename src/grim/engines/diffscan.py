"""Artifact diffing: baseline vs current — the drift detector for active compromise.

Handles the common backup case where everything is wrapped in a timestamped root
directory: the shared wrapper prefix is stripped before comparison.

Manifests store size plus a content hash (SHA-256 of size + a bounded content
prefix), so a same-size modification is still detected as changed. Changed files
are then content-scanned for webshell and exposure indicators, closing the
active-compromise blind spot.
"""

from __future__ import annotations

import hashlib

from ..core import limits
from ..core.findings import Finding, make_id
from .exposure import (
    MAX_ENTRIES,
    READ_LIMIT,
    Entry,
    Source,
    _check_by_name,
    _check_content,
    _in_web_path,
    open_source,
)

MAX_CLASSIFY = 5_000
SUSPICIOUS_EXT = (
    ".php", ".phtml", ".phar", ".sh", ".bash", ".pl", ".py", ".cgi",
    ".exe", ".elf", ".bin", ".so",
)

HASH_PREFIX_LIMIT = 131_072  # hash the first 128 KB of each file


def _entry_hash(entry: Entry, reader) -> str:
    """Hash of size plus a bounded content prefix. Same-size edits change the hash."""
    data = reader(HASH_PREFIX_LIMIT) if entry.size > 0 else b""
    return hashlib.sha256(f"{entry.size}|".encode() + data).hexdigest()[:24]


def diff_artifacts(path_a: str, path_b: str, classify_limit: int = MAX_CLASSIFY, deep: bool = False) -> tuple[list[Finding], dict]:
    info: dict = {}
    source_a = open_source(path_a, nested=deep)
    manifest_a_raw = _manifest(source_a, info)
    root_a = _common_root(manifest_a_raw)
    deep_a = source_a.stats() if deep and hasattr(source_a, "stats") else {}
    if getattr(source_a, "error", None):
        info.setdefault("errors", []).append(f"baseline: {source_a.error}")
    source_a.close()

    source_b = open_source(path_b, nested=deep)
    manifest_b_raw = _manifest(source_b, info)
    deep_b = source_b.stats() if deep and hasattr(source_b, "stats") else {}
    return _compare_manifests(
        manifest_a_raw, manifest_b_raw, source_b,
        path_a=path_a, path_b=path_b, root_a=root_a,
        classify_limit=classify_limit, deep=deep, deep_a=deep_a, deep_b=deep_b, info=info,
    )


def diff_against_manifest(
    baseline: dict,
    path: str,
    classify_limit: int = MAX_CLASSIFY,
    deep: bool = False,
) -> tuple[list[Finding], dict]:
    """Compare a saved baseline manifest against the current state of ``path``."""
    info: dict = {}
    source_b = open_source(path, nested=deep)
    manifest_b_raw = _manifest(source_b, info)
    deep_b = source_b.stats() if deep and hasattr(source_b, "stats") else {}
    return _compare_manifests(
        baseline.get("manifest") or {}, manifest_b_raw, source_b,
        path_a=baseline.get("target") or "baseline", path_b=path, root_a=baseline.get("root"),
        classify_limit=classify_limit, deep=deep, deep_a={}, deep_b=deep_b, info=info,
    )


def _compare_manifests(
    manifest_a_raw: dict,
    manifest_b_raw: dict,
    source_b,
    *,
    path_a: str,
    path_b: str,
    root_a: str | None,
    classify_limit: int,
    deep: bool,
    deep_a: dict,
    deep_b: dict,
    info: dict,
) -> tuple[list[Finding], dict]:
    root_b = _common_root(manifest_b_raw)
    manifest_a = _normalize(manifest_a_raw, root_a)
    manifest_b = _normalize(manifest_b_raw, root_b)

    def sig(m: dict, p: str) -> tuple[int, str] | None:
        e = m.get(p)
        return (e["size"], e["hash"]) if e else None

    added = sorted(set(manifest_b) - set(manifest_a))
    removed = sorted(set(manifest_a) - set(manifest_b))
    changed = sorted(
        p
        for p in (set(manifest_a) & set(manifest_b))
        if sig(manifest_a, p) != sig(manifest_b, p)
    )

    added_set = set(added)
    changed_set = set(changed)
    findings: list[Finding] = []
    stats = {
        "added": len(added),
        "removed": len(removed),
        "changed": len(changed),
        "classified": 0,
        "root_a": root_a,
        "root_b": root_b,
    }

    # content-scan both changed and added entries that are in web paths or suspicious
    scan_targets = added_set | changed_set
    if scan_targets:
        try:
            for entry, reader in source_b.iter_items():
                if entry.is_dir or entry.is_link:
                    continue
                npath = _strip_root(entry.path, root_b)
                if npath not in scan_targets or limits.reached(stats["classified"], classify_limit):
                    continue
                data = b""
                # use the full (unstripped) entry path for web-path context, since the
                # wrapper root is often the web root itself
                if entry.size > 0 and (_in_web_path(entry.path) or _looks_suspicious_name(entry.path)):
                    data = reader(min(READ_LIMIT, entry.size + 1))
                norm_entry = Entry(path=npath, size=entry.size)
                for f in _classify(norm_entry, data):
                    f.tags.append("added" if npath in added_set else "changed")
                    findings.append(f)
                stats["classified"] += 1
        finally:
            source_b.close()
    else:
        source_b.close()

    # changed executable marker (name level) when content scan did not flag it
    for rel in changed:
        if _looks_executable(rel) and not any(f.location.get("file") == rel for f in findings):
            findings.append(
                Finding(
                    id=make_id("DIFF", "changed-exec", rel),
                    severity="high",
                    confidence=0.75,
                    category="CWE-912",
                    owasp="A08:2021",
                    title="Web-executable file changed between baseline and current",
                    description="Modified scripts in web paths are a primary malware persistence vector.",
                    location={"file": rel},
                    evidence=f"{manifest_a[rel]['size']} B -> {manifest_b[rel]['size']} B",
                    remediation="Diff against baseline; remove if unexpected; scan for webshell indicators.",
                    engine="grim-diff",
                    tags=["drift", "changed"],
                )
            )

    for rel in removed[:classify_limit]:
        if _looks_executable(rel):
            findings.append(
                Finding(
                    id=make_id("DIFF", "removed-exec", rel),
                    severity="medium",
                    confidence=0.6,
                    category="CWE-912",
                    owasp="A08:2021",
                    title="Executable file present in baseline but missing now",
                    description="Could be legitimate cleanup or removal by an intruder. Verify with change history.",
                    location={"file": rel},
                    evidence=f"was {manifest_a[rel]['size']} B",
                    remediation="Confirm who removed the file and why.",
                    engine="grim-diff",
                    tags=["drift", "removed"],
                )
            )

    findings.append(
        Finding(
            id=make_id("DIFF", "summary", f"{path_a}|{path_b}"),
            severity="info",
            confidence=1.0,
            category="CWE-1059",
            owasp="A08:2021",
            title="Artifact drift summary",
            description=(
                f"Added: {stats['added']}, removed: {stats['removed']}, changed: {stats['changed']}"
                + (f" (wrapper roots stripped: '{root_a}' / '{root_b}')" if root_a and root_b and root_a != root_b else "")
            ),
            location={"file": f"a={path_a} b={path_b}"},
            evidence=f"classified {stats['classified']} added/changed entries",
            engine="grim-diff",
            tags=["drift", "summary"],
        )
    )
    reasons: list[str] = []
    errors: list[str] = list(info.get("errors", []))
    if getattr(source_b, "error", None):
        errors.append(f"current: {source_b.error}")
    for side in (deep_a, deep_b):
        errors.extend(side.get("errors", []))
    if info.get("manifest_truncated"):
        reasons.append("manifest entry limit reached")
    if limits.reached(stats["classified"], classify_limit):
        reasons.append(f"changed-file classify limit reached ({classify_limit})")
    if deep:
        stats["deep"] = {"a": deep_a, "b": deep_b}
        for side in (deep_a, deep_b):
            if side.get("depth_capped"):
                reasons.append("archive nesting depth limit reached")
            if side.get("budget_capped"):
                reasons.append("nested-archive byte budget exhausted")
            if side.get("oversize_skipped"):
                reasons.append("nested archive exceeded the per-archive size cap")
    for err in errors:
        reasons.append(f"unreadable archive: {err}")
    stats["truncated"] = bool(reasons)
    stats["reasons"] = reasons
    stats["errors"] = errors
    return findings, stats


def build_manifest(path: str, deep: bool = False) -> dict:
    source = open_source(path, nested=deep)
    try:
        return _manifest(source)
    finally:
        source.close()


def snapshot(path: str, deep: bool = False) -> tuple[dict, str | None, dict]:
    """Return (manifest, common_root, stats) for a target."""
    info: dict = {}
    source = open_source(path, nested=deep)
    try:
        manifest = _manifest(source, info)
        root = _common_root(manifest)
        deep_stats = source.stats() if deep and hasattr(source, "stats") else {}
        stats = {
            "entries": len(manifest),
            "root": root,
            "deep": deep_stats,
            "error": getattr(source, "error", None),
            "truncated": bool(info.get("manifest_truncated")),
        }
    finally:
        source.close()
    return manifest, root, stats


def _manifest(source: Source, info: dict | None = None) -> dict:
    max_entries = limits.resolve("GRIM_MAX_ENTRIES", MAX_ENTRIES)
    manifest: dict = {}
    for entry, reader in source.iter_items():
        if entry.is_dir or entry.is_link:
            continue
        manifest[entry.path] = {
            "size": entry.size,
            "hash": _entry_hash(entry, reader) if entry.size > 0 else "",
        }
        if limits.reached(len(manifest), max_entries):
            if info is not None:
                info["manifest_truncated"] = True
            break
    return manifest


def _common_root(manifest: dict) -> str | None:
    """If every path shares one top-level directory, return it (backup wrapper)."""
    if not manifest:
        return None
    roots = set()
    for k in manifest:
        if "/" not in k:
            return None
        roots.add(k.split("/", 1)[0])
        if len(roots) > 1:
            return None
    return roots.pop()


def _strip_root(path: str, root: str | None) -> str:
    if root and path.startswith(root + "/"):
        return path[len(root) + 1 :]
    return path


def _normalize(manifest: dict, root: str | None) -> dict:
    if not root:
        return manifest
    return {_strip_root(k, root): v for k, v in manifest.items()}


def _classify(entry: Entry, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    _check_by_name(entry, out)
    if data:
        _check_content(entry, data, out)
    return out


def _looks_suspicious_name(rel: str) -> bool:
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    if name.startswith(".") and not name.startswith(".htaccess"):
        return True
    if name in {"error_log", "php_errorlog", ".user.ini"}:
        return True
    return _looks_executable(rel)


def _looks_executable(rel: str) -> bool:
    lower = rel.lower()
    return lower.endswith(SUSPICIOUS_EXT) and (
        "public" in lower or "upload" in lower or "www" in lower or "htdocs" in lower or "web/" in lower
    )