"""GRIM tool registry: the MCP-facing surface."""

from __future__ import annotations

import json
from typing import Any, Callable

from .core.detector import detect_stack
from .core.findings import Finding, rank, summarize
from .core.report import render_json, render_markdown
from .engines.codepatterns import scan_code
from .engines.deps import audit_deps
from .engines.diffscan import diff_artifacts, build_manifest
from .engines.exposure import audit_exposure
from .engines.secrets import scan_secrets

Handler = Callable[[dict], dict]


def _findings_payload(findings: list[Finding], meta: dict | None = None) -> dict:
    ranked = rank(findings)
    return {
        "ok": True,
        "summary": summarize(ranked),
        "findings": [f.to_dict() for f in ranked],
        "meta": meta or {},
    }


def _tool_detect_stack(args: dict) -> dict:
    return {"ok": True, **detect_stack(args["path"])}


def _tool_audit_deps(args: dict) -> dict:
    findings = audit_deps(args["path"])
    return _findings_payload(findings, {"engine": "osv", "target": args["path"]})


def _tool_scan_secrets(args: dict) -> dict:
    findings = scan_secrets(args["path"], include_skipped=bool(args.get("include_skipped")))
    return _findings_payload(findings, {"engine": "grim-secrets", "target": args["path"]})


def _tool_scan_code(args: dict) -> dict:
    findings = scan_code(
        args["path"],
        languages=args.get("languages"),
        max_files=int(args.get("max_files", 20000)),
    )
    return _findings_payload(findings, {"engine": "grim-codepatterns", "target": args["path"]})


def _tool_audit_exposure(args: dict) -> dict:
    findings = audit_exposure(args["path"])
    return _findings_payload(findings, {"engine": "grim-exposure", "target": args["path"]})


def _tool_diff_artifacts(args: dict) -> dict:
    findings, stats = diff_artifacts(args["path_a"], args["path_b"])
    return _findings_payload(findings, {"engine": "grim-diff", "stats": stats,
                                        "baseline": args["path_a"], "current": args["path_b"]})


def _tool_report(args: dict) -> dict:
    raw = args.get("findings") or []
    findings = [_finding_from_dict(d) for d in raw]
    fmt = (args.get("format") or "markdown").lower()
    meta = args.get("meta") or {}
    if fmt == "json":
        text = render_json(findings, meta)
    else:
        text = render_markdown(findings, meta)
    return {"ok": True, "format": fmt, "report": text}


def _tool_scan(args: dict) -> dict:
    """Orchestrator: detect stack, then run the applicable v1 tools."""
    path = args["path"]
    selected = args.get("tools")
    include_network = bool(args.get("network", True))
    detect = detect_stack(path)
    findings: list[Finding] = []
    ran: list[str] = []

    def want(name: str) -> bool:
        return not selected or name in selected

    if want("exposure"):
        findings.extend(audit_exposure(path))
        ran.append("exposure")
    if want("secrets"):
        findings.extend(scan_secrets(path))
        ran.append("secrets")
    if want("code"):
        findings.extend(scan_code(path))
        ran.append("code")
    if want("deps") and include_network and (detect.get("lockfiles") or _has_manifest(detect)):
        try:
            findings.extend(audit_deps(path))
            ran.append("deps")
        except Exception as exc:  # keep scan resilient
            ran.append(f"deps:error:{exc}")

    return _findings_payload(
        findings,
        {"target": path, "tools_run": ran, "detect": detect},
    )


def _has_manifest(detect: dict) -> bool:
    return any(s.get("manifest") for s in detect.get("stacks", []))


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d.get("id", "GRIM-?"),
        severity=d.get("severity", "info"),
        confidence=float(d.get("confidence", 0.5)),
        category=d.get("category", ""),
        owasp=d.get("owasp", ""),
        title=d.get("title", ""),
        description=d.get("description", ""),
        location=d.get("location", {}),
        evidence=d.get("evidence", ""),
        remediation=d.get("remediation", ""),
        references=d.get("references", []),
        engine=d.get("engine", "grim"),
        first_seen=d.get("first_seen", ""),
        tags=d.get("tags", []),
    )


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


PATH_PROP = {"path": {"type": "string", "description": "File, directory, or archive (tar.gz/zip) to scan"}}

TOOLS: dict[str, dict[str, Any]] = {
    "detect_stack": {
        "description": "Identify the project stack(s) and web-served directories. Run this first.",
        "schema": _schema({**PATH_PROP}, ["path"]),
        "handler": _tool_detect_stack,
    },
    "audit_deps": {
        "description": "Find known CVEs in dependencies via the live OSV.dev database (npm, Composer, PyPI).",
        "schema": _schema({**PATH_PROP}, ["path"]),
        "handler": _tool_audit_deps,
    },
    "scan_secrets": {
        "description": "Scan for leaked credentials, API keys, tokens, private keys, and sensitive files.",
        "schema": _schema(
            {**PATH_PROP, "include_skipped": {"type": "boolean", "description": "Also scan node_modules/vendor (slower)"}},
            ["path"],
        ),
        "handler": _tool_scan_secrets,
    },
    "scan_code": {
        "description": "Static analysis for dangerous code patterns: client-controlled uploads, injection sinks, RCE preconditions.",
        "schema": _schema(
            {
                **PATH_PROP,
                "languages": {"type": "array", "items": {"type": "string"}, "description": "Filter: php, js, python"},
                "max_files": {"type": "integer", "description": "Max files to scan (default 20000)"},
            },
            ["path"],
        ),
        "handler": _tool_scan_code,
    },
    "audit_exposure": {
        "description": "Detect exposed/executable/malicious files in web paths and archives: webshells, polyglots, ELF binaries, .env, backups.",
        "schema": _schema({**PATH_PROP}, ["path"]),
        "handler": _tool_audit_exposure,
    },
    "diff_artifacts": {
        "description": "Compare two directories/archives (baseline vs current) to detect added, removed, or modified files — the active-compromise drift check.",
        "schema": _schema(
            {
                "path_a": {"type": "string", "description": "Baseline (older) directory or archive"},
                "path_b": {"type": "string", "description": "Current (newer) directory or archive"},
            },
            ["path_a", "path_b"],
        ),
        "handler": _tool_diff_artifacts,
    },
    "report": {
        "description": "Render findings into a unified Markdown or JSON report.",
        "schema": _schema(
            {
                "findings": {"type": "array", "items": {"type": "object"}, "description": "Finding objects (from other tools)"},
                "format": {"type": "string", "enum": ["markdown", "json"]},
                "meta": {"type": "object"},
            },
            ["findings"],
        ),
        "handler": _tool_report,
    },
    "scan": {
        "description": "One-shot audit: detect stack, then run exposure + secrets + code + deps and return ranked findings.",
        "schema": _schema(
            {
                **PATH_PROP,
                "tools": {"type": "array", "items": {"type": "string"}, "description": "Subset: exposure, secrets, code, deps"},
                "network": {"type": "boolean", "description": "Allow network calls for dependency CVE lookup (default true)"},
            },
            ["path"],
        ),
        "handler": _tool_scan,
    },
}


def call_tool(name: str, args: dict) -> dict:
    if name not in TOOLS:
        return {"ok": False, "error": f"unknown tool: {name}"}
    try:
        return TOOLS[name]["handler"](args)
    except Exception as exc:  # surface errors as data, never crash the agent
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def tool_catalog() -> list[dict]:
    return [
        {"name": name, "description": meta["description"], "inputSchema": meta["schema"]}
        for name, meta in TOOLS.items()
    ]
