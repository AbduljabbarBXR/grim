"""GRIM tool registry: the MCP-facing surface."""

from __future__ import annotations

from typing import Any, Callable

from . import sbom as _sbom
from .core import ledger as _ledger
from .core.attack import enrich
from .core.detector import detect_stack
from .core.findings import Finding, rank, summarize
from .core.planner import build_plan
from .core.report import render_json, render_markdown
from .engines.codepatterns import scan_code
from .engines.deps import audit_deps
from .engines.diffscan import diff_artifacts
from .engines.exposure import audit_exposure
from .engines.secrets import scan_secrets, scan_secrets_history
from .feeds import iocs as _iocs

Handler = Callable[[dict], dict]


def _findings_payload(findings: list[Finding], meta: dict | None = None) -> dict:
    ranked = enrich(rank(findings))
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
    meta = {"engine": "grim-secrets", "target": args["path"]}
    if args.get("include_history"):
        history = scan_secrets_history(args["path"])
        findings.extend(history)
        meta["history"] = True
    return _findings_payload(findings, meta)


def _tool_scan_code(args: dict) -> dict:
    findings = scan_code(
        args["path"],
        languages=args.get("languages"),
        max_files=int(args.get("max_files", 20000)),
        workers=args.get("workers"),
        use_cache=bool(args.get("use_cache", True)),
    )
    return _findings_payload(findings, {"engine": "grim-codepatterns", "target": args["path"]})


def _tool_audit_exposure(args: dict) -> dict:
    findings = audit_exposure(args["path"], deep=bool(args.get("deep")))
    return _findings_payload(findings, {"engine": "grim-exposure", "target": args["path"]})


def _tool_diff_artifacts(args: dict) -> dict:
    findings, stats = diff_artifacts(args["path_a"], args["path_b"], deep=bool(args.get("deep")))
    return _findings_payload(findings, {"engine": "grim-diff", "stats": stats,
                                        "baseline": args["path_a"], "current": args["path_b"]})


def _tool_plan(args: dict) -> dict:
    return {"ok": True, **build_plan(args["path"], network=bool(args.get("network", True)), deep=bool(args.get("deep")))}


def _tool_sbom(args: dict) -> dict:
    path = args["path"]
    fmt = (args.get("format") or "cyclonedx").lower()
    components = _sbom.collect_components(path)
    bom = _sbom.spdx(path, components) if fmt.startswith("spdx") else _sbom.cyclonedx(path, components)
    return {"ok": True, "format": fmt, "component_count": len(components), "bom": bom}


def _tool_scan_iocs(args: dict) -> dict:
    ioc_path = args.get("ioc_path")
    findings = _iocs.scan_iocs(args["path"], ioc_path=ioc_path, deep=bool(args.get("deep")))
    return _findings_payload(
        findings,
        {"engine": "grim-ioc", "target": args["path"], "indicators": len(_iocs.load(ioc_path))},
    )


def _tool_update_feeds(args: dict) -> dict:
    ioc_path = args.get("ioc_path")
    added = _iocs.sync(args.get("url"), ioc_path)
    return {"ok": True, "added": added, "total": len(_iocs.load(ioc_path))}


def _tool_ledger(args: dict) -> dict:
    action = (args.get("action") or "merge").lower()
    ledger_path = args.get("ledger_path")
    target = args.get("path") or ""

    if action == "status":
        led = _ledger.load(ledger_path, target)
        if not _ledger.set_status(led, args.get("finding_id", ""), args.get("status", "")):
            return {"ok": False, "error": "unknown finding_id or invalid status"}
        _ledger.save(led, ledger_path)
        return {"ok": True, "action": "status", "finding_id": args.get("finding_id"), "status": args.get("status")}

    if action == "read":
        led = _ledger.load(ledger_path, target)
        return {"ok": True, "action": "read", "ledger": led}

    if args.get("findings"):
        findings = [_finding_from_dict(d) for d in args["findings"]]
    elif target:
        payload = _tool_scan({
            "path": target,
            "tools": args.get("tools"),
            "network": bool(args.get("network", False)),
            "deep": bool(args.get("deep")),
        })
        findings = [_finding_from_dict(d) for d in payload.get("findings", [])]
    else:
        return {"ok": False, "error": "path or findings required"}

    led = _ledger.load(ledger_path, target)
    led, report = _ledger.merge(led, findings, target)
    saved = _ledger.save(led, ledger_path)
    return {"ok": True, "action": "merge", "ledger_path": str(saved),
            "new": report["new"], "known": report["known"], "reopened": report["reopened"],
            "resolved": report["resolved"], "totals": report["totals"]}


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
    deep = bool(args.get("deep"))
    detect = detect_stack(path)
    findings: list[Finding] = []
    ran: list[str] = []

    def want(name: str) -> bool:
        return not selected or name in selected

    if want("exposure"):
        findings.extend(audit_exposure(path, deep=deep))
        ran.append("exposure")
    if want("secrets"):
        findings.extend(scan_secrets(path))
        ran.append("secrets")
    if want("code"):
        findings.extend(scan_code(path))
        ran.append("code")
    if deep and want("iocs"):
        findings.extend(_iocs.scan_iocs(path, deep=deep))
        ran.append("iocs")
    if want("deps") and include_network and (detect.get("lockfiles") or _has_manifest(detect)):
        try:
            findings.extend(audit_deps(path))
            ran.append("deps")
        except Exception as exc:  # keep scan resilient
            ran.append(f"deps:error:{exc}")

    return _findings_payload(
        findings,
        {"target": path, "tools_run": ran, "detect": detect, "deep": deep},
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
        mitre=d.get("mitre", []),
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
        "description": "Scan for leaked credentials, API keys, tokens, private keys, and sensitive files. Set include_history to also scan committed git history.",
        "schema": _schema(
            {
                **PATH_PROP,
                "include_skipped": {"type": "boolean", "description": "Also scan node_modules/vendor (slower)"},
                "include_history": {"type": "boolean", "description": "Also scan git history blobs for leaked secrets"},
            },
            ["path"],
        ),
        "handler": _tool_scan_secrets,
    },
    "scan_code": {
        "description": "Static analysis for dangerous code patterns: client-controlled uploads, injection sinks, RCE preconditions.",
        "schema": _schema(
            {
                **PATH_PROP,
                "languages": {"type": "array", "items": {"type": "string"}, "description": "Filter: php, js, python, go, rust, java, kotlin, csharp, ruby, dart"},
                "max_files": {"type": "integer", "description": "Max files to scan (default 20000)"},
                "workers": {"type": "integer", "description": "Parallel scan workers (default CPU-based)"},
                "use_cache": {"type": "boolean", "description": "Reuse delta cache of unchanged files (default true)"},
            },
            ["path"],
        ),
        "handler": _tool_scan_code,
    },
    "audit_exposure": {
        "description": "Detect exposed/executable/malicious files in web paths and archives: webshells, polyglots, ELF binaries, .env, backups. Set deep to descend into nested archives.",
        "schema": _schema(
            {
                **PATH_PROP,
                "deep": {"type": "boolean", "description": "Extract and scan nested archives (zip/tar inside zip/tar)"},
            },
            ["path"],
        ),
        "handler": _tool_audit_exposure,
    },
    "diff_artifacts": {
        "description": "Compare two directories/archives (baseline vs current) to detect added, removed, or modified files - the active-compromise drift check.",
        "schema": _schema(
            {
                "path_a": {"type": "string", "description": "Baseline (older) directory or archive"},
                "path_b": {"type": "string", "description": "Current (newer) directory or archive"},
                "deep": {"type": "boolean", "description": "Descend into nested archives"},
            },
            ["path_a", "path_b"],
        ),
        "handler": _tool_diff_artifacts,
    },
    "plan": {
        "description": "Build an ordered, explainable audit plan for a target: which tools to run and why, based on detected stack and inputs.",
        "schema": _schema(
            {
                **PATH_PROP,
                "network": {"type": "boolean", "description": "Assume dependency CVE lookup is available (default true)"},
                "deep": {"type": "boolean", "description": "Include deep (nested archive / IoC) steps"},
            },
            ["path"],
        ),
        "handler": _tool_plan,
    },
    "sbom": {
        "description": "Generate a software bill of materials for resolved dependencies as CycloneDX 1.5 or SPDX 2.3 JSON.",
        "schema": _schema(
            {
                **PATH_PROP,
                "format": {"type": "string", "enum": ["cyclonedx", "spdx"], "description": "Output format (default cyclonedx)"},
            },
            ["path"],
        ),
        "handler": _tool_sbom,
    },
    "scan_iocs": {
        "description": "Hash files and match them against the known-bad IoC store. Detects known malware by content hash and the EICAR test file.",
        "schema": _schema(
            {
                **PATH_PROP,
                "ioc_path": {"type": "string", "description": "Override path to the IoC store JSON"},
                "deep": {"type": "boolean", "description": "Descend into nested archives"},
            },
            ["path"],
        ),
        "handler": _tool_scan_iocs,
    },
    "update_feeds": {
        "description": "Sync the indicator-of-compromise store from a remote JSON feed (URL or GRIM_IOC_FEED env).",
        "schema": _schema(
            {
                "url": {"type": "string", "description": "Feed URL (JSON list or {indicators:[...]})"},
                "ioc_path": {"type": "string", "description": "Override path to the IoC store JSON"},
            },
            [],
        ),
        "handler": _tool_update_feeds,
    },
    "ledger": {
        "description": "Persistent findings ledger: track first-seen, known, reopened, and resolved findings across audits. Actions: merge (default), read, status.",
        "schema": _schema(
            {
                **PATH_PROP,
                "action": {"type": "string", "enum": ["merge", "read", "status"], "description": "Ledger operation (default merge)"},
                "ledger_path": {"type": "string", "description": "Override ledger JSON path"},
                "findings": {"type": "array", "items": {"type": "object"}, "description": "Merge these findings instead of scanning"},
                "tools": {"type": "array", "items": {"type": "string"}, "description": "Scan subset when merging from a path"},
                "network": {"type": "boolean", "description": "Allow dependency CVE lookup during merge scan"},
                "deep": {"type": "boolean", "description": "Deep scan during merge"},
                "finding_id": {"type": "string", "description": "Finding id (status action)"},
                "status": {"type": "string", "enum": ["open", "acknowledged", "resolved"], "description": "New status (status action)"},
            },
            [],
        ),
        "handler": _tool_ledger,
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
                "tools": {"type": "array", "items": {"type": "string"}, "description": "Subset: exposure, secrets, code, deps, iocs"},
                "network": {"type": "boolean", "description": "Allow network calls for dependency CVE lookup (default true)"},
                "deep": {"type": "boolean", "description": "Nested archives + IoC hash matching"},
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
