"""GRIM tool registry: the MCP-facing surface."""

from __future__ import annotations

from typing import Any, Callable

from . import sbom as _sbom
from .core import baseline as _baseline
from .core import ledger as _ledger
from .core import policy as _policy
from .core.attack import enrich
from .core.detector import detect_stack
from .core.findings import SEVERITY_ORDER, Finding, make_id, rank, summarize
from .core.fixplan import build_fix_plan
from .core.planner import build_plan
from .core.report import render_json, render_markdown, render_sarif
from .engines.codepatterns import scan_code
from .engines.deps import audit_deps
from .engines.diffscan import diff_artifacts
from .engines.endpoints import inventory_endpoints
from .engines.exposure import audit_exposure
from .engines.live import LiveError, check_live
from .engines.malware import scan_malware
from .engines.secrets import scan_secrets, scan_secrets_history
from .engines.watch import save_baseline, watch_diff
from .feeds import iocs as _iocs

Handler = Callable[[dict], dict]


def _meta(engine: str, target: str, stats: dict | None = None, **extra: Any) -> dict:
    """Build tool meta and surface scan truncation, errors, and warnings."""
    meta: dict[str, Any] = {"engine": engine, "target": target, **extra}
    if stats:
        meta["stats"] = stats
        if stats.get("truncated"):
            meta["truncated"] = True
            meta["truncation_reasons"] = stats.get("reasons", [])
        if stats.get("errors"):
            meta["scan_errors"] = stats["errors"]
        if stats.get("warnings"):
            meta["scan_warnings"] = stats["warnings"]
    return meta


def _scan_error_finding(meta: dict) -> Finding:
    warnings = meta.get("scan_warnings") or []
    evidence = "; ".join(warnings) if warnings else "archive could not be read"
    return Finding(
        id=make_id("SCANERR", str(meta.get("target", "scan")), evidence[:120]),
        severity="low",
        confidence=1.0,
        category="CWE-1059",
        owasp="A09:2021",
        title="Scan completed with unreadable archives",
        description=(
            "One or more archives could not be parsed and were not fully scanned. "
            "The rest of the target was scanned normally."
        ),
        location={"file": str(meta.get("target", ""))},
        evidence=evidence[:300],
        remediation="Verify the archive is intact, or extract it and scan the extracted directory.",
        engine="grim",
        tags=["scan-error", "incomplete"],
    )


def _truncation_finding(meta: dict) -> Finding:
    reasons = meta.get("truncation_reasons") or ["result caps reached"]
    return Finding(
        id=make_id("TRUNC", str(meta.get("target", "scan")), "|".join(reasons)),
        severity="info",
        confidence=1.0,
        category="CWE-1059",
        owasp="A09:2021",
        title="Scan was truncated - results are incomplete",
        description=(
            "One or more limits were reached, so some files or archives were not fully scanned. "
            "Raise the relevant GRIM_MAX_* limit or scan a smaller target for complete coverage."
        ),
        location={"file": str(meta.get("target", ""))},
        evidence="; ".join(reasons),
        remediation="Increase the relevant GRIM_MAX_* environment limit and re-run, or split the target.",
        engine="grim",
        tags=["truncated", "incomplete"],
    )


def _findings_payload(findings: list[Finding], meta: dict | None = None) -> dict:
    meta = meta or {}
    if meta.get("truncated"):
        findings = list(findings) + [_truncation_finding(meta)]
    if meta.get("scan_errors"):
        findings = list(findings) + [_scan_error_finding(meta)]
    ranked = enrich(rank(findings))
    return {
        "ok": True,
        "summary": summarize(ranked),
        "findings": [f.to_dict() for f in ranked],
        "meta": meta,
    }


def _tool_detect_stack(args: dict) -> dict:
    return {"ok": True, **detect_stack(args["path"])}


def _tool_audit_deps(args: dict) -> dict:
    stats: dict = {}
    findings = audit_deps(args["path"], stats=stats)
    return _findings_payload(findings, _meta("osv", args["path"], stats))


def _tool_scan_secrets(args: dict) -> dict:
    stats: dict = {}
    findings = scan_secrets(
        args["path"], include_skipped=bool(args.get("include_skipped")), stats=stats
    )
    history = False
    if args.get("include_history"):
        findings.extend(scan_secrets_history(args["path"]))
        history = True
    return _findings_payload(findings, _meta("grim-secrets", args["path"], stats, history=history))


def _tool_watch(args: dict) -> dict:
    action = (args.get("action") or "diff").lower()
    target = args.get("path") or ""
    baseline_path = args.get("baseline_path")
    deep = bool(args.get("deep"))

    if action == "save":
        if not target:
            return {"ok": False, "error": "path is required for action=save"}
        info = save_baseline(target, deep=deep, path=baseline_path)
        return {"ok": True, "action": "save", **info}

    if action == "status":
        saved = _baseline.load(baseline_path, target)
        return {"ok": True, "action": "status", **_baseline.describe(saved)}

    if action == "diff":
        if not target:
            return {"ok": False, "error": "path is required for action=diff"}
        try:
            findings, stats, saved = watch_diff(target, deep=deep, baseline_path=baseline_path)
        except FileNotFoundError as exc:
            return {"ok": False, "error": str(exc)}
        meta = _meta("grim-watch", target, stats, baseline=saved.get("target"), baseline_created=saved.get("created"))
        return _findings_payload(findings, meta)

    return {"ok": False, "error": f"unknown action: {action}"}


def _tool_malware_scan(args: dict) -> dict:
    stats: dict = {}
    findings, _ = scan_malware(args["path"], deep=bool(args.get("deep")), stats=stats)
    return _findings_payload(findings, _meta("grim-malware", args["path"], stats))


def _tool_check_live(args: dict) -> dict:
    url = args.get("url")
    if not url:
        return {"ok": False, "error": "url is required"}
    try:
        scope = _policy.load(args.get("scope_path"), target=args.get("scope_dir"), inline=args.get("scope"))
        stats: dict = {}
        findings = check_live(
            url,
            scope,
            active=bool(args.get("active")),
            timeout=int(args.get("timeout", 10)),
            stats=stats,
        )
    except (_policy.PolicyError, LiveError) as exc:
        return {"ok": False, "error": str(exc)}
    return _findings_payload(findings, _meta("grim-live", url, stats))


def _tool_inventory_endpoints(args: dict) -> dict:
    stats: dict = {}
    endpoints, findings = inventory_endpoints(args["path"], stats=stats)
    by_risk = {r: sum(1 for e in endpoints if e["risk"] == r) for r in ("high", "medium", "low")}
    by_framework: dict[str, int] = {}
    for e in endpoints:
        by_framework[e["framework"]] = by_framework.get(e["framework"], 0) + 1
    payload = _findings_payload(findings, _meta("grim-endpoints", args["path"], stats))
    payload["endpoints"] = endpoints
    payload["endpoint_summary"] = {"total": len(endpoints), "by_risk": by_risk, "by_framework": by_framework}
    return payload


def _tool_fix_plan(args: dict) -> dict:
    if args.get("findings"):
        findings = [_finding_from_dict(d) for d in args["findings"]]
        root = args.get("root")
    elif args.get("path"):
        payload = _tool_scan(
            {
                "path": args["path"],
                "tools": args.get("tools"),
                "network": bool(args.get("network", False)),
                "deep": bool(args.get("deep")),
            }
        )
        findings = [_finding_from_dict(d) for d in payload.get("findings", [])]
        root = args["path"]
    else:
        return {"ok": False, "error": "path or findings required"}
    return build_fix_plan(findings, root=root, include_patches=bool(args.get("include_patches", True)))


def _tool_scan_code(args: dict) -> dict:
    stats: dict = {}
    findings = scan_code(
        args["path"],
        languages=args.get("languages"),
        max_files=args.get("max_files"),
        workers=args.get("workers"),
        use_cache=bool(args.get("use_cache", True)),
        stats=stats,
    )
    return _findings_payload(findings, _meta("grim-codepatterns", args["path"], stats))


def _tool_audit_exposure(args: dict) -> dict:
    stats: dict = {}
    deep = bool(args.get("deep"))
    findings = audit_exposure(args["path"], deep=deep, stats=stats)
    return _findings_payload(findings, _meta("grim-exposure", args["path"], stats, deep=deep))


def _tool_diff_artifacts(args: dict) -> dict:
    deep = bool(args.get("deep"))
    findings, stats = diff_artifacts(args["path_a"], args["path_b"], deep=deep)
    meta = _meta("grim-diff", args["path_b"], stats, baseline=args["path_a"], current=args["path_b"], deep=deep)
    return _findings_payload(findings, meta)


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
    import json

    from .feeds import rules as _rules_feed

    url = args.get("url") or _rules_feed.feed_url() or _iocs.FEED_URL
    if not url:
        return {"ok": False, "error": "no feed URL configured (set GRIM_FEEDS_URL or pass url)"}
    ioc_path = args.get("ioc_path")
    try:
        data = json.loads(_iocs._fetch(url))
    except Exception as exc:
        return {"ok": False, "error": f"feed fetch failed: {exc}"}

    rules_added = 0
    iocs_added = 0
    version = ""
    if isinstance(data, dict):
        version = str(data.get("version") or "")
        if isinstance(data.get("rules"), list):
            rules_added = _rules_feed.save(data["rules"], source=url, version=version)
        indicators = data.get("iocs") or data.get("indicators")
        if isinstance(indicators, list):
            iocs_added = _iocs.add([d for d in indicators if isinstance(d, dict)], ioc_path)
    elif isinstance(data, list):
        iocs_added = _iocs.add([d for d in data if isinstance(d, dict)], ioc_path)

    return {
        "ok": True,
        "source": url,
        "version": version,
        "rules_added": rules_added,
        "iocs_added": iocs_added,
        "rules_total": len(_rules_feed.load_raw().get("rules", [])),
    }


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
    elif fmt == "sarif":
        text = render_sarif(findings, meta)
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
    sub_stats: dict[str, dict] = {}
    reasons: list[str] = []
    errors: list[str] = []

    def want(name: str) -> bool:
        return not selected or name in selected

    def record(name: str, stats: dict) -> None:
        sub_stats[name] = stats
        if stats.get("truncated"):
            for r in stats.get("reasons", []):
                reasons.append(f"{name}: {r}")
        for e in stats.get("errors", []):
            errors.append(f"{name}: {e}")

    if want("exposure"):
        s: dict = {}
        findings.extend(audit_exposure(path, deep=deep, stats=s))
        record("exposure", s)
        ran.append("exposure")
    if want("secrets"):
        s = {}
        findings.extend(scan_secrets(path, stats=s))
        record("secrets", s)
        ran.append("secrets")
    if want("code"):
        s = {}
        findings.extend(scan_code(path, stats=s))
        record("code", s)
        ran.append("code")
    if deep and want("iocs"):
        findings.extend(_iocs.scan_iocs(path, deep=deep))
        ran.append("iocs")
    if want("deps") and include_network and (detect.get("lockfiles") or _has_manifest(detect)):
        try:
            s = {}
            findings.extend(audit_deps(path, stats=s))
            record("deps", s)
            ran.append("deps")
        except Exception as exc:  # keep scan resilient
            ran.append(f"deps:error:{exc}")

    meta: dict = {"target": path, "tools_run": ran, "detect": detect, "deep": deep, "stats": sub_stats}
    if reasons:
        meta["truncated"] = True
        meta["truncation_reasons"] = reasons
    if errors:
        meta["scan_errors"] = errors
        meta["scan_warnings"] = [f"unreadable archive: {e}" for e in errors]
    return _findings_payload(findings, meta)


def _has_manifest(detect: dict) -> bool:
    return any(s.get("manifest") for s in detect.get("stacks", []))


def _tool_ci_scan(args: dict) -> dict:
    """CI gate: run a full scan and return an exit code based on a severity threshold."""
    fail_on = (args.get("fail_on") or "high").lower()
    if fail_on not in SEVERITY_ORDER:
        return {"ok": False, "error": f"invalid fail_on: {fail_on}"}
    payload = _tool_scan(
        {
            "path": args["path"],
            "tools": args.get("tools"),
            "network": bool(args.get("network", True)),
            "deep": bool(args.get("deep")),
        }
    )
    threshold = SEVERITY_ORDER[fail_on]
    counts = payload.get("summary", {}).get("by_severity", {})
    failing = sum(n for sev, n in counts.items() if SEVERITY_ORDER.get(sev, 0) >= threshold)
    payload["fail_on"] = fail_on
    payload["failing"] = failing
    payload["exit_code"] = 1 if failing else 0

    fmt = (args.get("format") or "").lower()
    if fmt in ("json", "md", "markdown", "sarif"):
        findings = [_finding_from_dict(d) for d in payload.get("findings", [])]
        meta = payload.get("meta", {})
        if fmt == "sarif":
            payload["report"] = render_sarif(findings, meta)
        elif fmt == "json":
            payload["report"] = render_json(findings, meta)
        else:
            payload["report"] = render_markdown(findings, meta)
        payload["format"] = fmt
    return payload


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
                "languages": {"type": "array", "items": {"type": "string"}, "description": "Filter by language: php, js, python, ruby, go, rust, java, kotlin, csharp, dart, c, cpp, objc, swift, scala, groovy, elixir, erlang, lua, perl, r, julia, nim, powershell, shell, hcl, dockerfile, clojure, haskell"},
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
    "watch": {
        "description": "Persistent baseline and drift detection. action=save stores the current file manifest; action=diff compares the target to the saved baseline; action=status shows baseline info.",
        "schema": _schema(
            {
                **PATH_PROP,
                "action": {"type": "string", "enum": ["save", "diff", "status"], "description": "Watch operation (default diff)"},
                "baseline_path": {"type": "string", "description": "Override the baseline JSON path"},
                "deep": {"type": "boolean", "description": "Include nested archives"},
            },
            ["path"],
        ),
        "handler": _tool_watch,
    },
    "fix_plan": {
        "description": "Turn findings into an ordered remediation plan, with safe unified-diff patches where a fix is deterministic. Accepts findings or a path to scan.",
        "schema": _schema(
            {
                **PATH_PROP,
                "findings": {"type": "array", "items": {"type": "object"}, "description": "Findings to plan for (alternative to path)"},
                "root": {"type": "string", "description": "Root for relative finding paths"},
                "include_patches": {"type": "boolean", "description": "Emit unified diffs for deterministic fixes (default true)"},
                "tools": {"type": "array", "items": {"type": "string"}, "description": "Scan subset when planning from a path"},
                "network": {"type": "boolean", "description": "Allow dependency CVE lookup during the scan"},
                "deep": {"type": "boolean", "description": "Deep scan when planning from a path"},
            },
            [],
        ),
        "handler": _tool_fix_plan,
    },
    "inventory_endpoints": {
        "description": "Enumerate application routes (Express, Laravel, Django, Go, Next.js, Astro) with method, auth middleware, input surface, and risk rank.",
        "schema": _schema({**PATH_PROP}, ["path"]),
        "handler": _tool_inventory_endpoints,
    },
    "check_live": {
        "description": "Opt-in live checks for an authorized host: security headers, cookies, TLS, and (if the scope allows) allowlisted exposed paths. Requires a scope (file or inline).",
        "schema": _schema(
            {
                "url": {"type": "string", "description": "Target URL or host (must be authorized by the scope)"},
                "scope": {"type": "object", "description": "Inline scope object"},
                "scope_path": {"type": "string", "description": "Path to grim.scope.json"},
                "scope_dir": {"type": "string", "description": "Directory to search for grim.scope.json"},
                "active": {"type": "boolean", "description": "Allow active probes (also requires scope target mode=active)"},
                "timeout": {"type": "integer", "description": "Per-request timeout seconds (default 10)"},
            },
            ["url"],
        ),
        "handler": _tool_check_live,
    },
    "malware_scan": {
        "description": "Malware scan: built-in webshell/polyglot/ELF heuristics and IoC hashes, plus optional ClamAV and YARA if installed.",
        "schema": _schema(
            {
                **PATH_PROP,
                "deep": {"type": "boolean", "description": "Descend into nested archives"},
            },
            ["path"],
        ),
        "handler": _tool_malware_scan,
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
        "description": "Sync detection feeds: SAST rules and IoC hashes, from a URL or GRIM_FEEDS_URL. Feed is JSON: {version, rules:[...], iocs:[...]} or a bare IoC list.",
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
    "ci_scan": {
        "description": "CI gate: run a full scan and return an exit code (1 when findings at or above the fail_on severity exist). Pair with SARIF output for pipelines.",
        "schema": _schema(
            {
                **PATH_PROP,
                "fail_on": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity threshold that fails the build (default high)",
                },
                "tools": {"type": "array", "items": {"type": "string"}, "description": "Subset: exposure, secrets, code, deps, iocs"},
                "network": {"type": "boolean", "description": "Allow dependency CVE lookup (default true)"},
                "deep": {"type": "boolean", "description": "Nested archives + IoC hash matching"},
                "format": {"type": "string", "enum": ["sarif", "json", "md"], "description": "Also return a rendered report under 'report' (sarif for pipelines)"},
            },
            ["path"],
        ),
        "handler": _tool_ci_scan,
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
