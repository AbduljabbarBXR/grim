"""GRIM CLI entry point.

Usage:
  grim version
  grim mcp                                  # run MCP server (stdio)
  grim list                                 # list tools
  grim scan PATH [--format md|json] [--out FILE] [--tools ...] [--no-network] [--deep]
  grim tool NAME --path P [--path-b P2] [--format md|json]
  grim diff A B [--format md|json] [--deep]
  grim plan PATH [--no-network] [--deep]
  grim sbom PATH [--format cyclonedx|spdx] [--out FILE]
  grim ledger PATH [--ledger FILE] [--tools ...]
  grim iocs PATH [--deep]
  grim update-feeds [--url URL]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core.report import render_markdown, render_sarif, render_summary_line
from .tools import TOOLS, call_tool


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="grim", description="GRIM — security audit for code, deps, exposure, drift")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="print version")
    sub.add_parser("mcp", help="run MCP server over stdio")
    sub.add_parser("list", help="list available tools")

    p_scan = sub.add_parser("scan", help="one-shot audit of a path or archive")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    p_scan.add_argument("--out", default=None)
    p_scan.add_argument("--tools", default=None, help="subset: exposure,secrets,code,deps,iocs")
    p_scan.add_argument("--no-network", action="store_true")
    p_scan.add_argument("--deep", action="store_true", help="nested archives + IoC hash matching")

    p_tool = sub.add_parser("tool", help="run a single tool")
    p_tool.add_argument("name")
    p_tool.add_argument("--path", default=None)
    p_tool.add_argument("--path-a", default=None)
    p_tool.add_argument("--path-b", default=None)
    p_tool.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    p_tool.add_argument("--raw", action="store_true", help="print raw JSON result payload")

    p_diff = sub.add_parser("diff", help="diff two artifacts (baseline vs current)")
    p_diff.add_argument("path_a")
    p_diff.add_argument("path_b")
    p_diff.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    p_diff.add_argument("--deep", action="store_true")

    p_ci = sub.add_parser("ci", help="CI gate: scan and exit non-zero at or above --fail-on")
    p_ci.add_argument("path")
    p_ci.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default="high")
    p_ci.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    p_ci.add_argument("--out", default=None)
    p_ci.add_argument("--tools", default=None)
    p_ci.add_argument("--no-network", action="store_true")
    p_ci.add_argument("--deep", action="store_true")

    p_watch = sub.add_parser("watch", help="save a baseline and detect drift")
    p_watch.add_argument("path")
    p_watch.add_argument("--save", action="store_true", help="save/refresh the baseline")
    p_watch.add_argument("--status", action="store_true", help="show baseline info")
    p_watch.add_argument("--baseline", default=None, help="baseline JSON path")
    p_watch.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    p_watch.add_argument("--deep", action="store_true")

    p_fix = sub.add_parser("fix_plan", help="turn findings into a remediation plan and diffs")
    p_fix.add_argument("path")
    p_fix.add_argument("--format", choices=["md", "json"], default="md")
    p_fix.add_argument("--out", default=None)
    p_fix.add_argument("--no-network", action="store_true")
    p_fix.add_argument("--no-patches", action="store_true")
    p_fix.add_argument("--deep", action="store_true")

    p_ep = sub.add_parser("endpoints", help="inventory application routes and rank risk")
    p_ep.add_argument("path")
    p_ep.add_argument("--format", choices=["md", "json"], default="md")
    p_ep.add_argument("--out", default=None)

    p_plan = sub.add_parser("plan", help="show the audit plan for a target")
    p_plan.add_argument("path")
    p_plan.add_argument("--no-network", action="store_true")
    p_plan.add_argument("--deep", action="store_true")

    p_sbom = sub.add_parser("sbom", help="emit CycloneDX/SPDX SBOM")
    p_sbom.add_argument("path")
    p_sbom.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx")
    p_sbom.add_argument("--out", default=None)

    p_ledger = sub.add_parser("ledger", help="merge a scan into the persistent findings ledger")
    p_ledger.add_argument("path")
    p_ledger.add_argument("--ledger", default=None)
    p_ledger.add_argument("--tools", default=None)
    p_ledger.add_argument("--deep", action="store_true")

    p_iocs = sub.add_parser("iocs", help="match file hashes against the IoC store")
    p_iocs.add_argument("path")
    p_iocs.add_argument("--deep", action="store_true")

    p_feeds = sub.add_parser("update-feeds", help="sync the IoC store from a feed URL")
    p_feeds.add_argument("--url", default=None)
    p_feeds.add_argument("--ioc-path", default=None)

    args = parser.parse_args(argv)

    if args.command in (None, "version"):
        print(f"grim {__version__}")
        return 0
    if args.command == "mcp":
        from .mcp.server import run_server

        run_server()
        return 0
    if args.command == "list":
        for name, meta in TOOLS.items():
            print(f"{name:16s} {meta['description']}")
        return 0
    if args.command == "scan":
        tool_args = {"path": args.path}
        if args.tools:
            tool_args["tools"] = [t.strip() for t in args.tools.split(",") if t.strip()]
        if args.no_network:
            tool_args["network"] = False
        if args.deep:
            tool_args["deep"] = True
        payload = call_tool("scan", tool_args)
        return _emit(payload, args.format, args.out)
    if args.command == "tool":
        if args.name not in TOOLS:
            print(f"unknown tool: {args.name}", file=sys.stderr)
            return 2
        tool_args = _build_tool_args(args.name, args)
        payload = call_tool(args.name, tool_args)
        if args.raw:
            print(json.dumps(payload, indent=2, default=str))
            return 0 if payload.get("ok") else 1
        return _emit(payload, args.format, None)
    if args.command == "diff":
        payload = call_tool("diff_artifacts", {"path_a": args.path_a, "path_b": args.path_b,
                                               "deep": bool(args.deep)})
        return _emit(payload, args.format, None)
    if args.command == "ci":
        tool_args: dict = {"path": args.path, "fail_on": args.fail_on,
                           "network": not args.no_network, "deep": bool(args.deep)}
        if args.tools:
            tool_args["tools"] = [t.strip() for t in args.tools.split(",") if t.strip()]
        payload = call_tool("ci_scan", tool_args)
        if not payload.get("ok"):
            print(f"error: {payload.get('error')}", file=sys.stderr)
            return 2
        code = int(payload.get("exit_code", 0))
        summary = render_summary_line([_to_finding(d) for d in payload.get("findings", [])])
        if args.format == "md":
            text = render_markdown([_to_finding(d) for d in payload.get("findings", [])], payload.get("meta", {}))
            text += f"\n{summary}\nCI gate (fail_on={args.fail_on}): {'FAIL' if code else 'PASS'}\n"
        elif args.format == "sarif":
            text = render_sarif([_to_finding(d) for d in payload.get("findings", [])], payload.get("meta", {}))
        else:
            text = json.dumps(payload, indent=2, default=str)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.out} ({summary})")
        else:
            print(text)
        return code
    if args.command == "watch":
        action = "save" if args.save else "status" if args.status else "diff"
        tool_args: dict = {"path": args.path, "action": action, "deep": bool(args.deep)}
        if args.baseline:
            tool_args["baseline_path"] = args.baseline
        payload = call_tool("watch", tool_args)
        if action == "diff":
            return _emit(payload, args.format, None)
        return _print_json(payload)
    if args.command == "fix_plan":
        plan = call_tool("fix_plan", {
            "path": args.path,
            "network": not args.no_network,
            "include_patches": not args.no_patches,
            "deep": bool(args.deep),
        })
        if not plan.get("ok"):
            print(f"error: {plan.get('error')}", file=sys.stderr)
            return 1
        if args.format == "json":
            text = json.dumps(plan, indent=2, default=str)
        else:
            text = _render_fix_plan(plan)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0
    if args.command == "plan":
        return _print_json(call_tool("plan", {"path": args.path,
                                              "network": not args.no_network,
                                              "deep": args.deep}))
    if args.command == "endpoints":
        payload = call_tool("inventory_endpoints", {"path": args.path})
        if not payload.get("ok"):
            print(f"error: {payload.get('error')}", file=sys.stderr)
            return 1
        if args.format == "json":
            text = json.dumps(payload, indent=2, default=str)
        else:
            text = _render_endpoints(payload)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0
    if args.command == "sbom":
        payload = call_tool("sbom", {"path": args.path, "format": args.format})
        if not payload.get("ok"):
            print(f"error: {payload.get('error')}", file=sys.stderr)
            return 1
        text = json.dumps(payload["bom"], indent=2, default=str)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.out} ({payload['component_count']} components)")
        else:
            print(text)
        return 0
    if args.command == "ledger":
        tool_args: dict = {"path": args.path, "deep": bool(args.deep)}
        if args.ledger:
            tool_args["ledger_path"] = args.ledger
        if args.tools:
            tool_args["tools"] = [t.strip() for t in args.tools.split(",") if t.strip()]
        return _print_json(call_tool("ledger", tool_args))
    if args.command == "iocs":
        payload = call_tool("scan_iocs", {"path": args.path, "deep": bool(args.deep)})
        return _emit(payload, "md", None)
    if args.command == "update-feeds":
        tool_args = {"url": args.url, "ioc_path": args.ioc_path}
        return _print_json(call_tool("update_feeds", {k: v for k, v in tool_args.items() if v}))
    parser.print_help()
    return 1


def _print_json(payload: dict) -> int:
    print(json.dumps(payload, indent=2, default=str))
    return 0 if payload.get("ok") else 1


def _render_endpoints(payload: dict) -> str:
    s = payload.get("endpoint_summary", {})
    lines = ["# GRIM Endpoint Inventory", ""]
    lines.append(f"- total endpoints: {s.get('total', 0)}")
    lines.append(f"- by risk: {s.get('by_risk', {})}")
    lines.append(f"- by framework: {s.get('by_framework', {})}")
    lines.append("")
    order = {"high": 0, "medium": 1, "low": 2}
    rows = sorted(payload.get("endpoints", []), key=lambda e: (order.get(e.get("risk"), 3), e.get("path", "")))
    if rows:
        lines.append("| Risk | Method | Path | Auth | Inputs | File |")
        lines.append("|---|---|---|---|---|---|")
        for e in rows:
            lines.append(
                f"| {e.get('risk')} | {e.get('method')} | `{e.get('path')}` | "
                f"{'yes' if e.get('auth') else 'no'} | {'yes' if e.get('inputs') else 'no'} | "
                f"`{e.get('file')}:{e.get('line')}` |"
            )
    return "\n".join(lines)


def _render_fix_plan(plan: dict) -> str:
    s = plan.get("summary", {})
    lines = ["# GRIM Fix Plan", "", f"- findings: {s.get('total', 0)} | steps: {s.get('steps', 0)} | patchable: {s.get('patchable', 0)}", ""]
    for st in plan.get("steps", []):
        loc = str(st.get("file", "")) + (f":{st['line']}" if st.get("line") else "")
        review = " (review)" if st.get("requires_review") else ""
        lines.append(f"## [{str(st.get('severity', '')).upper()}] {st.get('title', '')}{review}")
        lines.append(f"- Location: `{loc}`")
        if st.get("action"):
            lines.append(f"- Action: {st['action']}")
        if st.get("evidence"):
            lines.append(f"- Evidence: `{str(st['evidence'])[:160]}`")
        lines.append("")
    if plan.get("patch"):
        lines.append("## Suggested patch")
        lines.append("```diff")
        lines.append(plan["patch"].rstrip())
        lines.append("```")
    return "\n".join(lines)


def _build_tool_args(name: str, args: argparse.Namespace) -> dict:
    schema_props = TOOLS[name]["schema"].get("properties", {})
    provided = {
        "path": args.path,
        "path_a": args.path_a,
        "path_b": args.path_b,
    }
    return {k: v for k, v in provided.items() if k in schema_props and v is not None}


def _emit(payload: dict, fmt: str, out: str | None) -> int:
    if not payload.get("ok"):
        print(f"error: {payload.get('error')}", file=sys.stderr)
        return 1
    if fmt == "json":
        text = json.dumps(payload, indent=2, default=str)
    elif fmt == "sarif":
        findings = [_to_finding(d) for d in payload.get("findings", [])]
        text = render_sarif(findings, payload.get("meta", {}))
    else:
        findings = [_to_finding(d) for d in payload.get("findings", [])]
        text = render_markdown(findings, payload.get("meta", {}))
        text += "\n" + render_summary_line(findings) + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {out} ({render_summary_line([_to_finding(d) for d in payload.get('findings', [])])})")
    else:
        print(text)
    return 0


def _to_finding(d: dict):
    from .core.findings import Finding

    return Finding(
        id=d.get("id", ""),
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


if __name__ == "__main__":
    raise SystemExit(main())
