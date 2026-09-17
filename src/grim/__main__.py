"""GRIM CLI entry point.

Usage:
  grim version
  grim mcp                                  # run MCP server (stdio)
  grim list                                 # list tools
  grim scan PATH [--format md|json] [--out FILE] [--tools ...] [--no-network]
  grim tool NAME --path P [--path-b P2] [--format md|json]
  grim diff A B [--format md|json]
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core.report import render_json, render_markdown, render_summary_line
from .tools import TOOLS, call_tool


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="grim", description="GRIM — security audit for code, deps, exposure, drift")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="print version")
    sub.add_parser("mcp", help="run MCP server over stdio")
    sub.add_parser("list", help="list available tools")

    p_scan = sub.add_parser("scan", help="one-shot audit of a path or archive")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", choices=["md", "json"], default="md")
    p_scan.add_argument("--out", default=None)
    p_scan.add_argument("--tools", default=None, help="subset: exposure,secrets,code,deps")
    p_scan.add_argument("--no-network", action="store_true")

    p_tool = sub.add_parser("tool", help="run a single tool")
    p_tool.add_argument("name")
    p_tool.add_argument("--path", default=None)
    p_tool.add_argument("--path-a", default=None)
    p_tool.add_argument("--path-b", default=None)
    p_tool.add_argument("--format", choices=["md", "json"], default="md")
    p_tool.add_argument("--raw", action="store_true", help="print raw JSON result payload")

    p_diff = sub.add_parser("diff", help="diff two artifacts (baseline vs current)")
    p_diff.add_argument("path_a")
    p_diff.add_argument("path_b")
    p_diff.add_argument("--format", choices=["md", "json"], default="md")

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
        payload = call_tool("diff_artifacts", {"path_a": args.path_a, "path_b": args.path_b})
        return _emit(payload, args.format, None)
    parser.print_help()
    return 1


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
    else:
        from .core.findings import Finding

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
    )


if __name__ == "__main__":
    raise SystemExit(main())
