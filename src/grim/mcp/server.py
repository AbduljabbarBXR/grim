"""Minimal, dependency-free MCP (Model Context Protocol) server over stdio.

Implements JSON-RPC 2.0 with newline-delimited messages as used by MCP stdio transport:
initialize, notifications/initialized, tools/list, tools/call, ping.
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from .. import __version__
from ..tools import call_tool, tool_catalog

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "grim", "version": __version__}


def run_server() -> None:
    """Serve MCP on stdin/stdout. All logging goes to stderr."""
    _log("grim MCP server started (stdio)")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _send_error(None, -32700, "Parse error")
            continue

        if not isinstance(msg, dict):
            continue
        _handle(msg)


def _handle(msg: dict[str, Any]) -> None:
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params") or {}

    if msg_id is None:
        # notification — no response
        if method:
            _log(f"notification: {method}")
        return

    try:
        if method == "initialize":
            requested = params.get("protocolVersion")
            result = {
                "protocolVersion": requested if requested else PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": tool_catalog()}
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not name:
                _send_error(msg_id, -32602, "missing tool name")
                return
            _log(f"tools/call {name}")
            payload = call_tool(name, args)
            result = _mcp_tool_result(payload)
        elif method in ("resources/list", "prompts/list"):
            result = {("resources" if method.startswith("resources") else "prompts"): []}
        else:
            _send_error(msg_id, -32601, f"method not found: {method}")
            return
    except Exception as exc:
        _log("error: " + traceback.format_exc())
        _send_error(msg_id, -32603, f"internal error: {exc}")
        return

    _send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def _mcp_tool_result(payload: dict) -> dict:
    text = json.dumps(payload, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}], "isError": not payload.get("ok", False)}


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, default=str) + "\n")
    sys.stdout.flush()


def _send_error(msg_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def _log(text: str) -> None:
    print(f"[grim] {text}", file=sys.stderr, flush=True)
