#!/usr/bin/env python3
"""Build the Smithery `.mcpb` bundle for grim-mcp.

Run after `node scripts/sync-python.mjs` (or via the npm script `build:mcpb`).
Requires the repo's `src/grim` to be importable.
"""

from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
NPM = HERE.parent
REPO = NPM.parent
STAGE = NPM / ".mcpb-stage"
OUT = NPM / "grim-mcp.mcpb"

sys.path.insert(0, str(REPO / "src"))

from grim import __version__  # noqa: E402
from grim.tools import TOOLS  # noqa: E402


def main() -> int:
    if not (NPM / "python" / "grim" / "__main__.py").exists():
        print("bundled python missing; run `node scripts/sync-python.mjs` first", file=sys.stderr)
        return 1
    shutil.rmtree(STAGE, ignore_errors=True)
    STAGE.mkdir(parents=True)
    shutil.copytree(
        NPM / "python",
        STAGE / "python",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    tools = [
        {"name": name, "description": meta["description"], "inputSchema": meta["schema"]}
        for name, meta in TOOLS.items()
    ]
    manifest = {
        "manifest_version": "0.2",
        "name": "grim-mcp",
        "version": __version__,
        "description": "Security audit for AI agents: code, deps, exposure, secrets, drift, SBOM, and IoC.",
        "author": {"name": "AbduljabbarBXR", "url": "https://github.com/AbduljabbarBXR/grim"},
        "homepage": "https://github.com/AbduljabbarBXR/grim",
        "server": {
            "type": "python",
            "mcp_config": {
                "command": "python3",
                "args": ["-m", "grim", "mcp"],
                "env": {"PYTHONPATH": "${__dirname}/python"},
            },
        },
        "tools": tools,
    }
    (STAGE / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if OUT.exists():
        OUT.unlink()
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(STAGE.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(STAGE).as_posix())
    shutil.rmtree(STAGE, ignore_errors=True)
    print(f"built {OUT} ({OUT.stat().st_size} bytes, {len(tools)} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
