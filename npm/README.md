# grim-mcp

**Security audit MCP server. Finds the gaps, exposures, and active compromise that other scanners miss.**

`grim-mcp` is the MCP distribution of [GRIM](https://github.com/AbduljabbarBXR/grim). The engine is Python that uses only the standard library. This package bundles it and runs it as a stdio MCP server, so any MCP client can use it with `npx`.

## Requirements

- Node.js 18 or newer
- Python 3.10 or newer on `PATH` (override with `GRIM_PYTHON`)

## Use with an MCP client

```json
{
  "mcpServers": {
    "grim": { "command": "npx", "args": ["-y", "grim-mcp"] }
  }
}
```

Or directly:

```bash
npx -y grim-mcp            # MCP server on stdio (default)
npx -y grim-mcp version    # print the engine version
npx -y grim-mcp list       # list audit tools
```

Or install the Python package instead:

```bash
pip install grim-mcp
grim mcp
```

## Tools

| Tool | Purpose |
| --- | --- |
| `detect_stack` | Identify the stack and web served directories |
| `audit_deps` | Known CVEs in dependencies through the live OSV database |
| `scan_secrets` | Leaked keys, tokens, private keys, and env files, with optional git history |
| `scan_code` | SAST across many languages |
| `audit_exposure` | Webshells, polyglots, ELF binaries, exposed config and backups, nested archives |
| `diff_artifacts` | Baseline and current drift, the active compromise check |
| `watch` | Save a baseline and detect drift |
| `plan` | Ordered, explainable audit plan for a target |
| `sbom` | CycloneDX 1.5 or SPDX 2.3 bill of materials |
| `scan_iocs` | Match file hashes against a known bad indicator store, plus EICAR |
| `update_feeds` | Sync detection rules and indicators from a JSON feed |
| `ledger` | Track findings as new, known, reopened, or resolved |
| `inventory_endpoints` | Routes with method, auth middleware, input surface, and risk |
| `malware_scan` | Built in heuristics and IoC, plus ClamAV and YARA when installed |
| `check_live` | Opt in, scope gated live checks |
| `fix_plan` | Remediation steps and safe unified diffs |
| `ci_scan` | CI gate that returns an exit code by severity |
| `report` | Unified Markdown, JSON, or SARIF report |

Every finding includes severity, confidence, location, evidence, remediation, and a MITRE ATT&CK technique.

## Links

- Source and full documentation: https://github.com/AbduljabbarBXR/grim
- npm: `grim-mcp`
- PyPI: `grim-mcp`
- MCP registry: `io.github.AbduljabbarBXR/grim-mcp`
- Smithery: `abdijabarboxer2009/grim-mcp` (https://smithery.ai/server/abdijabarboxer2009/grim-mcp)

MIT licensed.
