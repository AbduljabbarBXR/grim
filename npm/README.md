# grim-mcp

**Security audit MCP server — finds the gaps, exposures, and active compromise that other scanners miss.**

`grim-mcp` is the MCP distribution of [GRIM](https://github.com/AbduljabbarBXR/grim). The
engine is dependency-free Python (stdlib only); this package bundles it and runs it as a
stdio MCP server, so any MCP client can use it with `npx`.

## Requirements

- Node.js 18+
- Python 3.10+ on `PATH` (override with `GRIM_PYTHON=/path/to/python`)

## Use with an MCP client

```json
{
  "mcp": {
    "grim": {
      "type": "local",
      "command": ["npx", "-y", "grim-mcp"],
      "enabled": true
    }
  }
}
```

Or directly:

```bash
npx -y grim-mcp            # MCP server on stdio (default)
npx -y grim-mcp version    # print engine version
npx -y grim-mcp list       # list audit tools
```

## Tools

| Tool | Purpose |
|---|---|
| `detect_stack` | Identify stack(s) and web-served directories |
| `audit_deps` | Known CVEs in dependencies (live OSV.dev) |
| `scan_secrets` | Leaked keys, tokens, private keys, `.env`; optional git history |
| `scan_code` | SAST across PHP, JS/TS, Python, Ruby, Go, Rust, Java, Kotlin, C#, Dart |
| `audit_exposure` | Webshells, polyglots, ELF, exposed config/backups; nested archives |
| `diff_artifacts` | Baseline vs current drift — the active-compromise check |
| `plan` | Ordered, explainable audit plan for a target |
| `sbom` | CycloneDX 1.5 / SPDX 2.3 bill of materials |
| `scan_iocs` | Match file hashes against a known-bad IoC store (+ EICAR) |
| `update_feeds` | Sync the IoC store from a remote feed |
| `ledger` | Persistent findings ledger: new / known / reopened / resolved |
| `report` | Unified Markdown/JSON report |
| `scan` | One-shot audit across all engines |

Every finding includes severity, confidence, location, evidence, remediation, and a
MITRE ATT&CK technique ID.

## Links

- Source and full documentation: https://github.com/AbduljabbarBXR/grim
- MCP registry: `io.github.AbduljabbarBXR/grim-mcp`

MIT licensed.
