# GRIM

**Security audit server for AI agents. Finds the code, dependency, exposure, secret, and active compromise gaps that other scanners miss.**

> Point it at a folder, a repository, or an archive. Get a prioritized, evidence backed report with fixes.
> Works on any stack, from a new small codebase to a large existing one.

> MCP registry: `io.github.AbduljabbarBXR/grim-mcp` (`mcp-name: io.github.AbduljabbarBXR/grim-mcp`)

**Status: v0.6.2.** Zero runtime dependencies (Python standard library only). Runs on Linux, macOS, Windows, and Termux. 279 tests passing across Python 3.10 to 3.13.

---

## Install

Run it directly with npm:

```bash
npx -y grim-mcp
```

Or install the Python package:

```bash
pip install grim-mcp
grim mcp
```

## Use as an MCP server

```json
{
  "mcpServers": {
    "grim": { "command": "npx", "args": ["-y", "grim-mcp"] }
  }
}
```

Or point directly at a local checkout:

```json
{
  "mcpServers": {
    "grim": {
      "command": "python3",
      "args": ["-m", "grim", "mcp"],
      "env": { "PYTHONPATH": "/path/to/grim/src" }
    }
  }
}
```

## Quickstart

```bash
grim scan /path/to/app                          # one shot audit, Markdown report
grim scan backup.tar.gz --format json --out report.json
grim tool audit_exposure --path backup.tar.gz
grim diff old.tar.gz new.tar.gz                 # drift and active compromise
grim plan /path/to/app                          # ordered audit plan
grim watch /path/to/app --save                  # store a known good baseline
grim watch /path/to/app                          # diff the current state
grim endpoints /path/to/app                      # route inventory and auth risk
grim fix_plan /path/to/app                       # remediation steps and safe diffs
grim malware /path/to/app                        # heuristics, IoC, ClamAV, YARA
grim ci /path/to/app --fail-on high --format sarif
grim mcp                                         # MCP server on stdio
```

---

## What GRIM does

GRIM is an orchestrator for security audits. It runs the right checks for the target, normalizes every result into one finding schema, ranks the findings, and hands an agent or a developer a plain language fix.

- **Exposure and active compromise.** Web executable files in public paths, webshells, polyglots, native binaries, exposed `.env` and backups, and directory listings.
- **Secrets.** API keys, tokens, private keys, and sensitive files, with optional scanning of committed git history.
- **Static analysis.** Dangerous patterns and taint flows across many languages.
- **Dependencies.** Known vulnerabilities through the live OSV advisory database, for every supported lockfile.
- **Endpoints.** Route inventory with method, authentication, input surface, and a risk rank.
- **Drift.** Hashed manifests so a single byte change between a baseline and the current state is caught.
- **Malware.** Built in heuristics and known bad hash matching, plus optional ClamAV and YARA when they are installed.
- **Live checks.** Opt in, scope gated checks of security headers, cookies, TLS, and allowlisted exposed paths.
- **Reporting.** Markdown, JSON, and SARIF 2.1.0, a software bill of materials, and a persistent ledger.

## Design principles

1. **Orchestrator, not reinvention.** Wrap mature engines and feeds. The value is coverage, normalization, prioritization, and remediation.
2. **Evidence over alarms.** Every finding carries a location, a bounded evidence string, a confidence score, and a reproducible fix.
3. **Local first and read only by default.** File scans never write. Live checks are opt in and require an authorization scope.
4. **Any stack.** Next.js, Astro, plain HTML, Laravel and PHP, Node and Express, Python and Django, Go, Ruby, Java, and more.
5. **No silent gaps.** Every limit is configurable, and a scan that hits a limit says so in the result.
6. **Feed driven freshness.** New detection coverage arrives by syncing a signed JSON feed, not by shipping a new release.

## What GRIM is not

- It is not an antivirus and it does not claim complete protection.
- It is not a replacement for a host level scanner such as ClamAV or a server security suite.
- It is not an exploitation tool. Live checks are passive by default and never weaponized.
- It does not touch system files or user documents when it cleans suggestions, because it does not clean at all. It reports and recommends.

---

## How it works

```
detector  ->  planner  ->  runner  ->  normalizer  ->  ranker  ->  report
                                  \->  feeds (rules and indicators)
                                  \->  policy (scope and safety)
```

- **detector** identifies the stack and web served directories from manifests and file patterns.
- **planner** builds an ordered plan: which tools to run, in what order, and why.
- **runner** executes engines with timeouts, resource caps, caching, and parallel work.
- **normalizer** maps every engine result into the GRIM finding schema.
- **ranker** scores by severity and confidence, then deduplicates across engines.
- **report** renders Markdown, JSON, and SARIF, and attaches remediation guidance.
- **feeds** syncs rule overlays and indicator hashes from a JSON feed.
- **policy** enforces the authorization scope for live checks.

## Tools

| Tool | What it does |
| --- | --- |
| `detect_stack` | Identify the stack and the web served directories. Run this first. |
| `plan` | Ordered, explainable audit plan for a target. |
| `scan` | One shot audit across the applicable engines. |
| `audit_exposure` | Webshells, polyglots, ELF binaries, exposed config, and backups, including nested archives. |
| `scan_secrets` | Credentials, tokens, private keys, and sensitive files, with optional git history. |
| `scan_code` | Static analysis and taint flow across many languages. |
| `audit_deps` | Known vulnerabilities through the live OSV database. |
| `inventory_endpoints` | Routes with method, auth middleware, input surface, and risk. |
| `malware_scan` | Built in heuristics and IoC hashes, plus ClamAV and YARA when installed. |
| `watch` | Save a baseline and detect drift on later scans. |
| `diff_artifacts` | Compare a baseline and a current tree or archive. |
| `scan_iocs` | Match file hashes against a known bad indicator store. |
| `update_feeds` | Sync detection rules and indicators from a JSON feed. |
| `check_live` | Opt in live checks of headers, cookies, TLS, and allowlisted paths. |
| `ledger` | Track findings as new, known, reopened, or resolved across audits. |
| `sbom` | CycloneDX 1.5 or SPDX 2.3 bill of materials. |
| `fix_plan` | Remediation steps with safe unified diffs. |
| `ci_scan` | A CI gate that returns an exit code by severity. |
| `report` | Render findings as Markdown, JSON, or SARIF. |

## Language and stack coverage

Static analysis and taint flow:

```
PHP, JavaScript, TypeScript, Python, Ruby, Go, Rust, Java, Kotlin, C#,
Dart, C, C++, Objective C, Swift, Scala, Groovy, Elixir, Erlang, Lua,
Perl, R, Julia, Nim, PowerShell, Shell, Terraform and HCL, Dockerfile,
Clojure, Haskell
```

Lockfiles and manifests:

```
npm, Composer, PyPI, Go modules, Cargo, Pub, Maven, NuGet, RubyGems
```

Endpoint frameworks: Express, Laravel, Django, Go, Next.js, and Astro.

## Finding schema

```json
{
  "id": "GRIM-EXPOS-0007",
  "severity": "critical",
  "confidence": 0.99,
  "category": "CWE-434",
  "owasp": "A04:2021",
  "title": "PHP file present in public upload directory",
  "description": "Web executable code in a public path",
  "location": { "file": "app/public/uploads/example.php", "line": 1 },
  "evidence": "PHP code in a web served upload folder",
  "remediation": "Remove the file, block PHP execution in upload dirs, and fix upload validation on the server",
  "engine": "grim-exposure",
  "first_seen": "2026-09-19T12:00:00+00:00",
  "tags": ["webshell", "active-compromise"],
  "mitre": ["T1505.003"]
}
```

Every finding also carries a MITRE ATT&CK technique when one applies.

## Limits and truncation

Every limit is configurable through environment variables. A value of `0` means unlimited. When a limit is reached GRIM sets `truncated: true`, lists the reasons, adds an information finding, and prints a warning in Markdown reports. Unreadable archives are reported as errors and warnings, and they do not mark a scan as truncated.

| Variable | Default | Applies to |
| --- | --- | --- |
| `GRIM_MAX_ARCHIVE_DEPTH` | 5 | nested archive recursion depth |
| `GRIM_MAX_ARCHIVE_BYTES` | 512 MB | total bytes spilled from nested archives |
| `GRIM_MAX_ARCHIVE_ENTRY_BYTES` | 512 MB | per nested archive size cap |
| `GRIM_MAX_ENTRIES` | 600000 | entries examined and manifest entries |
| `GRIM_MAX_CONTENT_READS` | 60000 | per file content reads |
| `GRIM_MAX_FINDINGS` | 3000 | exposure findings |
| `GRIM_MAX_FILES` | 20000 | source files scanned |
| `GRIM_MAX_RULE_MATCHES` | 10 | hits per rule per file |
| `GRIM_MAX_FILE_FINDINGS` | 200 | findings per file |
| `GRIM_MAX_FLOW_FINDINGS` | 400 | flow analysis findings |
| `GRIM_MAX_CODE_FILE_BYTES` | 1 MB | per file code scan size |
| `GRIM_MAX_SECRET_FILE_BYTES` | 10 MB | per file secrets scan |
| `GRIM_MAX_SECRET_FINDINGS` | 800 | secrets findings |
| `GRIM_MAX_SECRET_FILES` | 200000 | files scanned for secrets |
| `GRIM_MAX_PACKAGES` | 3000 | dependency packages queried |
| `GRIM_MAX_SECONDS` | 0 (off) | wall clock budget per scan |
| `GRIM_SECRET_WORKERS` | 8 | secrets scan threads |
| `GRIM_OSV_WORKERS` | 8 | OSV request threads |
| `GRIM_OSV_BUDGET_SECONDS` | 60 | total OSV network budget |
| `GRIM_FEEDS_URL` | unset | rule and indicator feed URL |
| `GRIM_RULES_CACHE` | `~/.cache/grim/rules.json` | synced rule overlay path |
| `GRIM_CLAMAV` | from PATH | ClamAV binary for `malware_scan` |
| `GRIM_YARA` | from PATH | YARA binary for `malware_scan` |
| `GRIM_YARA_RULES` | unset | YARA rules file or directory |

The delta cache lives at `~/.cache/grim/code/findings.json`. It is keyed by file path and content, invalidated by a rules hash, and written atomically.

## Safety and authorization

- Default mode is local and read only. No network unless a live tool is called.
- Live checks require a scope, in `grim.scope.json` or inline:

```json
{
  "authorization": { "declared_by": "owner or authorized party", "reference": "ticket id" },
  "targets": [
    { "host": "example.com", "mode": "passive",
      "max_requests_per_minute": 30, "paths_allowlist": ["/", "/api/health"] }
  ],
  "deny": ["*/wp-admin/*"]
}
```

- Passive is the default. Active probes run only when the scope says `mode: active` and the exact path is in `paths_allowlist`. Denied patterns are never touched.
- Requests are paced by `max_requests_per_minute`.
- No exploitation payloads, ever.

## CLI reference

```
grim version
grim list
grim scan PATH [--format md|json|sarif] [--out FILE] [--tools ...] [--no-network] [--deep]
grim tool NAME --path P [--path-b P2] [--format md|json|sarif] [--raw]
grim diff A B [--format md|json|sarif] [--deep]
grim ci PATH [--fail-on critical|high|medium|low|info] [--format md|json|sarif] [--out FILE]
grim plan PATH [--no-network] [--deep]
grim sbom PATH [--format cyclonedx|spdx] [--out FILE]
grim watch PATH [--save|--status] [--baseline FILE] [--deep]
grim fix_plan PATH [--format md|json] [--no-patches]
grim endpoints PATH [--format md|json]
grim malware PATH [--deep]
grim check_live URL [--scope FILE] [--active] [--timeout N]
grim ledger PATH [--ledger FILE] [--tools ...]
grim iocs PATH [--deep]
grim update-feeds [--url URL]
grim mcp
```

## Distribution

- npm: `grim-mcp`
- PyPI: `grim-mcp`
- MCP registry: `io.github.AbduljabbarBXR/grim-mcp`, with both npm and PyPI packages
- Smithery: `abdijabarboxer2009/grim-mcp`

## Development

```bash
python3 tests/run_all.py     # runs every tests/test_*.py, no pytest needed
ruff check src tests         # optional lint
python -m build              # source and wheel
```

The test suite is Python standard library only and runs on Python 3.10 through 3.13. CI runs the full suite, lint, and a build and install smoke test.

## Repository layout

```
grim/
├── README.md
├── LICENSE
├── pyproject.toml
├── .github/workflows/ci.yml
├── docs/
│   └── validation.md
├── src/grim/
│   ├── __main__.py
│   ├── tools.py
│   ├── sbom.py
│   ├── core/
│   ├── engines/
│   ├── feeds/
│   └── mcp/
├── npm/
└── tests/
```

---

## Works with

Editors and agents:

<p>
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/claude.svg" alt="Claude Code" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/codex.svg" alt="OpenAI Codex" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/cursor.svg" alt="Cursor" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/cline.svg" alt="Cline" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/windsurf.svg" alt="Windsurf" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/zed.svg" alt="Zed" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/opencode.svg" alt="opencode" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/lmstudio.svg" alt="LM Studio" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/vscodium.svg" alt="VS Code compatible editors" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/neovim.svg" alt="Neovim" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/jetbrains.svg" alt="JetBrains" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/continue.svg" alt="Continue" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/roocode.svg" alt="Roo Code" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/kilocode.svg" alt="Kilo Code" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/goose.svg" alt="Goose" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/aider.svg" alt="Aider" height="26">
</p>

Model providers:

<p>
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/anthropic.svg" alt="Anthropic" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/claude.svg" alt="Claude" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/openai.svg" alt="OpenAI" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/gemini.svg" alt="Google Gemini" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/deepseek.svg" alt="DeepSeek" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/meta.svg" alt="Meta Llama" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/mistral.svg" alt="Mistral" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/qwen.svg" alt="Qwen" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/xai.svg" alt="xAI" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/ollama.svg" alt="Ollama" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/huggingface.svg" alt="Hugging Face" height="26">&nbsp;
<img src="https://cdn.jsdelivr.net/gh/AbduljabbarBXR/grim@main/docs/logos/cohere.svg" alt="Cohere" height="26">
</p>

*GRIM because the things that get you are the things nobody was looking at.*
