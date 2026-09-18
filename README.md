# GRIM

**Security audit MCP server — finds the gaps, exposures, and active compromise that other scanners miss.**

> Works on any stack. For AI-built apps and existing complex codebases. Point it at a folder,
> a repo, or an authorized live URL, and get a prioritized, evidence-backed report with fixes.

**Status: v0.2.0.** v1 validated against a real compromise; v2 adds the planner, SBOM,
MITRE ATT&CK tagging, an IoC hash feed, a persistent findings ledger, nested-archive
scanning, a delta cache, and parallel scanning. Zero runtime dependencies (Python stdlib
only), runs on Linux/macOS/Windows and Termux. 114 tests passing across Python 3.10–3.13.

---

## Quickstart

```bash
# from the repo root (no install needed)
PYTHONPATH=src python3 -m grim list
PYTHONPATH=src python3 -m grim scan /path/to/app            # one-shot audit (md report)
PYTHONPATH=src python3 -m grim scan backup.tar.gz --format json --out report.json
PYTHONPATH=src python3 -m grim tool audit_exposure --path /path/to/backup.tar.gz
PYTHONPATH=src python3 -m grim diff old.tar.gz new.tar.gz   # drift / active compromise
PYTHONPATH=src python3 -m grim mcp                          # MCP server on stdio
```

Optional real install: `pip install -e .` (then `grim ...` works anywhere).

### Develop and test

```bash
python3 tests/run_all.py     # runs every tests/test_*.py, no pytest needed
ruff check src tests         # optional lint (pip install ruff)
python -m build              # sdist + wheel
```

CI runs the full suite on Python 3.10, 3.11, 3.12, and 3.13, plus `ruff` and a
build/install smoke test (`.github/workflows/ci.yml`).

### Use as MCP server in opencode

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "grim": {
      "type": "local",
      "command": ["python3", "-m", "grim", "mcp"],
      "enabled": true,
      "environment": { "PYTHONPATH": "/path/to/grim/src" }
    }
  }
}
```

Then the agent can call `audit_exposure`, `scan_code`, `diff_artifacts`, `scan`, and friends
directly while building or reviewing any app.

---

## Table of Contents

1. [Why GRIM exists](#1-why-grim-exists)
2. [Design principles](#2-design-principles)
3. [What GRIM is / is not](#3-what-grim-is--is-not)
4. [Architecture](#4-architecture)
5. [The four gap classes](#5-the-four-gap-classes)
6. [MCP tool surface](#6-mcp-tool-surface)
7. [Finding schema](#7-finding-schema)
8. [Engines and auto-updating feeds](#8-engines-and-auto-updating-feeds)
9. [Safety and authorization model](#9-safety-and-authorization-model)
10. [Roadmap](#10-roadmap)
11. [Case study: what GRIM would have caught](#11-case-study-what-grim-would-have-caught)
12. [Repo layout](#12-repo-layout)
13. [Tech stack](#13-tech-stack)
14. [Non-goals and honest limitations](#14-non-goals-and-honest-limitations)
15. [Open questions](#15-open-questions)

---

## 1. Why GRIM exists

AI coding agents can build and modify whole applications in hours. Security tooling did not
adapt to that workflow:

- **Scanners exist. Orchestration does not.** Semgrep, Trivy, gitleaks, nuclei, ClamAV, YARA,
  OSV — all open source, all excellent, all separate. Nothing runs the right set per stack,
  normalizes the output, ranks it, explains it in plain language, and hands the AI agent a fix.
- **Signature engines are blind to app-logic flaws.** A server malware scanner cleans a webshell
  but cannot see the vulnerable upload handler that keeps writing new ones.
- **File-policy failures are invisible to antivirus.** Executable files landing in public upload
  directories is a *policy* problem, not a virus signature problem, until it is too late.
- **Nobody watches drift.** The single highest-signal security check for "is this system
  compromised right now?" is: *what changed since the last known-good state?* Almost nobody
  runs it.

One real incident (see [case study](#11-case-study-what-grim-would-have-caught)) took three
months of undetected access, credential harvesting, and executed native binaries before a
manual audit found it in under an hour. Every artifact was findable by existing engines.
No single tool was looking.

**GRIM is the looker.**

---

## 2. Design principles

1. **Orchestrator, not reinvention.** Wrap mature engines. The value is selection, coverage,
   normalization, prioritization, and remediation — not another regex engine.
2. **Evidence over alarms.** Every finding carries: file/URL, timestamp, engine, raw evidence,
   and reproducible command. No "something is wrong somewhere".
3. **Read-only by default.** File scanning never modifies. Live checks are passive unless an
   explicit authorization scope enables active probes.
4. **AI-native output.** Every tool returns machine-stable JSON plus an optional human narrative.
   Findings include remediation text an AI agent (or a junior dev) can apply directly.
5. **Feed-driven freshness.** New malware coverage arrives by syncing upstream feeds
   (OSV, Semgrep registry, nuclei templates, ClamAV, YARA repos) — not by shipping app updates.
6. **Any stack.** Next.js, Astro, plain HTML, Laravel/PHP, Node/Express, Python/Django, Go,
   static sites, container images. Detection first, then stack-specific engines.
7. **Low-resource capable.** Runs on a laptop, a small VPS, or an Android/Termux device for
   offline audits of downloaded backups and clones.

---

## 3. What GRIM is / is not

| GRIM is | GRIM is not |
|---|---|
| An MCP server exposing security tools to AI agents | An antivirus product |
| A security *orchestrator* over proven engines | A replacement for Imunify360/ClamAV |
| Code, dependency, exposure, and drift analysis | A guarantee of 100% coverage |
| Passive live checks + authorized active checks | An exploitation framework |
| A findings normalizer with fix guidance | A compliance certification tool |

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  AI agent (opencode / Claude / Cursor / any MCP client)      │
└──────────────────────────────┬───────────────────────────────┘
                               │  MCP (stdio / http)
┌──────────────────────────────▼───────────────────────────────┐
│                          GRIM CORE                            │
│  detector → planner → runner → normalizer → ranker → report  │
│  policy (scope, safety)      feeds (auto-update)             │
└───────┬───────────────────────────────────────────────┬──────┘
        │                                               │
┌───────▼──────────┐   ┌──────────────────┐   ┌─────────▼──────┐
│ Static engines   │   │ Exposure/Dir     │   │ Live engines   │
│ semgrep, gitleaks│   │ file-policy,     │   │ nuclei, header │
│ trivy, phpstan,  │   │ backup-diff,     │   │ checks, TLS    │
│ bandit, osv.dev  │   │ watch/baseline   │   │ fingerprint    │
└──────────────────┘   └──────────────────┘   └────────────────┘
        │                       │                      │
┌───────▼───────────────────────▼──────────────────────▼───────┐
│                        Malware engines                        │
│            ClamAV (freshclam) · YARA (community repos)        │
└──────────────────────────────────────────────────────────────┘
```

**Core modules**

- `detector` — identifies stack(s) from manifests and file patterns; selects engine plan.
- `planner` — decides which tools run given target type (repo/folder/live), depth, and policy.
- `runner` — executes engines with timeouts, resource caps, parallelism, caching of results.
- `normalizer` — maps every engine output into the GRIM finding schema (`§7`).
- `ranker` — severity × confidence × exploitability scoring; dedupes cross-engine findings.
- `report` — renders Markdown/JSON/SARIF; attaches remediation guidance.
- `feeds` — updates rule/signature/template feeds (`§8`).
- `policy` — authorization scope enforcement and safety gates (`§9`).

---

## 5. The four gap classes

GRIM's coverage model. Every tool belongs to one or more:

1. **Code-level gaps** — unvalidated inputs, unsafe uploads, missing authorization,
   injection sinks, dangerous patterns. *(classic SAST)*
2. **Dependency gaps** — known CVEs in package ecosystems.
3. **Exposure gaps** — secrets in code, `.env`/`.git`/backups/web-executable files reachable,
   misconfigured headers/cookies, writable public directories.
4. **Active compromise** — file drift since baseline, known malware signatures, polyglot
   webshells, unexpected executables, live indicators (suspicious paths responding 200).

---

## 6. MCP tool surface

### v1 (MVP — ship first)

| Tool | Purpose | Inputs | Engines |
|---|---|---|---|
| `detect_stack` | Identify stack(s) and produce an audit plan | `path` | built-in detectors |
| `audit_deps` | Known CVEs in dependencies | `path` | OSV.dev API, ecosystem lockfiles |
| `scan_secrets` | Leaked keys, tokens, `.env` in tree | `path`, `config?` | gitleaks, trufflehog, heuristics |
| `scan_code` | Injection, upload, authz, unsafe pattern findings | `path`, `ruleset?` | Semgrep (+registry), PHPStan/Psalm, Bandit, eslint-security |
| `audit_exposure` | Web-exposed dangerous files in a tree/backup | `path` (dir, tar, zip) | built-in file-policy engine |
| `report` | Unified prioritized report + fixes | `findings`, `format` | ranker + renderer |

### v2 planned (not yet shipped)

| Tool | Purpose | Inputs | Engines |
|---|---|---|---|
| `inventory_endpoints` | Every route: method, auth middleware, input surface, risk rank | `path` | framework parsers (Laravel, Next/Astro, Express, Django, Go) |
| `check_live` | Passive (default) / authorized active live checks | `url`, `scope` | nuclei (passive templates), custom HTTP/TLS/header checks |
| `malware_scan` | Known malware, webshells, polyglots, ELF-in-webdir | `path` | ClamAV, YARA (community rules) |
| `watch` | Baseline + drift detection between runs | `path`, `baseline` | hash manifests + semantic diff |

### v3

- `update_feeds` — force-sync all rule/signature feeds and report versions
- `ci_scan` — non-interactive mode for pipelines with exit codes
- `fix_plan` — turn findings into patch suggestions / PR-ready diffs
- Node agent mode — long-running watchdog for live servers without root (PHP/shell cron
  companion that reports into GRIM)

### v2 shipped (0.2.0)

| Tool / feature | Purpose |
|---|---|
| `plan` | Ordered, explainable audit plan derived from the detected stack |
| `sbom` | CycloneDX 1.5 / SPDX 2.3 bill of materials for resolved dependencies |
| `scan_iocs` | Match file hashes against a known-bad IoC store (+ EICAR) |
| `update_feeds` | Sync the IoC store from a remote JSON feed |
| `ledger` | Persistent findings ledger: new / known / reopened / resolved across audits |
| MITRE ATT&CK | Every finding auto-tagged with technique IDs (e.g. `T1505.003`) |
| Nested archives | `deep=true` extracts zip/tar inside zip/tar with traversal and size guards |
| Delta cache | SHA-256 keyed per-file result cache; unchanged files are not re-scanned |
| Parallel scanning | Thread-pool SAST across files (`workers`) |

### Example call

```json
{
  "tool": "audit_exposure",
  "arguments": {
    "path": "/audits/backup_2026_09_17.tar.gz",
    "checks": ["web-executable", "dotfiles", "exposed-config", "backup-files", "elf-in-public"]
  }
}
```

```json
{
  "findings": [
    {
      "id": "GRIM-EXPOS-0007",
      "severity": "critical",
      "category": "CWE-434",
      "owasp": "A04:2021",
      "title": "PHP file present in public upload directory",
      "location": { "file": "app/public/uploads/img/sample-....php" },
      "evidence": "520 bytes; contains password-gated command form; folder is web-served",
      "remediation": "Remove file; block PHP execution in upload dirs; fix upload validation server-side",
      "confidence": 0.99,
      "engine": "grim-filepolicy@0.1"
    }
  ]
}
```

---

## 7. Finding schema

All engines normalize to this object:

```json
{
  "id": "GRIM-<CLASS>-<NNNN>",
  "severity": "critical | high | medium | low | info",
  "confidence": 0.0,
  "category": "CWE-xxx",
  "owasp": "A01:2021 | ...",
  "title": "short human title",
  "description": "what it is and why it matters",
  "location": {
    "file": "relative/path",
    "line": 0,
    "url": "https://... (live findings)",
    "artifact": "backup.tar.gz (when extracted)"
  },
  "evidence": "raw snippet / header / hash / timestamp — minimal and safe",
  "remediation": "actionable fix, code-level when possible",
  "references": ["https://..."],
  "engine": "name@version",
  "first_seen": "ISO-8601",
  "tags": ["upload", "rce", "active-compromise"]
}
```

Design rules:
- **No false certainty**: `confidence` always present; ranker sorts by severity × confidence.
- **Dedupe**: same location + category from multiple engines merges into one finding.
- **Safe evidence**: truncate secrets; never include full key material in reports.

---

## 8. Engines and auto-updating feeds

| Domain | Engine | Feed / update path | Freshness |
|---|---|---|---|
| Dependencies (all ecosystems) | OSV.dev API | live API | real-time |
| SAST (multi-language) | Semgrep OSS | registry rules (`--config auto` + pinned sets) | continuous |
| Secrets | gitleaks / trufflehog | built-in rules + custom GRIM patterns | per release |
| PHP | PHPStan, Psalm, Enlightn | composer install | per release |
| JS/TS | eslint-plugin-security, `npm audit` | npm | continuous |
| Python | Bandit, `pip-audit` | PyPI advisories | continuous |
| Filesystem/containers | Trivy | built-in DB (auto-download) | daily |
| Live checks | nuclei | templates repo | daily |
| Malware signatures | ClamAV | `freshclam` | hours |
| Malware heuristics | YARA (Neo23x0/signature-base, Elastic, etc.) | git pull | days |
| File policy + drift | GRIM built-in | GRIM rules file (remote-syncable) | versioned |

**The auto-update answer:** new malware is caught by *feeds*, not by GRIM releases.
GRIM ships the pipeline; ClamAV/YARA/nuclei/Semgrep/OSV ship the ever-fresh detection data.
GRIM's own heuristic rules (upload-dir policy, dangerous patterns) are a single versioned
rules file that can be hosted remotely and pulled by every installation.

---

## 9. Safety and authorization model

- **Default mode is read-only and local.** File scans never write; no network unless a live
  tool is invoked.
- **Live checks require a scope file** (`grim.scope.yaml`):

```yaml
authorization:
  declared_by: "owner or authorized party"
  reference: "contract/ticket id"
targets:
  - host: "example.com"
    mode: passive        # passive | active
    max_requests_per_minute: 30
    paths_allowlist: ["/", "/api/health"]
deny:
  - "*/wp-admin/*"
```

- **No exploitation payloads, ever.** Active mode = safe probes (exposure checks, header/TLS
  analysis), not weaponized attacks.
- **Rate-limited, allowlisted, auditable.** Every live request logged with timestamp + target.
- **Backups treated as evidence**: extraction is isolated and never modifies source archives.

---

## 10. Roadmap

**Phase 0 — spec and fixtures (this document)**
- Two sanitized real-world corpora: a compromised app export and a clean baseline
- Golden output files for regression tests

**Phase 1 — v1 tools (MVP)**
- `detect_stack`, `audit_deps`, `scan_secrets`, `scan_code`, `audit_exposure`, `report`
- CLI mode + MCP server mode
- Finding schema + Markdown/JSON renderers
- Termux-friendly (no root dependencies for v1 tools)

**Phase 2 — v2 tools**
- Shipped in 0.2.0: `plan`, `sbom` (CycloneDX/SPDX), `scan_iocs` + `update_feeds`,
  `ledger`, MITRE ATT&CK tagging, nested-archive scanning, delta cache, parallel scanning
- Multi-language SAST + lockfile coverage: Go, Rust, Java, Kotlin, C#, Ruby, Dart
- Still planned: `inventory_endpoints`, `check_live` (passive first), `malware_scan`
- SARIF export for CI

**Phase 3 — platform**
- Shipped: stdlib test runner, CI matrix (3.10–3.13) with lint + build/install smoke,
  PyPI-ready metadata (classifiers, urls, LICENSE, MANIFEST)
- Still planned: `ci_scan` with fail thresholds, `fix_plan` PR generation, remote rules sync
- Optional node agent (PHP/shell, no root) for shared hosting drift alerts
- Dashboard/report hosting (optional paid tier)

**Success metric:** for the case-study corpus, GRIM v2 must detect 100% of the artifacts found
manually, with zero critical false positives on the clean baseline.

---

## 11. Case study: what GRIM would have caught

Sanitized summary of a real incident that motivated this project:

- A a web app stored uploads in a public directory and validated file types using a
  **client-supplied allowlist** (`mimes:'.$request->mimes`) — an arbitrary-file-upload leading
  to remote code execution.
- An attacker used it to write UUID-named `.php` webshells into the public upload folder.
- Over ~3 months: credential-harvesting scripts read every `.env` on the account, a downloader
  installed a remote C2 client, and later two native binaries binaries were downloaded and executed.
- The host's malware scanner eventually cleaned **one** file and left ~20 other artifacts,
  including the stager and the executables, publicly reachable.
- A manual audit found everything in under an hour by: diffing two backup file listings,
  inspecting suspicious files, and reading a stray `error_log`.

**GRIM coverage mapping:**

| Artifact | Tool that catches it |
|---|---|
| `mimes:'.$request->mimes` pattern | `scan_code` (Semgrep taint) |
| `.php` shells in public upload dir | `audit_exposure`, `malware_scan` |
| `.sh` stager, `ELF` binaries in web dir | `audit_exposure` (web-executable, elf-in-public) |
| New UUID `.php` files vs old backup | `watch` / backup diff |
| Credential-harvesting script pattern | `malware_scan` (YARA), `scan_code` |
| Publicly reachable shells | `check_live` (authorized exposure probes) |
| Exposed `.env` DB keys risk | `scan_secrets`, `audit_exposure` |

---

## 12. Repo layout

```
grim/
├── README.md
├── LICENSE
├── pyproject.toml
├── .github/workflows/ci.yml   # test matrix + lint + build
├── docs/
│   └── validation.md          # real-world case study
├── src/grim/
│   ├── __main__.py            # CLI (scan, tool, diff, plan, sbom, ledger, iocs, mcp)
│   ├── tools.py               # MCP tool registry
│   ├── sbom.py                # CycloneDX 1.5 / SPDX 2.3
│   ├── core/                  # detector, planner, findings, ledger, attack, report
│   ├── engines/               # exposure, secrets, codepatterns, flow, deps, diffscan
│   ├── feeds/                 # IoC store + remote feed sync
│   └── mcp/                   # dependency-free stdio MCP server
└── tests/
    ├── run_all.py             # stdlib test runner (CI entry point)
    ├── test_tools.py          # v1 regression
    ├── test_p0_v2.py          # drift, flow
    ├── test_p1_v2.py          # multi-language SAST, lockfiles, secrets
    ├── test_p2_v2.py          # ledger, sbom, ioc, planner, cache, nested archives
    └── test_p3_cli.py         # CLI, MCP, security edge cases
```
```

---

## 13. Tech stack

- **Language:** Python 3.11+ (MCP SDK maturity, scanner ecosystem, Termux support)
- **MCP:** official `mcp` Python SDK; stdio transport first, HTTP later
- **Packaging:** `uv`/`pipx` installable; single `grim` entry point; `grim mcp` server mode
- **Engines:** invoked as subprocesses with structured output (`--json` where available);
  adapters isolate version quirks
- **Rules:** YAML for GRIM heuristics; Semgrep YAML for custom code rules
- **Storage:** local cache dir for engine results + baselines (JSON/SQLite)

---

## 14. Non-goals and honest limitations

- **Not 100% coverage.** The promise is: *the four gap classes, with fast drift detection* —
  not "finds every possible exploit".
- **No proof of exploitation.** Detecting a live exploit in progress without server access is
  probabilistic; GRIM reports indicators with confidence levels.
- **No noisy scanners by default.** Aggressive/active scanning is opt-in and authorized.
- **Won't replace host-level security.** Imunify/ClamAV remain; GRIM adds the code- and
  policy-level layers they lack.
- **Shared-hosting reality:** some engines need a CLI environment (Termux/VPS/laptop); the v1
  toolset is designed to run against downloaded copies so live hosting is never required.

---

## 15. Open questions

- Rule hosting: GitHub raw vs. dedicated CDN for `rules/` sync?
- Baseline storage: per-project local vs. optional encrypted remote for `watch` across machines?
- Licensing model: open-core (v1 free, v2+ paid) vs. service-first (audits) while building?
- First vertical to prove out: freelance client audits, AI-IDE integrations, or hosting partners?
- Node agent language for shared hosting: PHP-only (most compatible) or shell + PHP fallback?

---

*GRIM — because the things that get you are the things nobody was looking at.*
