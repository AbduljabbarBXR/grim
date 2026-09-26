# GRIM Growth Roadmap

Goal: make GRIM comprehensive across every class of threat to the security
integrity of an application or system — malware, phishing, trojans, ransomware,
rootkits, backdoors, miners, fileless abuse — on Linux and Windows, while
staying what GRIM is: deterministic, stdlib-only Python, no native dependencies,
fast enough to run in an agent loop, with findings an agent can act on.

This document comes from a full audit of 0.6.2 plus end-to-end testing against a
deliberately vulnerable target. Every gap below was reproduced by running the
tool, and each root cause is cited to the file and line.

---

## 1. What already works (do not regress)

| Capability | Implementation | Why it matters |
|---|---|---|
| Unified findings | every finding carries severity, confidence, CWE, OWASP, MITRE ATT&CK, evidence line, remediation | this is GRIM's moat: an agent can triage without reading source |
| Direct taint flows | `engines/flow.py`, block-scoped variable tracking | catches request-to-sink chains regex alone misses |
| Secrets | `engines/secrets.py`, regex + entropy | caught a live-format Stripe key in testing |
| Malware core | `engines/malware.py` + `engines/exposure.py`, webshell families, polyglots, ELF-in-webroot | built-in layer always runs, no external tools needed |
| IoC store | `feeds/iocs.py`, SHA-256/SHA-1/MD5, EICAR sanity check, opt-in feed sync | hash matching with graceful offline behaviour |
| External adapters | ClamAV + YARA, subprocess-based, absent = reported not fatal | the extension point for all future signature engines |
| Endpoint inventory | `engines/endpoints.py`, framework detection | route-level view an agent can reason about |
| SBOM | `sbom.py`, valid CycloneDX 1.5 | supply-chain artifact output |
| Live checks | `engines/live.py`, passive by default, active probing gated behind a scope allowlist | the trust-boundary model to reuse for host scanning |
| Drift | `core/baseline.py`, `watch`, persistent `ledger` | snapshot known-good and alert on change |

Preserve these invariants while extending:

- **Stdlib only.** No third-party runtime dependency, no bundled binaries, no
  build step. This is what makes GRIM trustworthy to drop into any pipeline.
- **Graceful degradation.** Absent external engines are reported, never fatal.
- **Bounded work.** `core/limits.py` deadlines and per-pass caps exist
  deliberately. Deepen them with a budget, never remove them.
- **Silent rather than guessing.** State coverage honestly; a gap documented is
  better than a gap hidden.

---

## 2. Verified gaps

### 2.1 SQL injection is undetectable in any language

A planted `const q = "SELECT * FROM users WHERE id = " + req.query.id; db.query(q);`
produced **zero findings**. Root cause: `flow.py:139` defines `SINKS` per
language, and **no language has an SQL sink**. JavaScript sinks are only
`eval`/`new Function`, `exec`/`spawn`, and `innerHTML`. CWE-89 has no detection
path today. Note the sister project HEIDES has SQL sinks but misses this same
case because `run` is not in its list — the two tools fail on the same input for
opposite reasons, which is exactly why they are complementary.

### 2.2 JavaScript secret declarations are missed

`const DB_PASSWORD = "supersecret-prod-12345"` was not flagged, while a bare
`DB_PASSWORD = "..."` was. Root cause: the rule at `secrets.py:60` is anchored
`^([A-Z0-9_]*(?:SECRET|PASSWORD|...)...)\s*=`, so it matches Python/env-style
assignments at column 0 but breaks on `const`, `let`, `var`, `export`, and Java
modifiers. Verified by direct regex test.

### 2.3 Endpoint risk ranking ignores data flow

With three routes — `/users` (SQLi), `/run` (command injection), `/debug` (eval)
— the inventory ranked `/debug` high and the other two **low**, all reported with
`Inputs: no`. Root cause: `endpoints.py` does not consume `flow.py` results, so
it cannot see request input reaching a handler sink. Risk is ranked on route
shape alone, not on reachability.

### 2.4 Version skew

`pyproject.toml` declares `0.6.3` while `src/grim/__init__.py:3` declares
`0.6.2`. The npm wrapper and the engine disagree. Same bug class as HEIDES.

### 2.5 YARA effectively never fires

The YARA adapter requires the user to set `GRIM_YARA_RULES`. Without a shipped
default ruleset the most powerful signature engine in the stack is inert for
almost every installation.

### 2.6 `fix_plan` produces no patches

On the test target `fix_plan` reported `patchable: 0` and emitted remediation
text only. The command name implies diffs that an agent can apply.

---

## 3. Strategy: be the unifier, not the signature database

"Comprehensive detection of all malware classes on Windows and Linux" is the
whole antivirus and EDR industry's problem statement. GRIM cannot and should not
out-signature ClamAV, Windows Defender and CrowdStrike. GRIM's moat is different:

- **GRIM reads source.** A compiled binary reveals a hash; source reveals
  *intent*. No signature engine has this.
- **GRIM unifies.** One finding format, one severity vocabulary, one remediation
  path, across every engine it coordinates.
- **GRIM is dependency-free.** It runs anywhere Python 3.10+ exists, in seconds,
  inside an agent loop.

So: extend the adapter pattern for external engines, and own the layer they
structurally cannot do — behavioural detection in source, config, and host state.

### Coverage matrix — own versus delegate

| Threat class | Signal | Own? |
|---|---|---|
| Ransomware | mass file enumeration + crypto + `vssadmin delete shadows` + ransom-note text | **own** |
| Cryptominer | stratum pool strings, wallet addresses, miner script patterns | **own** |
| Backdoor / RAT | hardcoded C2 host + beacon, reverse shells, listeners | **own** |
| Persistence | cron, systemd units/timers, registry Run keys, WMI subscriptions, `authorized_keys`, AppInit_DLLs, startup folders | **own** |
| Fileless / LotL | PowerShell `DownloadString`+`IEX`, encoded commands, `mshta`, `rundll32` shells, `bash -i` pipes | **own** |
| Spyware / keylogger | form grabbing, credential-capture APIs, exfil channels | **own** (reuse flow engine) |
| Obfuscation / evasion | base64/hex/gzip blobs, charcode assembly, string stacking, unicode escapes, VM/sandbox/debugger checks | **own** |
| Trojan (masquerade) | spoofed names and metadata impersonating system binaries, fake update bundles | partially |
| Worm / virus | replication loops, scan-and-copy-to-target logic | partially |
| Rootkit | kernel hooking, hidden PIDs, `/dev` anomalies, libc string-table mismatch | **delegate** (chkrootkit/rkhunter) |
| Known malware binaries | hashes and signatures | **delegate** (ClamAV/YARA/Defender) |
| Polymorphic / packed | entropy, unpack heuristics, dynamic analysis | delegate, report honestly as unknown |
| Phishing | brand impersonation, lookalike domains, form-action domains, DKIM/SPF/DMARC, punycode homographs | **separate engine** |

---

## 4. Roadmap

### Tier 0 — make existing claims true (days)

| Fix | Where | Safeguard |
|---|---|---|
| Add SQL sink classes to every language (`query`, `execute`, `executemany`, `raw`, `literal`, `db.run`, `stmt.run`) plus a syntactic string-concat query rule | `flow.py:139` | one more sink list, no new pass |
| Unanchor the assignment rule so `const`/`let`/`var`/`export`/Java modifiers precede the credential name | `secrets.py:60` | regex change only |
| Feed flow results into endpoint risk so tainted routes rank correctly and `Inputs` reflects request usage | `endpoints.py` ← `flow.py` | join on route location |
| Sync `pyproject.toml` and `__init__.py` versions, single source of truth | `pyproject.toml`, `__init__.py:3` | no engine change |
| Ship a curated default YARA ruleset so the adapter fires out of the box | `feeds/` | rules are data, not code |
| `fix_plan` emits real patches/diffs where deterministic, `patchable: n` reflects it | `core/fixplan.py` | only patch when the edit is mechanical |

### Tier 1 — behavioural malware families in source (highest value)

Split the existing `WEBSHELL_PATTERNS` list into per-family rule packs, all
stdlib, all reusing the limits and findings infrastructure:

- `ransomware.py` — enumeration + crypto + shadow-copy deletion + note text
- `miner.py` — stratum, wallet addresses, miner scripts
- `c2.py` — hardcoded hosts, beacons, callback timing patterns
- `persistence.py` — cron, systemd, registry Run keys, WMI subscriptions,
  `authorized_keys`, AppInit_DLLs, startup folders
- `lotl.py` — PowerShell one-liners, encoded commands, `mshta`, `rundll32`,
  `bash -i` reverse shells
- `obfuscation.py` — encoded blobs, charcode assembly, string stacking,
  unicode escapes, anti-analysis checks
- Windows-specific and Linux-specific pattern sets live inside these packs.

Reuse `flow.py` for exfiltration and credential-harvest paths rather than
writing parallel taint logic. Every family maps to MITRE ATT&CK in the finding,
which is already the output vocabulary.

### Tier 2 — adapter layer (unify, never rebuild)

- Windows Defender via `MpCmdRun`, opt-in, same subprocess normalization as
  ClamAV
- chkrootkit / rkhunter as rootkit-delegation adapters
- curated default YARA ruleset (Tier 0) with a documented update path
- An explicit **coverage manifest** in scan output: which engines ran, which
  were absent, and which threat classes were therefore not checked. An agent
  must be able to see the blind spots.

### Tier 3 — phishing as its own engine

Different input type (HTML, email, URLs, not application source) and different
signals: brand-asset and logo mismatch, credential form action domains,
lookalike and punycode homograph domains, open-redirect chains, sender
authentication (SPF/DKIM/DMARC), domain age and certificate validity. Bind it to
the `live.py` scope and allowlist model, because phishing checks touch external
infrastructure and that boundary must stay explicit and authorized.

### Tier 4 — host integrity as a separate opt-in mode

A different trust boundary from repository scanning, and never default-on. Gate
it on the existing `core/policy.py` authorization model.

- Windows artifacts: registry Run/RunOnce, scheduled tasks, services, WMI event
  subscriptions, AppInit_DLLs, startup folders, hosts file
- Linux artifacts: cron, systemd units and timers, `.bashrc`/`.profile`
  injection, `LD_PRELOAD`, `authorized_keys` drift, immutable binaries,
  rootkit indicators delegated to adapters

The key insight: **host integrity is a drift problem.** Snapshot known-good and
alert on change. `core/baseline.py`, `watch` and the persistent `ledger` already
implement exactly this for code; applying them to host artifacts is the same
superpower on a new input, not a new product.

---

## 5. Guardrails

- **Do not build a signature database you must keep current.** Lagging ClamAV
  and Defender is guaranteed. Be the unifier with the best source-level signal.
- **Do not bundle engines or add native dependencies.** It breaks the stdlib-only
  identity and the supply-chain trust that comes with it. Adapters stay optional
  and subprocess-based.
- **Do not blur trust boundaries.** Repository scan is safe and default; live
  host and phishing checks require explicit authorization, in a separate
  command, gated by policy.
- **Report coverage, not confidence.** The output must say what was not checked.
  The `interproc.rs` discipline of the sister project applies here: stay silent
  rather than guess, and never imply total protection.
- **Keep the performance contract.** Bounded passes, `limits.deadline()` honoured,
  no full-binary entropy scanning, no unbounded archive walking.

---

## 6. Sequencing

Tier 0 first — days of work, and it makes the security capabilities already
documented actually hold, including SQL injection which currently has no
detection path at all. Then Tier 1, the behavioural families, because that is
the layer signature engines handle worst and where GRIM reading source is an
unfair advantage. Tier 2 makes the coordinated engines actually fire. Tiers 3
and 4 extend the input types and the trust boundary, in that order, because
phishing is closer to what GRIM already parses while host scanning is a new
authorization surface.

The single highest-leverage change is **Tier 0 item 1: add SQL sinks and a
syntactic string-concat query rule.** It is a small change to one sink table,
and it closes a whole OWASP class that is currently invisible.
