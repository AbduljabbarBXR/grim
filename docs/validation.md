# GRIM Validation — Real-World Case

Sanitized results from validating GRIM v1 against a real, previously-undetected
compromise of a a web application (a hosting account).

## Context

- The app stored user uploads in a web-served directory and validated file types with a
  **client-supplied allowlist** (`mimes:'.$request->mimes`) — arbitrary file upload → RCE.
- Intrusion timeline established from file timestamps and logs:
  - **day 1** — first webshell execution visible in a stray `error_log`
  - **day 30** — credential-harvesting script reads `.env` files, C2 downloader placed
  - **day 60** — new password-gated webshells uploaded
  - **day 62** — stager downloaded and executed two native binaries binaries
- The host's server-side scanner had cleaned one artifact but left ~20 others publicly
  reachable for months.

## GRIM results

### 1. Exposure scan — single pass over a a large archive the hosting account backup archive

- Runtime: **~23 seconds** (Termux, Android device, single thread)
- Findings: 3,000 (capped), **76 critical**
- Detected artifacts (all confirmed by manual analysis):

| Artifact | GRIM finding |
|---|---|
| `downloader.sh` stager (downloads + `setsid` executes payload) | Webshell indicator: Detached process execution (stager) |
| Both `.s*` native binaries binaries | Native executable in web-served directory |
| 6 × a small file password-gated shells | Webshell indicator: Password-gated command form |
| Image-polyglot shells (an image file / an image file) | Polyglot file: image header with embedded PHP |
| C2 downloader (a small file) | Webshell indicator: Detached process execution (stager) |
| Credential harvester (a small file) | Webshell indicator + web-executable in upload dir |
| `__*` shell data directories | (covered by exposure rules on web paths) |

### 2. Drift scan — diffing baseline backup (Sep 7) vs current backup (Sep 17)

- Runtime: **~1m41s** for two a large archive archives
- Findings: 43 — **16 critical, 26 high**
- Correctly isolated everything added between the two snapshots:
  - new stager + both ELF binaries
  - 6 newly-uploaded webshells
  - newly modified executable files
- Wrapper-root normalization: both backups wrap content in timestamped root folders;
  GRIM strips the wrapper and aligns paths automatically.
- Reproduces, in ~2 minutes and zero manual work, an audit that took an experienced
  engineer ~1 hour of manual extraction, grepping, and file inspection.

### 3. Code scan — the root cause

- `scan_code` flags `mimes:'.$request->mimes` as **critical**
  ("Upload validation uses a request-controlled file-type list").
- This is the finding that prevents the entire incident class: fix it and the door closes.

## What this proves

1. **Detection gap closed for the exact class of incident that motivated GRIM.**
   File-policy + heuristic scanning catches what signature engines miss.
2. **Drift detection is the highest-signal check** — added executables in web paths
   appear within one scan of a new backup.
3. **Fast enough for practical use**: full-account archive audit in under a minute on a phone.
4. **AI-usable output**: every finding carries location, evidence, confidence, and remediation.

## Reproduce

```bash
PYTHONPATH=src python3 -m grim tool audit_exposure --path backup.tar.gz --format md
PYTHONPATH=src python3 -m grim diff baseline.tar.gz current.tar.gz --format md
PYTHONPATH=src python3 -m grim scan /path/to/app-source --no-network
python3 tests/run_all.py       # full suite: 114 checks, stdlib only, no pytest
```
