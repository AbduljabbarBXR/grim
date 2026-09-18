"""Lightweight flow analysis: does untrusted input reach a dangerous sink?

Regex and block based, dependency free. For each source file we split it into
function-like blocks and track tainted variable names from request/user sources
to dangerous sinks. This is not a full dataflow engine; it is a bounded,
explainable pass that catches the classic request-to-sink chains regex alone
misses because the input and the sink are on different lines.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..core import limits
from ..core.findings import Finding, make_id

MAX_FILE_BYTES = 1024 * 1024
MAX_FINDINGS = 400

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", ".cache", "storage/framework",
}

EXT_LANG = {
    ".php": "php",
    ".blade.php": "php",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js",
    ".vue": "js", ".svelte": "js",
    ".py": "python",
    ".rb": "ruby",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".dart": "dart",
}

# Untrusted-input source markers, per language. A variable assigned from one of
# these expressions is considered tainted.
SOURCES: dict[str, list[re.Pattern]] = {
    "python": [
        re.compile(r"\b(request|req)\b"),
        re.compile(r"\b(sys\.argv|input\s*\(|os\.environ)\b"),
        re.compile(r"json\.loads\s*\(\s*(request|req)"),
    ],
    "js": [
        re.compile(r"\b(req|request)\b"),
        re.compile(r"\b(ctx\.request|process\.argv|document\.location)\b"),
        re.compile(r"\b(requestBody|query|params)\b"),
    ],
    "php": [
        re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)"),
        re.compile(r"request->(input|query|all|post)"),
    ],
    "ruby": [
        re.compile(r"\bparams\b"),
        re.compile(r"\b(request|ARGV)\b"),
    ],
    "go": [
        re.compile(r"\br\.(FormValue|URL\.Query|PostFormValue|Body)\b"),
        re.compile(r"\bos\.Args\b"),
    ],
    "java": [
        re.compile(r"\brequest\.get(Parameter|ParameterValues|Header|InputStream)"),
    ],
    "kotlin": [
        re.compile(r"\brequest\.get(Parameter|ParameterValues|Header|InputStream)"),
    ],
    "csharp": [
        re.compile(r"\bRequest\.(QueryString|Form|Headers|InputStream|Body)\b"),
        re.compile(r"\bConsole\.ReadLine\b"),
    ],
    "dart": [
        re.compile(r"\brequest\.(body|uri\.queryParameters|headers)\b"),
    ],
}

# Dangerous sinks. (regex, severity, title, description, remediation)
SINKS: dict[str, list[tuple[re.Pattern, str, str, str, str]]] = {
    "python": [
        (re.compile(r"\b(eval|exec)\s*\("), "high", "eval/exec with possibly tainted input",
         "Untrusted input may reach a dynamic code execution sink.", "Never eval/exec input; use safe parsers."),
        (re.compile(r"\b(os\.system|subprocess\.\w+)\s*\("), "high", "shell invocation with possibly tainted input",
         "Untrusted input may reach a shell invocation.", "Use argument arrays and validate inputs."),
        (re.compile(r"\b(pickle\.loads?|yaml\.load)\s*\("), "medium", "unsafe deserialization with possibly tainted input",
         "Untrusted input may reach deserialization.", "Use JSON or safe_load."),
    ],
    "js": [
        (re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("), "high", "dynamic code execution with possibly tainted input",
         "Untrusted input may reach eval or new Function.", "Remove dynamic code construction."),
        (re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\("), "high", "shell command with possibly tainted input",
         "Untrusted input may reach a shell command.", "Use argument arrays and validated inputs."),
        (re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*="), "medium", "HTML injection with possibly tainted input",
         "Untrusted input may reach an HTML sink.", "Sanitize with DOMPurify."),
    ],
    "php": [
        (re.compile(r"\b(eval|assert)\s*\("), "high", "dynamic code execution with possibly tainted input",
         "Untrusted input may reach eval or assert.", "Remove eval; never evaluate input."),
        (re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\("), "high", "shell command with possibly tainted input",
         "Untrusted input may reach a shell command.", "Never pass request data to shell functions."),
        (re.compile(r"\b(include|require)(_once)?\s*\("), "medium", "dynamic include with possibly tainted input",
         "Untrusted input may reach a dynamic include.", "Use static includes and allowlists."),
        (re.compile(r"\bunserialize\s*\("), "medium", "unserialize with possibly tainted input",
         "Untrusted input may reach unserialize.", "Use JSON."),
    ],
    "ruby": [
        (re.compile(r"\beval\s*\(|\binstance_eval\b|\bclass_eval\b|\bsend\s*\("), "high", "dynamic execution with possibly tainted input",
         "Untrusted input may reach eval or send.", "Never eval input."),
        (re.compile(r"\b(system|exec|spawn|`)\s*"), "high", "shell invocation with possibly tainted input",
         "Untrusted input may reach a shell command.", "Use argument arrays."),
    ],
    "go": [
        (re.compile(r"\b(exec\.Command|os\.StartProcess|syscall\.Exec)\s*\("), "high", "process execution with possibly tainted input",
         "Untrusted input may reach a process execution sink.", "Validate and use argument arrays."),
        (re.compile(r"\btext/template\b|\bhtml/template\b"), "medium", "template execution with possibly tainted input",
         "Untrusted input may reach a template sink.", "Use proper escaping."),
    ],
    "java": [
        (re.compile(r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("), "high", "process execution with possibly tainted input",
         "Untrusted input may reach a process execution sink.", "Validate input strictly."),
        (re.compile(r"\bClass\.forName\s*\(|\bnew\s+URLClassLoader\b"), "medium", "dynamic class loading with possibly tainted input",
         "Untrusted input may reach dynamic class loading.", "Avoid dynamic loading from input."),
    ],
    "kotlin": [
        (re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\("), "high", "process execution with possibly tainted input",
         "Untrusted input may reach a process execution sink.", "Validate input strictly."),
    ],
    "csharp": [
        (re.compile(r"\bProcess\.Start\s*\("), "high", "process execution with possibly tainted input",
         "Untrusted input may reach Process.Start.", "Validate input strictly."),
        (re.compile(r"\bXmlDocument\.Load\s*\(|XDocument\.Parse\s*\("), "medium", "XML parsing with possibly tainted input",
         "Untrusted input may reach XML parsing with XXE risk.", "Disable DTD processing."),
    ],
    "dart": [
        (re.compile(r"\bProcess\.run\s*\(|\bProcess\.start\s*\("), "high", "process execution with possibly tainted input",
         "Untrusted input may reach Process.run.", "Validate input strictly."),
        (re.compile(r"\beval\s*\(|\bHttp\.get\s*\("), "medium", "dynamic request with possibly tainted input",
         "Untrusted input may reach a dynamic request.", "Validate URLs."),
    ],
}


def rules_hash() -> str:
    """Stable hash of the flow source/sink rules, for cache invalidation."""
    import hashlib

    basis = []
    for lang, pats in sorted(SOURCES.items()):
        basis.extend(f"src:{lang}:{p.pattern}" for p in pats)
    for lang, rules in sorted(SINKS.items()):
        basis.extend(f"sink:{lang}:{r[0].pattern}:{r[1]}" for r in rules)
    return hashlib.sha256("|".join(basis).encode("utf-8", "ignore")).hexdigest()[:16]


def scan_flow(
    path: str,
    languages: list[str] | None = None,
    max_files: int | None = None,
    stats: dict | None = None,
) -> list[Finding]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    file_limit = max_files if max_files is not None else limits.resolve("GRIM_MAX_FILES", 20000)
    finding_limit = limits.resolve("GRIM_MAX_FLOW_FINDINGS", MAX_FINDINGS)
    findings: list[Finding] = []
    files = [p] if p.is_file() else _walk(p, file_limit)
    files.sort(key=lambda x: str(x))
    lang_filter = set(languages) if languages else None
    reasons: list[str] = []
    scanned = 0
    dl = limits.deadline()

    for fp in files:
        if limits.expired(dl):
            reasons.append("time budget reached")
            break
        if limits.reached(len(findings), finding_limit):
            reasons.append(f"flow finding limit reached ({finding_limit})")
            break
        lang = _lang_of(fp)
        if lang is None:
            continue
        if lang_filter and lang not in lang_filter:
            continue
        scanned += 1
        findings.extend(_scan_file(fp, lang))
    if limits.reached(len(files), file_limit):
        reasons.append(f"file limit reached ({file_limit})")
    if stats is not None:
        stats.update(
            {
                "flow_files_scanned": scanned,
                "flow_findings": len(findings),
                "truncated": bool(reasons),
                "reasons": reasons,
            }
        )
    return findings


def _walk(root: Path, max_files: int) -> list[Path]:
    out: list[Path] = []
    for r, dirs, fnames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(fnames):
            fp = Path(r) / fn
            if fp.is_symlink():
                continue
            if _lang_of(fp):
                out.append(fp)
                if len(out) >= max_files:
                    return out
    return out


def _lang_of(fp: Path) -> str | None:
    name = fp.name.lower()
    if name.endswith(".blade.php"):
        return "php"
    return EXT_LANG.get(fp.suffix.lower())


def _scan_file(fp: Path, lang: str) -> list[Finding]:
    try:
        if fp.stat().st_size > limits.resolve("GRIM_MAX_CODE_FILE_BYTES", MAX_FILE_BYTES):
            return []
        text = fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return analyze_text(text, fp, lang)


def analyze_text(text: str, fp: Path, lang: str) -> list[Finding]:
    """Run the taint pass over already-loaded text (used by scan_code to avoid re-reading)."""
    out: list[Finding] = []
    sources = SOURCES.get(lang, [])
    sinks = SINKS.get(lang, [])
    if not sources or not sinks:
        return out

    lines = text.splitlines()
    tainted: set[str] = set()
    src_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)")

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*", "<!--")):
            continue

        # direct sink with source expression on the same line
        for sink_re, sev, title, desc, fix in sinks:
            m = sink_re.search(stripped)
            if not m:
                continue
            arg_region = stripped[m.end():]
            if any(src.search(arg_region) for src in sources) and not arg_region.startswith("="):
                out.append(_mk(fp, lang, sev, title, desc, fix, stripped, lineno, direct=True))
                break

        # assignments that taint a variable
        m = src_re.match(stripped)
        if m:
            var, expr = m.group(1), m.group(2)
            if any(src.search(expr) for src in sources):
                tainted.add(var)
                continue
            # alias propagation: var = another tainted var (possibly wrapped)
            for tv in list(tainted):
                if re.search(rf"\b{re.escape(tv)}\b", expr):
                    tainted.add(var)
                    break

        # sink whose arguments reference a tainted variable
        for sink_re, sev, title, desc, fix in sinks:
            m = sink_re.search(stripped)
            if not m:
                continue
            arg_region = stripped[m.end():]
            if any(re.search(rf"\b{re.escape(tv)}\b", arg_region) for tv in tainted):
                out.append(_mk(fp, lang, sev, title, desc, fix, stripped, lineno, direct=False))
                break

    # keep only unique taint findings per file (id dedupes anyway)
    return out


def _mk(fp: Path, lang: str, sev: str, title: str, desc: str, fix: str,
        line_text: str, line_no: int, direct: bool) -> Finding:
    prefix = "FLOW"
    tag = "direct-taint" if direct else "taint"
    return Finding(
        id=make_id(prefix, title + ("-direct" if direct else ""), f"{fp}:{line_no}"),
        severity=sev,
        confidence=0.8 if direct else 0.65,
        category="CWE-20",
        owasp="A03:2021",
        title=title,
        description=desc + (" Direct source to sink on one line." if direct else " Tainted variable reaches the sink."),
        location={"file": str(fp), "line": line_no},
        evidence=line_text[:160],
        remediation=fix,
        engine="grim-flow",
        tags=["flow", lang, tag],
    )