"""Dangerous code pattern scanning (SAST-lite), language aware, dependency free."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields as dataclass_fields
from pathlib import Path

from ..core.findings import Finding, make_id
from .flow import scan_flow

MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 20000
MAX_FINDINGS = 800

CACHE_DIR = Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim")) / "code"
CACHE_MAX_ENTRIES = 50000
_FINDING_FIELDS = {f.name for f in dataclass_fields(Finding)}
_FINDING_FIELDS.discard("severity_rank")

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", ".cache", "storage/framework",
}

EXT_LANG = {
    ".php": "php",
    ".blade.php": "php",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".vue": "js",
    ".svelte": "js",
    ".py": "python",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".dart": "dart",
}

# (id, regex, severity, title, description, remediation, languages)
RULES: list[tuple[str, re.Pattern, str, str, str, str, set[str]]] = [
    (
        "php-client-mimes",
        re.compile(r"mimes\s*:\s*[^,\n]*\$(?:request|_GET|_POST|_REQUEST)"),
        "critical",
        "Upload validation uses a request-controlled file-type list",
        "The allowed file types come from the request itself, so an attacker can allow .php or any type, enabling arbitrary file upload and remote code execution.",
        "Use a fixed server-side list, e.g. 'required|file|mimes:jpg,jpeg,png,gif,webp|max:5120'.",
        {"php"},
    ),
    (
        "php-client-extension",
        re.compile(r"getClientOriginalExtension\s*\(\s*\)"),
        "medium",
        "Stored filename built from client-supplied extension",
        "The extension is taken from the uploaded file name as sent by the client. Combine with a public storage path and this becomes arbitrary upload.",
        "Derive the extension from the validated MIME type, not the client filename.",
        {"php"},
    ),
    (
        "php-move-upload",
        re.compile(r"move_uploaded_file\s*\("),
        "low",
        "Raw upload move (review destination and validation)",
        "move_uploaded_file into a web-served path is the classic RCE chain when validation is weak.",
        "Ensure server-side type validation and a non-executable storage location.",
        {"php"},
    ),
    (
        "php-eval",
        re.compile(r"\beval\s*\("),
        "high",
        "eval() usage",
        "eval executes arbitrary PHP and is a top webshell/backdoor indicator.",
        "Remove eval; never accept evaluated code from input.",
        {"php"},
    ),
    (
        "php-base64-decode",
        re.compile(r"\bbase64_decode\s*\("),
        "medium",
        "base64_decode() usage",
        "Common in obfuscated malware and dynamic code loading.",
        "Verify purpose; remove dynamic decoding of stored or input data when possible.",
        {"php"},
    ),
    (
        "php-request-exec",
        re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)\n]*\$(?:_GET|_POST|_REQUEST|request)"),
        "critical",
        "Command execution fed by request input",
        "Direct OS command execution from user input allows full server compromise.",
        "Never pass request data to shell functions; use native APIs with strict validation.",
        {"php"},
    ),
    (
        "php-exec",
        re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
        "low",
        "Shell execution function (review)",
        "Shell execution is legitimate in some tools but is a key malware behavior.",
        "Confirm necessity; avoid user input; log usage.",
        {"php"},
    ),
    (
        "php-include-request",
        re.compile(r"\b(include|require)(_once)?\s*\(\s*\$(?:_GET|_POST|_REQUEST|request)"),
        "critical",
        "Dynamic include/require from request input (LFI/RFI)",
        "Attacker-controlled include can read local files or execute remote code.",
        "Use static includes and allowlists for any dynamic paths.",
        {"php"},
    ),
    (
        "php-unserialize-input",
        re.compile(r"\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|request)"),
        "high",
        "unserialize() on request input (object injection)",
        "Untrusted deserialization can lead to object injection and RCE.",
        "Use JSON and strict validation instead.",
        {"php"},
    ),
    (
        "php-extract-input",
        re.compile(r"\bextract\s*\(\s*\$(?:_GET|_POST|_REQUEST|request)"),
        "high",
        "extract() on request input",
        "extract() can overwrite internal variables from user input.",
        "Avoid extract on user data.",
        {"php"},
    ),
    (
        "php-preg-e",
        re.compile(r"preg_replace\s*\([^)]*/[a-z]*e[a-z]*['\"]?\s*,"),
        "high",
        "preg_replace /e modifier (code execution)",
        "The /e modifier evaluates the replacement as PHP. Removed in PHP 7 but still an indicator of legacy vulnerable code.",
        "Use preg_replace_callback.",
        {"php"},
    ),
    (
        "php-raw-sql",
        re.compile(r"(?:DB::raw|whereRaw|orderByRaw|selectRaw)\s*\([^)\n]*\$"),
        "high",
        "Raw SQL expression containing a variable",
        "If the variable can come from a request, this is SQL injection.",
        "Use bindings/query builder parameters.",
        {"php"},
    ),
    (
        "php-ssrf-fetch",
        re.compile(r"file_get_contents\s*\(\s*\$(?:request|_GET|_POST|_REQUEST)"),
        "high",
        "Remote fetch from request input (SSRF)",
        "Attacker can make the server fetch internal or malicious URLs.",
        "Validate URLs against an allowlist; block private ranges.",
        {"php"},
    ),
    (
        "js-eval",
        re.compile(r"\beval\s*\("),
        "high",
        "eval() in JavaScript",
        "eval executes arbitrary code; a common injection sink.",
        "Replace with JSON.parse or explicit logic.",
        {"js"},
    ),
    (
        "js-new-function",
        re.compile(r"\bnew\s+Function\s*\("),
        "high",
        "new Function() (dynamic code execution)",
        "Equivalent of eval; executes strings as code.",
        "Remove dynamic code construction.",
        {"js"},
    ),
    (
        "js-child-process-exec",
        re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\([^)\n]*\$\{"),
        "critical",
        "Shell command built with a template literal",
        "Unvalidated interpolation into a shell command is command injection.",
        "Use execFile/spawn with argument arrays and validated inputs.",
        {"js"},
    ),
    (
        "js-dangerous-html",
        re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*="),
        "medium",
        "Direct HTML injection sink",
        "Unsanitized HTML insertion enables XSS.",
        "Sanitize with DOMPurify or use safe text bindings.",
        {"js"},
    ),
    (
        "js-document-write",
        re.compile(r"document\.write\s*\("),
        "low",
        "document.write usage",
        "Legacy injection-prone API.",
        "Use DOM APIs.",
        {"js"},
    ),
    (
        "py-eval-exec",
        re.compile(r"\b(eval|exec)\s*\("),
        "high",
        "eval/exec in Python",
        "Executes arbitrary code; dangerous with any external input.",
        "Avoid; use safe parsers (ast.literal_eval for data).",
        {"python"},
    ),
    (
        "py-shell-true",
        re.compile(r"subprocess\.\w+\s*\([^)\n]*shell\s*=\s*True"),
        "high",
        "subprocess with shell=True",
        "Shell interpretation enables command injection when inputs are uncontrolled.",
        "Use argument lists and shell=False.",
        {"python"},
    ),
    (
        "py-os-system",
        re.compile(r"\bos\.system\s*\("),
        "medium",
        "os.system usage",
        "Shell invocation; injection risk with any external input.",
        "Prefer subprocess with argument arrays.",
        {"python"},
    ),
    (
        "py-pickle",
        re.compile(r"\bpickle\.loads?\s*\("),
        "medium",
        "pickle deserialization",
        "Pickle can execute code during deserialization.",
        "Use JSON or restricted formats.",
        {"python"},
    ),
    (
        "py-yaml-load",
        re.compile(r"\byaml\.load\s*\((?![^)\n]*SafeLoader)"),
        "medium",
        "yaml.load without SafeLoader",
        "Unsafe YAML loading can instantiate arbitrary Python objects.",
        "Use yaml.safe_load.",
        {"python"},
    ),
    (
        "go-exec-command",
        re.compile(r"\bexec\.Command\s*\([^)]*\"(sh|bash)\"|\bexec\.Command\s*\([^)]*\+"),
        "critical",
        "Process execution with shell or string concatenation",
        "Shell invocation or concatenated command building is command injection prone.",
        "Use argument arrays and validated inputs.",
        {"go"},
    ),
    (
        "go-raw-sql",
        re.compile(r"(?:fmt\.Sprintf|fmt\.Sprintln)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)|db\.(?:Query|Exec)\s*\([^)]*\+"),
        "high",
        "SQL built with string formatting or concatenation",
        "If the interpolated value can come from input, this is SQL injection.",
        "Use parameterized queries.",
        {"go"},
    ),
    (
        "rust-command-sh",
        re.compile(r"Command::new\(\s*\"(sh|bash)\"|\"sh\".*\.arg\(\"\-c\"\)"),
        "critical",
        "Shell command construction",
        "Shell invocation via sh -c is command injection prone.",
        "Use argument arrays and validated inputs.",
        {"rust"},
    ),
    (
        "rust-unsafe-block",
        re.compile(r"\bunsafe\s*\{"),
        "low",
        "Unsafe block usage",
        "Unsafe Rust can bypass memory safety; review any block touching input.",
        "Audit unsafe blocks; avoid on untrusted data.",
        {"rust"},
    ),
    (
        "java-exec",
        re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\"|\bProcessBuilder\s*\([^)]*\+"),
        "critical",
        "Process execution with concatenation",
        "Command building with concatenation is injection prone.",
        "Use argument arrays and validated inputs.",
        {"java", "kotlin"},
    ),
    (
        "java-raw-sql",
        re.compile(r"(?:Statement|PreparedStatement)?\.?\b(?:executeQuery|executeUpdate|execute)\s*\(\s*\"[^)]*\+|\"SELECT.*\"\s*\+"),
        "high",
        "SQL built with string concatenation",
        "Concatenated SQL is injection prone when values come from input.",
        "Use parameterized queries.",
        {"java", "kotlin"},
    ),
    (
        "java-deserialization",
        re.compile(r"ObjectInputStream\b[^)]*\.readObject\s*\(|ObjectMapper\b[^)]*\.enableDefaultTyping\b"),
        "high",
        "Untrusted deserialization",
        "Deserializing untrusted streams can lead to code execution.",
        "Use safe formats and allowlists.",
        {"java", "kotlin"},
    ),
    (
        "csharp-process",
        re.compile(r"Process\.Start\s*\(\s*\"\w+\"\s*,\s*\"[^\"]*\"\s*\+"),
        "high",
        "Process.Start with string concatenation",
        "Concatenated arguments to Process.Start are injection prone.",
        "Use argument lists and validated inputs.",
        {"csharp"},
    ),
    (
        "csharp-raw-sql",
        re.compile(r"(?:SqlCommand|NpgsqlCommand)\b[^;]*\+\s*[\"']"),
        "high",
        "SQL command built with concatenation",
        "Concatenated SQL is injection prone.",
        "Use parameterized queries.",
        {"csharp"},
    ),
    (
        "csharp-xxe",
        re.compile(r"XmlDocument\.Load\s*\(|XmlReader\.Settings\s*\{[^}]*DtdProcessing\s*=\s*Parse"),
        "high",
        "XML parsing with DTD enabled",
        "DTD processing enables XXE when parsing untrusted XML.",
        "Set DtdProcessing to Prohibit and disable external entities.",
        {"csharp"},
    ),
    (
        "ruby-eval",
        re.compile(r"\beval\s*\(|\binstance_eval\b|\bclass_eval\b"),
        "high",
        "Dynamic code execution",
        "eval and friends execute arbitrary Ruby.",
        "Never eval input.",
        {"ruby"},
    ),
    (
        "ruby-shell",
        re.compile(r"\b(system|exec|spawn|`)\s*[(\"]"),
        "high",
        "Shell invocation",
        "Shell execution is injection prone with any external input.",
        "Use argument arrays and validated inputs.",
        {"ruby"},
    ),
    (
        "ruby-raw-sql",
        re.compile(r"\.where\s*\(\s*\"[^\"]*#\{|find_by_sql\s*\(\s*\"[^\"]*#\{"),
        "high",
        "SQL built with string interpolation",
        "Interpolated SQL is injection prone.",
        "Use parameterized queries.",
        {"ruby"},
    ),
    (
        "dart-process",
        re.compile(r"Process\.(run|start)\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\[[^\]]*\$"),
        "high",
        "Process with interpolated arguments",
        "Interpolated arguments to Process are injection prone.",
        "Use validated argument lists.",
        {"dart"},
    ),
    (
        "dart-process-review",
        re.compile(r"\bProcess\.(run|start)\s*\("),
        "low",
        "Process execution (review)",
        "Launching processes with derived arguments is injection prone.",
        "Validate inputs and prefer argument lists.",
        {"dart"},
    ),
    (
        "go-exec-review",
        re.compile(r"\bexec\.Command\s*\(|\bos/exec\b"),
        "low",
        "Process execution (review)",
        "Command execution is injection prone when arguments derive from input.",
        "Use validated argument arrays.",
        {"go"},
    ),
    (
        "csharp-sql-concat",
        re.compile(r"[\"'](?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\+"),
        "high",
        "SQL built with string concatenation",
        "Concatenated SQL is injection prone when values come from input.",
        "Use parameterized queries.",
        {"csharp"},
    ),
]

IP_URL = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?")
PRIVATE_IP = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)")


def _cache_version() -> str:
    from .. import __version__

    return f"{__version__}:{len(RULES)}"


def _cache_path() -> Path:
    return CACHE_DIR / "findings.json"


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if len(cache) > CACHE_MAX_ENTRIES:
            cache = dict(list(cache.items())[-CACHE_MAX_ENTRIES:])
        _cache_path().write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def _from_dicts(dicts: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for d in dicts:
        try:
            out.append(Finding(**{k: v for k, v in d.items() if k in _FINDING_FIELDS}))
        except TypeError:
            continue
    return out


def scan_code(
    path: str,
    languages: list[str] | None = None,
    max_files: int = MAX_FILES,
    workers: int | None = None,
    use_cache: bool = True,
) -> list[Finding]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    files = [p] if p.is_file() else _walk(p, max_files)
    lang_filter = set(languages) if languages else None
    files = [f for f in files if _lang_of(f) is not None and (not lang_filter or _lang_of(f) in lang_filter)]
    files.sort(key=lambda x: str(x))

    if workers is None:
        workers = min(8, os.cpu_count() or 1)

    cache = _load_cache() if (use_cache and files) else {}
    lock = threading.Lock()
    version = _cache_version()

    def task(fp: Path) -> list[Finding]:
        lang = _lang_of(fp)
        if lang is None:
            return []
        text = _read_text(fp)
        if text is None:
            return []
        key = ""
        if use_cache:
            key = f"{version}:{_hash_text(text)}"
            with lock:
                cached = cache.get(key)
            if cached is not None:
                return _from_dicts(cached)
        result = _scan_text(text, fp, lang)
        if use_cache and key:
            payload = [f.to_dict() for f in result]
            with lock:
                cache[key] = payload
        return result

    findings: list[Finding] = []
    if workers > 1 and len(files) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(task, files):
                findings.extend(result)
    else:
        for fp in files:
            findings.extend(task(fp))

    if use_cache and files:
        _save_cache(cache)

    # lightweight taint/flow pass on top of the pattern rules
    findings.extend(scan_flow(path, languages=languages, max_files=max_files))
    return findings


def _walk(root: Path, max_files: int) -> list[Path]:
    out: list[Path] = []
    for r, dirs, fnames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in fnames:
            fp = Path(r) / fn
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


def _read_text(fp: Path) -> str | None:
    try:
        if fp.stat().st_size > MAX_FILE_BYTES:
            return None
        return fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _scan_file(fp: Path, lang: str) -> list[Finding]:
    text = _read_text(fp)
    if text is None:
        return []
    return _scan_text(text, fp, lang)


def _scan_text(text: str, fp: Path, lang: str) -> list[Finding]:
    out: list[Finding] = []

    for rid, pat, sev, title, desc, fix, langs in RULES:
        if lang not in langs:
            continue
        m = pat.search(text)
        if not m:
            continue
        line = text[: m.start()].count("\n") + 1
        out.append(
            Finding(
                id=make_id("CODE", rid, str(fp)),
                severity=sev,
                confidence=0.9 if rid in {"php-client-mimes", "php-request-exec", "php-include-request", "js-child-process-exec"} else 0.7,
                category="CWE-94" if sev == "critical" else "CWE-20",
                owasp="A03:2021",
                title=title,
                description=desc,
                location={"file": str(fp), "line": line},
                evidence=m.group(0)[:160],
                remediation=fix,
                engine="grim-codepatterns",
                tags=["sast", lang],
            )
        )

    # hardcoded public IP URLs in code (stager/backdoor indicator)
    for m in IP_URL.finditer(text):
        ip = m.group(1)
        if PRIVATE_IP.match(ip):
            continue
        line = text[: m.start()].count("\n") + 1
        out.append(
            Finding(
                id=make_id("CODE", "hardcoded-ip", f"{fp}:{ip}"),
                severity="medium",
                confidence=0.6,
                category="CWE-912",
                owasp="A08:2021",
                title=f"Hardcoded public IP URL in code: {ip}",
                description="Direct-IP endpoints are uncommon in legitimate app code and frequent in malware/stagers.",
                location={"file": str(fp), "line": line},
                evidence=m.group(0)[:160],
                remediation="Verify the endpoint; use domain names and configuration, not hardcoded IPs.",
                engine="grim-codepatterns",
                tags=["sast", "suspicious"],
            )
        )
        break  # one per file
    return out
