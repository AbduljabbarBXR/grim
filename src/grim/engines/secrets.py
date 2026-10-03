"""Secrets scanning: leaked credentials, keys, tokens, sensitive files."""

from __future__ import annotations

import base64
import math
import os
import re
import subprocess
import tarfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..core import limits
from ..core.findings import Finding, make_id

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FINDINGS = 800
# Bytes read to decide whether a file is text or binary. A NUL byte or a high
# ratio of non-printable bytes means regex scanning is pointless.
BINARY_SNIFF_BYTES = 8192
# Upper bound on bytes handed to the regex passes. Scanning every byte of a large
# tree is the dominant cost in a full scan; secrets live near the top of files.
MAX_REGEX_BYTES = 2 * 1024 * 1024
# Bytes that count as text: tab, newline, carriage return, and 0x20..0xff.
# Anything else (NUL and the C0/C1 control range) marks a file as binary.
_BINARY_DELETE = bytes(
    b for b in range(256)
    if b not in (9, 10, 13) and not (32 <= b <= 255)
)


def _looks_binary(head: bytes) -> bool:
    """True when the head looks like binary rather than text.

    Compressed and media payloads (PDF, PNG, gzip, wasm) often contain no NUL byte
    in the first block, so a NUL check alone is not enough to skip them. Uses a
    translation table so the check is C-speed rather than a Python loop.
    """
    sample = head[:BINARY_SNIFF_BYTES]
    if not sample:
        return False
    # Keep tab, newline, carriage return, space..~ and every high byte (UTF-8).
    text_bytes = sample.translate(None, delete=_BINARY_DELETE)
    return len(text_bytes) / len(sample) < 0.85


SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", ".cache",
}

# (name, pattern, severity, description, [required literal substrings])
# The optional literal list is a prefilter: `needle in text` is a C-speed substring
# search, while running the regex over every file is the dominant cost of a large
# scan. Any pattern whose regex requires a fixed literal gets one, so the regex runs
# only on files that can possibly match.
PATTERNS: list[tuple] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", "AWS access key ID", ["AKIA"]),
    ("aws-secret", re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "critical", "AWS secret access key", ["aws_secret", "aws-secret"]),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high", "Google API key", ["AIza"]),
    ("stripe-live-secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical", "Stripe live secret key", ["sk_live_"]),
    ("stripe-live-publishable", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "medium", "Stripe live publishable key", ["pk_live_"]),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", "GitHub token", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"), "critical", "OpenAI-style secret key", ["sk-"]),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "critical", "Anthropic API key", ["sk-ant-"]),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high", "Slack token", ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"]),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical", "Private key block", ["PRIVATE KEY"]),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium", "JSON Web Token", ["eyJ"]),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "critical", "SendGrid API key", ["SG."]),
    ("twilio-sid", re.compile(r"\bAC[a-f0-9]{32}\b"), "high", "Twilio account SID", ["AC"]),
    ("mailgun-key", re.compile(r"\bkey-[a-z0-9]{32}\b"), "medium", "Mailgun API key", ["key-"]),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), "medium", "Telegram bot token", [":AA"]),
    ("basic-auth-url", re.compile(r"https?://[^/\s:@'\"]+:[^/\s@'\"]{6,}@[^\s'\"]+"), "high", "Credentials embedded in URL"),
]

# Sensitive files that should not be web-accessible (presence finding)
SENSITIVE_FILES = {
    ".env": ("critical", "Environment file may expose all secrets"),
    ".env.local": ("critical", "Environment file may expose all secrets"),
    ".env.production": ("critical", "Environment file may expose all secrets"),
    "id_rsa": ("critical", "SSH private key"),
    "id_ed25519": ("critical", "SSH private key"),
    ".npmrc": ("high", "npm registry credentials"),
    ".netrc": ("high", "Network credentials file"),
    "credentials.json": ("high", "Possible cloud credentials"),
    "service-account.json": ("high", "Possible cloud service account key"),
    ".htpasswd": ("high", "Password file"),
}

ENV_SECRET_ASSIGN = re.compile(
    # Optional declaration prefix so `const`/`let`/`var`/`export`/`final`/`private`/
    # `public`/`static` and Java/C#/Kotlin modifiers may precede the credential name.
    # Without this the rule only matched column-0 env-style assignments and missed
    # every JS/TS/Java constant, which is where real leaks live.
    r"(?im)^[ \t]*(?:(?:const|let|var|export|final|public|private|protected|static|"
    r"readonly|inline|internal|virtual|pub|mut|def|val|val\s)\s+)*"
    r"([A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|ACCESS_?KEY|"
    r"TOKEN|AUTH|PRIVATE|CREDENTIAL)[A-Za-z0-9_]*)\s*[:=]\s*['\"]?([^\s'\"#]{8,})"
)

# Source/config extensions where a credential-shaped assignment is a real leak.
# Deliberately excludes .json and lockfiles, which are handled by other rules.
SOURCE_SECRET_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".php", ".rb", ".go", ".rs", ".java", ".kt", ".kts", ".scala",
    ".cs", ".dart", ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm", ".swift",
    ".groovy", ".clj", ".cljs", ".ex", ".exs", ".erl", ".hs", ".lua", ".pl",
    ".pm", ".r", ".jl", ".nim", ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".tf", ".tfvars", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".sql",
}
_SECRET_BASENAMES = {".env", "credentials", "secrets", "config", "settings"}


def _source_ext(name: str) -> bool:
    """True for source and config files where a literal credential assignment leaks."""
    lower = name.lower()
    if lower.endswith(".blade.php"):
        return True
    if lower in _SECRET_BASENAMES or lower.startswith(".env"):
        return True
    return any(lower.endswith(ext) for ext in SOURCE_SECRET_EXTS)


def scan_secrets(path: str, include_skipped: bool = False, stats: dict | None = None) -> list[Finding]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)

    findings: list[Finding] = []
    state = {"files": 0, "oversize": 0}
    lock = threading.Lock()
    reasons: list[str] = []
    max_findings = limits.resolve("GRIM_MAX_SECRET_FINDINGS", MAX_FINDINGS)
    file_cap = limits.resolve("GRIM_MAX_SECRET_FILES", 200_000)
    workers = max(1, limits.resolve("GRIM_SECRET_WORKERS", 8))
    start = time.monotonic()
    dl = limits.deadline()

    if p.is_file() and _is_archive(p):
        # `scan` accepts an archive, so secrets inside one must be found too. Members
        # are read in memory; the on-disk cache key does not apply to them.
        member_cap = 200_000 if limits.is_unlimited(file_cap) else file_cap
        byte_cap = limits.resolve("GRIM_MAX_SECRET_FILE_BYTES", MAX_FILE_BYTES)
        members = _iter_archive_files(p, member_cap, min(byte_cap, MAX_REGEX_BYTES))
        state["files"] = len(members)
        for name, text in members:
            if limits.expired(dl):
                reasons.append("time budget reached")
                break
            virtual = Path(name)
            findings.extend(_scan_text(text, virtual))
    elif p.is_file():
        state["files"] = 1
        findings.extend(_scan_file(p, root=p.parent, include_skipped=include_skipped, state=state, lock=lock))
    else:
        files = _walk_files(p, include_skipped, file_cap)
        state["files"] = len(files)
        if not limits.is_unlimited(file_cap) and len(files) >= file_cap:
            reasons.append(f"file limit reached ({file_cap})")
        if workers > 1 and len(files) > 1:
            def task(fp: Path) -> list[Finding]:
                if limits.expired(dl):
                    return []
                return _scan_file(fp, root=p, include_skipped=include_skipped, state=state, lock=lock)

            with ThreadPoolExecutor(max_workers=workers) as pool:
                for res in pool.map(task, files):
                    findings.extend(res)
        else:
            for fp in files:
                if limits.expired(dl):
                    break
                findings.extend(_scan_file(fp, root=p, include_skipped=include_skipped, state=state, lock=lock))

    if limits.expired(dl):
        reasons.append("time budget reached")
    if limits.reached(len(findings), max_findings):
        reasons.append(f"finding limit reached ({max_findings})")
    if state["oversize"]:
        reasons.append(f"{state['oversize']} file(s) exceeded the size cap and were skipped")
    if stats is not None:
        stats.update(
            {
                "files_scanned": state["files"],
                "oversize_skipped": state["oversize"],
                "findings": len(findings),
                "truncated": bool(reasons),
                "reasons": reasons,
                "elapsed_seconds": limits.elapsed_str(start),
            }
        )
    return findings


def _is_archive(path: Path) -> bool:
    """True when the path is a tar or zip archive GRIM can open."""
    try:
        if zipfile.is_zipfile(path):
            return True
    except OSError:
        return False
    return path.name.lower().endswith(
        (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
    )


def _iter_archive_files(path: Path, max_files: int, max_bytes: int) -> list[tuple[str, str]]:
    """Return (member name, text) for text members inside an archive.

    Binary members are skipped using the same sniff test as on-disk files, and each
    member is size-capped so a crafted archive cannot exhaust memory.
    """
    out: list[tuple[str, str]] = []

    def _add(name: str, raw: bytes) -> None:
        if len(out) >= max_files or not name or name.endswith("/"):
            return
        head = raw[:BINARY_SNIFF_BYTES]
        if b"\x00" in head or _looks_binary(head):
            return
        out.append((name, raw[:max_bytes].decode("utf-8", errors="ignore")))

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if len(out) >= max_files:
                        break
                    if info.is_dir():
                        continue
                    try:
                        with zf.open(info) as fh:
                            _add(info.filename, fh.read(max_bytes + 1))
                    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
                        continue
            return out
        with tarfile.open(path, "r:*") as tf:
            for member in tf:
                if len(out) >= max_files:
                    break
                if not member.isfile():
                    continue
                try:
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    with fh:
                        _add(member.name, fh.read(max_bytes + 1))
                except (OSError, tarfile.TarError):
                    continue
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError):
        return out
    return out


def _walk_files(root: Path, include_skipped: bool, cap: int) -> list[Path]:
    """Deterministic, symlink-safe, capped file list."""
    out: list[Path] = []
    for r, dirs, files in os.walk(root):
        if not include_skipped:
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        dirs.sort()
        for fn in sorted(files):
            fp = Path(r) / fn
            if fp.is_symlink():
                continue
            out.append(fp)
            if not limits.is_unlimited(cap) and len(out) >= cap:
                return out
    return out


def _scan_file(
    fp: Path,
    root: Path,
    include_skipped: bool,
    state: dict | None = None,
    lock: threading.Lock | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    name = fp.name

    if name in SENSITIVE_FILES:
        sev, desc = SENSITIVE_FILES[name]
        is_env = name.startswith(".env")
        # .env in project root is normal for dev; severity stays critical only if in a web dir
        in_web = _in_web_dir(fp, root)
        if is_env and not in_web:
            sev = "low"
        out.append(
            Finding(
                id=make_id("SECR", f"sensitive-file-{name}", str(fp)),
                severity=sev,
                confidence=0.9,
                category="CWE-538",
                owasp="A05:2021",
                title=f"Sensitive file present: {name}",
                description=desc + (" (inside a web-served directory)" if in_web else ""),
                location={"file": str(fp)},
                evidence=f"{name} ({_size_str(fp)})",
                remediation="Remove from deploy artifacts; ensure it is never web-accessible; rotate if it was exposed.",
                engine="grim-secrets",
                tags=["secrets", "exposure"],
            )
        )

    if not fp.is_file():
        return out
    try:
        size = fp.stat().st_size
    except OSError:
        return out
    max_file_bytes = limits.resolve("GRIM_MAX_SECRET_FILE_BYTES", MAX_FILE_BYTES)
    if size == 0:
        return out
    if not limits.is_unlimited(max_file_bytes) and size > max_file_bytes:
        if state is not None:
            if lock is not None:
                with lock:
                    state["oversize"] = state.get("oversize", 0) + 1
            else:
                state["oversize"] = state.get("oversize", 0) + 1
        return out

    try:
        # Only the head is needed to classify the file as text or binary. Reading a
        # 18 MB PDF in full and regex-scanning it was the single biggest cost in a
        # large-tree scan.
        with fp.open("rb") as fh:
            head = fh.read(BINARY_SNIFF_BYTES)
            if b"\x00" in head:
                return out
            if _looks_binary(head):
                return out
            size_left = max(0, size - len(head))
            data = head + (fh.read(size_left) if size_left else b"")
    except OSError:
        return out
    if len(data) > MAX_REGEX_BYTES:
        # Keep the head only: a credential past the cap in a huge file is an
        # acceptable miss versus scanning hundreds of megabytes of text.
        data = data[:MAX_REGEX_BYTES]
    text = data.decode("utf-8", errors="ignore")

    out.extend(_scan_text(text, fp, include_skipped))
    return out


def _redact(value: str) -> str:
    v = value.strip().strip("'\"")
    if len(v) <= 8:
        return "***"
    return f"{v[:4]}…{v[-2:]}(len={len(v)})"



def _scan_text(text: str, fp: Path, include_skipped: bool = False) -> list[Finding]:
    """Run every text-level secret rule over already-decoded content.

    Used for archive members, which are read into memory rather than opened
    from disk, and for regular files after they have been read and sniffed.
    """
    name = fp.name
    out: list[Finding] = []

    for entry in PATTERNS:
        pname, pat, sev, desc = entry[:4]
        needles = entry[4] if len(entry) > 4 else None
        # Literal prefilter: skip the regex entirely when no required substring is
        # present. This is what keeps a large-tree scan fast.
        if needles and not any(n in text for n in needles):
            continue
        for m in pat.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            out.append(
                Finding(
                    id=make_id("SECR", pname, str(fp)),
                    severity=sev,
                    confidence=0.85 if not include_skipped else 0.9,
                    category="CWE-798",
                    owasp="A07:2021",
                    title=f"Possible secret: {desc}",
                    description="Hardcoded credential detected. If this file ships or is committed, treat the secret as compromised.",
                    location={"file": str(fp), "line": text.count("\n", 0, m.start()) + 1},
                    evidence=f"{pname}: {_redact(value)}",
                    remediation="Move to environment variables/secret manager and rotate the credential.",
                    engine="grim-secrets",
                    tags=["secrets"],
                )
            )
            break  # one finding per pattern per file is enough

    # Credential-shaped assignments in source files. The .env rule above only runs on
    # env files, so `const DB_PASSWORD = "..."` in JS or `String apiKey = "..."` in
    # Java was invisible. Gated to source extensions to avoid re-flagging config blobs.
    if _source_ext(name):
        for m in ENV_SECRET_ASSIGN.finditer(text):
            key, value = m.group(1), m.group(2)
            out.append(
                Finding(
                    id=make_id("SECR", f"assign-{key}", str(fp)),
                    severity="high",
                    confidence=0.75,
                    category="CWE-798",
                    owasp="A07:2021",
                    title=f"Hardcoded credential assignment: {key}",
                    description=(
                        "A credential-shaped name is assigned a literal value in source. "
                        "Move it to an environment variable or secret manager."
                    ),
                    location={"file": str(fp), "line": text.count("\n", 0, m.start()) + 1},
                    evidence=f"{key}={_redact(value)}",
                    remediation="Move to environment variables/secret manager and rotate the credential.",
                    engine="grim-secrets",
                    tags=["secrets", "source"],
                )
            )
            if len(out) > 200:
                break

    if name.startswith(".env") or name.endswith(".env"):
        for m in ENV_SECRET_ASSIGN.finditer(text):
            key, value = m.group(1), m.group(2)
            out.append(
                Finding(
                    id=make_id("SECR", f"env-{key}", str(fp)),
                    severity="high",
                    confidence=0.7,
                    category="CWE-798",
                    owasp="A07:2021",
                    title=f".env secret assignment: {key}",
                    description="Secret stored in an environment file. Ensure the file is not web-accessible, not committed, and not inside deploy artifacts.",
                    location={"file": str(fp), "line": text.count("\n", 0, m.start()) + 1},
                    evidence=f"{key}={_redact(value)}",
                    remediation="Keep only on server; rotate if exposure is possible.",
                    engine="grim-secrets",
                    tags=["secrets", "env"],
                )
            )
            if len(out) > 200:
                break

    out.extend(_scan_entropy(text, fp))
    out.extend(_scan_encoded(text, fp))
    return out

def _size_str(fp: Path) -> str:
    try:
        return f"{fp.stat().st_size} B"
    except OSError:
        return "?"


def _in_web_dir(fp: Path, root: Path) -> bool:
    try:
        rel = fp.relative_to(root)
    except ValueError:
        rel = fp
    parts = [s.lower() for s in rel.parts[:-1]]
    return any(s in {"public", "public_html", "www", "htdocs", "web", "uploads", "upload", "static"} for s in parts)


# --------------------------------------------------------------------------- entropy


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


HIGH_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9_\-]{20,}")

# Entropy scanning is only meaningful for source/config text. Data, docs, generated
# bundles and lockfiles are full of high-entropy strings (hashes, uuids, base64) that
# are not credentials, so skip them. Known secret patterns still run on every file.
ENTROPY_SKIP_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "go.sum", "cargo.lock", "poetry.lock", "pipfile.lock",
    "gemfile.lock", "pubspec.lock", "packages.lock.json",
    # Checksum manifests are hex digests by definition; entropy always fires on them.
    "sha256sums", "sha256sums.txt", "sha512sums", "sha512sums.txt", "md5sums",
    "checksums", "checksums.txt", "checksum.txt", "sha1sums", "versions.json",
}
ENTROPY_SKIP_EXTS = {
    ".map", ".min.js", ".min.css", ".md", ".markdown", ".rst", ".txt", ".log",
    ".csv", ".tsv", ".svg", ".html", ".htm", ".lock", ".sum", ".json", ".snap",
    # Checksum and digest files: hex/base64 by construction, never credentials.
    ".sha256", ".sha512", ".sha1", ".md5", ".sha256sum", ".asc", ".sig", ".pub",
    # Data and asset payloads that embed compressed or encoded content.
    ".wasm", ".bin", ".dat", ".pak", ".gz", ".zip", ".bz2", ".xz", ".7z",
    ".pdf", ".eot", ".woff", ".woff2", ".ttf", ".otf",
}
# Directory names whose contents are vendored or generated, not authored source.
ENTROPY_SKIP_DIR_PARTS = {
    "vendor", "vendors", "node_modules", "third_party", "thirdparty", "dist",
    "build", "out", "coverage", ".git", "assets", "static", "public", "media",
    "fonts", "images", "img", "reference", "references", "fixtures", "testdata",
    "golden", "snapshots", "__snapshots__", "migrations", "seeds", "locale",
    "locales", "i18n", "docs", "doc", "examples", "example", "samples",
}

# A credential is a value bound to a name or returned by an auth API. Bare 20+ char
# tokens inside data files are almost always identifiers, so the entropy pass only
# reports a token when it sits in a credential context.
CREDENTIAL_CONTEXT = re.compile(
    r"(?i)(?:"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|auth|credential|bearer|session|cookie|signature|salt|"
    r"client[_-]?secret|refresh[_-]?token)\s*[:=]\s*['\"]?"
    r"|['\"](?:password|secret|token|key)['\"]\s*:\s*['\"]"
    r"|(?:getenv|process\.env|ENV\[|os\.environ|getString|System\.getenv)\s*[(\[]"
    r"|Basic\s+[A-Za-z0-9+/]{16,}|Bearer\s+[A-Za-z0-9._~+/-]{16,}"
    r"|://[^/\s:@'\"]+:[^/\s@'\"]{8,}@"
    r")"
)
# Same signal, matched against the text preceding a token on its own line.
CREDENTIAL_KEY_ON_LINE = re.compile(
    r"(?i)(?:"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|auth|credential|bearer|session|cookie|signature|salt)\s*[:=]"
    r"|['\"](?:password|secret|token|key|auth)['\"]\s*:\s*['\"]?"
    r"|(?:getenv|process\.env|os\.environ)\s*[(\[]\s*['\"]?"
    r")"
)


def _entropy_enabled(fp: Path) -> bool:
    name = fp.name.lower()
    if name in ENTROPY_SKIP_NAMES:
        return False
    if any(name.endswith(ext) for ext in ENTROPY_SKIP_EXTS):
        return False
    parts = {p.lower() for p in fp.parts[:-1]}
    if parts & ENTROPY_SKIP_DIR_PARTS:
        return False
    return True


def _has_credential_context(text: str, start: int, end: int) -> bool:
    """True when the token at [start, end) sits in a credential-shaped context.

    Only the token's own line is inspected. A wider window lets an unrelated
    credential several lines above lend its context to an innocent identifier,
    which is how data-file identifiers turned into false positives.
    """
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    # `name = <token>` or `name: <token>` where name is credential shaped.
    if CREDENTIAL_CONTEXT.search(prefix):
        return True
    # A credential-shaped key immediately preceding the token on the same line.
    return bool(CREDENTIAL_KEY_ON_LINE.search(prefix))


def _scan_entropy(text: str, fp: Path) -> list[Finding]:
    if not _entropy_enabled(fp):
        return []
    out: list[Finding] = []
    # Cheap rejections first. Entropy is only computed for tokens that already have
    # mixed case and a digit, which is what makes entropy meaningful anyway. On a
    # large tree this ordering removes millions of entropy computations.
    candidates = []
    for m in HIGH_ENTROPY_CANDIDATE.finditer(text):
        token = m.group(0)
        if not (any(c.islower() for c in token) and any(c.isupper() for c in token)):
            continue
        if not any(c.isdigit() for c in token):
            continue
        # pure hex is a hash, not a credential (and hashes are handled elsewhere)
        if re.fullmatch(r"[0-9a-fA-F]+", token):
            continue
        candidates.append(m)
    for m in candidates:
        token = m.group(0)
        if _entropy(token) < 4.3:
            continue
        # A bare high-entropy token in a data file is almost always an identifier,
        # digest, or base64 asset fragment. Require a credential-shaped name nearby.
        if not _has_credential_context(text, m.start(), m.end()):
            continue
        out.append(
            Finding(
                id=make_id("SECR", f"entropy-{token[:12]}", str(fp)),
                severity="medium",
                confidence=0.55,
                category="CWE-798",
                owasp="A07:2021",
                title="High entropy string (possible credential)",
                description="A long high entropy token that is not a plain hex hash. Could be a generated credential.",
                location={"file": str(fp), "line": text.count("\n", 0, m.start()) + 1},
                evidence=_redact(token),
                remediation="Verify what this string is; if it is a credential, move it to a secret manager.",
                engine="grim-secrets",
                tags=["secrets", "entropy"],
            )
        )
        if len(out) >= 8:
            break
    return out


# --------------------------------------------------------------------------- encoded

B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HEX_BLOB = re.compile(r"[0-9a-fA-F]{64,}")


def _decode_candidates(token: str) -> list[bytes]:
    decoded: list[bytes] = []
    try:
        b = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
        if len(b) > 4:
            decoded.append(b)
    except Exception:
        pass
    try:
        b = bytes.fromhex(token if len(token) % 2 == 0 else token[:-1])
        if len(b) > 4:
            decoded.append(b)
    except ValueError:
        pass
    return decoded


def _scan_encoded(text: str, fp: Path) -> list[Finding]:
    out: list[Finding] = []
    markers = (b"begin", b"api_key", b"apikey", b"secret", b"password", b"token")
    seen: set[str] = set()
    for m in B64_BLOB.finditer(text):
        token = m.group(0)
        if token in seen:
            continue
        seen.add(token)
        for dec in _decode_candidates(token):
            low = dec.lower()
            if any(mk in low for mk in markers):
                out.append(
                    Finding(
                        id=make_id("SECR", f"encoded-{token[:12]}", str(fp)),
                        severity="high",
                        confidence=0.7,
                        category="CWE-798",
                        owasp="A07:2021",
                        title="Encoded blob contains credential markers",
                        description="A base64 or hex blob decodes to text containing credential markers.",
                        location={"file": str(fp), "line": text.count("\n", 0, m.start()) + 1},
                        evidence=f"encoded({len(token)} chars) decodes to credential-like content",
                        remediation="Decode and inspect; rotate if it is a real credential.",
                        engine="grim-secrets",
                        tags=["secrets", "encoded"],
                    )
                )
                break
        if len(out) > 10:
            break
    return out


# --------------------------------------------------------------------------- git history


def _git(cwd: Path, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(cwd)] + args,
            capture_output=True, text=True, timeout=60,
        )
        return proc.stdout
    except Exception:
        return ""


def scan_secrets_history(path: str, max_blobs: int = 2000) -> list[Finding]:
    """Scan historical git blobs for leaked secrets. Returns findings tied to the commit."""
    p = Path(path)
    if not p.exists() or not (p / ".git").exists():
        return []
    objects = _git(p, ["rev-list", "--all", "--objects"]).splitlines()
    blobs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in objects:
        parts = line.split()
        if len(parts) < 2:
            continue
        blob_id, blob_path = parts[0], " ".join(parts[1:])
        if blob_id in seen:
            continue
        seen.add(blob_id)
        blobs.append((blob_id, blob_path))
        if len(blobs) >= max_blobs:
            break

    findings: list[Finding] = []
    for blob_id, blob_path in blobs:
        data = _git(p, ["cat-file", "blob", blob_id])
        if not data or len(data) > MAX_FILE_BYTES:
            continue
        text = data.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
        if "\x00" in text[:4096]:
            continue
        for entry in PATTERNS:
            pname, pat, sev, desc = entry[:4]
            needles = entry[4] if len(entry) > 4 else None
            if needles and not any(n in text for n in needles):
                continue
            m = pat.search(text)
            if not m:
                continue
            value = m.group(1) if m.groups() else m.group(0)
            findings.append(
                Finding(
                    id=make_id("SECRHIST", pname, f"{blob_path}@{blob_id[:8]}"),
                    severity=sev,
                    confidence=0.9,
                    category="CWE-798",
                    owasp="A07:2021",
                    title=f"Secret in git history: {desc}",
                    description="A credential exists in committed history. Even if removed later, the blob survives in git objects and is recoverable.",
                    location={"file": blob_path, "commit": blob_id[:8]},
                    evidence=f"{pname}: {_redact(value)}",
                    remediation="Rotate the credential now, then purge history (filter-branch or BFG) and force-push.",
                    engine="grim-secrets-history",
                    tags=["secrets", "history"],
                )
            )
            break
        if len(findings) > 200:
            break
    return findings
