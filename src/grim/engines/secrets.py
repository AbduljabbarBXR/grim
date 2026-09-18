"""Secrets scanning: leaked credentials, keys, tokens, sensitive files."""

from __future__ import annotations

import base64
import math
import os
import re
import subprocess
from pathlib import Path

from ..core import limits
from ..core.findings import Finding, make_id

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 800
SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", ".cache",
}

# (name, pattern, severity, description)
PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", "AWS access key ID"),
    ("aws-secret", re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "critical", "AWS secret access key"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high", "Google API key"),
    ("stripe-live-secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical", "Stripe live secret key"),
    ("stripe-live-publishable", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "medium", "Stripe live publishable key"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", "GitHub token"),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "critical", "OpenAI-style secret key"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "critical", "Anthropic API key"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high", "Slack token"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical", "Private key block"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium", "JSON Web Token"),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "critical", "SendGrid API key"),
    ("twilio-sid", re.compile(r"\bAC[a-f0-9]{32}\b"), "high", "Twilio account SID"),
    ("mailgun-key", re.compile(r"\bkey-[a-z0-9]{32}\b"), "medium", "Mailgun API key"),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), "medium", "Telegram bot token"),
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
    r"(?im)^([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_?KEY|TOKEN|AUTH|PRIVATE)[A-Z0-9_]*)\s*=\s*['\"]?([^\s'\"#]{8,})"
)


def scan_secrets(path: str, include_skipped: bool = False, stats: dict | None = None) -> list[Finding]:
    p = Path(path)
    findings: list[Finding] = []
    state = {"files": 0, "oversize": 0}
    reasons: list[str] = []
    max_findings = limits.resolve("GRIM_MAX_SECRET_FINDINGS", MAX_FINDINGS)

    if not p.exists():
        raise FileNotFoundError(path)

    def finish() -> list[Finding]:
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
                }
            )
        return findings

    if p.is_file():
        state["files"] = 1
        findings.extend(_scan_file(p, root=p.parent, include_skipped=include_skipped, state=state))
        return finish()

    for root, dirs, files in os.walk(p):
        if not include_skipped:
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            fp = Path(root) / fn
            state["files"] += 1
            findings.extend(_scan_file(fp, root=p, include_skipped=include_skipped, state=state))
            if limits.reached(len(findings), max_findings):
                reasons.append(f"finding limit reached ({max_findings})")
                return finish()
    return finish()


def _scan_file(fp: Path, root: Path, include_skipped: bool, state: dict | None = None) -> list[Finding]:
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
            state["oversize"] = state.get("oversize", 0) + 1
        return out

    try:
        data = fp.read_bytes()
    except OSError:
        return out
    if b"\x00" in data[:4096]:
        return out
    text = data.decode("utf-8", errors="ignore")

    for pname, pat, sev, desc in PATTERNS:
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
                    location={"file": str(fp), "line": text[: m.start()].count("\n") + 1},
                    evidence=f"{pname}: {_redact(value)}",
                    remediation="Move to environment variables/secret manager and rotate the credential.",
                    engine="grim-secrets",
                    tags=["secrets"],
                )
            )
            break  # one finding per pattern per file is enough

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
                    location={"file": str(fp), "line": text[: m.start()].count("\n") + 1},
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


def _redact(value: str) -> str:
    v = value.strip().strip("'\"")
    if len(v) <= 8:
        return "***"
    return f"{v[:4]}…{v[-2:]}(len={len(v)})"


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
    return any(s in {"public", "public_html", "www", "htdocs", "web", "uploads", "upload", "uploads", "static"} for s in parts)


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
}
ENTROPY_SKIP_EXTS = {
    ".map", ".min.js", ".min.css", ".md", ".markdown", ".rst", ".txt", ".log",
    ".csv", ".tsv", ".svg", ".html", ".htm", ".lock", ".sum", ".json", ".snap",
}


def _entropy_enabled(fp: Path) -> bool:
    name = fp.name.lower()
    if name in ENTROPY_SKIP_NAMES:
        return False
    if any(name.endswith(ext) for ext in ENTROPY_SKIP_EXTS):
        return False
    return True


def _scan_entropy(text: str, fp: Path) -> list[Finding]:
    if not _entropy_enabled(fp):
        return []
    out: list[Finding] = []
    for m in HIGH_ENTROPY_CANDIDATE.finditer(text):
        token = m.group(0)
        if _entropy(token) < 4.3:
            continue
        # must look like a generated secret: mixed case plus digits
        if not (any(c.islower() for c in token) and any(c.isupper() for c in token)):
            continue
        if not any(c.isdigit() for c in token):
            continue
        # pure hex is a hash, not a credential (and hashes are handled elsewhere)
        if re.fullmatch(r"[0-9a-fA-F]+", token):
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
                location={"file": str(fp), "line": text[: m.start()].count("\n") + 1},
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
                        location={"file": str(fp), "line": text[: m.start()].count("\n") + 1},
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
        for pname, pat, sev, desc in PATTERNS:
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
