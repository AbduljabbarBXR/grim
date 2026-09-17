"""Secrets scanning: leaked credentials, keys, tokens, sensitive files."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..core.findings import Finding, make_id

MAX_FILE_BYTES = 2 * 1024 * 1024
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


def scan_secrets(path: str, include_skipped: bool = False) -> list[Finding]:
    p = Path(path)
    findings: list[Finding] = []
    if not p.exists():
        raise FileNotFoundError(path)
    if p.is_file():
        findings.extend(_scan_file(p, root=p.parent, include_skipped=include_skipped))
        return findings

    for root, dirs, files in os.walk(p):
        if not include_skipped:
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            fp = Path(root) / fn
            findings.extend(_scan_file(fp, root=p, include_skipped=include_skipped))
            if len(findings) > 800:
                return findings
    return findings


def _scan_file(fp: Path, root: Path, include_skipped: bool) -> list[Finding]:
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
    if size == 0 or size > MAX_FILE_BYTES:
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
