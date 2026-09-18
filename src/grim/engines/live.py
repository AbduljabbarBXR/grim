"""Opt-in live checks for a single authorized host.

Passive by default (headers, cookies, TLS). Active path probing only runs when the scope
grants ``mode: active`` and the exact path is in ``paths_allowlist``. Denied paths are never
touched. Rate-limited per the scope. Stdlib only.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..core import policy
from ..core.findings import Finding, make_id

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# path -> (bytes that must appear to confirm, severity, title)
ACTIVE_PROBES: dict[str, tuple[bytes, str, str]] = {
    "/.env": (b"=", "critical", "Exposed environment file (.env)"),
    "/.git/config": (b"[core]", "critical", "Exposed .git directory"),
    "/phpinfo.php": (b"phpinfo", "high", "Exposed phpinfo() page"),
    "/server-status": (b"Server Status", "medium", "Exposed server-status page"),
    "/backup.zip": (b"PK\x03\x04", "high", "Exposed backup archive"),
    "/.DS_Store": (b"\x00\x00\x00\x01Bud1", "low", "Exposed .DS_Store"),
}

USER_AGENT = "grim-live/0.5 (authorized security check)"


class LiveError(Exception):
    pass


def check_live(
    url: str,
    scope: dict,
    active: bool = False,
    timeout: int = 10,
    stats: dict | None = None,
) -> list[Finding]:
    decision = policy.authorize(scope, url)
    if not decision.get("allowed"):
        raise LiveError(decision.get("reason", "target not authorized"))

    mode = "active" if (active and decision.get("mode") == "active") else "passive"
    limiter = policy.RateLimiter(int(decision.get("max_rpm", 0)))
    allowlist = decision.get("paths_allowlist") or []
    findings: list[Finding] = []
    requests = 0

    limiter.wait()
    status, headers, body, final_url = _fetch(url, timeout)
    requests += 1
    if status is None:
        raise LiveError(f"could not reach {url}")

    findings.extend(_passive(url, final_url, status, headers, body))

    parsed = urlparse(final_url)
    if parsed.scheme == "https":
        findings.extend(_tls(parsed.hostname or "", parsed.port or 443, timeout))

    if mode == "active":
        for path, (marker, sev, title) in ACTIVE_PROBES.items():
            if not policy.path_allowed(path, allowlist):
                continue
            probe = f"{parsed.scheme}://{parsed.netloc}{path}"
            limiter.wait()
            pstatus, pheaders, pbody, _ = _fetch(probe, timeout)
            requests += 1
            if pstatus == 200 and marker in pbody:
                findings.append(
                    Finding(
                        id=make_id("LIVE", title, probe),
                        severity=sev,
                        confidence=0.9,
                        category="CWE-538",
                        owasp="A05:2021",
                        title=title,
                        description="An authorized active probe confirmed this resource is publicly reachable.",
                        location={"url": probe},
                        evidence=f"HTTP {pstatus}; matched {marker[:12]!r}",
                        remediation="Block access at the server/reverse proxy and remove the file from the deploy.",
                        engine="grim-live",
                        tags=["live", "exposure", "authorized"],
                    )
                )

    if stats is not None:
        stats.update(
            {
                "mode": mode,
                "host": decision.get("host"),
                "requests": requests,
                "status": status,
                "findings": len(findings),
                "active_allowed": decision.get("mode") == "active",
            }
        )
    return findings


def _fetch(url: str, timeout: int, max_bytes: int = 20000):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read(max_bytes), resp.geturl()
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read(max_bytes)
        except Exception:
            data = b""
        return exc.code, exc.headers, data, url
    except (urllib.error.URLError, OSError, ssl.SSLError):
        return None, None, b"", url


def _headers(msg) -> dict:
    out: dict[str, str] = {}
    if msg is None:
        return out
    for k, v in msg.items():
        out.setdefault(k.lower(), v)
    return out


def _cookie_list(msg) -> list[str]:
    get_all = getattr(msg, "get_all", None)
    if get_all:
        return get_all("Set-Cookie") or []
    return []


def _passive(url: str, final_url: str, status: int, msg, body: bytes) -> list[Finding]:
    out: list[Finding] = []
    headers = _headers(msg)
    https = (urlparse(final_url).scheme == "https")

    missing = [label for h, label in SECURITY_HEADERS.items() if h not in headers and not (h == "strict-transport-security" and not https)]
    if missing:
        out.append(
            Finding(
                id=make_id("LIVE", "missing-headers", final_url),
                severity="medium",
                confidence=0.8,
                category="CWE-693",
                owasp="A05:2021",
                title=f"Missing security headers ({len(missing)})",
                description="Security response headers reduce XSS, clickjacking, and MIME-confusion risk.",
                location={"url": final_url},
                evidence=", ".join(missing),
                remediation="Add the missing headers at the web server or reverse proxy.",
                engine="grim-live",
                tags=["live", "headers"],
            )
        )

    disclosure = [f"{k}: {headers[k]}" for k in ("server", "x-powered-by") if k in headers]
    if disclosure:
        out.append(
            Finding(
                id=make_id("LIVE", "tech-disclosure", final_url),
                severity="low",
                confidence=0.7,
                category="CWE-200",
                owasp="A05:2021",
                title="Technology disclosure in response headers",
                description="Server/version banners help attackers target known vulnerabilities.",
                location={"url": final_url},
                evidence="; ".join(disclosure),
                remediation="Suppress version banners (e.g. ServerTokens Prod, expose_php Off).",
                engine="grim-live",
                tags=["live", "disclosure"],
            )
        )

    weak_cookies = [c for c in _cookie_list(msg) if _cookie_weak(c)]
    if weak_cookies:
        out.append(
            Finding(
                id=make_id("LIVE", "cookie-flags", final_url),
                severity="medium",
                confidence=0.7,
                category="CWE-614",
                owasp="A05:2021",
                title="Cookie missing Secure/HttpOnly/SameSite",
                description="Cookies without protective flags are exposed to theft or CSRF.",
                location={"url": final_url},
                evidence="; ".join(c.split(";")[0] for c in weak_cookies[:5]),
                remediation="Set Secure, HttpOnly, and SameSite on session cookies.",
                engine="grim-live",
                tags=["live", "cookies"],
            )
        )
    return out


def _cookie_weak(cookie: str) -> bool:
    low = cookie.lower()
    return not ("secure" in low and "httponly" in low and "samesite" in low)


def _tls(host: str, port: int, timeout: int) -> list[Finding]:
    try:
        ctx = ssl.create_default_context()
        import socket

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                version = ss.version()
    except (OSError, ssl.SSLError):
        return []

    out: list[Finding] = []
    if version and version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        out.append(
            Finding(
                id=make_id("LIVE", "tls-version", host),
                severity="high",
                confidence=0.9,
                category="CWE-327",
                owasp="A02:2021",
                title=f"Outdated TLS version negotiated ({version})",
                description="Legacy TLS versions have known weaknesses.",
                location={"url": f"https://{host}"},
                evidence=version,
                remediation="Disable TLS < 1.2 and prefer TLS 1.3.",
                engine="grim-live",
                tags=["live", "tls"],
            )
        )
    if cert and cert.get("notAfter"):
        try:
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
            days = int((expires - time.time()) / 86400)
        except (ValueError, KeyError):
            days = None
        if days is not None and days < 30:
            sev = "high" if days < 7 else "medium"
            out.append(
                Finding(
                    id=make_id("LIVE", "tls-expiry", host),
                    severity=sev,
                    confidence=0.95,
                    category="CWE-298",
                    owasp="A02:2021",
                    title=f"TLS certificate expires in {days} day(s)",
                    description="An expired certificate breaks trust and availability.",
                    location={"url": f"https://{host}"},
                    evidence=cert.get("notAfter", ""),
                    remediation="Renew the certificate and automate renewal.",
                    engine="grim-live",
                    tags=["live", "tls"],
                )
            )
    return out
