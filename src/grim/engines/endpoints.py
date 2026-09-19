"""Endpoint inventory: enumerate routes across common frameworks and rank their risk.

Best-effort, regex/file based, dependency free. For each route we record method, path,
whether an auth middleware appears nearby, whether a request input surface is present,
and a risk level. Unauthenticated routes with input surfaces rank highest.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..core import limits
from ..core.findings import Finding, make_id

MAX_FILES = 20000
MAX_ENDPOINTS = 5000
MAX_FINDINGS = 500

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", ".cache", "storage/framework",
}

AUTH_MARKERS = re.compile(
    r"(requireauth|require_auth|isauthenticated|is_admin|authorize|passport|jwt|bearer"
    r"|authmiddleware|authenticate|ensureauthenticated|ensureloggedin"
    r"|middleware\(\s*\[?\s*['\"]auth"
    r"|middleware['\"]?\s*=>\s*\[?[^\]]{0,80}['\"]auth"
    r"|auth:|auth\(|permission_required|login_required|@login_required|verifytoken|checkauth)",
    re.I,
)
INPUT_MARKERS = re.compile(
    r"(req\.(body|query|params|files|json|text|formData|nextUrl|cookies|headers)"
    r"|request\.(body|query|params|form|json|files|args|POST|GET)"
    r"|\$request|\$_(GET|POST|REQUEST|FILES)|request\.json|request\.form|HttpRequest|searchParams)",
    re.I,
)
SENSITIVE = re.compile(r"(admin|upload|debug|exec|shell|eval|sql|export|import|backup|\.\.)", re.I)

EXPRESS = re.compile(
    r"\b(?:app|router|server|api)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    re.I,
)
LARAVEL = re.compile(
    r"Route\s*::\s*(get|post|put|delete|patch|any|match|options)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.I,
)
LARAVEL_CHAIN = re.compile(
    r"(?:Route\s*::|->)\s*(get|post|put|delete|patch|any|match|options)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.I,
)
DJANGO = re.compile(r"\b(?:path|re_path|url)\s*\(\s*r?['\"]([^'\"]+)['\"]")
GO_METHOD = re.compile(r"\b\w+\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*\"([^\"]+)\"")
GO_HANDLE = re.compile(r"(?:http\.HandleFunc|\w+\.HandleFunc|\w+\.Handle)\s*\(\s*\"([^\"]+)\"")
NEXT_ROUTE_METHOD = re.compile(r"export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
_PHP_STRING = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")


def _strip_php_strings(line: str) -> str:
    """Remove PHP string literal contents so braces inside routes (for example
    '/products/{id}/edit') are not counted as scope delimiters."""
    return _PHP_STRING.sub("''", line)


FRAMEWORK_MIDDLEWARE = (
    "web", "api", "throttle", "cors", "bindings", "localization", "startsession",
    "encryptcookies", "shareerrorsfromsession", "substitutebindings", "trustproxies",
    "handlecors", "validatecsrftoken",
)
AUTH_MIDDLEWARE_HINTS = re.compile(
    r"(auth|admin|role|can|permission|seller|verified|user|customer|subscribed|onboarded"
    r"|jwt|passport|bearer|signed|password\.confirm|owner|staff|member)",
    re.I,
)


def _middleware_names(text: str) -> list[str]:
    """Extract middleware names from an assoc-array or call form."""
    names: list[str] = []
    for m in re.finditer(r"middleware['\"]?\s*=>\s*\[([^\]]*)\]", text):
        names += re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
    for m in re.finditer(r"middleware\s*\(\s*\[([^\]]*)\]", text):
        names += re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
    for m in re.finditer(r"middleware\s*\(\s*['\"]([^'\"]+)['\"]", text):
        names.append(m.group(1))
    return [n.strip().lower() for n in names if n.strip()]


def _middleware_protected(text: str) -> bool:
    names = _middleware_names(text)
    if not names:
        return False
    if any(AUTH_MIDDLEWARE_HINTS.search(n) for n in names):
        return True
    # A route or group that declares custom middleware beyond the framework defaults
    # is presumptively guarded (for example a domain specific 'seller' middleware).
    return any(not n.startswith(FRAMEWORK_MIDDLEWARE) for n in names)


def _group_protected(text: str) -> bool:
    return bool(AUTH_MARKERS.search(text)) or _middleware_protected(text)


def _strip_php_comments(text: str) -> str:
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"(?m)^\s*#[^\n]*", "", text)
    return text


def _registered_route_files(root: Path) -> set[str] | None:
    """Route file basenames referenced by RouteServiceProvider or bootstrap/app.php.

    Returns None when the project exposes no provider (scan everything). Commented
    registrations are ignored, so an unreferenced routes file is not scanned.
    """
    if not root.is_dir():
        return None
    providers = list(root.rglob("RouteServiceProvider.php")) + list(root.rglob("bootstrap/app.php"))
    if not providers:
        return None
    names: set[str] = set()
    for f in providers:
        try:
            text = _strip_php_comments(f.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        for m in re.finditer(r"routes/([A-Za-z0-9_./-]+\.php)", text):
            names.add(Path(m.group(1)).name)
    return names or None


def _lang_of(fp: Path) -> str | None:
    name = fp.name.lower()
    suffix = fp.suffix.lower()
    if name in ("route.ts", "route.js", "route.tsx") or name.endswith(".route.ts") or name.endswith(".route.js"):
        return "next"
    parts = fp.parts
    if "pages" in parts and "api" in parts:
        return "next"
    if suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
        return "js"
    if suffix == ".php":
        return "php"
    if suffix == ".py":
        return "python"
    if suffix == ".go":
        return "go"
    if suffix == ".astro":
        return "astro"
    return None


def inventory_endpoints(path: str, stats: dict | None = None) -> tuple[list[dict], list[Finding]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    max_files = limits.resolve("GRIM_MAX_FILES", MAX_FILES)
    files = [p] if p.is_file() else _walk(p, max_files)
    registered = _registered_route_files(p) if p.is_dir() else None
    endpoints: list[dict] = []
    reasons: list[str] = []
    for fp in files:
        if limits.reached(len(endpoints), MAX_ENDPOINTS):
            reasons.append(f"endpoint limit reached ({MAX_ENDPOINTS})")
            break
        endpoints.extend(_parse_file(fp, p, registered))
    if limits.reached(len(files), max_files):
        reasons.append(f"file limit reached ({max_files})")

    findings = _to_findings(endpoints[:MAX_ENDPOINTS])
    if stats is not None:
        stats.update(
            {
                "files_scanned": len(files),
                "endpoints": len(endpoints),
                "findings": len(findings),
                "truncated": bool(reasons),
                "reasons": reasons,
            }
        )
    return endpoints, findings


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


def _parse_file(fp: Path, root: Path, registered: set[str] | None = None) -> list[dict]:
    lang = _lang_of(fp)
    if lang is None:
        return []
    if lang == "php" and registered is not None:
        try:
            parts = fp.relative_to(root).parts
        except ValueError:
            parts = fp.parts
        if "routes" in parts and fp.name not in registered:
            return []
    try:
        if fp.stat().st_size > limits.resolve("GRIM_MAX_CODE_FILE_BYTES", 1024 * 1024):
            return []
        text = fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if lang in ("js",):
        return _parse_express(text, fp, root)
    if lang == "php":
        return _parse_laravel(text, fp, root)
    if lang == "python":
        return _regex_routes(text, fp, root, "django", DJANGO, group_path=1, method="ANY")
    if lang == "go":
        return _parse_go(text, fp, root)
    if lang == "next":
        return _next_routes(text, fp, root)
    if lang == "astro":
        return _astro_route(fp, root)
    return []


def _parse_laravel(text: str, fp: Path, root: Path) -> list[dict]:
    """Laravel routes, tracking auth inherited from enclosing middleware groups.

    Handles both ``middleware([...])`` on the route (including a chained call on the
    next line) and group middleware declared as ``Route::group([...])`` or
    ``Route::middleware([...])->group(function () { ... })``.
    """
    lines = text.splitlines()
    out: list[dict] = []
    group_auth: list[bool] = []
    pending: str | None = None

    for i, line in enumerate(lines):
        if "group" in line and re.search(r"(?:Route\s*::|->)\s*(?:middleware\s*\([^)]*\)\s*->\s*)?group\s*\(", line):
            pending = line
        elif pending is not None:
            pending += " " + line

        if "Route" in line:
            context = _statement_context(lines, i)
            inherited = any(group_auth)
            for m in LARAVEL_CHAIN.finditer(line):
                out.append(
                    _from_line(m.group(1).upper(), m.group(2), line, fp, root, i + 1, "laravel",
                               context=context, auth_extra=inherited)
                )

        if pending is not None and "{" in _strip_php_strings(line):
            group_auth.append(_group_protected(pending))
            pending = None
        for _ in range(_strip_php_strings(line).count("}")):
            if group_auth:
                group_auth.pop()
    return out


def _parse_express(text: str, fp: Path, root: Path) -> list[dict]:
    """Express routes, inheriting auth from any preceding ``app.use(auth)``."""
    lines = text.splitlines()
    out: list[dict] = []
    file_auth = False
    for i, line in enumerate(lines):
        if re.search(r"\b(?:app|router|server|api)\s*\.\s*use\s*\(", line) and AUTH_MARKERS.search(line):
            file_auth = True
        if not EXPRESS.search(line):
            continue
        for m in EXPRESS.finditer(line):
            meth = m.group(1).upper()
            if meth == "USE":
                continue
            out.append(
                _from_line(meth, m.group(2), line, fp, root, i + 1, "express",
                           auth_extra=file_auth)
            )
    return out


def _statement_context(lines: list[str], i: int, max_lines: int = 3) -> str:
    """Join a route statement with its chained continuation lines (until a semicolon)."""
    text = lines[i]
    k = i
    while not text.rstrip().endswith(";") and k + 1 < len(lines) and (k - i) < max_lines:
        k += 1
        text += " " + lines[k]
    return text


def _parse_go(text: str, fp: Path, root: Path) -> list[dict]:
    out: list[dict] = []
    for i, line in enumerate(text.splitlines()):
        for m in GO_METHOD.finditer(line):
            out.append(_from_line(m.group(1), m.group(2), line, fp, root, i + 1, "go"))
        for m in GO_HANDLE.finditer(line):
            out.append(_from_line("ANY", m.group(1), line, fp, root, i + 1, "go"))
    return out


def _from_line(
    method: str,
    route: str,
    line: str,
    fp: Path,
    root: Path,
    lineno: int,
    framework: str,
    context: str | None = None,
    auth_extra: bool = False,
) -> dict:
    probe = context if context is not None else line
    auth = auth_extra or bool(AUTH_MARKERS.search(probe)) or _middleware_protected(probe)
    inputs = bool(INPUT_MARKERS.search(probe))
    return _endpoint(framework, method, route, fp, root, lineno, auth, inputs)


def _regex_routes(
    text: str,
    fp: Path,
    root: Path,
    framework: str,
    pattern: re.Pattern,
    group_path: int = 2,
    method: str | None = None,
) -> list[dict]:
    out: list[dict] = []
    for i, line in enumerate(text.splitlines()):
        for m in pattern.finditer(line):
            meth = method if method is not None else m.group(1).upper()
            if meth == "USE":
                continue
            out.append(_from_line(meth, m.group(group_path), line, fp, root, i + 1, framework))
    return out


def _next_routes(text: str, fp: Path, root: Path) -> list[dict]:
    route = _file_route(fp, root, markers=("app", "pages"), api_prefix="/api")
    methods = sorted(set(NEXT_ROUTE_METHOD.findall(text)))
    auth = bool(AUTH_MARKERS.search(text))
    inputs = bool(INPUT_MARKERS.search(text))
    if not methods:
        methods = ["ANY"] if "export default" in text else ["GET"]
    out: list[dict] = []
    for meth in methods or ["GET"]:
        out.append(_endpoint("nextjs", meth, route, fp, root, 1, auth, inputs))
    return out


def _astro_route(fp: Path, root: Path) -> list[dict]:
    route = _file_route(fp, root, markers=("pages",), api_prefix="/")
    text = ""
    try:
        text = fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass
    return [_endpoint("astro", "GET", route, fp, root, 1, bool(AUTH_MARKERS.search(text)), bool(INPUT_MARKERS.search(text)))]


def _file_route(fp: Path, root: Path, markers: tuple[str, ...], api_prefix: str) -> str:
    try:
        rel = fp.relative_to(root)
    except ValueError:
        rel = fp
    parts = list(rel.parts)
    for marker in markers:
        if marker in parts:
            parts = parts[parts.index(marker) + 1 :]
            break
    stem = parts[-1]
    for ext in (".astro", ".tsx", ".ts", ".js", ".jsx", ".mjs"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    parts = parts[:-1] + [stem]
    parts = [p for p in parts if p not in ("route", "index")]
    route = "/" + "/".join(parts)
    if route == "/":
        route = api_prefix
    elif api_prefix != "/" and not route.startswith(api_prefix):
        route = api_prefix + route
    return re.sub(r"/{2,}", "/", route)


def _endpoint(
    framework: str, method: str, path: str, fp: Path, root: Path, line: int, auth: bool, inputs: bool
) -> dict:
    try:
        rel = str(fp.relative_to(root))
    except ValueError:
        rel = str(fp)
    sensitive = bool(SENSITIVE.search(path))
    if inputs and not auth:
        risk, reason = "high", "unauthenticated route with a request input surface"
    elif sensitive and not auth:
        risk, reason = "high", "unauthenticated sensitive route"
    elif inputs:
        risk, reason = "medium", "route accepts input; confirm authorization"
    else:
        risk, reason = "low", "no input surface detected"
    return {
        "framework": framework,
        "method": (method or "ANY").upper(),
        "path": path,
        "file": rel,
        "line": line,
        "auth": auth,
        "inputs": inputs,
        "risk": risk,
        "reason": reason,
    }


def _to_findings(endpoints: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    risky = [e for e in endpoints if e["risk"] in ("high", "medium")]
    risky.sort(key=lambda e: (0 if e["risk"] == "high" else 1, e["file"], e["line"]))
    for e in risky[:MAX_FINDINGS]:
        sev = "high" if e["risk"] == "high" else "medium"
        out.append(
            Finding(
                id=make_id("EP", f"{e['method']} {e['path']}", f"{e['file']}:{e['line']}"),
                severity=sev,
                confidence=0.6,
                category="CWE-306" if e["risk"] == "high" else "CWE-862",
                owasp="A01:2021",
                title=f"{e['method']} {e['path']} ({e['reason']})",
                description=f"{e['framework']} route; auth detected: {e['auth']}; input surface: {e['inputs']}.",
                location={"file": e["file"], "line": e["line"]},
                evidence=f"{e['method']} {e['path']}",
                remediation="Add authentication/authorization middleware and validate all inputs server-side.",
                engine="grim-endpoints",
                tags=["endpoint", e["framework"], "authz", e["risk"]],
            )
        )
    return out
