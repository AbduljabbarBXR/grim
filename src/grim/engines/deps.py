"""Dependency vulnerability scanning via OSV.dev (live advisory database)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.findings import Finding, cvss_to_severity, make_id

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
CACHE_DIR = Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim")) / "osv"
TIMEOUT = 25
BATCH_SIZE = 100
MAX_PACKAGES = 3000


def audit_deps(path: str) -> list[Finding]:
    """Parse lockfiles/manifests, query OSV, return findings."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)

    packages = _collect_packages(p)
    if not packages:
        return []

    findings: list[Finding] = []
    for chunk in _chunks(packages[:MAX_PACKAGES], BATCH_SIZE):
        results = _osv_querybatch(chunk)
        for (eco, name, version), res in zip(chunk, results):
            for vuln_stub in res.get("vulns", []) or []:
                vid = vuln_stub.get("id", "?")
                detail = _osv_vuln(vid)
                findings.append(_to_finding(eco, name, version, detail))
    return findings


def _collect_packages(p: Path) -> list[tuple[str, str, str]]:
    """Return list of (ecosystem, package, version) from manifests/lockfiles."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(eco: str, name: str, version: str) -> None:
        version = _clean_version(version)
        if not name or not version:
            return
        key = (eco, name.lower(), version)
        if key in seen:
            return
        seen.add(key)
        out.append((eco, name, version))

    files = [p] if p.is_file() else list(p.rglob("*"))
    for fp in files:
        name = fp.name
        if not fp.is_file():
            continue
        try:
            if name == "package-lock.json":
                for pkg, ver in _parse_npm_lock(fp):
                    add("npm", pkg, ver)
            elif name == "package.json":
                for pkg, ver in _parse_package_json(fp):
                    add("npm", pkg, ver)
            elif name == "composer.lock":
                for pkg, ver in _parse_composer_lock(fp):
                    add("Packagist", pkg, ver)
            elif name == "requirements.txt":
                for pkg, ver in _parse_requirements(fp):
                    add("PyPI", pkg, ver)
            elif name in ("go.mod", "go.sum"):
                for pkg, ver in _parse_go(fp):
                    add("Go", pkg, ver)
            elif name == "Cargo.lock":
                for pkg, ver in _parse_cargo(fp):
                    add("crates.io", pkg, ver)
            elif name == "pubspec.lock":
                for pkg, ver in _parse_pubspec(fp):
                    add("Pub", pkg, ver)
            elif name == "pom.xml":
                for pkg, ver in _parse_maven(fp):
                    add("Maven", pkg, ver)
            elif name in ("packages.lock.json", "packages.config"):
                for pkg, ver in _parse_nuget(fp):
                    add("NuGet", pkg, ver)
            elif name == "Gemfile.lock":
                for pkg, ver in _parse_gemfile(fp):
                    add("RubyGems", pkg, ver)
        except Exception:
            continue
    return out


def _parse_go(fp: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if fp.name == "go.mod":
        for m in re.finditer(r"^\s*(?:require\s+)?([A-Za-z0-9._/\-]+\.[A-Za-z0-9._/\-]+)\s+v?(\d+\.\d+\.\d+[0-9A-Za-z.\-+]*)", fp.read_text(errors="ignore"), re.M):
            out.append((m.group(1), m.group(2)))
        return out
    # go.sum lines: <module> <version> <hash>
    for line in fp.read_text(errors="ignore").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].endswith("/go.mod"):
            out.append((parts[0], parts[1].lstrip("v")))
    return out


def _parse_cargo(fp: Path) -> list[tuple[str, str]]:
    text = fp.read_text(errors="ignore")
    out = []
    for block in re.findall(r"\[\[package\]\](.*?)(?=\n\[\[package\]\]|\Z)", text, re.S):
        name = re.search(r'name\s*=\s*"([^"]+)"', block)
        ver = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name and ver:
            out.append((name.group(1), ver.group(1)))
    return out


def _parse_pubspec(fp: Path) -> list[tuple[str, str]]:
    text = fp.read_text(errors="ignore")
    out = []
    # pubspec.lock has flat YAML: "  name: foo" then "    version: \"1.2.3\""
    current = None
    for line in text.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_.\-]+):$", line)
        if m:
            current = m.group(1)
            continue
        m2 = re.match(r'^    version:\s*"([^"]+)"', line)
        if m2 and current:
            out.append((current, m2.group(1)))
    return out


def _parse_maven(fp: Path) -> list[tuple[str, str]]:
    out = []
    try:
        root = ET.parse(str(fp)).getroot()
    except ET.ParseError:
        return out

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def child_text(el, name):
        for c in el:
            if local(c.tag) == name:
                return (c.text or "").strip()
        return None

    for dep in root.iter():
        if local(dep.tag) != "dependency":
            continue
        g = child_text(dep, "groupId")
        a = child_text(dep, "artifactId")
        v = child_text(dep, "version")
        if g and a and v and not v.startswith("$"):
            out.append((f"{g}:{a}", v))
    return out


def _parse_nuget(fp: Path) -> list[tuple[str, str]]:
    out = []
    if fp.name == "packages.lock.json":
        data = json.loads(fp.read_text(errors="ignore"))
        for deps in (data.get("dependencies") or {}).values():
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get("resolved"):
                    out.append((name, str(meta["resolved"])))
    else:
        # packages.config XML
        try:
            root = ET.fromstring(fp.read_text(errors="ignore"))
        except ET.ParseError:
            return out
        for pkg in root.iter("package"):
            out.append((pkg.get("id", ""), pkg.get("version", "")))
    return out


def _parse_gemfile(fp: Path) -> list[tuple[str, str]]:
    out = []
    for line in fp.read_text(errors="ignore").splitlines():
        m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", line)
        if m:
            out.append((m.group(1), m.group(2).split()[0]))
    return out


def _parse_npm_lock(fp: Path) -> list[tuple[str, str]]:
    data = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
    out: list[tuple[str, str]] = []
    if isinstance(data.get("packages"), dict):
        for key, meta in data["packages"].items():
            if "node_modules/" in key and isinstance(meta, dict) and meta.get("version"):
                name = key.split("node_modules/")[-1]
                out.append((name, str(meta["version"])))
    elif isinstance(data.get("dependencies"), dict):
        def walk(deps: dict) -> None:
            for name, meta in deps.items():
                if isinstance(meta, dict):
                    if meta.get("version"):
                        out.append((name, str(meta["version"])))
                    walk(meta.get("dependencies") or {})
        walk(data["dependencies"])
    return out


def _parse_package_json(fp: Path) -> list[tuple[str, str]]:
    data = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            if re.fullmatch(r"\d+\.\d+\.\d+[0-9A-Za-z.\-+]*", str(ver).strip()):
                out.append((name, str(ver).strip()))
    return out


def _parse_composer_lock(fp: Path) -> list[tuple[str, str]]:
    data = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
    out = []
    for section in ("packages", "packages-dev"):
        for meta in data.get(section) or []:
            if meta.get("name") and meta.get("version"):
                out.append((meta["name"], str(meta["version"])))
    return out


def _parse_requirements(fp: Path) -> list[tuple[str, str]]:
    out = []
    for line in fp.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _clean_version(v: str) -> str:
    v = str(v).strip().lstrip("v")
    return v if v and not v.startswith(("^", "~", ">", "<", "*", "dev", "git", "http")) else ""


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _osv_querybatch(packages: list[tuple[str, str, str]]) -> list[dict]:
    queries = []
    for eco, name, version in packages:
        q: dict = {"package": {"name": name, "ecosystem": eco}}
        if eco == "Packagist":
            q["package"]["name"] = name.lower()
        q["version"] = version
        queries.append(q)
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(OSV_BATCH, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        return data.get("results", [])
    except Exception:
        # fallback: curl (handles networks where urllib struggles)
        try:
            proc = subprocess.run(
                ["curl", "-s", "--max-time", str(TIMEOUT), "-X", "POST", OSV_BATCH,
                 "-H", "Content-Type: application/json", "-d", json.dumps({"queries": queries})],
                capture_output=True, text=True, check=True,
            )
            return json.loads(proc.stdout).get("results", [])
        except Exception:
            return [{} for _ in packages]


def _osv_vuln(vid: str) -> dict:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{vid}.json"
    if cache_file.exists() and cache_file.stat().st_size > 0:
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass
    detail: dict = {}
    try:
        with urllib.request.urlopen(OSV_VULN.format(id=vid), timeout=TIMEOUT) as resp:
            detail = json.loads(resp.read().decode())
    except Exception:
        try:
            proc = subprocess.run(
                ["curl", "-s", "--max-time", str(TIMEOUT), OSV_VULN.format(id=vid)],
                capture_output=True, text=True, check=True,
            )
            detail = json.loads(proc.stdout)
        except Exception:
            detail = {"id": vid}
    if detail:
        try:
            cache_file.write_text(json.dumps(detail))
        except OSError:
            pass
    return detail


def _to_finding(eco: str, name: str, version: str, vuln: dict) -> Finding:
    vid = vuln.get("id", "?")
    summary = vuln.get("summary") or (vuln.get("details") or "")[:160] or "Known vulnerability"
    score = _cvss_score(vuln)
    sev = cvss_to_severity(score) if score is not None else _db_severity(vuln)
    fixed = _fixed_version(vuln, name)
    remediation = f"Upgrade {name} to {fixed} or later." if fixed else f"Upgrade {name} to a patched version; see reference."
    return Finding(
        id=make_id("DEPS", vid, f"{name}@{version}"),
        severity=sev,
        confidence=0.95,
        category="CWE-1395",
        owasp="A06:2021",
        title=f"Vulnerable dependency: {name}@{version} ({vid})",
        description=summary,
        location={"file": f"{eco}:{name}@{version}"},
        evidence=f"{vid}" + (f" | fixed: {fixed}" if fixed else ""),
        remediation=remediation,
        references=[f"https://osv.dev/vulnerability/{vid}"],
        engine="grim-osv",
        tags=["dependencies", eco.lower()],
    )


def _cvss_score(vuln: dict) -> float | None:
    for sev in vuln.get("severity") or []:
        if sev.get("type", "").startswith("CVSS"):
            try:
                return float(sev.get("score", ""))
            except (TypeError, ValueError):
                continue
    return None


def _db_severity(vuln: dict) -> str:
    raw = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
    return raw if raw in {"critical", "high", "medium", "low"} else "medium"


def _fixed_version(vuln: dict, name: str) -> str | None:
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return None
