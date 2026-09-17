"""Stack detection: identify project type(s) from manifests and file patterns."""

from __future__ import annotations

import json
import os
from pathlib import Path

MANIFESTS = {
    "package.json": "node",
    "composer.json": "php",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
}

JS_FRAMEWORKS = {
    "next": "nextjs",
    "nuxt": "nuxt",
    "astro": "astro",
    "react": "react",
    "vue": "vue",
    "svelte": "svelte",
    "@angular/core": "angular",
    "express": "express",
    "fastify": "fastify",
}

PHP_FRAMEWORKS = {
    "laravel/framework": "laravel",
    "symfony/symfony": "symfony",
    "cakephp/cakephp": "cakephp",
}

CONFIG_MARKERS = {
    "next.config.js": "nextjs",
    "next.config.mjs": "nextjs",
    "nuxt.config.ts": "nuxt",
    "astro.config.mjs": "astro",
    "angular.json": "angular",
}

MAX_DEPTH = 4
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build"}


def detect_stack(path: str) -> dict:
    """Return {stacks: [{language, framework, manifest, path}], web_dirs: [...]}."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"path not found: {path}")

    stacks: list[dict] = []
    manifests_found: list[str] = []
    web_dirs: list[str] = []
    lockfiles: list[str] = []

    if p.is_file():
        manifests_found.append(p.name)
    else:
        for root, dirs, files in os.walk(p):
            rel = os.path.relpath(root, p)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and depth < MAX_DEPTH]
            base = os.path.basename(root).lower()
            if base in {"public", "public_html", "www", "htdocs", "web"}:
                web_dirs.append(str(Path(root)))
            for fn in files:
                if fn in MANIFESTS:
                    manifests_found.append(str(Path(root) / fn))
                if fn in CONFIG_MARKERS:
                    manifests_found.append(str(Path(root) / fn))
                if fn.endswith(".lock") and fn in {"composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
                    lockfiles.append(str(Path(root) / fn))

    for m in manifests_found:
        mp = Path(m)
        lang = MANIFESTS.get(mp.name)
        framework = None
        if lang is None and mp.name in CONFIG_MARKERS:
            framework = CONFIG_MARKERS[mp.name]
            lang = "node"
        if mp.name == "package.json":
            framework = framework or _js_framework(mp)
        if mp.name == "composer.json":
            framework = _php_framework(mp)

        stacks.append(
            {
                "language": lang or "unknown",
                "framework": framework,
                "manifest": m,
            }
        )

    # Static site detection
    if not stacks:
        for candidate in ["index.html", "index.htm"]:
            if (p / candidate).is_file() if p.is_dir() else False:
                stacks.append({"language": "static", "framework": "html", "manifest": candidate})

    return {
        "path": str(p),
        "is_archive": p.is_file() and _looks_archive(p.name),
        "stacks": _dedupe_stacks(stacks),
        "web_dirs": web_dirs[:20],
        "lockfiles": lockfiles[:20],
    }


def _js_framework(package_json: Path) -> str | None:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    deps = {}
    deps.update(data.get("dependencies") or {})
    deps.update(data.get("devDependencies") or {})
    for key, fw in JS_FRAMEWORKS.items():
        if key in deps:
            return fw
    return None


def _php_framework(composer_json: Path) -> str | None:
    try:
        data = json.loads(composer_json.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    deps = {}
    deps.update(data.get("require") or {})
    deps.update(data.get("require-dev") or {})
    for key, fw in PHP_FRAMEWORKS.items():
        if key in deps:
            return fw
    return None


def _dedupe_stacks(stacks: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for s in stacks:
        key = (s["language"], s["framework"])
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _looks_archive(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(
        (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz")
    )
