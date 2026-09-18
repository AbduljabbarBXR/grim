"""Fix planning: turn findings into an ordered remediation plan and, where a change is
deterministic and safe, a unified diff that can be applied with `git apply`.

Auto-patches are intentionally conservative: only high-confidence, local, textual fixes
are emitted. Everything else becomes an advisory step. No files are modified.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from .findings import SEVERITY_ORDER, Finding, summarize

PHP_MIMES_EXPR = re.compile(r"\$(?:request|_GET|_POST|_REQUEST)[A-Za-z0-9_>\-]*")
YAML_LOAD = re.compile(r"\byaml\.load\s*\(")
SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")


def build_fix_plan(
    findings: list[Finding],
    root: str | None = None,
    include_patches: bool = True,
) -> dict:
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), str(f.location.get("file", "")), int(f.location.get("line", 0) or 0)),
    )
    steps: list[dict] = []
    diffs: list[str] = []
    with_patch = 0
    for f in ordered:
        step: dict = {
            "severity": f.severity,
            "title": f.title,
            "file": f.location.get("file", ""),
            "line": f.location.get("line", 0),
            "category": f.category,
            "action": f.remediation,
            "evidence": f.evidence,
            "requires_review": False,
        }
        if include_patches and root:
            patch = _try_patch(f, Path(root))
            if patch:
                step["patch"] = patch["diff"]
                step["requires_review"] = patch["review"]
                with_patch += 1
                diffs.append(patch["diff"])
        steps.append(step)

    return {
        "ok": True,
        "summary": {
            **summarize(ordered),
            "steps": len(steps),
            "patchable": with_patch,
        },
        "steps": steps,
        "patch": "\n".join(diffs).strip() + ("\n" if diffs else ""),
    }


def _try_patch(finding: Finding, root: Path) -> dict | None:
    file_path = finding.location.get("file")
    line_no = int(finding.location.get("line", 0) or 0)
    if not file_path or line_no <= 0:
        return None
    p = Path(file_path)
    if not p.is_absolute():
        p = root / p
    try:
        if not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
            return None
        original = p.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    except OSError:
        return None
    if line_no > len(original):
        return None

    line = original[line_no - 1]
    new_line, review = _transform(finding, line)
    if new_line is None or new_line == line:
        return None

    updated = list(original)
    updated[line_no - 1] = new_line
    diff = "".join(
        difflib.unified_diff(
            original, updated,
            fromfile=f"a/{p.name}", tofile=f"b/{p.name}", n=1,
            lineterm="\n",
        )
    )
    return {"diff": diff, "review": review}


def _transform(finding: Finding, line: str) -> tuple[str | None, bool]:
    title = finding.title.lower()

    # Upload validation using a request-controlled allowlist -> fixed literal allowlist.
    # Only the request expression is replaced, so surrounding PHP syntax is preserved.
    if "request-controlled" in title and PHP_MIMES_EXPR.search(line):
        return PHP_MIMES_EXPR.sub("'jpg,jpeg,png,pdf'", line, count=1), True

    # Unsafe YAML load -> safe_load.
    if "yaml" in title and YAML_LOAD.search(line) and "safe_load" not in line:
        return YAML_LOAD.sub("yaml.safe_load(", line, count=1), False

    # shell=True with untrusted input -> disable shell execution (review the call).
    if SHELL_TRUE.search(line):
        return SHELL_TRUE.sub("shell=False", line, count=1), True

    return None, False
