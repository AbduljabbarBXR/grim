"""P8 tests: fix_plan remediation steps and safe, applyable unified diffs."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p8-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.core.fixplan import build_fix_plan  # noqa: E402
from grim.core.findings import Finding  # noqa: E402
from grim.tools import call_tool  # noqa: E402

FAIL = 0
TOTAL = 0


def check(name: str, cond: bool) -> None:
    global FAIL, TOTAL
    TOTAL += 1
    if not cond:
        FAIL += 1
        print(f"  FAIL {name}")
    else:
        print(f"  ok   {name}")


def main() -> int:
    try:
        _test_transforms()
        _test_patch_applies()
        _test_advisory_only()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP8: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_transforms() -> None:
    d = _TMP / "app"
    d.mkdir(parents=True)
    (d / "Upload.php").write_text(
        "<?php\nclass U {\n  function r() {\n    return ['file' => 'required|mimes:'.$request->mimes];\n  }\n}\n"
    )
    (d / "app.py").write_text("import yaml\ndef load(x):\n    return yaml.load(x)\n")
    (d / "shell.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")

    plan = build_fix_plan(
        [
            Finding(id="a", severity="critical", confidence=0.9, category="CWE-434", owasp="A04:2021",
                    title="Upload validation uses a request-controlled file-type list", location={"file": str(d / "Upload.php"), "line": 4}),
            Finding(id="b", severity="medium", confidence=0.7, category="CWE-20", owasp="A03:2021",
                    title="yaml.load without SafeLoader", location={"file": str(d / "app.py"), "line": 3}),
            Finding(id="c", severity="high", confidence=0.7, category="CWE-78", owasp="A03:2021",
                    title="subprocess with shell=True", location={"file": str(d / "shell.py"), "line": 2}),
        ],
        root=str(d),
        include_patches=True,
    )
    check("plan has steps", plan["summary"]["steps"] == 3)
    check("plan patchable", plan["summary"]["patchable"] == 3)
    check("yaml transform", "yaml.safe_load(x)" in plan["patch"])
    check("php mimes transform valid", "'.'jpg,jpeg,png,pdf'" in plan["patch"])
    check("shell transform", "shell=False" in plan["patch"])
    check("mimes flagged for review", any(s.get("requires_review") for s in plan["steps"] if "Upload" in s["file"]))


def _test_patch_applies() -> None:
    d = _TMP / "repo"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import yaml\ndef load(x):\n    return yaml.load(x)\n")
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=d, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=d, check=True)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=d, check=True)

    plan = call_tool("fix_plan", {"path": str(d), "network": False})
    patch_file = d / "fix.patch"
    patch_file.write_text(plan["patch"])
    result = subprocess.run(["git", "apply", "--check", str(patch_file)], cwd=d, capture_output=True, text=True)
    if result.returncode != 0:
        print("    git apply stderr:", result.stderr[:200])
    check("patch passes git apply --check", result.returncode == 0)


def _test_advisory_only() -> None:
    d = _TMP / "webshell"
    (d / "public" / "uploads").mkdir(parents=True)
    (d / "public" / "uploads" / "s.php").write_bytes(b"<?php eval($_POST['c']); ?>")
    plan = call_tool("fix_plan", {"path": str(d), "network": False})
    check("critical findings still produce steps", plan["summary"]["steps"] >= 1)
    check("no unsafe patch for webshell", plan["summary"]["patchable"] == 0)


if __name__ == "__main__":
    raise SystemExit(main())
