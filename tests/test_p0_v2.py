"""P0 tests: hashed diff detection, changed-file content scan, taint flow."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.diffscan import diff_artifacts, build_manifest  # noqa: E402
from grim.engines.flow import scan_flow  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402

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


def make_dir(base: Path, files: dict[str, str]) -> Path:
    d = base / "tree"
    d.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="grim-p0-"))
    try:
        # --- same-size modification detected ---
        base_a = tmp / "a"
        base_b = tmp / "b"
        a = make_dir(base_a, {"public/index.php": "<?php echo 'hello world';"})
        b = make_dir(base_b, {"public/index.php": "<?php echo 'hello worle';"})
        check("manifest hashes differ on same-size edit",
              build_manifest(str(a))["public/index.php"]["hash"] != build_manifest(str(b))["public/index.php"]["hash"])
        findings, stats = diff_artifacts(str(a), str(b))
        check("diff reports changed on same-size edit", stats["changed"] == 1 and stats["added"] == 0)
        check("diff summary finding present", any("drift" in f.tags for f in findings))

        # --- changed file content-scanned (webshell in changed file) ---
        base_c = tmp / "c"
        base_d = tmp / "d"
        c = make_dir(base_c, {"public/index.php": "<?php echo 'hello';"})
        d = make_dir(base_d, {"public/index.php": "<?php eval($_POST['x']);"})
        findings2, _ = diff_artifacts(str(c), str(d))
        check("changed file content-scanned for webshell",
              any("webshell" in f.tags and "changed" in f.tags for f in findings2))

        # --- taint flow: python request to exec ---
        code_dir = tmp / "flow"
        code_dir.mkdir()
        (code_dir / "app.py").write_text(
            "from flask import request\n"
            "def run():\n"
            "    cmd = request.form['cmd']\n"
            "    os.system(cmd)\n"
        )
        flow = scan_flow(str(code_dir))
        check("flow detects request to shell sink", any("flow" in f.tags for f in flow))
        check("flow finding is high severity", any(f.severity == "high" for f in flow))

        # --- direct taint one line ---
        (code_dir / "app.py").write_text(
            "import os\n"
            "def run():\n"
            "    os.system(request.form['cmd'])\n"
        )
        flow2 = scan_flow(str(code_dir))
        check("flow detects direct source into sink",
              any("direct-taint" in f.tags for f in flow2))

        # --- code scan integrates flow ---
        code = scan_code(str(code_dir))
        check("scan_code includes flow findings", any(f.engine == "grim-flow" for f in code))

        # --- no false positive on clean file ---
        clean = tmp / "clean"
        clean.mkdir()
        (clean / "app.py").write_text(
            "def add(a, b):\n"
            "    return a + b\n"
        )
        check("no flow findings on clean code", scan_flow(str(clean)) == [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nP0: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())