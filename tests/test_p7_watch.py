"""P7 tests: watch (persistent baseline + drift) and bounded finditer rules."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p7-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.tools import call_tool  # noqa: E402

SHELL = b"<?php eval($_POST['c']); ?>"
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
        _test_watch()
        _test_finditer()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP7: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_watch() -> None:
    d = _TMP / "site"
    (d / "public" / "uploads").mkdir(parents=True)
    (d / "public" / "index.php").write_text("<?php echo 1;")
    (d / "public" / "uploads" / "old.php").write_text("<?php echo 2;")

    saved = call_tool("watch", {"path": str(d), "action": "save"})
    check("watch save ok", saved.get("ok") and saved.get("entries") == 2)

    status = call_tool("watch", {"path": str(d), "action": "status"})
    check("watch status exists", status.get("ok") and status.get("exists") is True)

    # removed executable should be reported as drift
    (d / "public" / "uploads" / "old.php").unlink()
    res_removed = call_tool("watch", {"path": str(d), "action": "diff"})
    check("watch reports removed executable",
          any("removed" in f["tags"] for f in res_removed["findings"]))

    # added webshell should be reported as drift
    (d / "public" / "uploads" / "shell.php").write_bytes(SHELL)
    res = call_tool("watch", {"path": str(d), "action": "diff"})
    check("watch diff ok", res.get("ok") is True)
    check("watch detects added webshell",
          any("webshell" in f["tags"] and "added" in f["tags"] for f in res["findings"]))
    check("watch stats counts added", res["meta"]["stats"]["added"] >= 1)

    # missing baseline is a clean error
    missing = call_tool("watch", {"path": str(_TMP / "nope"), "action": "diff",
                                  "baseline_path": str(_TMP / "no-baseline.json")})
    check("watch missing baseline errors cleanly", missing.get("ok") is False)


def _test_finditer() -> None:
    d = _TMP / "sinks"
    d.mkdir(parents=True)
    (d / "many.py").write_text("import os\n" + "os.system(request.form['c'])\n" * 5)
    fs = scan_code(str(d))
    systemic = [f for f in fs if "os.system" in f.title.lower() or f.category in ("CWE-94", "CWE-20")]
    check("finditer reports repeated sinks", len(systemic) >= 3)
    lines = {f.location.get("line") for f in fs if f.location.get("line")}
    check("finditer yields distinct lines", len(lines) >= 3)


if __name__ == "__main__":
    raise SystemExit(main())
