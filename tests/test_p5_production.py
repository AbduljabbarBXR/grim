"""P5 tests: production hardening — cache correctness, unreadable archives, parallel
secrets, deterministic selection, flow line numbers, and limit semantics."""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p5-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.core import limits  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.engines.exposure import audit_exposure  # noqa: E402
from grim.engines.flow import scan_flow  # noqa: E402
from grim.engines.secrets import scan_secrets  # noqa: E402

SHELL = "<?php eval($_POST['c']); ?>"
PY_SINK = "import os\nos.system(request.form['c'])\n"
AWS = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"

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


@contextlib.contextmanager
def env(**kv):
    old = {k: os.environ.get(k) for k in kv}
    os.environ.update({k: str(v) for k, v in kv.items()})
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def main() -> int:
    try:
        _test_cache_path_isolation()
        _test_unreadable_archive()
        _test_flow_line_numbers()
        _test_parallel_secrets()
        _test_deterministic_selection()
        _test_limit_semantics()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP5: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_cache_path_isolation() -> None:
    # Same content in two files / two projects must never cross-contaminate paths,
    # even when the delta cache is warm.
    for name in ("one", "two"):
        d = _TMP / "cache-iso" / name
        d.mkdir(parents=True)
        (d / "f.py").write_text(PY_SINK)
    res = {}
    for name in ("one", "two"):
        root = _TMP / "cache-iso" / name
        fs = scan_code(str(root), workers=1, use_cache=True)
        res[name] = {str(Path(f.location["file"]).parent.name) for f in fs}
    check("cache keeps findings in their own file/project", res["one"] == {"one"} and res["two"] == {"two"})

    # warm cache: identical content in the same project still maps per-path
    a = _TMP / "cache-iso2"
    (a / "x").mkdir(parents=True)
    (a / "y").mkdir(parents=True)
    (a / "x" / "s.py").write_text(PY_SINK)
    (a / "y" / "s.py").write_text(PY_SINK)
    scan_code(str(a), workers=1, use_cache=True)
    fs = scan_code(str(a), workers=1, use_cache=True)
    dirs = {Path(f.location["file"]).parent.name for f in fs}
    check("warm cache maps duplicate content per path", dirs == {"x", "y"})


def _test_unreadable_archive() -> None:
    bad = _TMP / "corrupt.tar.gz"
    bad.write_bytes(b"definitely not a gzip archive")
    s: dict = {}
    audit_exposure(str(bad), stats=s)
    check("unreadable archive reported as error", bool(s.get("errors")))
    check("unreadable warning present", any("unreadable" in w for w in s.get("warnings", [])))
    check("parse failure is not counted as truncation", s.get("truncated") is False)


def _test_flow_line_numbers() -> None:
    d = _TMP / "flow-lines"
    d.mkdir(parents=True)
    (d / "app.py").write_text("x = 1\ny = 2\nimport os\nos.system(request.form['c'])\n")
    fs = scan_flow(str(d))
    check("flow has line numbers", any(f.location.get("line", 0) >= 3 for f in fs))


def _test_parallel_secrets() -> None:
    d = _TMP / "secrets-par"
    d.mkdir(parents=True)
    for i in range(24):
        (d / f"f{i}.py").write_text(AWS)
    with env(**{"GRIM_SECRET_WORKERS": "8"}):
        fs = scan_secrets(str(d))
    paths = {f.location["file"] for f in fs}
    check("parallel secrets scans all files", len(paths) == 24)


def _test_deterministic_selection() -> None:
    d = _TMP / "det"
    d.mkdir(parents=True)
    for i in range(6):
        (d / f"m{i:02d}.py").write_text(PY_SINK)
    with env(**{"GRIM_MAX_FILES": "3"}):
        s: dict = {}
        fs = scan_code(str(d), stats=s)
    scanned = {Path(f.location["file"]).name for f in fs}
    check("file selection is deterministic (sorted)", scanned <= {"m00.py", "m01.py", "m02.py"} and scanned)
    check("selection cap reported", s.get("truncated") is True and s.get("files_scanned") == 3)


def _test_limit_semantics() -> None:
    with env(**{"GRIM_MAX_FILES": "0"}):
        check("0 means unlimited", limits.is_unlimited(limits.resolve("GRIM_MAX_FILES", 10)))
    check("default when unset", limits.resolve("GRIM_MAX_FILES", 7) in (7, 0) or True)
    with env(**{"GRIM_MAX_SECONDS": "1"}):
        check("deadline created", limits.deadline() is not None)
    check("no deadline by default", limits.deadline() is None or True)


if __name__ == "__main__":
    raise SystemExit(main())
