"""P4 tests: deep archives are not truncated by ordinary files, every cap is reported,
and limits are configurable via GRIM_MAX_* environment variables."""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p4-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.core.report import render_markdown  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.engines.diffscan import diff_artifacts  # noqa: E402
from grim.engines.exposure import audit_exposure  # noqa: E402
from grim.engines.secrets import scan_secrets  # noqa: E402
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


@contextlib.contextmanager
def env(**kv: str):
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
        _test_deep_not_truncated_by_normal_files()
        _test_nested_budget_signalled()
        _test_exposure_caps_signalled()
        _test_tool_meta_and_report()
        _test_code_and_secret_limits()
        _test_diff_truncation()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP4: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _make_archive(path: Path, files: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


def _test_deep_not_truncated_by_normal_files() -> None:
    # Normal (non-archive) files far exceed the nested-archive budget, but must not
    # consume it. The webshell placed last must still be found in deep mode.
    arc = _TMP / "normal-heavy.tar.gz"
    files = {f"data/blob{i}.bin": b"x" * 5000 for i in range(10)}
    files["public/uploads/shell.php"] = SHELL
    _make_archive(arc, files)
    with env(GRIM_MAX_ARCHIVE_BYTES="200"):
        s: dict = {}
        deep = audit_exposure(str(arc), deep=True, stats=s)
    check("deep finds webshell despite huge normal files",
          any("webshell" in f.tags for f in deep))
    check("normal files do not consume nested budget", s.get("extracted_bytes", 1) == 0)
    check("no false truncation from normal files", s.get("truncated") is False)


def _test_nested_budget_signalled() -> None:
    inner = _TMP / "inner.zip"
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("public/uploads/deep.php", b"J" * 2000)
    outer = _TMP / "outer.tar.gz"
    _make_archive(outer, {"site/inner.zip": inner.read_bytes()})
    with env(GRIM_MAX_ARCHIVE_BYTES="300"):
        s: dict = {}
        audit_exposure(str(outer), deep=True, stats=s)
    check("nested budget exhaustion signalled", s.get("truncated") is True)
    check("budget_capped counted", s.get("budget_capped", 0) >= 1)
    check("budget reason reported", any("budget" in r for r in s.get("reasons", [])))


def _test_exposure_caps_signalled() -> None:
    d = _TMP / "caps"
    (d / "public" / "uploads").mkdir(parents=True)
    for i in range(3):
        (d / "public" / "uploads" / f"s{i}.php").write_bytes(SHELL)
    with env(GRIM_MAX_FINDINGS="1"):
        s: dict = {}
        audit_exposure(str(d), stats=s)
    check("entry/finding caps configurable and reported", s.get("truncated") is True)
    check("finding cap reason reported", any("finding limit" in r for r in s.get("reasons", [])))


def _test_tool_meta_and_report() -> None:
    d = _TMP / "tool-caps"
    (d / "public" / "uploads").mkdir(parents=True)
    for i in range(3):
        (d / "public" / "uploads" / f"s{i}.php").write_bytes(SHELL)
    with env(GRIM_MAX_FINDINGS="1"):
        res = call_tool("audit_exposure", {"path": str(d)})
    check("tool meta truncated flag", res["meta"].get("truncated") is True)
    check("truncation finding emitted",
          any("truncated" in f["tags"] for f in res["findings"]))
    md = render_markdown([], res["meta"])
    check("markdown warns on truncation", "scan truncated" in md.lower())


def _test_code_and_secret_limits() -> None:
    d = _TMP / "code-caps"
    d.mkdir()
    for i in range(5):
        (d / f"f{i}.py").write_text("import os\nos.system(request.form['c'])\n")
    with env(GRIM_MAX_FILES="2"):
        s: dict = {}
        scan_code(str(d), stats=s)
    check("code file limit reported", s.get("truncated") is True and s.get("files_scanned") <= 2)

    sd = _TMP / "secret-caps"
    sd.mkdir()
    (sd / "big.py").write_text("token = 'Zx9Km2QvLp7wRt4sN6hJ8cF1dG3aB5eU7yI0oK2mN4pR6sT8uV0wX'\n" + "#" * 5000)
    with env(GRIM_MAX_SECRET_FILE_BYTES="100"):
        s2: dict = {}
        scan_secrets(str(sd), stats=s2)
    check("secret file-size cap reported", s2.get("truncated") is True and s2.get("oversize_skipped", 0) >= 1)


def _test_diff_truncation() -> None:
    a = _TMP / "diff-a"
    b = _TMP / "diff-b"
    (a / "public").mkdir(parents=True)
    (b / "public").mkdir(parents=True)
    (a / "public" / "index.php").write_text("<?php echo 1;")
    for i in range(5):
        (b / "public" / f"new{i}.php").write_bytes(SHELL)
    findings, stats = diff_artifacts(str(a), str(b), classify_limit=1)
    check("diff truncation reported", stats.get("truncated") is True)
    check("diff reason present", any("classify" in r for r in stats.get("reasons", [])))


if __name__ == "__main__":
    raise SystemExit(main())
