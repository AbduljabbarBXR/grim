"""P6 tests: SARIF output, CI gate exit codes, newer MCP protocol, scale soak, symlinks."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p6-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.core.findings import Finding  # noqa: E402
from grim.core.report import render_sarif  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.engines.secrets import scan_secrets  # noqa: E402
from grim.tools import call_tool  # noqa: E402

ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(ROOT / "src")

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


def grim(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "grim", *args], cwd=ROOT, env=ENV,
                          capture_output=True, text=True, timeout=300)


def main() -> int:
    try:
        _test_sarif()
        _test_ci_gate()
        _test_mcp_v2()
        _test_scale_cap()
        _test_symlinks()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP6: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_sarif() -> None:
    f = Finding(
        id="GRIM-EXPOS-abc", severity="critical", confidence=0.99, category="CWE-434",
        owasp="A04:2021", title="Executable php file in web-served directory",
        description="Shell in uploads", location={"file": "public/uploads/s.php", "line": 1},
        evidence="eval", remediation="Remove it", tags=["webshell"], mitre=["T1505.003"],
    )
    doc = json.loads(render_sarif([f]))
    check("sarif version", doc["version"] == "2.1.0")
    run = doc["runs"][0]
    check("sarif driver", run["tool"]["driver"]["name"] == "GRIM")
    res = run["results"][0]
    check("sarif level mapping", res["level"] == "error")
    check("sarif location+line", res["locations"][0]["physicalLocation"]["region"]["startLine"] == 1)
    check("sarif fix present", bool(res.get("fixes")))
    check("sarif rule present", any(r["id"] == "CWE-434" for r in run["tool"]["driver"]["rules"]))


def _test_ci_gate() -> None:
    bad = _TMP / "ci-bad"
    (bad / "public" / "uploads").mkdir(parents=True)
    (bad / "public" / "uploads" / "s.php").write_bytes(SHELL)
    r = grim("ci", str(bad), "--no-network", "--format", "json")
    check("ci fails on critical", r.returncode == 1)
    payload = json.loads(r.stdout)
    check("ci exit_code in payload", payload.get("exit_code") == 1 and payload.get("failing", 0) >= 1)

    clean = _TMP / "ci-clean"
    clean.mkdir(parents=True)
    (clean / "index.html").write_text("<html>ok</html>")
    r2 = grim("ci", str(clean), "--no-network", "--fail-on", "high", "--format", "md")
    check("ci passes clean", r2.returncode == 0)

    r3 = grim("ci", str(bad), "--no-network", "--fail-on", "critical", "--format", "sarif")
    check("ci sarif output", r3.returncode == 1 and '"version": "2.1.0"' in r3.stdout)

    tool = call_tool("ci_scan", {"path": str(bad), "network": False, "fail_on": "critical"})
    check("ci_scan tool exit_code", tool.get("ok") and tool.get("exit_code") == 1)


def _test_mcp_v2() -> None:
    proc = subprocess.Popen([sys.executable, "-m", "grim", "mcp"], cwd=ROOT, env=ENV,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for m in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]:
            proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
        resp = {}
        deadline = time.time() + 20
        while len(resp) < 2 and time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            o = json.loads(line)
            if "id" in o:
                resp[o["id"]] = o
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    init = resp.get(1, {}).get("result", {})
    check("mcp echoes requested protocol", init.get("protocolVersion") == "2025-06-18")
    check("mcp provides instructions", bool(init.get("instructions")))
    tools = [t["name"] for t in resp.get(2, {}).get("result", {}).get("tools", [])]
    check("mcp exposes ci_scan", "ci_scan" in tools)


def _test_scale_cap() -> None:
    d = _TMP / "scale"
    d.mkdir(parents=True)
    for i in range(1500):
        (d / f"f{i:05d}.py").write_text("import os\nos.system(request.form['c'])\n")
    t0 = time.time()
    s: dict = {}
    fs = scan_code(str(d), max_files=5000, stats=s)
    dt = time.time() - t0
    check("scale scan completes and covers all files", s.get("files_scanned") == 1500)
    check("scale scan finds issues", len(fs) > 0)
    check("scale scan is bounded in time (<120s)", dt < 120)

    s2: dict = {}
    scan_code(str(d), max_files=500, stats=s2)
    check("scale cap enforced and reported", s2.get("files_scanned") == 500 and s2.get("truncated") is True)


def _test_symlinks() -> None:
    outside = _TMP / "outside-secret.txt"
    outside.write_text("AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n")
    d = _TMP / "symlink-tree"
    d.mkdir(parents=True)
    link = d / "link.txt"
    try:
        os.symlink(outside, link)
    except OSError:
        print("  skip (symlink not permitted)")
        return
    fs = scan_secrets(str(d))
    check("symlinked files are not read", not any(f.location.get("file", "").endswith("link.txt") for f in fs))


if __name__ == "__main__":
    raise SystemExit(main())
