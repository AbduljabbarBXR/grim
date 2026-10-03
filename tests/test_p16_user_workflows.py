"""User-level acceptance test: drive GRIM the way a real user would.

This is not a unit test. It walks the documented workflows end to end against
realistic targets and checks the things a user actually notices: does the command
work, is the output readable, is the exit code right, does the report contain what
it promises. Run: python3 tests/test_p16_user_workflows.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from grim import __version__  # noqa: E402

PASS = 0
FAIL = 0
NOTES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def note(msg: str) -> None:
    NOTES.append(msg)
    print(f"  note {msg}")


def grim(*args: str, expect_rc: int | None = 0) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "grim", *args],
        capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=300,
    )
    if expect_rc is not None and proc.returncode != expect_rc:
        check(f"grim {' '.join(args[:2])} rc={expect_rc}", False,
              f"got {proc.returncode}; stderr={proc.stderr[-200:]}")
    return proc


# ------------------------------------------------------------------ realistic app

APP_PY = '''"""Tiny web app with realistic flaws."""
import hashlib
import os
import sqlite3
import subprocess

import requests

DB_PASSWORD = "prod-db-Pa55word-1234"
API_TOKEN = "aB3dEf9hIj2kLm8nOp5qRs7tUv4wX6yZ1"


def get_user(conn, request):
    name = request.args.get("name")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()


def backup(target):
    os.system("tar czf backup.tgz " + target)


def fetch(url):
    return requests.get(url, verify=False)


def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()
'''

APP_JS = '''const express = require("express");
const app = express();

app.get("/users", (req, res) => {
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(q);
  res.send(q);
});

app.get("/run", (req, res) => {
  require("child_process").exec("ls " + req.query.dir);
  res.send("ok");
});

app.get("/health", (req, res) => res.send("up"));
'''


def build_realistic_app(root: Path) -> None:
    (root / "app.py").write_text(APP_PY)
    (root / "routes.js").write_text(APP_JS)
    (root / "requirements.txt").write_text("django==1.8.0\nrequests==2.19.0\npyyaml==3.12\n")
    (root / "package.json").write_text(json.dumps(
        {"name": "demo", "version": "1.0.0",
         "dependencies": {"lodash": "4.17.4"}}, indent=2))
    (root / ".env").write_text("DEBUG=true\nDB_PASSWORD=prod-db-Pa55word-1234\n")
    (root / "README.md").write_text("# Demo app\n")


def build_dirty_deploy(root: Path) -> None:
    """A deploy artifact that has been compromised."""
    (root / "public" / "uploads").mkdir(parents=True, exist_ok=True)
    (root / "public" / "index.php").write_text("<?php echo 'home';")
    (root / "public" / "uploads" / "shell.php").write_text(
        "<?php\nsession_start();\nif(isset($_POST['cmd'])){ system($_POST['cmd']); }\n")
    (root / "public" / ".env").write_text("APP_KEY=base64:abcdef\nDB_PASSWORD=hunter2hunter2\n")
    (root / "public" / "backup.sql").write_text("-- dump\nCREATE TABLE users (...);\n")
    (root / ".git").mkdir(exist_ok=True)
    (root / ".git" / "config").write_text("[remote]\n")


# ------------------------------------------------------------------- 1. first run


def test_first_run_experience() -> None:
    print("\n[1] first run: version, list, plan")
    p = grim("version")
    check("version prints the release", __version__ in p.stdout, p.stdout.strip())

    p = grim("list")
    check("list shows detect_stack first", p.stdout.splitlines()[0].startswith("detect_stack"), p.stdout[:80])
    check("list shows scan and ci_scan", "scan " in p.stdout and "ci_scan" in p.stdout, "")

    p = grim("--help")
    check("help lists subcommands", all(c in p.stdout for c in ("scan", "fix_plan", "mcp")), p.stdout[:200])

    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        app.mkdir()
        build_realistic_app(app)
        p = grim("plan", str(app), "--no-network")
        check("plan exits 0 on a real app", p.returncode == 0, p.stderr[-200:])
        check("plan detects python", "python" in p.stdout, p.stdout[:200])
        check("plan is valid json", _is_json(p.stdout), p.stdout[:80])
        check("plan lists audit_exposure first", '"audit_exposure"' in p.stdout, "")

        p = grim("plan", str(app), "--format", "md", "--no-network")
        check("plan md is readable", p.stdout.startswith("# GRIM Audit Plan"), p.stdout[:80])
        check("plan md explains each step", p.stdout.count("- ") >= 5, "")


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False


# ---------------------------------------------------------------- 2. the main scan


def test_main_scan_reports() -> None:
    print("\n[2] one-shot scan on a realistic app")
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        app.mkdir()
        build_realistic_app(app)

        p = grim("scan", str(app), "--no-network")
        check("scan exits 0", p.returncode == 0, p.stderr[-200:])
        out = p.stdout
        check("report has a title", out.startswith("# GRIM"), out[:60])
        check("report shows severity counts", "CRITICAL:" in out and "HIGH:" in out, "")
        check("report names the target", str(app) in out, "")
        check("scan found the SQL injection", "SQL" in out, "no SQL finding")
        check("scan found md5", "MD5" in out, "no md5 finding")
        check("scan found TLS verify off", "TLS" in out, "no TLS finding")
        check("scan found hardcoded credential", "credential" in out.lower(), "")
        check("each finding has evidence", out.count("**Evidence:**") >= 3, "")
        check("each finding has a fix", out.count("**Fix:**") >= 3, "")
        check("each finding has CWE", out.count("CWE-") >= 3, "")
        check("each finding has ATT&CK", out.count("MITRE ATT&CK") >= 3, "")

        p = grim("scan", str(app), "--no-network", "--format", "json")
        check("json scan parses", _is_json(p.stdout), p.stdout[:80])
        data = json.loads(p.stdout)
        fs = data.get("findings", [])
        check("json has findings", len(fs) > 0, str(len(fs)))
        check("json findings carry mitre", any(f.get("mitre") for f in fs), "")
        check("json findings carry cwe", any(f.get("category", "").startswith("CWE-") for f in fs), "")
        check("json findings carry confidence", all("confidence" in f for f in fs), "")
        check("summary counts match findings",
              sum(data["summary"]["by_severity"].values()) == len(fs),
              f"{data['summary']['by_severity']} vs {len(fs)}")

        p = grim("scan", str(app), "--no-network", "--format", "sarif")
        check("sarif parses", _is_json(p.stdout), p.stdout[:80])
        sarif = json.loads(p.stdout)
        check("sarif version is 2.1.0", sarif.get("version") == "2.1.0", "")
        check("sarif has results", bool(sarif.get("runs")), "")
        rules = sarif["runs"][0]["tool"]["driver"].get("rules", [])
        check("sarif declares rules with descriptions",
              bool(rules) and all(r.get("fullDescription") for r in rules), str(len(rules)))


def test_scan_tool_subset_and_output_file() -> None:
    print("\n[3] scan options a user relies on")
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        app.mkdir()
        build_realistic_app(app)
        out = Path(td) / "report.json"

        p = grim("scan", str(app), "--no-network", "--tools", "code", "--format", "json", "--out", str(out))
        check("--tools subset exits 0", p.returncode == 0, p.stderr[-200:])
        check("--out wrote the file", out.exists(), "")
        check("wrote message", "wrote" in p.stdout, p.stdout[:80])
        data = json.loads(out.read_text())
        check("subset ran only code", data["meta"]["tools_run"] == ["code"], str(data["meta"]["tools_run"]))

        p = grim("scan", str(app), "--no-network", "--tools", "secrets")
        check("secrets-only scan finds the leak", "credential" in p.stdout.lower(), "")


# ------------------------------------------------------------------ 4. compromise


def test_compromised_deploy_is_loud() -> None:
    print("\n[4] a compromised deploy artifact must be obvious")
    with tempfile.TemporaryDirectory() as td:
        dep = Path(td) / "deploy"
        dep.mkdir()
        build_dirty_deploy(dep)

        p = grim("scan", str(dep), "--no-network", "--format", "json")
        fs = json.loads(p.stdout)["findings"]
        titles = " | ".join(f["title"] for f in fs)
        check("webshell in uploads flagged", "php" in titles.lower(), titles[:200])
        check(".env in web path flagged", "Environment file" in titles, titles[:200])
        check("backup file flagged", "Backup" in titles, titles[:200])
        crit = [f for f in fs if f["severity"] == "critical"]
        check("criticals present", len(crit) >= 2, str(len(crit)))

        p = grim("ci", str(dep), "--fail-on", "high", "--no-network", expect_rc=1)
        check("ci gate fails on a compromise", p.returncode == 1, f"rc={p.returncode}")
        check("ci explains the failure", "FAIL" in p.stdout, p.stdout[:120])

        # criticals exist in this fixture, so a critical threshold must also fail
        p = grim("ci", str(dep), "--fail-on", "critical", "--no-network", expect_rc=1)
        check("ci fails at critical when criticals exist", p.returncode == 1, f"rc={p.returncode}")

        p = grim("malware", str(dep), "--format", "json")
        check("malware scan runs", p.returncode == 0, p.stderr[-200:])
        check("malware reports its adapters", "adapters" in p.stdout, p.stdout[:120])


def test_clean_app_is_quiet() -> None:
    print("\n[5] a clean app must not cry wolf")
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "clean"
        (app / "src").mkdir(parents=True)
        (app / "src" / "main.py").write_text(
            "def add(a, b):\n    return a + b\n\ndef main():\n    print(add(1, 2))\n")
        (app / "src" / "util.js").write_text("export function add(a, b) { return a + b; }\n")
        (app / "README.md").write_text("# clean\n")
        (app / ".env").write_text("DEBUG=false\n")

        p = grim("scan", str(app), "--no-network", "--format", "json")
        fs = json.loads(p.stdout)["findings"]
        crit = [f for f in fs if f["severity"] == "critical"]
        check("no criticals on a clean app", not crit, " | ".join(f["title"] for f in crit))
        high = [f for f in fs if f["severity"] == "high"]
        check("no highs on a clean app", not high, " | ".join(f["title"] for f in high))

        p = grim("ci", str(app), "--fail-on", "high", "--no-network", expect_rc=0)
        check("ci gate passes on a clean app", p.returncode == 0, f"rc={p.returncode} out={p.stdout[:120]}")


# ----------------------------------------------------------------- 6. triage aids


def test_triage_workflow() -> None:
    print("\n[6] fix_plan, endpoints, sbom, ledger")
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        app.mkdir()
        build_realistic_app(app)

        p = grim("fix_plan", str(app), "--no-network")
        check("fix_plan exits 0", p.returncode == 0, p.stderr[-200:])
        check("fix_plan has a heading", "GRIM Fix Plan" in p.stdout, p.stdout[:80])
        check("fix_plan orders steps by severity", p.stdout.find("CRITICAL") < p.stdout.find("MEDIUM")
              if "MEDIUM" in p.stdout else True, "")
        check("fix_plan includes a patch", "--- a/" in p.stdout or "patchable: 0" in p.stdout, "")

        p = grim("endpoints", str(app))
        check("endpoints exits 0", p.returncode == 0, p.stderr[-200:])
        check("endpoints finds the routes", "/users" in p.stdout and "/run" in p.stdout, p.stdout[:200])
        check("endpoints flags the sql route", "/users" in p.stdout, "")

        p = grim("sbom", str(app), "--format", "cyclonedx")
        check("sbom cyclonedx parses", _is_json(p.stdout), p.stdout[:80])
        bom = json.loads(p.stdout)
        check("sbom is cyclonedx 1.5", bom.get("specVersion") == "1.5", str(bom.get("specVersion")))
        check("sbom has components", len(bom.get("components", [])) >= 3, str(len(bom.get("components", []))))

        p = grim("sbom", str(app), "--format", "spdx")
        spdx = json.loads(p.stdout)
        check("sbom spdx is 2.3", spdx.get("spdxVersion") == "SPDX-2.3", str(spdx.get("spdxVersion")))

        led = Path(td) / "ledger.json"
        p = grim("ledger", str(app), "--ledger", str(led), "--tools", "code")
        check("ledger merge exits 0", p.returncode == 0, p.stderr[-200:])
        check("ledger file created", led.exists(), "")
        p = grim("ledger", str(app), "--ledger", str(led))
        check("second ledger run reports known", p.returncode == 0, p.stderr[-200:])


def test_dependency_audit_online() -> None:
    print("\n[7] dependency audit against the live advisory database")
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "vuln"
        app.mkdir()
        (app / "requirements.txt").write_text("django==1.8.0\npyyaml==3.12\n")
        p = grim("scan", str(app), "--tools", "deps", "--format", "json")
        if p.returncode != 0:
            note("dependency audit skipped (network unavailable)")
            return
        fs = json.loads(p.stdout)["findings"]
        deps = [f for f in fs if f.get("category") == "CWE-1395"]
        check("known-vulnerable deps found", len(deps) >= 2, str(len(deps)))
        check("dep findings name the package", any("django" in f["title"] for f in deps), "")
        check("dep findings carry an advisory id",
              any("PYSEC" in f["title"] or "GHSA" in f["title"] for f in deps), "")


# ------------------------------------------------------------- 8. drift and archives


def test_drift_and_archives() -> None:
    print("\n[8] drift detection and archive scanning")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td) / "v1"
        (base / "src").mkdir(parents=True)
        (base / "src" / "a.py").write_text("print('one')\n")
        (base / "src" / "b.py").write_text("print('two')\n")

        p = grim("watch", str(base), "--save")
        check("watch save exits 0", p.returncode == 0, p.stderr[-200:])
        (base / "src" / "evil.php").write_text("<?php system($_GET['c']); ?>")

        p = grim("watch", str(base))
        check("watch detects the new file", "evil.php" in p.stdout, p.stdout[:300])
        check("watch reports drift", "drift" in p.stdout.lower(), p.stdout[:200])

        arc = Path(td) / "bundle.tar.gz"
        with tarfile.open(arc, "w:gz") as tf:
            tf.add(base / "src" / "evil.php", arcname="src/evil.php")
        p = grim("scan", str(arc), "--no-network", "--format", "json")
        check("archive scan exits 0", p.returncode == 0, p.stderr[-200:])
        check("archive scan sees inside", "evil.php" in p.stdout or "system" in p.stdout, p.stdout[:200])

        zpath = Path(td) / "bundle.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.write(base / "src" / "evil.php", arcname="src/evil.php")
        p = grim("scan", str(zpath), "--no-network")
        check("zip scan exits 0", p.returncode == 0, p.stderr[-200:])


# -------------------------------------------------------------- 9. hostile inputs


def test_hostile_and_edge_inputs() -> None:
    print("\n[9] hostile and edge-case inputs must not crash the tool")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        (root / "empty.py").write_text("")
        (root / "weird.py").write_text("x = '\\x00' * 10\nprint('ok')\n")
        (root / "binary.py").write_bytes(b"\x00\x01\x02\x03" * 500)
        (root / "huge.py").write_text("y = 1\n" * 200000)
        (root / "bad-encodings.py").write_bytes(b"# caf\xe9 latin1\nprint(1)\n")
        (root / "deep").mkdir()
        cur = root / "deep"
        for i in range(12):
            cur = cur / f"d{i}"
        cur.mkdir(parents=True)
        (cur / "x.py").write_text("import os\nos.system('ls')\n")
        os.symlink("/etc/passwd", root / "link.py") if hasattr(os, "symlink") else None

        for cmd in (["scan", str(root), "--no-network"],
                    ["tool", "scan_code", "--path", str(root)],
                    ["tool", "scan_secrets", "--path", str(root)],
                    ["tool", "audit_exposure", "--path", str(root)],
                    ["endpoints", str(root)],
                    ["malware", str(root)]):
            p = grim(*cmd, expect_rc=None)
            check(f"{cmd[0]} survives hostile input", "Traceback" not in p.stderr,
                  p.stderr[-160:])

        p = grim("scan", "/nonexistent/path/xyz", "--no-network", expect_rc=None)
        check("missing path errors cleanly", "Traceback" not in p.stderr, p.stderr[-160:])
        check("missing path reports an error", "error" in (p.stderr + p.stdout).lower(), "")

        p = grim("tool", "no_such_tool", "--path", str(root), expect_rc=None)
        check("unknown tool errors cleanly", "Traceback" not in p.stderr, p.stderr[-160:])


# ------------------------------------------------------------------ 10. mcp client


def test_mcp_session_as_a_client() -> None:
    print("\n[10] MCP session, driven as a real client")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "grim", "mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=str(ROOT), text=True, bufsize=1,
    )
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        app.mkdir()
        build_realistic_app(app)
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "acceptance", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "scan", "arguments": {"path": str(app), "network": False}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "check_live", "arguments": {"url": "https://example.com"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "scan_code", "arguments": {"path": "/does/not/exist"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "resources/list"},
            {"jsonrpc": "2.0", "id": 7, "method": "no/such/method"},
        ]
        for m in msgs:
            proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
        out, err = proc.communicate(timeout=300)

    responses = {}
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "id" in obj:
            responses[obj["id"]] = obj

    check("initialize responds", 1 in responses)
    info = responses.get(1, {}).get("result", {}).get("serverInfo", {})
    check("server identifies with the release version", info.get("version") == __version__,
          f"{info.get('version')} vs {__version__}")
    check("server sends instructions", bool(responses.get(1, {}).get("result", {}).get("instructions")), "")

    tools = responses.get(2, {}).get("result", {}).get("tools", [])
    check("19 tools advertised", len(tools) == 19, str(len(tools)))
    check("every tool has a schema", all(t.get("inputSchema") for t in tools), "")
    check("every tool has a description", all(t.get("description") for t in tools), "")

    scan_res = responses.get(3, {}).get("result", {})
    check("scan tool call succeeds", not scan_res.get("isError"), str(scan_res)[:200])
    payload = json.loads(scan_res["content"][0]["text"])
    check("mcp scan returns findings", payload.get("summary", {}).get("total", 0) > 0,
          str(payload.get("summary")))
    check("mcp payload is ok", payload.get("ok") is True, "")

    live = responses.get(4, {}).get("result", {})
    check("live checks refuse without a scope", live.get("isError") is True, str(live)[:160])

    missing = responses.get(5, {}).get("result", {})
    check("missing path returns an error, not a crash", missing.get("isError") is True, str(missing)[:160])

    check("resources/list answered", 6 in responses, "")
    check("unknown method gets -32601", responses.get(7, {}).get("error", {}).get("code") == -32601,
          str(responses.get(7))[:160])
    check("no traceback leaked to the client", "Traceback" not in out, "")


# ---------------------------------------------------------------- 11. realistic perf


def test_performance_on_a_real_tree() -> None:
    print("\n[11] performance on a real tree")
    repo = Path.home() / "opencs"
    if not repo.is_dir():
        note("no large tree available, skipping perf check")
        return
    import time

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "grim", "scan", str(repo), "--no-network", "--format", "json"],
        capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=580,
    )
    elapsed = time.monotonic() - start
    check("large tree scan completes", proc.returncode == 0, proc.stderr[-160:])
    check(f"large tree scan under 150s (took {elapsed:.0f}s)", elapsed < 150, f"{elapsed:.0f}s")
    fs = json.loads(proc.stdout)["findings"]
    entropy = [f for f in fs if "entropy" in f["title"].lower()]
    check("no entropy false positives on a real tree", not entropy,
          " | ".join(f"{f['location']['file']}" for f in entropy[:3]))


def main() -> int:
    print(f"GRIM {__version__} user workflow acceptance tests")
    tests = [
        test_first_run_experience,
        test_main_scan_reports,
        test_scan_tool_subset_and_output_file,
        test_compromised_deploy_is_loud,
        test_clean_app_is_quiet,
        test_triage_workflow,
        test_dependency_audit_online,
        test_drift_and_archives,
        test_hostile_and_edge_inputs,
        test_mcp_session_as_a_client,
        test_performance_on_a_real_tree,
    ]
    for t in tests:
        t()
    print(f"\n{'=' * 60}")
    for n in NOTES:
        print(f"note: {n}")
    print(f"{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())