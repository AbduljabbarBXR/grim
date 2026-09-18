"""P3 tests: CLI end to end, MCP handshake with v2 tools, and edge/security cases."""

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
_TMP = Path(tempfile.mkdtemp(prefix="grim-p3-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
os.environ["GRIM_IOC_CACHE"] = str(_TMP / "iocs.json")
sys.path.insert(0, str(ROOT / "src"))

from grim import sbom  # noqa: E402
from grim.core import attack  # noqa: E402
from grim.core.planner import build_plan  # noqa: E402
from grim.engines.exposure import _safe_rel, audit_exposure  # noqa: E402
from grim.feeds import iocs  # noqa: E402
from grim.tools import call_tool  # noqa: E402

ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(ROOT / "src")
ENV["GRIM_CACHE"] = str(_TMP / "cache")
ENV["GRIM_IOC_CACHE"] = str(_TMP / "iocs.json")

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
    return subprocess.run(
        [sys.executable, "-m", "grim", *args],
        cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=120,
    )


def main() -> int:
    try:
        _test_cli()
        _test_mcp()
        _test_edge_cases()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP3: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_cli() -> None:
    r = grim("version")
    check("cli version", r.returncode == 0 and "grim 0.2" in r.stdout)

    r = grim("list")
    check("cli list shows v2 tools", r.returncode == 0 and "sbom" in r.stdout and "ledger" in r.stdout)

    app = _TMP / "cli-app"
    (app / "public" / "uploads").mkdir(parents=True)
    (app / "public" / "uploads" / "s.php").write_text(
        "<?php $r = 'mimes:'.$request->mimes; eval($_POST['c']); ?>"
    )
    (app / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}')

    r = grim("plan", str(app), "--no-network")
    check("cli plan", r.returncode == 0 and '"ok": true' in r.stdout and "audit_exposure" in r.stdout)

    out = _TMP / "bom.json"
    r = grim("sbom", str(app), "--format", "spdx", "--out", str(out))
    check("cli sbom writes file", r.returncode == 0 and out.exists())
    check("cli sbom valid spdx", json.loads(out.read_text())["spdxVersion"] == "SPDX-2.3")

    lp = _TMP / "cli-ledger.json"
    r = grim("ledger", str(app), "--ledger", str(lp), "--tools", "exposure")
    check("cli ledger merge", r.returncode == 0 and lp.exists() and '"new"' in r.stdout)

    r = grim("scan", str(app), "--tools", "code,exposure", "--no-network")
    check("cli scan finds code", r.returncode == 0 and "request-controlled" in r.stdout)

    r = grim("iocs", str(app))
    check("cli iocs clean run", r.returncode == 0)

    base = _TMP / "base"
    base.mkdir()
    (base / "public").mkdir()
    (base / "public" / "index.php").write_text("<?php echo 'hi';")
    r = grim("diff", str(base), str(app))
    check("cli diff", r.returncode == 0 and "drift" in r.stdout.lower())


def _test_mcp() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-m", "grim", "mcp"],
        cwd=ROOT, env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    try:
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "plan", "arguments": {"path": str(_TMP), "network": False}}},
        ]
        for m in messages:
            proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()

        responses: dict[int, dict] = {}
        import time
        deadline = time.time() + 25
        while len(responses) < 3 and time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            obj = json.loads(line)
            if "id" in obj:
                responses[obj["id"]] = obj
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    check("mcp initialize", responses.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "grim")
    tools = [t["name"] for t in responses.get(2, {}).get("result", {}).get("tools", [])]
    check("mcp lists v2 tools", all(t in tools for t in ("plan", "sbom", "scan_iocs", "ledger", "update_feeds")))
    content = responses.get(3, {}).get("result", {}).get("content", [{}])
    check("mcp tools/call plan", content and '"ok": true' in content[0].get("text", ""))


def _test_edge_cases() -> None:
    check("safe_rel strips traversal", _safe_rel("../../etc/passwd") == "etc/passwd")
    check("safe_rel strips absolute", _safe_rel("/etc/passwd") == "etc/passwd")
    check("safe_rel keeps normal path", _safe_rel("public/uploads/x.php") == "public/uploads/x.php")

    # zip slip: a malicious member must not escape the extraction root
    d = _TMP / "zipslip"
    d.mkdir(parents=True)
    evil = d / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../../../tmp/grim_evil.txt", "pwned")
        z.writestr("public/uploads/x.php", "<?php eval($_POST['c']); ?>")
    outside = Path("/tmp/grim_evil.txt")
    if outside.exists():
        outside.unlink()
    found = audit_exposure(str(evil), deep=True)
    check("zip slip neutralized", not outside.exists())
    check("zip slip scan still finds webshell", any("webshell" in f.tags for f in found))

    # Maven purl in SBOM
    mvn = _TMP / "maven"
    mvn.mkdir()
    (mvn / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.example</groupId>"
        "<artifactId>lib</artifactId><version>1.0.0</version></dependency></dependencies></project>"
    )
    comps = sbom.collect_components(str(mvn))
    check("maven purl", any(c["purl"] == "pkg:maven/org.example/lib@1.0.0" for c in comps))

    # planner detects archives + deep note
    arc = _TMP / "bundle.tar.gz"
    with tarfile.open(arc, "w:gz") as t:
        t.add(mvn / "pom.xml", arcname="app/pom.xml")
    plan = build_plan(str(arc), network=False, deep=True)
    check("planner flags archive", plan["is_archive"] is True)
    check("planner deep note", any("nested archives" in n for n in plan["notes"]))

    # ledger invalid status is a clean error, not a crash
    bad = call_tool("ledger", {"action": "status", "ledger_path": str(_TMP / "x.json"),
                               "finding_id": "nope", "status": "bogus"})
    check("ledger invalid status errors cleanly", bad.get("ok") is False)

    # ATT&CK catalog is populated and stable
    cat = attack.catalog()
    check("attack catalog non-empty", len(cat) > 5 and any(c["id"] == "T1505.003" for c in cat))

    # IoC add dedupes; sync works over file://
    store = _TMP / "edge-iocs.json"
    e = {"sha256": "a" * 64, "name": "Edge.Sample"}
    check("ioc add first", iocs.add([e], store) == 1)
    check("ioc add deduped", iocs.add([e], store) == 0)

    feed = _TMP / "feed.json"
    feed.write_text(json.dumps([{"sha256": "b" * 64, "name": "Feed.Sample", "severity": "medium"}]))
    added = iocs.sync("file://" + str(feed), store)
    check("ioc sync file url", added == 1 and len(iocs.load(store)) == 2)


if __name__ == "__main__":
    raise SystemExit(main())
