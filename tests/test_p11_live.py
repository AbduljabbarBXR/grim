"""P11 tests: opt-in live checks — passive, active (allowlisted), deny, authorization."""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p11-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

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


def _serve(directory: str):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=directory, **k)

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def main() -> int:
    web = _TMP / "web"
    web.mkdir(parents=True)
    (web / "index.html").write_text("<html>ok</html>")
    (web / "phpinfo.php").write_text("phpinfo();")
    srv, port = _serve(str(web))
    scope = {
        "authorization": {"declared_by": "test"},
        "targets": [{"host": "127.0.0.1", "mode": "active", "max_requests_per_minute": 0,
                     "paths_allowlist": ["/phpinfo.php"]}],
    }
    try:
        _run(port, scope)
    finally:
        srv.shutdown()
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP11: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _run(port: int, scope: dict) -> None:
    url = f"http://127.0.0.1:{port}/"

    passive = call_tool("check_live", {"url": url, "scope": scope, "active": False})
    check("passive ok", passive.get("ok") is True and passive["meta"]["stats"]["mode"] == "passive")
    check("passive flags missing headers", any("security headers" in f["title"] for f in passive["findings"]))
    check("passive does not probe", passive["meta"]["stats"]["requests"] == 1)

    active = call_tool("check_live", {"url": url, "scope": scope, "active": True})
    check("active mode", active["meta"]["stats"]["mode"] == "active")
    check("active finds allowlisted exposure", any("phpinfo" in f["title"] for f in active["findings"]))
    check("active made extra request", active["meta"]["stats"]["requests"] >= 2)

    no_allow = {"targets": [{"host": "127.0.0.1", "mode": "active", "max_requests_per_minute": 0, "paths_allowlist": []}]}
    limited = call_tool("check_live", {"url": url, "scope": no_allow, "active": True})
    check("active without allowlist does not probe", limited["meta"]["stats"]["requests"] == 1)

    unauthorized = call_tool("check_live", {"url": "http://example.com/", "scope": scope})
    check("unauthorized host rejected", unauthorized.get("ok") is False)

    denied = call_tool("check_live", {"url": url + "phpinfo.php",
                                      "scope": {"targets": [{"host": "127.0.0.1"}], "deny": ["*/phpinfo*"]}})
    check("deny rule enforced", denied.get("ok") is False and "denied" in denied.get("error", ""))

    # scope file discovery
    scopedir = _TMP / "scoped"
    scopedir.mkdir()
    (scopedir / "grim.scope.json").write_text(json.dumps(scope))
    via_file = call_tool("check_live", {"url": url, "scope_dir": str(scopedir), "active": False})
    check("scope file discovered", via_file.get("ok") is True)

    missing_scope = call_tool("check_live", {"url": url, "scope_path": str(_TMP / "nope.json")})
    check("missing scope errors", missing_scope.get("ok") is False)


if __name__ == "__main__":
    raise SystemExit(main())
