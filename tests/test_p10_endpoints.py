"""P10 tests: endpoint inventory across frameworks and risk ranking."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p10-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.endpoints import inventory_endpoints  # noqa: E402
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
        _test_frameworks()
        _test_tool()
        _test_planner()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP10: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _build() -> Path:
    d = _TMP / "app"
    (d / "src" / "app" / "api" / "users").mkdir(parents=True, exist_ok=True)
    (d / "src" / "pages" / "api").mkdir(parents=True, exist_ok=True)
    (d / "routes").mkdir(parents=True, exist_ok=True)
    (d / "srv").mkdir(parents=True, exist_ok=True)
    (d / "app.js").write_text(
        "const app = express();\n"
        "app.get('/admin/users', (req, res) => res.json(req.query));\n"
        "app.post('/safe', requireAuth, (req, res) => res.json(req.body));\n"
    )
    (d / "routes" / "web.php").write_text(
        "<?php\nRoute::post('/upload', [UploadController::class, 'store']);\n"
        "Route::middleware('auth')->get('/profile', [ProfileController::class, 'show']);\n"
    )
    (d / "urls.py").write_text("from django.urls import path\nurlpatterns = [path('api/items/', views.items)]\n")
    (d / "srv" / "main.go").write_text('package main\nfunc main() { r.GET("/admin/debug", h); http.HandleFunc("/health", h2) }\n')
    (d / "src" / "app" / "api" / "users" / "route.ts").write_text(
        "export async function GET(req) { return new Response(req.nextUrl.searchParams.get('x')); }\n"
    )
    (d / "src" / "pages" / "api" / "legacy.ts").write_text(
        "export default function handler(req, res) { res.json(req.query); }\n"
    )
    return d


def _test_frameworks() -> None:
    d = _build()
    endpoints, findings = inventory_endpoints(str(d))
    by = {(e["framework"], e["path"]): e for e in endpoints}
    check("express detected", ("express", "/admin/users") in by and ("express", "/safe") in by)
    check("express unauthenticated input is high", by[("express", "/admin/users")]["risk"] == "high")
    check("express authed route is not high", by[("express", "/safe")]["risk"] != "high" and by[("express", "/safe")]["auth"])
    check("laravel upload high", by[("laravel", "/upload")]["risk"] == "high")
    check("laravel middleware auth detected", by[("laravel", "/profile")]["auth"] is True)
    check("django any-method", by[("django", "api/items/")]["method"] == "ANY")
    check("go method parsed", by[("go", "/admin/debug")]["method"] == "GET")
    check("go handlefunc any", by[("go", "/health")]["method"] == "ANY")
    check("next route methods", by[("nextjs", "/api/users")]["method"] in ("GET", "POST"))
    check("next pages handler any+input", by[("nextjs", "/api/legacy")]["method"] == "ANY" and by[("nextjs", "/api/legacy")]["inputs"])
    check("risky findings emitted", any(f.engine == "grim-endpoints" for f in findings))


def _test_tool() -> None:
    d = _build()
    payload = call_tool("inventory_endpoints", {"path": str(d)})
    check("tool ok with summary", payload.get("ok") and payload["endpoint_summary"]["total"] >= 6)
    check("tool returns endpoints list", isinstance(payload.get("endpoints"), list))


def _test_planner() -> None:
    from grim.core.planner import build_plan

    plan = build_plan(str(_build()), network=False)
    check("planner recommends endpoints", "inventory_endpoints" in plan["recommended_order"])


if __name__ == "__main__":
    raise SystemExit(main())
