"""P13 behavior tests for cross-platform scanning and reporting:

- scanning a web directory directly keeps web context
- plain .gz files are scanned as gzip streams, not misread as tar
- endpoint inventory inherits auth from arrays, groups, and app.use
- watch diffs itemize added, changed, and removed files
- ci_scan can emit a SARIF report
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p13-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
os.environ["GRIM_IOC_CACHE"] = str(_TMP / "iocs.json")
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.endpoints import inventory_endpoints  # noqa: E402
from grim.engines.exposure import audit_exposure  # noqa: E402
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
        _test_web_context()
        _test_gzip()
        _test_endpoints_auth()
        _test_laravel_param_routes()
        _test_laravel_custom_middleware()
        _test_laravel_unregistered_routes()
        _test_astro_api_routes()
        _test_watch_itemize()
        _test_ci_sarif()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP13: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_web_context() -> None:
    base = _TMP / "site" / "public" / "uploads"
    base.mkdir(parents=True)
    (base / "shell.php").write_bytes(SHELL)

    # scanning the upload directory itself must still flag the webshell
    s: dict = {}
    direct = audit_exposure(str(base), stats=s)
    check("direct web dir scan keeps context", any("webshell" in f.tags for f in direct))
    check("direct web dir scan reads content", s.get("content_reads", 0) >= 1)

    # scanning a deeper subdirectory of a web root too
    deeper = base / "img"
    deeper.mkdir()
    (deeper / "x.php").write_bytes(SHELL)
    s2: dict = {}
    deep = audit_exposure(str(deeper), stats=s2)
    check("deeper web subdir scan keeps context", any(f.severity == "critical" for f in deep))


def _test_gzip() -> None:
    # a plain .gz log (not a tar) must not be reported as an unreadable tar
    plain = _TMP / "app.log.gz"
    with gzip.open(plain, "wb") as fh:
        fh.write(b"ordinary log line\n" * 100)
    s: dict = {}
    audit_exposure(str(plain), deep=True, stats=s)
    check("plain gz not truncated", s.get("truncated") is False)
    check("plain gz has no unreadable errors", not s.get("errors"))

    # a tar.gz containing a .gz member (rotated log) must scan cleanly
    outer = _TMP / "backup.tar.gz"
    inner_bytes = io.BytesIO()
    with gzip.GzipFile(fileobj=inner_bytes, mode="wb") as gz:
        gz.write(SHELL)
    with tarfile.open(outer, "w:gz") as t:
        data = inner_bytes.getvalue()
        ti = tarfile.TarInfo("public/uploads/site.log.gz")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    s2: dict = {}
    findings = audit_exposure(str(outer), deep=True, stats=s2)
    check("nested gz scan not truncated", s2.get("truncated") is False)
    check("nested gz scan has no unreadable errors", not s2.get("errors"))
    check("nested gz content is scanned", any("webshell" in f.tags for f in findings))

    # a genuinely corrupt tar archive is an error, not truncation
    bad = _TMP / "broken.tar.gz"
    bad.write_bytes(b"not a gzip at all")
    s3: dict = {}
    audit_exposure(str(bad), deep=True, stats=s3)
    check("corrupt tar reported as error", bool(s3.get("errors")))
    check("corrupt tar not marked truncated", s3.get("truncated") is False)


def _test_endpoints_auth() -> None:
    d = _TMP / "app"
    (d / "routes").mkdir(parents=True)
    (d / "routes" / "admin.php").write_text(
        "<?php\n"
        "Route::get('/admin', [AdminController::class, 'admin_dashboard'])\n"
        "    ->name('admin.dashboard')->middleware(['auth', 'admin', 'prevent-back-history']);\n"
        "Route::group(['prefix' => 'admin', 'middleware' => ['auth', 'admin']], function () {\n"
        "    Route::get('/brand-bulk-upload', 'index')->name('brand_bulk_upload.index');\n"
        "});\n"
        "Route::post('/upload', [UploadController::class, 'store']);\n"
    )
    (d / "app.js").write_text(
        "const app = express();\n"
        "app.use(requireAuth);\n"
        "app.get('/secure', (req, res) => res.json(req.query));\n"
        "app.get('/admin/users', (req, res) => res.json(req.query));\n"
        "app.get('/blocked', (req, res) => res.json(req.query));\n"
    )
    endpoints, _ = inventory_endpoints(str(d))
    by = {(e["framework"], e["path"]): e for e in endpoints}

    check("laravel inline array middleware detected",
          by.get(("laravel", "/admin"), {}).get("auth") is True)
    check("laravel group middleware inherited",
          by.get(("laravel", "/brand-bulk-upload"), {}).get("auth") is True)
    check("laravel unprotected route not falsely authed",
          by.get(("laravel", "/upload"), {}).get("auth") is False)

    # express: app.get route-level array middleware on its own
    (d / "arr.js").write_text(
        "const app = express();\n"
        "app.get('/arr', [requireAuth, handler], (req, res) => res.json(req.query));\n"
    )
    endpoints2, _ = inventory_endpoints(str(d / "arr.js"))
    check("express array middleware detected", endpoints2 and endpoints2[0]["auth"] is True)


def _test_laravel_param_routes() -> None:
    # `{param}` inside a route string must not be counted as a scope close
    d = _TMP / "laravel-params"
    d.mkdir(parents=True)
    (d / "admin.php").write_text(
        "<?php\n"
        "Route::group(['prefix' => 'admin', 'middleware' => ['auth', 'admin']], function () {\n"
        "    Route::get('/plain', 'index');\n"
        "    Route::get('/products/{id}/edit', 'edit');\n"
        "    Route::get('/brand-bulk-upload', 'bulk');\n"
        "});\n"
    )
    endpoints, _ = inventory_endpoints(str(d))
    by = {e["path"]: e for e in endpoints}
    check("param route keeps group auth", by.get("/products/{id}/edit", {}).get("auth") is True)
    check("route after param keeps group auth", by.get("/brand-bulk-upload", {}).get("auth") is True)
    check("param route not high risk", by.get("/brand-bulk-upload", {}).get("risk") == "low")

    # controller-level group with no middleware must stay flagged (true positive)
    d2 = _TMP / "laravel-open"
    d2.mkdir(parents=True)
    (d2 / "web.php").write_text(
        "<?php\n"
        "Route::controller(App\\Http\\Controllers\\UploaderController::class)->group(function () {\n"
        "    Route::post('/aiz-uploader/upload', 'upload');\n"
        "});\n"
    )
    endpoints2, _ = inventory_endpoints(str(d2))
    upload = next((e for e in endpoints2 if e["path"] == "/aiz-uploader/upload"), None)
    check("unauthenticated controller group still flagged",
          upload is not None and upload["auth"] is False)
    check("unauthenticated upload is high risk", upload is not None and upload["risk"] == "high")


def _test_laravel_custom_middleware() -> None:
    # a group guarded by domain specific middleware names (no literal 'auth') is protected
    d = _TMP / "laravel-custom"
    d.mkdir(parents=True)
    (d / "seller.php").write_text(
        "<?php\n"
        "Route::group(['prefix' => 'seller', 'middleware' => ['seller', 'verified', 'user', 'prevent-back-history']], function () {\n"
        "    Route::any('/uploads', 'index');\n"
        "    Route::get('/uploads/destroy/{id}', 'destroy');\n"
        "});\n"
    )
    endpoints, _ = inventory_endpoints(str(d))
    by = {e["path"]: e for e in endpoints}
    check("custom middleware group is protected", by.get("/uploads", {}).get("auth") is True)
    check("custom middleware route not high risk", by.get("/uploads", {}).get("risk") == "low")
    check("param route in custom group protected", by.get("/uploads/destroy/{id}", {}).get("auth") is True)


def _test_laravel_unregistered_routes() -> None:
    # the mapping method exists and is uncommented, but the call to it is commented out
    d = _TMP / "laravel-unregistered"
    (d / "routes").mkdir(parents=True)
    (d / "app" / "Providers").mkdir(parents=True)
    (d / "routes" / "web.php").write_text(
        "<?php\n"
        "Route::controller(Uploader::class)->group(function () {\n"
        "    Route::post('/aiz-uploader/upload', 'upload');\n"
        "});\n"
    )
    (d / "routes" / "seller.php").write_text(
        "<?php\n"
        "Route::group(['prefix' => 'seller', 'middleware' => ['seller']], function () {\n"
        "    Route::get('/orders', 'index');\n"
        "});\n"
    )
    (d / "routes" / "install.php").write_text("<?php\nRoute::get('import_sql', 'x');\n")
    (d / "app" / "Providers" / "RouteServiceProvider.php").write_text(
        "<?php\n"
        "class RouteServiceProvider {\n"
        "  public function boot() {\n"
        "    $this->routes(function () {\n"
        "      Route::middleware('web')->group(base_path('routes/web.php'));\n"
        "    });\n"
        "    $this->mapSellerRoutes();\n"
        "    // $this->mapInstallRoutes();\n"
        "  }\n"
        "  protected function mapSellerRoutes() {\n"
        "    Route::middleware('web')->group(base_path('routes/seller.php'));\n"
        "  }\n"
        "  protected function mapInstallRoutes() {\n"
        "    Route::middleware('web')->namespace($this->namespace)->group(base_path('routes/install.php'));\n"
        "  }\n"
        "}\n"
    )
    endpoints, _ = inventory_endpoints(str(d))
    check("uncalled mapping method route file skipped", not any("import_sql" in e["path"] for e in endpoints))
    check("called mapping method route file scanned", any(e["path"] == "/orders" for e in endpoints))
    upload = next((e for e in endpoints if e["path"] == "/aiz-uploader/upload"), None)
    check("registered true positive still flagged", upload is not None and upload["auth"] is False and upload["risk"] == "high")


def _test_astro_api_routes() -> None:
    # Astro API routes must be labelled astro, not nextjs
    d = _TMP / "astro-app"
    (d / "src" / "pages" / "api").mkdir(parents=True)
    (d / "astro.config.mjs").write_text("export default {};\n")
    (d / "src" / "pages" / "api" / "items.ts").write_text(
        'export async function GET() { return new Response("[]"); }\n'
        'export async function POST({ request }) { return new Response("ok"); }\n'
    )
    endpoints, _ = inventory_endpoints(str(d))
    check("astro api route labelled astro", len(endpoints) == 2 and all(e["framework"] == "astro" for e in endpoints))

    # Astro without astro.config: detected via the src/pages plus src/layouts convention
    a2 = _TMP / "astro-noconfig"
    (a2 / "src" / "pages" / "api").mkdir(parents=True)
    (a2 / "src" / "layouts").mkdir(parents=True)
    (a2 / "src" / "pages" / "api" / "items.ts").write_text('export async function GET() { return new Response("[]"); }\n')
    e2, _ = inventory_endpoints(str(a2))
    check("astro without config is detected", bool(e2) and all(e["framework"] == "astro" for e in e2))

    # a Next project with pages/api stays nextjs
    n = _TMP / "next-app"
    (n / "pages" / "api").mkdir(parents=True)
    (n / "next.config.js").write_text("module.exports = {};\n")
    (n / "pages" / "api" / "x.ts").write_text("export default function handler(req, res) { res.json(req.query); }\n")
    next_eps, _ = inventory_endpoints(str(n))
    check("next project stays nextjs", bool(next_eps) and all(e["framework"] == "nextjs" for e in next_eps))


def _test_watch_itemize() -> None:
    d = _TMP / "watch"
    d.mkdir(parents=True)
    (d / "index.html").write_text("<html>ok</html>")
    lp = _TMP / "watch-baseline.json"
    call_tool("watch", {"path": str(d), "action": "save", "baseline_path": str(lp)})
    (d / "notes.txt").write_text("a benign added file")
    res = call_tool("watch", {"path": str(d), "action": "diff", "baseline_path": str(lp)})
    titles = [f["title"] for f in res["findings"]]
    check("watch itemizes added file", any("notes.txt" in t for t in titles))
    check("watch stats list added path", "notes.txt" in (res["meta"]["stats"].get("added_paths") or []))


def _test_ci_sarif() -> None:
    d = _TMP / "ci"
    (d / "public" / "uploads").mkdir(parents=True)
    (d / "public" / "uploads" / "s.php").write_bytes(SHELL)
    res = call_tool("ci_scan", {"path": str(d), "network": False, "fail_on": "critical", "format": "sarif"})
    check("ci_scan exit code", res.get("exit_code") == 1)
    check("ci_scan returns sarif", res.get("format") == "sarif" and '"version": "2.1.0"' in res.get("report", ""))


if __name__ == "__main__":
    raise SystemExit(main())
