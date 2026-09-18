"""P9 tests: remote rules/feed sync — overlay rules, IoC feed, validation, invalidation."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p9-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
os.environ["GRIM_RULES_CACHE"] = str(_TMP / "cache" / "rules.json")
os.environ["GRIM_IOC_CACHE"] = str(_TMP / "iocs.json")
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.feeds import iocs as iocs_mod  # noqa: E402
from grim.feeds import rules as rules_mod  # noqa: E402
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
        _test_overlay_and_invalidation()
        _test_feed_sync()
        _test_validation()
        _test_no_url()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print(f"\nP9: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _src() -> Path:
    d = _TMP / "src"
    d.mkdir(parents=True, exist_ok=True)
    (d / "app.py").write_text("x = 1\nDANGER_RULE_MARKER = 2\n")
    (d / "page.php").write_text("<?php DANGER_RULE_MARKER; ?>\n")
    return d


def _test_overlay_and_invalidation() -> None:
    d = _src()
    before = scan_code(str(d), use_cache=True)
    check("no finding before feed", not any("Danger marker" in f.title for f in before))

    rules_mod.save([{"id": "danger-marker", "pattern": "DANGER_RULE_MARKER", "severity": "high",
                     "title": "Danger marker present", "languages": ["python"]}], source="test")
    after = scan_code(str(d), use_cache=True)
    hits = [f for f in after if "Danger marker present" in f.title]
    check("overlay rule fires after sync", len(hits) == 1)
    check("overlay respects language", hits and hits[0].location["file"].endswith("app.py"))


def _test_feed_sync() -> None:
    feed = _TMP / "feed.json"
    feed.write_text(json.dumps({
        "version": "2026.09",
        "rules": [{"id": "marker2", "pattern": "SECOND_MARKER", "severity": "medium",
                   "title": "Second marker", "languages": ["python"]}],
        "iocs": [{"sha256": "b" * 64, "name": "Feed.Bad", "severity": "high"}],
    }))
    res = call_tool("update_feeds", {"url": "file://" + str(feed), "ioc_path": str(_TMP / "iocs.json")})
    check("feed sync ok", res.get("ok") and res.get("version") == "2026.09")
    check("feed rules installed", res.get("rules_added") == 1 and res.get("rules_total") == 1)
    check("feed iocs installed", res.get("iocs_added") == 1 and len(iocs_mod.load(str(_TMP / "iocs.json"))) == 1)


def _test_validation() -> None:
    n = rules_mod.save([
        {"id": "bad-regex", "pattern": "([unclosed", "severity": "high"},
        {"id": "ok-rule", "pattern": "OK_MARKER", "severity": "nonsense", "title": "ok"},
    ], source="test")
    check("invalid pattern skipped, invalid severity coerced", n == 1)
    loaded = rules_mod.load_raw().get("rules", [])
    check("stored rule severity coerced to medium", loaded and loaded[0]["severity"] == "medium")


def _test_no_url() -> None:
    for var in ("GRIM_FEEDS_URL", "GRIM_RULES_FEED"):
        os.environ.pop(var, None)
    res = call_tool("update_feeds", {})
    check("no url errors cleanly", res.get("ok") is False)


if __name__ == "__main__":
    raise SystemExit(main())
