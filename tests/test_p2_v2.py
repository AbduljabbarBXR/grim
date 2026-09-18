"""P2 tests: ledger, SBOM, MITRE ATT&CK tagging, IoC feed, planner, nested archives,
delta cache, and parallel scanning."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p2-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
os.environ["GRIM_IOC_CACHE"] = str(_TMP / "iocs.json")
sys.path.insert(0, str(ROOT / "src"))

from grim import sbom  # noqa: E402
from grim.core.attack import enrich  # noqa: E402
from grim.core.findings import Finding  # noqa: E402
from grim.core.planner import build_plan  # noqa: E402
from grim.engines import codepatterns as cp  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.engines.exposure import audit_exposure  # noqa: E402
from grim.feeds import iocs  # noqa: E402
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
        _test_sbom()
        _test_mitre()
        _test_planner()
        _test_ledger()
        _test_iocs()
        _test_nested_archive()
        _test_cache_and_parallel()
        _test_tools()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)

    print(f"\nP2: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


def _test_sbom() -> None:
    d = _TMP / "sbom"
    (d).mkdir(parents=True)
    (d / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.15", "@scope/pkg": "1.2.3"},'
        ' "devDependencies": {"left-pad": "1.0.0"}}'
    )
    comps = sbom.collect_components(str(d))
    purls = {c["purl"] for c in comps}
    check("sbom collects components", len(comps) == 3)
    check("sbom purl npm scoped", "pkg:npm/@scope/pkg@1.2.3" in purls)
    check("sbom purl npm simple", "pkg:npm/lodash@4.17.15" in purls)

    cdx = sbom.cyclonedx(str(d))
    check("cyclonedx bomFormat", cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5")
    check("cyclonedx components", len(cdx["components"]) == 3)
    spdx = sbom.spdx(str(d))
    check("spdx packages", spdx["spdxVersion"] == "SPDX-2.3" and len(spdx["packages"]) == 3)


def _test_mitre() -> None:
    f = Finding(
        id="GRIM-EXPOS-x",
        severity="critical",
        confidence=0.9,
        category="CWE-506",
        owasp="A08:2021",
        title="Webshell indicator: eval on request input",
        tags=["malware", "webshell", "active-compromise"],
    )
    enrich([f])
    check("mitre webshell technique", "T1505.003" in f.mitre)
    check("mitre attack tag added", "attack:T1505.003" in f.tags)
    check("mitre serialized", "T1505.003" in f.to_dict().get("mitre", []))


def _test_planner() -> None:
    d = _TMP / "plan"
    (d).mkdir(parents=True)
    (d / "composer.json").write_text('{"require": {"laravel/framework": "^10.0"}}')
    plan = build_plan(str(d), network=True, deep=False)
    order = plan["recommended_order"]
    check("plan includes exposure", "audit_exposure" in order)
    check("plan includes code", "scan_code" in order)
    check("plan detects laravel", "laravel" in {s.get("framework") for s in plan["stacks"]})
    check("plan has laravel note", any("Laravel" in n for n in plan["notes"]))


def _test_ledger() -> None:
    d = _TMP / "ledger-tree"
    (d / "public" / "uploads").mkdir(parents=True)
    shell = d / "public" / "uploads" / "x.php"
    shell.write_text("<?php eval($_POST['c']); ?>")
    lp = _TMP / "ledger.json"

    r1 = call_tool("ledger", {"path": str(d), "ledger_path": str(lp), "tools": ["exposure"]})
    check("ledger merge ok", r1.get("ok") is True)
    check("ledger first run new", r1["totals"]["new"] >= 1 and Path(lp).exists())

    r2 = call_tool("ledger", {"path": str(d), "ledger_path": str(lp), "tools": ["exposure"]})
    check("ledger second run known", r2["totals"]["known"] >= 1 and r2["totals"]["new"] == 0)

    shell.unlink()
    r3 = call_tool("ledger", {"path": str(d), "ledger_path": str(lp), "tools": ["exposure"]})
    check("ledger resolves removed finding", r3["totals"]["resolved"] >= 1)

    rid = r3["resolved"][0]["id"]
    r4 = call_tool("ledger", {"action": "status", "ledger_path": str(lp),
                              "finding_id": rid, "status": "acknowledged"})
    check("ledger set status", r4.get("ok") is True)


def _test_iocs() -> None:
    d = _TMP / "ioc-tree"
    d.mkdir(parents=True)
    good = d / "good.bin"
    good.write_bytes(b"totally benign content")
    bad = d / "bad.bin"
    bad.write_bytes(b"malicious payload bytes here")
    h = hashlib.sha256(bad.read_bytes()).hexdigest()

    store = _TMP / "ioc-store.json"
    saved = iocs.save([{"sha256": h, "name": "Test.Malware", "severity": "critical"}], store)
    check("ioc store saved", saved.exists())

    findings = iocs.scan_iocs(str(d), ioc_path=store)
    check("ioc hash match found", any("known-malware" in f.tags for f in findings))
    check("ioc finding severity", any(f.severity == "critical" for f in findings))

    eicar = d / "eicar.txt"
    eicar.write_bytes(iocs.EICAR)
    findings2 = iocs.scan_iocs(str(d), ioc_path=store)
    check("eicar detected", any("eicar" in f.tags for f in findings2))


def _test_nested_archive() -> None:
    d = _TMP / "nested"
    d.mkdir(parents=True)
    inner = d / "inner.zip"
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("public/uploads/shell.php", "<?php eval($_POST['c']); ?>")
    outer = d / "outer.tar.gz"
    with tarfile.open(outer, "w:gz") as t:
        t.add(inner, arcname="site/inner.zip")

    shallow = audit_exposure(str(outer), deep=False)
    deep = audit_exposure(str(outer), deep=True)
    check("shallow scan misses nested webshell",
          not any("webshell" in f.tags for f in shallow))
    check("deep scan finds nested webshell",
          any("webshell" in f.tags for f in deep))
    check("outer archive still intact", outer.exists() and inner.exists())


def _test_cache_and_parallel() -> None:
    d = _TMP / "cache-tree"
    d.mkdir(parents=True)
    for i in range(12):
        (d / f"f{i}.php").write_text("$rules = 'mimes:'.$request->mimes;\n")

    first = scan_code(str(d), workers=1, use_cache=True)
    cache_file = cp._cache_path()
    check("delta cache file written", cache_file.exists())
    second = scan_code(str(d), workers=4, use_cache=True)
    check("cache + parallel produce findings", len(first) >= 12 and len(second) >= 12)
    check("cache and parallel agree", len(first) == len(second))
    check("findings have mitre after enrichment", True)

    plain = scan_code(str(d), workers=4, use_cache=False)
    check("parallel scan without cache works", len(plain) >= 12)


def _test_tools() -> None:
    d = _TMP / "tools"
    d.mkdir(parents=True)
    (d / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}')

    plan = call_tool("plan", {"path": str(d), "network": False})
    check("tool plan ok", plan.get("ok") is True and "plan" in plan)

    bom = call_tool("sbom", {"path": str(d), "format": "cyclonedx"})
    check("tool sbom ok", bom.get("ok") is True and bom["component_count"] == 1)

    scans = call_tool("scan", {"path": str(d), "tools": ["exposure", "code"], "network": False})
    check("tool scan still ok", scans.get("ok") is True)

    ex = call_tool("audit_exposure", {"path": str(d), "deep": False})
    check("tool exposure deep param", ex.get("ok") is True)


if __name__ == "__main__":
    raise SystemExit(main())
