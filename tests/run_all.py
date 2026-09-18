#!/usr/bin/env python3
"""Run every tests/test_*.py as an isolated subprocess and aggregate the result.

GRIM's tests are stdlib scripts (no pytest dependency), so this is the single entry
point used locally and in CI: `python3 tests/run_all.py`.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    files = sorted(HERE.glob("test_*.py"))
    if not files:
        print("no test files found", file=sys.stderr)
        return 1

    failures: list[str] = []
    for f in files:
        print(f"\n=== {f.name} " + "=" * (52 - len(f.name)))
        start = time.time()
        proc = subprocess.run([sys.executable, str(f)])
        elapsed = time.time() - start
        status = "PASS" if proc.returncode == 0 else "FAIL"
        print(f"--- {f.name}: {status} ({elapsed:.1f}s)")
        if proc.returncode != 0:
            failures.append(f.name)

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED ({len(failures)}): {', '.join(failures)}")
        return 1
    print(f"ALL {len(files)} TEST FILES PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
