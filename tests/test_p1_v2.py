"""P1 tests: new lockfiles, new language SAST rules, secrets history/entropy/encoded."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.deps import _collect_packages
from grim.engines.codepatterns import scan_code
from grim.engines.secrets import scan_secrets, scan_secrets_history

FAIL = 0
TOTAL = 0


def check(name, cond):
    global FAIL, TOTAL
    TOTAL += 1
    if not cond:
        FAIL += 1
        print(f"  FAIL {name}")
    else:
        print(f"  ok   {name}")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="grim-p1-"))
    try:
        locks = tmp / "locks"
        locks.mkdir()
        (locks / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.200"\n\n[[package]]\nname = "tokio"\nversion = "1.40.0"\n')
        (locks / "pubspec.lock").write_text('packages:\n  http:\n    dependency: "direct main"\n    version: "1.2.0"\n  path:\n    version: "1.9.0"\n')
        (locks / "go.mod").write_text("module example.com/app\n\ngo 1.22\n\nrequire github.com/gorilla/mux v1.8.1\n")
        (locks / "pom.xml").write_text("<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.17.0</version></dependency></dependencies></project>")
        (locks / "packages.lock.json").write_text('{"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3","contentHash":"x"}}}}')
        (locks / "Gemfile.lock").write_text("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.3)\n    rack (3.0.9)\n")
        pkgs = _collect_packages(locks)
        check("Cargo.lock parsed", ("crates.io", "serde", "1.0.200") in pkgs)
        check("pubspec.lock parsed", ("Pub", "http", "1.2.0") in pkgs)
        check("go.mod parsed", ("Go", "github.com/gorilla/mux", "1.8.1") in pkgs)
        check("pom.xml parsed", ("Maven", "org.apache.logging.log4j:log4j-core", "2.17.0") in pkgs)
        check("packages.lock.json parsed", ("NuGet", "Newtonsoft.Json", "13.0.3") in pkgs)
        check("Gemfile.lock parsed", ("RubyGems", "rails", "7.1.3") in pkgs)

        codes = tmp / "codes"
        codes.mkdir()
        (codes / "main.go").write_text('cmd := "sh -c " + userInput\nexec.Command(cmd)\n')
        (codes / "Main.java").write_text('String sql = "SELECT * FROM users WHERE id = " + id;\nstmt.executeQuery(sql);\n')
        (codes / "app.cs").write_text('var cmd = new SqlCommand("SELECT * FROM t WHERE x = " + input);\n')
        (codes / "app.rb").write_text("eval(params[:code])\n")
        (codes / "lib.rs").write_text('Command::new("sh").arg("-c").arg(user_input).status()\n')
        (codes / "main.dart").write_text('Process.run("sh", ["-c", "$userInput"]);\n')
        titles = " | ".join(f.title for f in scan_code(str(codes)))
        check("go rule fires", "exec.Command" in titles or "Process execution" in titles)
        check("java sql rule fires", "SQL built" in titles)
        check("csharp sql rule fires", "SQL command built" in titles or "SQL built with string concatenation" in titles)
        check("ruby eval rule fires", "Dynamic code execution" in titles)
        check("rust shell rule fires", "Shell command construction" in titles)
        check("dart process rule fires", "Process with interpolated" in titles)

        # history + entropy + encoded
        repo = tmp / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
        (repo / "app.py").write_text("api_key = 'sk-1234567890abcdef1234567890abcdef'\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        (repo / "app.py").write_text("api_key = 'sk-REPLACED-abcdef1234567890abcdef'\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "rotate"], cwd=repo, check=True)
        hist = scan_secrets_history(str(repo))
        check("history finds rotated secret", any("history" in f.tags for f in hist))

        sec = tmp / "sec"
        sec.mkdir()
        (sec / "cfg.py").write_text("token = 'Zx9Km2QvLp7wRt4sN6hJ8cF1dG3aB5eU7yI0oK2mN4pR6sT8uV0wX'\n")
        s = scan_secrets(str(sec))
        check("entropy detector fires", any("entropy" in f.tags for f in s))
        import base64
        blob = base64.b64encode(b"-----BEGIN PRIVATE KEY----- abcdef").decode()
        (sec / "b64.py").write_text(f"data = '{blob}'\n")
        s2 = scan_secrets(str(sec))
        check("encoded detector fires", any("encoded" in f.tags for f in s2))

        # entropy must not flag lockfiles, data, docs, or bundled text
        noisy = "AbCdEf0123456789XyZ0123456789QqWwEeRrTtYy"
        (sec / "package-lock.json").write_text('{"integrity": "sha512-AA' + noisy + '=="}')
        (sec / "notes.md").write_text(f"sample token {noisy} in prose\n")
        (sec / "page.html").write_text(f"<div data-x=\"{noisy}\"></div>\n")
        s3 = scan_secrets(str(sec))
        noisy_hits = [
            f for f in s3
            if "entropy" in f.tags
            and f.location.get("file", "").endswith(("package-lock.json", "notes.md", "page.html"))
        ]
        check("entropy skips lockfiles/data/docs", not noisy_hits)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\nP1: {TOTAL - FAIL}/{TOTAL} passed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
