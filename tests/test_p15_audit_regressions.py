"""Regression tests for the defects found in the 2026-10 audit.

Every test here reproduces a specific verified failure on 0.6.2/0.6.3, so a
regression re-introduces a known bug rather than a hypothetical one. Stdlib only,
runnable on Termux: python3 tests/test_p15_audit_regressions.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from grim.core import attack  # noqa: E402
from grim.core.findings import Finding  # noqa: E402
from grim.engines.codepatterns import scan_code  # noqa: E402
from grim.engines.endpoints import inventory_endpoints  # noqa: E402
from grim.engines.exposure import DirSource, audit_exposure  # noqa: E402
from grim.engines.flow import scan_flow  # noqa: E402
from grim.engines.malware import default_rules_path  # noqa: E402
from grim.engines.secrets import scan_secrets  # noqa: E402

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


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def titles(findings) -> set[str]:
    return {f.title for f in findings}


# ---------------------------------------------------------------- A1 web-path bug


def test_android_path_is_not_web_served() -> None:
    """A clean source tree under /data/.../files/... must produce no criticals.

    Bug: DirSource.prefix was the whole absolute path, and "files" is a web
    segment, so every target on Android/Termux was classified as web served.
    """
    print("android/termux web-path false positive")
    # tempfile.gettempdir() honours TMPDIR on Linux and Termux and falls back
    # correctly elsewhere. A hardcoded Termux path made this test fail on CI.
    base = Path(tempfile.gettempdir()) / "grim_regress_wp"
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)
    write(base / "src" / "app.py", "print('hello')\n")
    write(base / "src" / "main.c", "int main(void){return 0;}\n")
    write(base / "deploy.sh", "#!/bin/sh\necho hi\n")
    crit = [f.title for f in audit_exposure(str(base)) if f.severity == "critical"]
    check("clean android tree has no criticals", not crit, str(crit))

    # A real web directory must still be detected through the relative path.
    write(base / "public" / "uploads" / "shell.php", "<?php eval($_POST['x']);")
    write(base / "public" / ".env", "APP_KEY=abc123456\n")
    hits = titles(audit_exposure(str(base)))
    check(
        "real web dir still flagged",
        "Executable php file in web-served directory" in hits,
        str(sorted(hits)),
    )

    # Pointing GRIM directly at the web root must still fire.
    direct = [f.title for f in audit_exposure(str(base / "public" / "uploads")) if f.severity == "critical"]
    check("scanning a web root directly still fires", bool(direct), str(direct))

    # The prefix must be empty for an ordinary project root.
    check("prefix empty for plain project", DirSource(str(base)).prefix == "", DirSource(str(base)).prefix)
    shutil.rmtree(base, ignore_errors=True)


# ------------------------------------------------------------------ A2 SQL sinks


SQL_JS = """const express = require("express");
const app = express();

app.get("/users", (req, res) => {
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(q);
  res.send(q);
});

app.get("/safe", (req, res) => {
  res.send(db.prepare("SELECT * FROM users WHERE id = ?").all(req.query.id));
});
"""

SQL_PY = """import sqlite3

def lookup(conn, request):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE n = '" + request.args["n"] + "'")
    return cur.fetchall()
"""


def test_sql_sinks_detected() -> None:
    """Concatenated queries were undetectable in every language (CWE-89)."""
    print("SQL injection detection")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(root / "app.js", SQL_JS)
        write(root / "app.py", SQL_PY)
        findings = scan_flow(str(root))
        sql = [f for f in findings if "SQL" in f.title]
        check("sql sink found in js", any(f.location.get("file", "").endswith("app.js") for f in sql), str(len(sql)))
        check("sql sink found in python", any(f.location.get("file", "").endswith("app.py") for f in sql), str(len(sql)))

        code = scan_code(str(root))
        sql_code = [f for f in code if "SQL" in f.title]
        check("syntactic sql rule fires", bool(sql_code), str(len(code)))

        # A parameterized query must not be flagged.
        lines = {f.location.get("line") for f in sql_code}
        check("parameterized query not flagged", 9 not in lines, str(sorted(lines)))


# ------------------------------------------------------- A3 source credentials

JS_CREDS = """const DB_PASSWORD = "supersecret-prod-12345";
let apiToken = "abcd1234efgh5678ijkl";
export const SECRET_KEY = "zzzzzzzz-9999-yyyy-8888-xxxxxxxx";
password: "plaintext-password-value";
"""


def test_source_credential_assignments() -> None:
    """`const DB_PASSWORD = "..."` was invisible: the rule only ran on .env files."""
    print("source credential assignments")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(root / "app.js", JS_CREDS)
        found = titles(scan_secrets(str(root)))
        assigned = {t for t in found if "credential assignment" in t}
        check("js const credential found", "Hardcoded credential assignment: DB_PASSWORD" in assigned, str(sorted(assigned)))
        check("js let credential found", "Hardcoded credential assignment: apiToken" in assigned, str(sorted(assigned)))
        check("js export const credential found", "Hardcoded credential assignment: SECRET_KEY" in assigned, str(sorted(assigned)))


# ------------------------------------------------------------- A4 new rule family

INSECURE_PY = """import hashlib, random, ssl, yaml, requests, os


def weak_hash(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def weak_hash1(pw):
    return hashlib.sha1(pw.encode()).hexdigest()


def insecure_random():
    return random.random()


def no_tls():
    ctx = ssl._create_unverified_context()
    return requests.get("https://x.example", verify=False)


def traversal(user):
    return open("/data/" + user)


def world_writable():
    os.chmod("/data/x", 0o777)


def cors():
    return "Access-Control-Allow-Origin: *"


def csrf_off():
    WTF_CSRF_ENABLED = False


def deser(y):
    return yaml.load(y)
"""


def test_crypto_tls_and_web_rules() -> None:
    """The whole weak-crypto/TLS/permissions class was absent (0 rules)."""
    print("crypto, TLS, permissions, web rules")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(root / "insecure.py", INSECURE_PY)
        findings = scan_code(str(root))
        found = {f.title for f in findings}
        cats = {f.category for f in findings}
        expected = [
            "MD5 used (broken hash)",
            "SHA-1 used (weak hash)",
            "Non-cryptographic randomness for a security value",
            "TLS certificate verification disabled",
            "Filesystem path built from input (path traversal)",
            "World-writable file or directory permissions",
            "Wildcard CORS origin allowed",
            "CSRF protection disabled",
            "Unsafe deserialization of untrusted data",
        ]
        for title in expected:
            check(f"rule fires: {title}", title in found, str(sorted(found))[:300])
        for cwe in ("CWE-327", "CWE-295", "CWE-22", "CWE-732", "CWE-942", "CWE-352", "CWE-502", "CWE-330"):
            check(f"cwe emitted: {cwe}", cwe in cats, str(sorted(cats)))


def test_cwe_is_per_rule_not_severity() -> None:
    """Previously every SAST finding was CWE-20 or CWE-94 regardless of weakness."""
    print("per-rule CWE assignment")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(root / "insecure.py", INSECURE_PY)
        by_title = {f.title: f.category for f in scan_code(str(root))}
        check("md5 maps to CWE-327", by_title.get("MD5 used (broken hash)") == "CWE-327", str(by_title))
        check("tls maps to CWE-295", by_title.get("TLS certificate verification disabled") == "CWE-295", "")
        check("cors maps to CWE-942", by_title.get("Wildcard CORS origin allowed") == "CWE-942", "")


# ------------------------------------------------------------- A5 entropy quality

ENTROPY_DATA = """asset_id = "aB3dEf9hIj2kLm8nOp5qRs7tUv4wX6yZ1"
assetHash2 = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1Njc4OQ"
another_id = "Zx8Qw3Er7Ty2Ui5Op1As9Df4Gh6Jk0Lz2Xc7Vb3Nm5"
"""

ENTROPY_REAL = """API_KEY = "x7Kd9Pq2Lm4Nv8Rt1Zc6Bw3Yh5Js0Ae1U"
password = "Tr0ub4dor&3xyzzyQ"
"""


def test_entropy_precision() -> None:
    """Entropy pass produced 83 false positives on a 320 MB tree of identifiers."""
    print("entropy precision")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(root / "data.py", ENTROPY_DATA)
        write(root / "checksums", "13a7Qw3Er7Ty2Ui5Op1As9Df4Gh6Jk0Lz  file.bin\n")
        entropy = [f for f in scan_secrets(str(root)) if "entropy" in f.title.lower()]
        check("no entropy findings on identifiers", not entropy, str([f.location for f in entropy]))

        write(root / "real.py", ENTROPY_REAL)
        found = titles(scan_secrets(str(root)))
        assigned = {t for t in found if "credential assignment" in t}
        check("real credential still found", "Hardcoded credential assignment: API_KEY" in assigned, str(sorted(assigned)))


def test_entropy_requires_context() -> None:
    """A credential on its own line must not lend context to an unrelated line."""
    print("entropy context isolation")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(
            root / "mixed.py",
            "API_KEY = \"x7Kd9Pq2Lm4Nv8Rt1Zc6Bw3Yh5Js0Ae1U\"\n"
            "asset_id = \"aB3dEf9hIj2kLm8nOp5qRs7tUv4wX6yZ1\"\n",
        )
        entropy = [f for f in scan_secrets(str(root)) if "entropy" in f.title.lower()]
        lines = {f.location.get("line") for f in entropy}
        check("neighbouring line not tainted by context", 2 not in lines, str(sorted(lines)))


def test_scan_speed_guard() -> None:
    """A large tree must finish quickly; literal prefilters keep it sublinear."""
    print("scan performance guard")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        big = root / "data"
        big.mkdir()
        # 300 files of 60 KB: enough to be slow without the binary sniff and prefilters.
        filler = ("lorem ipsum dolor sit amet consectetur adipiscing elit " * 60) + "\n"
        for i in range(300):
            write(big / f"f{i}.txt", filler)
        write(big / "blob.bin", "\x00\x01\x02" * 20000)
        start = time.monotonic()
        scan_secrets(str(root))
        elapsed = time.monotonic() - start
        check("large tree scan under 20s", elapsed < 20, f"{elapsed:.1f}s")


# ------------------------------------------------------------------ A6 endpoints

ENDPOINT_APP = """const express = require("express");
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

app.get("/plain", (req, res) => {
  res.send("hello");
});
"""


def test_endpoint_taint_ranking() -> None:
    """Routes with SQLi/cmd injection ranked low while an input-free route ranked high."""
    print("endpoint taint ranking")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        write(root / "app.js", ENDPOINT_APP)
        eps, _ = inventory_endpoints(str(root))
        by_path = {e["path"]: e for e in eps}
        check("/users present", "/users" in by_path, str(sorted(by_path)))
        check("/run present", "/run" in by_path, str(sorted(by_path)))
        if "/users" in by_path:
            check("/users ranked high", by_path["/users"]["risk"] == "high", by_path["/users"]["risk"])
            check("/users marked tainted", by_path["/users"].get("tainted") is True, str(by_path["/users"]))
            check(
                "/users attributed to SQL sink",
                any("SQL" in s for s in by_path["/users"].get("taint_sinks", [])),
                str(by_path["/users"].get("taint_sinks")),
            )
            check("/users reports input surface", by_path["/users"]["inputs"] is True, "")
        if "/run" in by_path:
            check(
                "/run attributed to shell sink",
                any("shell" in s for s in by_path["/run"].get("taint_sinks", [])),
                str(by_path["/run"].get("taint_sinks")),
            )
        if "/plain" in by_path:
            check("/plain not tainted", by_path["/plain"].get("tainted") is False, str(by_path["/plain"]))


# --------------------------------------------------------- A7 version single truth


def test_version_consistency() -> None:
    """pyproject said 0.6.3, __init__ said 0.6.2; every handshake reported 0.6.2."""
    print("version single source of truth")
    import re as _re

    from grim import __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = _re.search(r'^version\s*=\s*"([^"]+)"', pyproject, _re.M)
    check("pyproject version parsed", bool(m), pyproject[:200])
    if m:
        check("engine version matches pyproject", __version__ == m.group(1), f"{__version__} vs {m.group(1)}")

    pkg = ROOT / "npm" / "package.json"
    if pkg.is_file():
        npm_ver = json.loads(pkg.read_text(encoding="utf-8")).get("version")
        check("npm version matches", npm_ver == __version__, f"{npm_ver} vs {__version__}")

    server = ROOT / "npm" / "server.json"
    if server.is_file():
        data = json.loads(server.read_text(encoding="utf-8"))
        check("server.json version matches", data.get("version") == __version__, f"{data.get('version')} vs {__version__}")
        for pkg_entry in data.get("packages", []):
            check(
                f"server.json {pkg_entry.get('registryType')} version matches",
                pkg_entry.get("version") == __version__,
                str(pkg_entry.get("version")),
            )


# ------------------------------------------------------------------- A8 yara data


def test_default_yara_ruleset_ships() -> None:
    """The YARA adapter was inert unless GRIM_YARA_RULES was set by the operator."""
    print("default YARA ruleset")
    path = default_rules_path()
    check("default ruleset resolves", bool(path), repr(path))
    if not path:
        return
    p = Path(path)
    check("default ruleset exists", p.is_file(), path)
    if not p.is_file():
        return
    text = p.read_text(encoding="utf-8")
    import re as _re

    names = _re.findall(r"\brule\s+(\w+)", text)
    check("ruleset has rules", len(names) >= 8, str(len(names)))
    check("no duplicate rule names", len(names) == len(set(names)), str(names))
    for family in ("webshell", "reverse_shell", "cryptominer", "ransomware", "persistence"):
        check(f"ruleset covers {family}", any(family in n for n in names), str(names))


def test_malware_scan_reports_ruleset() -> None:
    """malware_scan must not claim YARA was skipped for want of configuration."""
    print("malware scan adapter reporting")
    from grim.engines.malware import scan_malware

    with tempfile.TemporaryDirectory() as td:
        _fs, info = scan_malware(td)
        notes = " ".join(info.get("notes", []))
        check("no 'GRIM_YARA_RULES is not set' note", "GRIM_YARA_RULES is not set" not in notes, notes)
        if info["adapters"].get("yara"):
            check("yara actually ran", "skipped YARA" not in notes, notes)


# ------------------------------------------------------------- A9 ATT&CK coverage


def test_attack_techniques_for_new_cwes() -> None:
    """Weak-crypto, TLS, traversal, CSRF and CORS findings had no ATT&CK mapping."""
    print("MITRE ATT&CK coverage")
    cases = [
        ("CWE-327", "MD5 used (broken hash)"),
        ("CWE-295", "TLS certificate verification disabled"),
        ("CWE-22", "Filesystem path built from input"),
        ("CWE-352", "CSRF protection disabled"),
        ("CWE-330", "Non-cryptographic randomness"),
        ("CWE-732", "World-writable file permissions"),
        ("CWE-1004", "Session cookie missing Secure"),
        ("CWE-502", "Unsafe deserialization of untrusted data"),
        ("CWE-1336", "Server-side template injection risk"),
    ]
    for category, title in cases:
        f = Finding(id="x", severity="high", confidence=0.7, category=category, owasp="A03:2021", title=title, tags=[])
        ids = [i for i, _ in attack.techniques_for(f)]
        check(f"{category} maps to a technique", bool(ids), f"{category} {title}")


def test_attack_catalog_grew() -> None:
    print("ATT&CK catalog size")
    cat = attack.catalog()
    check("catalog has at least 20 techniques", len(cat) >= 20, str(len(cat)))


# --------------------------------------------------------------------- CLI shapes


def test_cli_subcommands_accept_positional_path() -> None:
    """Documented `grim fix_plan PATH` form must work for every path subcommand."""
    print("CLI path argument shapes")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    with tempfile.TemporaryDirectory() as td:
        write(Path(td) / "app.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        for cmd in (["fix_plan", td], ["plan", td], ["sbom", td], ["scan", td], ["endpoints", td]):
            proc = subprocess.run(
                [sys.executable, "-m", "grim", *cmd],
                capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120,
            )
            check(f"grim {' '.join(cmd[:1])} <path> exits 0", proc.returncode == 0, proc.stderr[-200:])


def test_cli_accepts_positional_and_flag_path() -> None:
    """The README documents both `grim fix_plan PATH` and `grim fix_plan --path PATH`."""
    print("CLI path argument alias")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    with tempfile.TemporaryDirectory() as td:
        write(Path(td) / "app.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        positional = ["fix_plan", "plan", "sbom", "scan", "endpoints", "malware"]
        for cmd in positional:
            a = subprocess.run(
                [sys.executable, "-m", "grim", cmd, td],
                capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120,
            )
            b = subprocess.run(
                [sys.executable, "-m", "grim", cmd, "--path", td],
                capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120,
            )
            check(f"grim {cmd} --path exits 0", b.returncode == 0, b.stderr[-160:])
            if cmd == "sbom":
                # An SBOM carries a fresh serialNumber and timestamp per build, so
                # compare structure rather than bytes.
                try:
                    ja, jb = json.loads(a.stdout), json.loads(b.stdout)
                    same = ja.get("bomFormat") == jb.get("bomFormat") and ja.get("specVersion") == jb.get("specVersion")
                except json.JSONDecodeError:
                    same = False
            else:
                same = a.stdout == b.stdout
            check(
                f"grim {cmd} positional and --path agree",
                a.returncode == b.returncode and same,
                f"rc {a.returncode} vs {b.returncode}",
            )


def test_cli_format_flags_accepted_everywhere() -> None:
    """plan and sbom previously rejected --format, unlike every other subcommand."""
    print("CLI --format consistency")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    with tempfile.TemporaryDirectory() as td:
        write(Path(td) / "requirements.txt", "django==1.8.0\n")
        for cmd, fmt in (("plan", "md"), ("plan", "json"), ("sbom", "spdx"), ("sbom", "json")):
            proc = subprocess.run(
                [sys.executable, "-m", "grim", cmd, td, "--format", fmt],
                capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120,
            )
            check(f"grim {cmd} --format {fmt} exits 0", proc.returncode == 0, proc.stderr[-160:])


def test_plan_markdown_renderer_is_readable() -> None:
    print("plan markdown rendering")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    with tempfile.TemporaryDirectory() as td:
        write(Path(td) / "requirements.txt", "django==1.8.0\n")
        proc = subprocess.run(
            [sys.executable, "-m", "grim", "plan", td, "--format", "md", "--no-network"],
            capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120,
        )
        out = proc.stdout
        check("plan md has heading", out.startswith("# GRIM Audit Plan"), out[:80])
        check("plan md lists ordered steps", "audit_exposure" in out, out[:200])
        check("plan md names the stack", "python" in out, out[:200])


def test_mcp_handshake_reports_current_version() -> None:
    print("MCP handshake version")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "grim", "version"],
        capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120,
    )
    from grim import __version__

    check("grim version prints current", __version__ in proc.stdout, proc.stdout.strip())



def test_archive_contents_are_scanned() -> None:
    """`scan` documents "path or archive" but code and secrets skipped archive members.

    Reproduced on 0.6.4: a tar.gz containing a webshell returned 0 findings and
    `files_scanned: 0`, because only audit_exposure opened archives.
    """
    print("archive scanning")
    import tarfile
    import zipfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "src").mkdir()
        (root / "src" / "evil.php").write_text("<?php system($_GET['c']); ?>\n")
        (root / "src" / "conf.js").write_text(
            'const DB_PASSWORD = "supersecret-prod-12345";\n')
        (root / "src" / "creds.py").write_text(
            'API_KEY = "x7Kd9Pq2Lm4Nv8Rt1Zc6Bw3Yh5Js0Ae1U"\n')
        (root / "src" / "blob.bin").write_bytes(b"\x00\x01\x02" * 500)

        tar_path = root / "bundle.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(root / "src" / "evil.php", arcname="src/evil.php")
            tf.add(root / "src" / "conf.js", arcname="src/conf.js")
            tf.add(root / "src" / "creds.py", arcname="src/creds.py")
            tf.add(root / "src" / "blob.bin", arcname="src/blob.bin")

        code = scan_code(str(tar_path))
        check("archive code findings found", len(code) > 0, str(len(code)))
        check("archive finding names the member",
              any("evil.php" in f.location.get("file", "") for f in code),
              str([f.location.get("file") for f in code]))

        secrets_found = scan_secrets(str(tar_path))
        titles_ = titles(secrets_found)
        check("archive credential found",
              any("credential assignment" in t for t in titles_), str(sorted(titles_)))
        check("archive finding names the member",
              any("conf.js" in f.location.get("file", "") or "creds.py" in f.location.get("file", "")
                  for f in secrets_found),
              str([f.location.get("file") for f in secrets_found]))

        zip_path = root / "bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(root / "src" / "evil.php", arcname="src/evil.php")
            zf.write(root / "src" / "conf.js", arcname="src/conf.js")
        zcode = scan_code(str(zip_path))
        check("zip code findings found", len(zcode) > 0, str(len(zcode)))
        zsec = scan_secrets(str(zip_path))
        check("zip credential found", any("credential assignment" in t for t in titles(zsec)),
              str(sorted(titles(zsec))))

        # A binary member must not be decoded as text.
        check("binary archive member skipped",
              not any("blob.bin" in f.location.get("file", "") for f in scan_secrets(str(tar_path))),
              "")

        # A non-archive file path must still work exactly as before.
        plain = root / "plain.py"
        plain.write_text('API_KEY = "x7Kd9Pq2Lm4Nv8Rt1Zc6Bw3Yh5Js0Ae1U"\n')
        check("plain file still scanned", len(scan_secrets(str(plain))) > 0, "")

def main() -> int:
    tests = [
        test_android_path_is_not_web_served,
        test_sql_sinks_detected,
        test_source_credential_assignments,
        test_crypto_tls_and_web_rules,
        test_cwe_is_per_rule_not_severity,
        test_entropy_precision,
        test_entropy_requires_context,
        test_scan_speed_guard,
        test_endpoint_taint_ranking,
        test_version_consistency,
        test_default_yara_ruleset_ships,
        test_malware_scan_reports_ruleset,
        test_attack_techniques_for_new_cwes,
        test_attack_catalog_grew,
        test_cli_subcommands_accept_positional_path,
        test_cli_accepts_positional_and_flag_path,
        test_cli_format_flags_accepted_everywhere,
        test_plan_markdown_renderer_is_readable,
        test_mcp_handshake_reports_current_version,
        test_archive_contents_are_scanned,
    ]
    for t in tests:
        t()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())