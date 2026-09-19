"""Dangerous code pattern scanning (SAST-lite), language aware, dependency free."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields as dataclass_fields
from pathlib import Path

from ..core import limits
from ..core.findings import Finding, make_id
from ..feeds import rules as _rules_feed
from .flow import analyze_text
from .flow import rules_hash as _flow_rules_hash

MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 20000
MAX_FINDINGS = 800
MAX_RULE_MATCHES = 10
MAX_FILE_FINDINGS = 200

CACHE_DIR = Path(os.environ.get("GRIM_CACHE", Path.home() / ".cache" / "grim")) / "code"
CACHE_MAX_ENTRIES = 50000
_FINDING_FIELDS = {f.name for f in dataclass_fields(Finding)}
_FINDING_FIELDS.discard("severity_rank")

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", ".next", ".nuxt", ".cache", "storage/framework",
}

EXT_LANG = {
    ".php": "php",
    ".blade.php": "php",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".vue": "js",
    ".svelte": "js",
    ".py": "python",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".dart": "dart",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".m": "objc",
    ".mm": "objc",
    ".swift": "swift",
    ".scala": "scala",
    ".sc": "scala",
    ".groovy": "groovy",
    ".gradle": "groovy",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".lua": "lua",
    ".pl": "perl",
    ".pm": "perl",
    ".r": "r",
    ".jl": "julia",
    ".nim": "nim",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".tf": "hcl",
    ".tfvars": "hcl",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".hs": "haskell",
}

# (id, regex, severity, title, description, remediation, languages)
RULES: list[tuple[str, re.Pattern, str, str, str, str, set[str]]] = [
    (
        "php-client-mimes",
        re.compile(r"mimes\s*:\s*[^,\n]*\$(?:request|_GET|_POST|_REQUEST)"),
        "critical",
        "Upload validation uses a request-controlled file-type list",
        "The allowed file types come from the request itself, so an attacker can allow .php or any type, enabling arbitrary file upload and remote code execution.",
        "Use a fixed server-side list, e.g. 'required|file|mimes:jpg,jpeg,png,gif,webp|max:5120'.",
        {"php"},
    ),
    (
        "php-client-extension",
        re.compile(r"getClientOriginalExtension\s*\(\s*\)"),
        "medium",
        "Stored filename built from client-supplied extension",
        "The extension is taken from the uploaded file name as sent by the client. Combine with a public storage path and this becomes arbitrary upload.",
        "Derive the extension from the validated MIME type, not the client filename.",
        {"php"},
    ),
    (
        "php-move-upload",
        re.compile(r"move_uploaded_file\s*\("),
        "low",
        "Raw upload move (review destination and validation)",
        "move_uploaded_file into a web-served path is the classic RCE chain when validation is weak.",
        "Ensure server-side type validation and a non-executable storage location.",
        {"php"},
    ),
    (
        "php-eval",
        re.compile(r"\beval\s*\("),
        "high",
        "eval() usage",
        "eval executes arbitrary PHP and is a top webshell/backdoor indicator.",
        "Remove eval; never accept evaluated code from input.",
        {"php"},
    ),
    (
        "php-base64-decode",
        re.compile(r"\bbase64_decode\s*\("),
        "medium",
        "base64_decode() usage",
        "Common in obfuscated malware and dynamic code loading.",
        "Verify purpose; remove dynamic decoding of stored or input data when possible.",
        {"php"},
    ),
    (
        "php-request-exec",
        re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)\n]*\$(?:_GET|_POST|_REQUEST|request)"),
        "critical",
        "Command execution fed by request input",
        "Direct OS command execution from user input allows full server compromise.",
        "Never pass request data to shell functions; use native APIs with strict validation.",
        {"php"},
    ),
    (
        "php-exec",
        re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
        "low",
        "Shell execution function (review)",
        "Shell execution is legitimate in some tools but is a key malware behavior.",
        "Confirm necessity; avoid user input; log usage.",
        {"php"},
    ),
    (
        "php-include-request",
        re.compile(r"\b(include|require)(_once)?\s*\(\s*\$(?:_GET|_POST|_REQUEST|request)"),
        "critical",
        "Dynamic include/require from request input (LFI/RFI)",
        "Attacker-controlled include can read local files or execute remote code.",
        "Use static includes and allowlists for any dynamic paths.",
        {"php"},
    ),
    (
        "php-unserialize-input",
        re.compile(r"\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|request)"),
        "high",
        "unserialize() on request input (object injection)",
        "Untrusted deserialization can lead to object injection and RCE.",
        "Use JSON and strict validation instead.",
        {"php"},
    ),
    (
        "php-extract-input",
        re.compile(r"\bextract\s*\(\s*\$(?:_GET|_POST|_REQUEST|request)"),
        "high",
        "extract() on request input",
        "extract() can overwrite internal variables from user input.",
        "Avoid extract on user data.",
        {"php"},
    ),
    (
        "php-preg-e",
        re.compile(r"preg_replace\s*\([^)]*/[a-z]*e[a-z]*['\"]?\s*,"),
        "high",
        "preg_replace /e modifier (code execution)",
        "The /e modifier evaluates the replacement as PHP. Removed in PHP 7 but still an indicator of legacy vulnerable code.",
        "Use preg_replace_callback.",
        {"php"},
    ),
    (
        "php-raw-sql",
        re.compile(r"(?:DB::raw|whereRaw|orderByRaw|selectRaw)\s*\([^)\n]*\$"),
        "high",
        "Raw SQL expression containing a variable",
        "If the variable can come from a request, this is SQL injection.",
        "Use bindings/query builder parameters.",
        {"php"},
    ),
    (
        "php-ssrf-fetch",
        re.compile(r"file_get_contents\s*\(\s*\$(?:request|_GET|_POST|_REQUEST)"),
        "high",
        "Remote fetch from request input (SSRF)",
        "Attacker can make the server fetch internal or malicious URLs.",
        "Validate URLs against an allowlist; block private ranges.",
        {"php"},
    ),
    (
        "js-eval",
        re.compile(r"\beval\s*\("),
        "high",
        "eval() in JavaScript",
        "eval executes arbitrary code; a common injection sink.",
        "Replace with JSON.parse or explicit logic.",
        {"js"},
    ),
    (
        "js-new-function",
        re.compile(r"\bnew\s+Function\s*\("),
        "high",
        "new Function() (dynamic code execution)",
        "Equivalent of eval; executes strings as code.",
        "Remove dynamic code construction.",
        {"js"},
    ),
    (
        "js-child-process-exec",
        re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\([^)\n]*\$\{"),
        "critical",
        "Shell command built with a template literal",
        "Unvalidated interpolation into a shell command is command injection.",
        "Use execFile/spawn with argument arrays and validated inputs.",
        {"js"},
    ),
    (
        "js-dangerous-html",
        re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*="),
        "medium",
        "Direct HTML injection sink",
        "Unsanitized HTML insertion enables XSS.",
        "Sanitize with DOMPurify or use safe text bindings.",
        {"js"},
    ),
    (
        "js-document-write",
        re.compile(r"document\.write\s*\("),
        "low",
        "document.write usage",
        "Legacy injection-prone API.",
        "Use DOM APIs.",
        {"js"},
    ),
    (
        "py-eval-exec",
        re.compile(r"\b(eval|exec)\s*\("),
        "high",
        "eval/exec in Python",
        "Executes arbitrary code; dangerous with any external input.",
        "Avoid; use safe parsers (ast.literal_eval for data).",
        {"python"},
    ),
    (
        "py-shell-true",
        re.compile(r"subprocess\.\w+\s*\([^)\n]*shell\s*=\s*True"),
        "high",
        "subprocess with shell=True",
        "Shell interpretation enables command injection when inputs are uncontrolled.",
        "Use argument lists and shell=False.",
        {"python"},
    ),
    (
        "py-os-system",
        re.compile(r"\bos\.system\s*\("),
        "medium",
        "os.system usage",
        "Shell invocation; injection risk with any external input.",
        "Prefer subprocess with argument arrays.",
        {"python"},
    ),
    (
        "py-pickle",
        re.compile(r"\bpickle\.loads?\s*\("),
        "medium",
        "pickle deserialization",
        "Pickle can execute code during deserialization.",
        "Use JSON or restricted formats.",
        {"python"},
    ),
    (
        "py-yaml-load",
        re.compile(r"\byaml\.load\s*\((?![^)\n]*SafeLoader)"),
        "medium",
        "yaml.load without SafeLoader",
        "Unsafe YAML loading can instantiate arbitrary Python objects.",
        "Use yaml.safe_load.",
        {"python"},
    ),
    (
        "go-exec-command",
        re.compile(r"\bexec\.Command\s*\([^)]*\"(sh|bash)\"|\bexec\.Command\s*\([^)]*\+"),
        "critical",
        "Process execution with shell or string concatenation",
        "Shell invocation or concatenated command building is command injection prone.",
        "Use argument arrays and validated inputs.",
        {"go"},
    ),
    (
        "go-raw-sql",
        re.compile(r"(?:fmt\.Sprintf|fmt\.Sprintln)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)|db\.(?:Query|Exec)\s*\([^)]*\+"),
        "high",
        "SQL built with string formatting or concatenation",
        "If the interpolated value can come from input, this is SQL injection.",
        "Use parameterized queries.",
        {"go"},
    ),
    (
        "rust-command-sh",
        re.compile(r"Command::new\(\s*\"(sh|bash)\"|\"sh\".*\.arg\(\"\-c\"\)"),
        "critical",
        "Shell command construction",
        "Shell invocation via sh -c is command injection prone.",
        "Use argument arrays and validated inputs.",
        {"rust"},
    ),
    (
        "rust-unsafe-block",
        re.compile(r"\bunsafe\s*\{"),
        "low",
        "Unsafe block usage",
        "Unsafe Rust can bypass memory safety; review any block touching input.",
        "Audit unsafe blocks; avoid on untrusted data.",
        {"rust"},
    ),
    (
        "java-exec",
        re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\"|\bProcessBuilder\s*\([^)]*\+"),
        "critical",
        "Process execution with concatenation",
        "Command building with concatenation is injection prone.",
        "Use argument arrays and validated inputs.",
        {"java", "kotlin"},
    ),
    (
        "java-raw-sql",
        re.compile(r"(?:Statement|PreparedStatement)?\.?\b(?:executeQuery|executeUpdate|execute)\s*\(\s*\"[^)]*\+|\"SELECT.*\"\s*\+"),
        "high",
        "SQL built with string concatenation",
        "Concatenated SQL is injection prone when values come from input.",
        "Use parameterized queries.",
        {"java", "kotlin"},
    ),
    (
        "java-deserialization",
        re.compile(r"ObjectInputStream\b[^)]*\.readObject\s*\(|ObjectMapper\b[^)]*\.enableDefaultTyping\b"),
        "high",
        "Untrusted deserialization",
        "Deserializing untrusted streams can lead to code execution.",
        "Use safe formats and allowlists.",
        {"java", "kotlin"},
    ),
    (
        "csharp-process",
        re.compile(r"Process\.Start\s*\(\s*\"\w+\"\s*,\s*\"[^\"]*\"\s*\+"),
        "high",
        "Process.Start with string concatenation",
        "Concatenated arguments to Process.Start are injection prone.",
        "Use argument lists and validated inputs.",
        {"csharp"},
    ),
    (
        "csharp-raw-sql",
        re.compile(r"(?:SqlCommand|NpgsqlCommand)\b[^;]*\+\s*[\"']"),
        "high",
        "SQL command built with concatenation",
        "Concatenated SQL is injection prone.",
        "Use parameterized queries.",
        {"csharp"},
    ),
    (
        "csharp-xxe",
        re.compile(r"XmlDocument\.Load\s*\(|XmlReader\.Settings\s*\{[^}]*DtdProcessing\s*=\s*Parse"),
        "high",
        "XML parsing with DTD enabled",
        "DTD processing enables XXE when parsing untrusted XML.",
        "Set DtdProcessing to Prohibit and disable external entities.",
        {"csharp"},
    ),
    (
        "ruby-eval",
        re.compile(r"\beval\s*\(|\binstance_eval\b|\bclass_eval\b"),
        "high",
        "Dynamic code execution",
        "eval and friends execute arbitrary Ruby.",
        "Never eval input.",
        {"ruby"},
    ),
    (
        "ruby-shell",
        re.compile(r"\b(system|exec|spawn|`)\s*[(\"]"),
        "high",
        "Shell invocation",
        "Shell execution is injection prone with any external input.",
        "Use argument arrays and validated inputs.",
        {"ruby"},
    ),
    (
        "ruby-raw-sql",
        re.compile(r"\.where\s*\(\s*\"[^\"]*#\{|find_by_sql\s*\(\s*\"[^\"]*#\{"),
        "high",
        "SQL built with string interpolation",
        "Interpolated SQL is injection prone.",
        "Use parameterized queries.",
        {"ruby"},
    ),
    (
        "dart-process",
        re.compile(r"Process\.(run|start)\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\[[^\]]*\$"),
        "high",
        "Process with interpolated arguments",
        "Interpolated arguments to Process are injection prone.",
        "Use validated argument lists.",
        {"dart"},
    ),
    (
        "dart-process-review",
        re.compile(r"\bProcess\.(run|start)\s*\("),
        "low",
        "Process execution (review)",
        "Launching processes with derived arguments is injection prone.",
        "Validate inputs and prefer argument lists.",
        {"dart"},
    ),
    (
        "go-exec-review",
        re.compile(r"\bexec\.Command\s*\(|\bos/exec\b"),
        "low",
        "Process execution (review)",
        "Command execution is injection prone when arguments derive from input.",
        "Use validated argument arrays.",
        {"go"},
    ),
    (
        "csharp-sql-concat",
        re.compile(r"[\"'](?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\+"),
        "high",
        "SQL built with string concatenation",
        "Concatenated SQL is injection prone when values come from input.",
        "Use parameterized queries.",
        {"csharp"},
    ),
    # ---- C / C++ / Objective-C ----
    (
        "c-unbounded-copy",
        re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf|gets)\s*\("),
        "high",
        "Unbounded C string operation",
        "strcpy, strcat, sprintf, and gets do not bounds check; classic buffer overflow.",
        "Use snprintf, strlcpy, or a length bounded API.",
        {"c", "cpp"},
    ),
    (
        "c-command-exec",
        re.compile(r"\b(?:system|popen|execl|execv|execvp|execve)\s*\("),
        "high",
        "Process execution",
        "Shell and process execution are injection prone when arguments derive from input.",
        "Avoid the shell and pass an argument vector to execve.",
        {"c", "cpp"},
    ),
    (
        "c-format-string",
        re.compile(r"\b(?:printf|fprintf|syslog)\s*\(\s*[A-Za-z_]\w*\s*[,)]"),
        "medium",
        "Potential format string",
        "Passing a variable directly as a format string can leak or overwrite memory.",
        'Use a literal format, for example printf("%s", var).',
        {"c", "cpp"},
    ),
    (
        "objc-process",
        re.compile(r"\bNSTask\b|\bposix_spawn\b"),
        "medium",
        "Process execution (Objective-C)",
        "Launching processes from user data is injection prone.",
        "Validate inputs and pass argument arrays.",
        {"objc"},
    ),
    # ---- Swift ----
    (
        "swift-process",
        re.compile(r"\b(?:Process|NSTask)\s*\("),
        "medium",
        "Process execution (Swift)",
        "Process/NSTask with untrusted arguments can execute arbitrary commands.",
        "Validate inputs and prefer argument arrays.",
        {"swift"},
    ),
    # ---- Scala ----
    (
        "scala-runtime-exec",
        re.compile(r"getRuntime\s*\(\s*\)\s*\.\s*exec|\bscala\.sys\.process\b|(?:^|[^.\w])Process\s*\("),
        "high",
        "Command execution (Scala)",
        "Runtime.exec and scala.sys.process execute commands from untrusted input.",
        "Validate inputs and avoid the shell.",
        {"scala"},
    ),
    (
        "scala-ssrf",
        re.compile(r"Source\s*\.\s*fromURL\s*\("),
        "medium",
        "Outbound request (Scala)",
        "Fetching a user controlled URL enables server side request forgery.",
        "Validate and allowlist URLs.",
        {"scala"},
    ),
    # ---- Groovy ----
    (
        "groovy-eval",
        re.compile(r"\bGroovyShell\b|\bEval\s*\.\s*(?:me|x)\s*\(|\bevaluate\s*\("),
        "high",
        "Dynamic Groovy execution",
        "Evaluating untrusted strings executes arbitrary code.",
        "Avoid eval and use a safe parser.",
        {"groovy"},
    ),
    (
        "groovy-exec",
        re.compile(r"\.execute\s*\(\s*['\"]|\bexecute\s*\(\s*['\"]"),
        "high",
        "Command execution (Groovy)",
        "Executing a shell string is injection prone.",
        "Use an argument list and validate input.",
        {"groovy"},
    ),
    # ---- Elixir ----
    (
        "elixir-system",
        re.compile(r"\bSystem\.cmd\s*\(|\b:os\.cmd\s*\("),
        "high",
        "Command execution (Elixir)",
        "System.cmd and :os.cmd execute commands; untrusted input is injection.",
        "Validate inputs and avoid the shell.",
        {"elixir"},
    ),
    (
        "elixir-eval",
        re.compile(r"\bCode\.eval_(?:string|quoted)\s*\("),
        "high",
        "Dynamic code evaluation (Elixir)",
        "Evaluating dynamic code executes arbitrary terms.",
        "Avoid eval and parse data safely.",
        {"elixir"},
    ),
    (
        "elixir-raw-sql",
        re.compile(r"\bRepo\.(?:query|query!)\s*\("),
        "medium",
        "Raw SQL query (Elixir)",
        "Repo.query bypasses Ecto parameterization when values are interpolated.",
        "Use Ecto query macros with parameters.",
        {"elixir"},
    ),
    # ---- Erlang ----
    (
        "erlang-os",
        re.compile(r"\bos:cmd\s*\("),
        "high",
        "Command execution (Erlang)",
        "os:cmd runs a shell command.",
        "Use open_port with an argument list and validate input.",
        {"erlang"},
    ),
    (
        "erlang-binary-to-term",
        re.compile(r"\bbinary_to_term\s*\("),
        "high",
        "Unsafe term deserialization (Erlang)",
        "binary_to_term on untrusted data can exhaust atoms and restore funs.",
        "Use binary_to_term/2 with the safe option.",
        {"erlang"},
    ),
    (
        "erlang-http",
        re.compile(r"\bhttpc:request\s*\("),
        "medium",
        "Outbound HTTP (Erlang)",
        "User controlled URLs enable server side request forgery.",
        "Validate and allowlist URLs.",
        {"erlang"},
    ),
    # ---- Lua ----
    (
        "lua-exec",
        re.compile(r"\b(?:os\.execute|io\.popen)\s*\("),
        "high",
        "Command execution (Lua)",
        "os.execute and io.popen run shell commands.",
        "Validate inputs and avoid the shell.",
        {"lua"},
    ),
    (
        "lua-load",
        re.compile(r"\bloadstring\s*\(|\bload\s*\("),
        "high",
        "Dynamic code load (Lua)",
        "Loading untrusted code executes arbitrary instructions.",
        "Do not load or loadstring untrusted content.",
        {"lua"},
    ),
    # ---- Perl ----
    (
        "perl-exec",
        re.compile(r"\b(?:system|exec)\s*[\s(]|qx\s*[/({]|\bopen\s*\(\s*[A-Za-z_$][^,)]*\|"),
        "high",
        "Shell or process execution (Perl)",
        "system, exec, qx, and piped open run shell commands.",
        "Use the list form and validated arguments.",
        {"perl"},
    ),
    (
        "perl-eval",
        re.compile(r"\beval\s*(?:[\(\{]\s*['\"]|['\"]|\{)"),
        "high",
        "String eval (Perl)",
        "String eval executes arbitrary Perl.",
        "Avoid eval on input.",
        {"perl"},
    ),
    # ---- R ----
    (
        "r-exec",
        re.compile(r"\b(?:system|system2|shell)\s*\("),
        "high",
        "Command execution (R)",
        "system, system2, and shell run OS commands.",
        "Validate inputs and avoid the shell.",
        {"r"},
    ),
    (
        "r-eval-parse",
        re.compile(r"\beval\s*\(\s*parse\s*\("),
        "high",
        "Dynamic code evaluation (R)",
        "eval(parse(...)) executes arbitrary R code.",
        "Avoid eval(parse()) on input.",
        {"r"},
    ),
    # ---- Julia ----
    (
        "julia-run",
        re.compile(r"\brun\s*\(\s*`|\brun\s*\(\s*Cmd"),
        "high",
        "Command execution (Julia)",
        "run with interpolated commands executes arbitrary processes.",
        "Validate inputs and use argument vectors.",
        {"julia"},
    ),
    (
        "julia-eval",
        re.compile(r"\beval\s*\(\s*(?:Meta\.)?parse\s*\("),
        "high",
        "Dynamic code evaluation (Julia)",
        "eval(parse(...)) executes arbitrary code.",
        "Avoid eval on input.",
        {"julia"},
    ),
    # ---- Nim ----
    (
        "nim-exec",
        re.compile(r"\b(?:execProcess|execCmdEx|execCmd|startProcess|staticExec|osproc\.exec)\b"),
        "high",
        "Command execution (Nim)",
        "execProcess and execCmd run shell commands.",
        "Validate inputs and avoid the shell.",
        {"nim"},
    ),
    # ---- PowerShell ----
    (
        "ps-iex",
        re.compile(r"\b(?:Invoke-Expression|iex)\b", re.I),
        "high",
        "Dynamic PowerShell execution",
        "Invoke-Expression runs arbitrary PowerShell.",
        "Avoid iex on external input.",
        {"powershell"},
    ),
    (
        "ps-download",
        re.compile(r"(?:New-Object\s+(?:Net\.)?WebClient|Invoke-WebRequest|DownloadString|DownloadData|DownloadFile)", re.I),
        "high",
        "Download cradle (PowerShell)",
        "Downloading and executing remote content is a common stager.",
        "Avoid remote execution and use signed packages.",
        {"powershell"},
    ),
    (
        "ps-encoded",
        re.compile(r"-EncodedCommand|FromBase64String", re.I),
        "high",
        "Encoded command (PowerShell)",
        "Encoded commands hide intent and are common in stagers.",
        "Decode and review; avoid encoded commands.",
        {"powershell"},
    ),
    (
        "ps-exec",
        re.compile(r"\bStart-Process\b", re.I),
        "medium",
        "Process execution (PowerShell)",
        "Starting a process from untrusted input is injection prone.",
        "Validate inputs.",
        {"powershell"},
    ),
    # ---- Shell ----
    (
        "sh-pipe-shell",
        re.compile(r"(?:curl|wget)[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z)?sh"),
        "critical",
        "Piped shell download",
        "curl or wget piped to a shell executes remote content without verification.",
        "Download, verify a checksum or signature, then run.",
        {"shell"},
    ),
    (
        "sh-eval",
        re.compile(r"\beval\s+"),
        "high",
        "Dynamic shell execution",
        "eval executes arbitrary shell.",
        "Avoid eval on input.",
        {"shell"},
    ),
    (
        "sh-reverse-shell",
        re.compile(r"/dev/(?:tcp|udp)/"),
        "critical",
        "Reverse shell (bash /dev/tcp)",
        "The /dev/tcp trick opens a network socket from a shell.",
        "Remove the file and investigate the host.",
        {"shell"},
    ),
    (
        "sh-netcat",
        re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]{0,40}(?:-e|-c)\b"),
        "high",
        "Netcat command execution",
        "nc -e runs a program over the network.",
        "Remove and investigate.",
        {"shell"},
    ),
    # ---- Terraform / HCL ----
    (
        "tf-remote-exec",
        re.compile(r"provisioner\s+\"(?:remote|local)-exec\""),
        "medium",
        "Provisioner command execution",
        "remote-exec and local-exec run commands on hosts.",
        "Prefer cloud-init or a prebuilt image.",
        {"hcl"},
    ),
    (
        "tf-public-acl",
        re.compile(r"acl\s*=\s*\"public-read(?:-write)?\""),
        "high",
        "Public bucket ACL",
        "Public ACLs expose objects to the internet.",
        "Use private ACLs and signed URLs.",
        {"hcl"},
    ),
    (
        "tf-open-ingress",
        re.compile(r"cidr_blocks\s*=\s*\[[^\]]*\"0\.0\.0\.0/0\""),
        "medium",
        "Security group open to the world",
        "0.0.0.0/0 exposes the port to the internet.",
        "Restrict CIDRs to required ranges.",
        {"hcl"},
    ),
    # ---- Dockerfile ----
    (
        "docker-curl-sh",
        re.compile(r"(?:curl|wget)[^\n]{0,160}\|\s*(?:ba|z)?sh"),
        "high",
        "Piped shell download in image build",
        "Running remote scripts during build is not reproducible or verifiable.",
        "Download, verify a checksum, then run.",
        {"dockerfile"},
    ),
    (
        "docker-add-url",
        re.compile(r"(?im)^\s*ADD\s+https?://"),
        "medium",
        "ADD from a URL",
        "ADD from a URL fetches remote content into the image.",
        "Use COPY of a verified artifact.",
        {"dockerfile"},
    ),
    (
        "docker-secret",
        re.compile(r"(?im)^\s*(?:ARG|ENV)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE)"),
        "high",
        "Secret in build ARG or ENV",
        "Build args and env vars are baked into image layers.",
        "Use build secrets or a runtime secret store.",
        {"dockerfile"},
    ),
    (
        "docker-root",
        re.compile(r"(?im)^\s*USER\s+root\b"),
        "low",
        "Container runs as root",
        "Running as root increases the impact of a compromise.",
        "Create and use an unprivileged user.",
        {"dockerfile"},
    ),
    # ---- Clojure ----
    (
        "clj-eval",
        re.compile(r"\beval\b|\bread-string\b"),
        "medium",
        "Dynamic evaluation (Clojure)",
        "eval and read-string on untrusted data can execute code.",
        "Avoid eval and use data readers.",
        {"clojure"},
    ),
    (
        "clj-shell",
        re.compile(r"clojure\.java\.shell/(?:sh|exec)"),
        "high",
        "Command execution (Clojure)",
        "Shelling out with untrusted input is injection prone.",
        "Validate inputs.",
        {"clojure"},
    ),
    # ---- Haskell ----
    (
        "hs-process",
        re.compile(r"\b(?:callCommand|callProcess|readProcess|readProcessWithExitCode|createProcess|system)\b"),
        "high",
        "Command execution (Haskell)",
        "Launching processes from untrusted input is injection prone.",
        "Validate inputs and avoid the shell.",
        {"haskell"},
    ),
]

IP_URL = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?")
PRIVATE_IP = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)")


def _rules_hash() -> str:
    basis = "".join(f"{rid}|{pat.pattern}|{sev}" for rid, pat, sev, *_ in RULES)
    basis += "|" + _flow_rules_hash() + "|" + _rules_feed.digest()
    return hashlib.sha256(basis.encode("utf-8", "ignore")).hexdigest()[:16]


_overlay_cache: dict = {"mtime": None, "rules": []}


def _overlay_rules() -> list:
    """Compiled feed rules, reloaded when the overlay file changes."""
    p = _rules_feed.cache_path()
    try:
        mtime = p.stat().st_mtime
    except OSError:
        mtime = None
    if mtime != _overlay_cache["mtime"]:
        _overlay_cache["rules"] = _rules_feed.overlay()
        _overlay_cache["mtime"] = mtime
    return _overlay_cache["rules"]


def active_rules() -> list:
    """Built-in rules plus any synced feed rules."""
    return RULES + _overlay_rules()


def _cache_version() -> str:
    from .. import __version__

    return f"{__version__}:{_rules_hash()}"


def _path_key(fp: Path) -> str:
    return os.path.abspath(str(fp))


def _cache_path() -> Path:
    return CACHE_DIR / "findings.json"


def _load_cache() -> dict:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    """Atomically persist the cache so concurrent scans never see a half-written file."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if len(cache) > CACHE_MAX_ENTRIES:
            cache = dict(list(cache.items())[-CACHE_MAX_ENTRIES:])
        tmp = _cache_path().with_name("findings.json.tmp")
        tmp.write_text(json.dumps(cache), encoding="utf-8")
        os.replace(tmp, _cache_path())
    except OSError:
        pass


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def _from_dicts(dicts: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for d in dicts:
        try:
            out.append(Finding(**{k: v for k, v in d.items() if k in _FINDING_FIELDS}))
        except TypeError:
            continue
    return out


def scan_code(
    path: str,
    languages: list[str] | None = None,
    max_files: int | None = None,
    workers: int | None = None,
    use_cache: bool = True,
    stats: dict | None = None,
) -> list[Finding]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    file_limit = max_files if max_files is not None else limits.resolve("GRIM_MAX_FILES", MAX_FILES)
    is_file = p.is_file()
    if is_file:
        candidates = [p]
    else:
        # Collect deterministically (sorted names) up to a hard ceiling, then apply the
        # limit after sorting so coverage does not depend on filesystem walk order.
        if limits.is_unlimited(file_limit):
            ceiling = 2_000_000
        else:
            ceiling = max(file_limit * 5, 200_000, file_limit)
        candidates = _walk(p, ceiling)
    lang_filter = set(languages) if languages else None
    candidates = [f for f in candidates if _lang_of(f) is not None and (not lang_filter or _lang_of(f) in lang_filter)]
    candidates.sort(key=lambda x: str(x))
    files = candidates if limits.is_unlimited(file_limit) else candidates[:file_limit]
    walk_capped = (not is_file) and len(candidates) >= (file_limit * 5 if not limits.is_unlimited(file_limit) else 2_000_000)

    if workers is None:
        workers = min(8, os.cpu_count() or 1)

    cache = _load_cache() if (use_cache and files) else {}
    lock = threading.Lock()
    version = _cache_version()
    start = time.monotonic()
    dl = limits.deadline()

    def task(fp: Path) -> list[Finding]:
        if limits.expired(dl):
            return []
        lang = _lang_of(fp)
        if lang is None:
            return []
        text = _read_text(fp)
        if text is None:
            return []
        key = ""
        if use_cache:
            # Path is part of the key: identical content in two files must not replay
            # one file's findings for the other (the finding carries its path and id).
            key = f"{version}:{_path_key(fp)}:{_hash_text(text)}"
            with lock:
                cached = cache.get(key)
            if cached is not None:
                replay = _from_dicts(cached)
                if all(Path(r.location.get("file", "")) == Path(str(fp)) for r in replay):
                    return replay
        result = _scan_text(text, fp, lang)
        result.extend(analyze_text(text, fp, lang))
        if use_cache and key:
            payload = [f.to_dict() for f in result]
            with lock:
                cache[key] = payload
        return result

    findings: list[Finding] = []
    if workers > 1 and len(files) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(task, files):
                findings.extend(result)
    else:
        for fp in files:
            findings.extend(task(fp))

    if use_cache and files:
        _save_cache(cache)

    reasons: list[str] = []
    if limits.expired(dl):
        reasons.append("time budget reached")
    if not limits.is_unlimited(file_limit) and len(candidates) > len(files):
        reasons.append(f"file limit reached ({file_limit} of {len(candidates)})")
    elif walk_capped:
        reasons.append("file discovery ceiling reached; coverage may be incomplete")
    flow_findings = sum(1 for f in findings if f.engine == "grim-flow")
    if stats is not None:
        stats.update(
            {
                "files_scanned": len(files),
                "findings": len(findings),
                "flow_findings": flow_findings,
                "truncated": bool(reasons),
                "reasons": reasons,
                "elapsed_seconds": limits.elapsed_str(start),
            }
        )
    return findings


def _walk(root: Path, max_files: int) -> list[Path]:
    out: list[Path] = []
    for r, dirs, fnames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(fnames):
            fp = Path(r) / fn
            if fp.is_symlink():
                continue
            if _lang_of(fp):
                out.append(fp)
                if len(out) >= max_files:
                    return out
    return out


def _lang_of(fp: Path) -> str | None:
    name = fp.name.lower()
    if name.endswith(".blade.php"):
        return "php"
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    return EXT_LANG.get(fp.suffix.lower())


def _read_text(fp: Path) -> str | None:
    try:
        if fp.stat().st_size > MAX_FILE_BYTES:
            return None
        return fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _scan_file(fp: Path, lang: str) -> list[Finding]:
    text = _read_text(fp)
    if text is None:
        return []
    return _scan_text(text, fp, lang)


def _scan_text(text: str, fp: Path, lang: str) -> list[Finding]:
    out: list[Finding] = []
    per_rule = limits.resolve("GRIM_MAX_RULE_MATCHES", MAX_RULE_MATCHES)
    per_file = limits.resolve("GRIM_MAX_FILE_FINDINGS", MAX_FILE_FINDINGS)

    for rid, pat, sev, title, desc, fix, langs in active_rules():
        if "all" not in langs and lang not in langs:
            continue
        hits = 0
        for m in pat.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(
                Finding(
                    id=make_id("CODE", f"{rid}@{line}", str(fp)),
                    severity=sev,
                    confidence=0.9 if rid in {"php-client-mimes", "php-request-exec", "php-include-request", "js-child-process-exec"} else 0.7,
                    category="CWE-94" if sev == "critical" else "CWE-20",
                    owasp="A03:2021",
                    title=title,
                    description=desc,
                    location={"file": str(fp), "line": line},
                    evidence=m.group(0)[:160],
                    remediation=fix,
                    engine="grim-codepatterns",
                    tags=["sast", lang],
                )
            )
            hits += 1
            if limits.reached(hits, per_rule) or limits.reached(len(out), per_file):
                break
        if limits.reached(len(out), per_file):
            break

    # hardcoded public IP URLs in code (stager/backdoor indicator)
    ip_hits = 0
    for m in IP_URL.finditer(text):
        ip = m.group(1)
        if PRIVATE_IP.match(ip):
            continue
        line = text[: m.start()].count("\n") + 1
        out.append(
            Finding(
                id=make_id("CODE", f"hardcoded-ip@{line}", f"{fp}:{ip}"),
                severity="medium",
                confidence=0.6,
                category="CWE-912",
                owasp="A08:2021",
                title=f"Hardcoded public IP URL in code: {ip}",
                description="Direct-IP endpoints are uncommon in legitimate app code and frequent in malware/stagers.",
                location={"file": str(fp), "line": line},
                evidence=m.group(0)[:160],
                remediation="Verify the endpoint; use domain names and configuration, not hardcoded IPs.",
                engine="grim-codepatterns",
                tags=["sast", "suspicious"],
            )
        )
        ip_hits += 1
        if limits.reached(ip_hits, per_rule) or limits.reached(len(out), per_file):
            break
    return out
