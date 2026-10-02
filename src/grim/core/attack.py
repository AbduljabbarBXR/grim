"""MITRE ATT&CK tagging for GRIM findings.

Maps finding signals (tags, category, title) to ATT&CK technique IDs so reports can
be correlated with threat-intel tooling. Pure lookup, no network, no deps.
"""

from __future__ import annotations

from typing import Iterable

from .findings import Finding

# (signal substrings matched against tags/category/title, technique id, name)
# CWE ids are the primary key: they are stable and unambiguous, whereas title
# substrings collide. Title signals are kept as a fallback for engines that do not
# set a precise CWE, and are ordered after the CWE rules so a finding with a real
# weakness class is not labelled by an incidental word in its title.
RULES: list[tuple[tuple[str, ...], str, str]] = [
    # ---- precise CWE keyed rules ----
    (("cwe-327",), "T1027.009", "Obfuscated Files or Information: Embedded Payloads"),
    (("cwe-295",), "T1557", "Adversary-in-the-Middle"),
    (("cwe-319",), "T1040", "Network Sniffing"),
    (("cwe-330",), "T1110", "Brute Force"),
    (("cwe-22",), "T1083", "File and Directory Discovery"),
    (("cwe-732",), "T1222.001", "File and Directory Permissions Modification: Windows File and Directory Permissions Modification"),
    (("cwe-377",), "T1222.001", "File and Directory Permissions Modification: Windows File and Directory Permissions Modification"),
    (("cwe-59",), "T1222", "File and Directory Permissions Modification"),
    (("cwe-352",), "T1189", "Drive-by Compromise"),
    (("cwe-942",), "T1189", "Drive-by Compromise"),
    (("cwe-1004",), "T1539", "Steal Web Session Cookie"),
    (("cwe-502",), "T1200", "Hardware Additions"),
    (("cwe-1336",), "T1059", "Command and Scripting Interpreter"),
    (("cwe-611",), "T1190", "Exploit Public-Facing Application"),
    (("cwe-617",), "T1078", "Valid Accounts"),
    (("cwe-321",), "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (("cwe-329",), "T1600.001", "Weaken Encryption: Reduce Key Space"),
    (("cwe-94",), "T1059", "Command and Scripting Interpreter"),
    (("cwe-89",), "T1190", "Exploit Public-Facing Application"),
    (("cwe-78",), "T1059", "Command and Scripting Interpreter"),
    (("cwe-306",), "T1190", "Exploit Public-Facing Application"),
    (("cwe-862",), "T1190", "Exploit Public-Facing Application"),
    # ---- title/tag keyed rules ----
    (("webshell", "web shell", "webshell indicator"), "T1505.003", "Server Software Component: Web Shell"),
    (("polyglot",), "T1505.003", "Server Software Component: Web Shell"),
    (("upload", "cwe-434", "arbitrary file"), "T1190", "Exploit Public-Facing Application"),
    (("elf", "native executable", "pe binary"), "T1204.002", "User Execution: Malicious File"),
    (("stager", "downloader", "payload host", "c2"), "T1105", "Ingress Tool Transfer"),
    (("piped shell", "curl | sh"), "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (("reverse shell", "netcat"), "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (("shell", "command execution", "exec.command", "child_process", "process.start"), "T1059", "Command and Scripting Interpreter"),
    (("eval", "dynamic code execution", "deserialization"), "T1059", "Command and Scripting Interpreter"),
    (("sql", "injection"), "T1190", "Exploit Public-Facing Application"),
    (("xxe", "xml parsing"), "T1190", "Exploit Public-Facing Application"),
    (("template injection",), "T1059", "Command and Scripting Interpreter"),
    (("secrets", "cwe-798", "credential", "environment file", ".env"), "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (("dependencies", "supply chain", "cwe-1395"), "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain"),
    (("drift", "changed"), "T1565.001", "Data Manipulation: Stored Data Manipulation"),
    (("removed", "cleanup"), "T1070.004", "Indicator Removal: File Deletion"),
    (("encoded", "obfuscat", "gzinflate", "str_rot13"), "T1027", "Obfuscated Files or Information"),
    (("miner", "resource hijack"), "T1496", "Resource Hijacking"),
    (("ransomware", "shadow"), "T1486", "Data Encrypted for Impact"),
    (("persistence", "cron", "systemd"), "T1053.003", "Scheduled Task/Job: Cron"),
    (("keylogger", "keypress", "credential capture"), "T1056.001", "Input Capture: Keylogging"),
    (("cwe-532",), "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (("backup", "cwe-530", "dump"), "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (("exposed .git", "vcs", "cwe-538"), "T1213", "Data from Information Repositories"),
    (("ioc", "known malware"), "T1204.002", "User Execution: Malicious File"),
    (("hardcoded-ip", "suspicious"), "T1071.001", "Application Layer Protocol: Web Protocols"),
]


def techniques_for(finding: Finding) -> list[tuple[str, str]]:
    """Return ordered, de-duplicated (id, name) techniques for a finding."""
    haystack = " ".join(
        [finding.category.lower(), finding.title.lower(), " ".join(finding.tags).lower()]
    )
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for signals, tid, name in RULES:
        if tid in seen:
            continue
        if any(sig in haystack for sig in signals):
            seen.add(tid)
            out.append((tid, name))
    return out


def enrich_one(finding: Finding) -> Finding:
    for tid, _name in techniques_for(finding):
        if tid not in finding.mitre:
            finding.mitre.append(tid)
        tag = f"attack:{tid}"
        if tag not in finding.tags:
            finding.tags.append(tag)
    return finding


def enrich(findings: Iterable[Finding]) -> list[Finding]:
    """In-place MITRE tagging; returns the list for convenience."""
    out = list(findings)
    for f in out:
        enrich_one(f)
    return out


def catalog() -> list[dict[str, str]]:
    """All techniques GRIM can emit, for documentation/discovery."""
    seen: dict[str, str] = {}
    for _signals, tid, name in RULES:
        seen.setdefault(tid, name)
    return [{"id": k, "name": v} for k, v in sorted(seen.items())]
