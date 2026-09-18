"""Planner: turn stack detection into an ordered, explainable audit plan.

The plan is advisory: it tells the agent which tools to run, in what order, and why,
plus which stack-specific checks are most valuable for the target.
"""

from __future__ import annotations

from pathlib import Path

from .detector import detect_stack

# stack keyword -> extra focus note
STACK_NOTES = {
    "php": "PHP: check public upload/writable dirs for executable files and request-driven sinks.",
    "laravel": "Laravel: verify upload validation is server-side (mimes rule), not client-supplied.",
    "node": "Node: check child_process/exec sinks, SSRF, and prototype pollution in request handlers.",
    "nextjs": "Next.js: check route handlers/server actions for unvalidated input and exposed env.",
    "astro": "Astro: check SSR endpoints and that build artifacts do not include secrets.",
    "python": "Python: check eval/exec, subprocess with shell=True, and unsafe deserialization.",
    "go": "Go: check exec.Command with request input and template injection.",
    "ruby": "Ruby: check eval/system/backticks and mass-assignment endpoints.",
    "java": "Java/Kotlin: check deserialization, SpEL/OGNL, and concatenated SQL.",
    "static": "Static site: exposure and drift checks are primary; code SAST has little surface.",
}


def build_plan(path: str, network: bool = True, deep: bool = False) -> dict:
    detect = detect_stack(path)
    p = Path(path)
    stacks = detect.get("stacks", [])
    langs = {s.get("language") for s in stacks}
    frameworks = {s.get("framework") for s in stacks if s.get("framework")}
    is_archive = detect.get("is_archive", False)

    plan: list[dict] = []

    def add(tool: str, priority: str, reason: str) -> None:
        plan.append({"tool": tool, "priority": priority, "reason": reason})

    add("audit_exposure", "first",
        "Archive/web tree: web-executable files, webshells, ELF payloads, exposed .env/backups.")
    add("scan_secrets", "first",
        "Leaked credentials and sensitive files are high-signal and cheap to check.")
    add("scan_code", "second",
        "Static analysis for upload/injection/RCE patterns in application code.")
    add("inventory_endpoints", "second",
        "Map routes and flag unauthenticated input surfaces (web/API apps).")
    if deep:
        add("scan_iocs", "second", "Deep mode: match file hashes against known-bad IoC feeds.")
    if network and (detect.get("lockfiles") or any(s.get("manifest") for s in stacks)):
        add("audit_deps", "third",
            "Known CVEs in dependencies via live OSV.dev advisories.")
    add("sbom", "optional",
        "Emit a CycloneDX/SPDX software bill of materials for the resolved dependencies.")
    add("diff_artifacts", "optional",
        "If a known-good baseline exists, diff it to catch active-compromise drift.")

    notes: list[str] = []
    if is_archive:
        notes.append("Target is an archive; use deep=true to descend into nested archives.")
    for key, note in STACK_NOTES.items():
        if key in langs or key in frameworks:
            notes.append(note)
    if not stacks:
        notes.append("No known manifest detected; exposure, secrets, and IoC checks still apply.")
    if not network:
        notes.append("Network disabled: dependency CVE lookup and feed sync are skipped.")
    if detect.get("web_dirs"):
        notes.append(f"Web-served directories: {', '.join(detect['web_dirs'][:5])}")

    return {
        "target": str(p),
        "is_archive": is_archive,
        "stacks": stacks,
        "web_dirs": detect.get("web_dirs", []),
        "lockfiles": detect.get("lockfiles", []),
        "plan": plan,
        "notes": notes,
        "recommended_order": [step["tool"] for step in plan],
    }
