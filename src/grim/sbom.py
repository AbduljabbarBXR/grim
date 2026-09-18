"""Software Bill of Materials generation (CycloneDX 1.5 JSON and SPDX 2.3 JSON).

Reuses the dependency parsers so every ecosystem GRIM understands (npm, PyPI,
Packagist, Go, crates.io, Pub, Maven, NuGet, RubyGems) can be inventoried.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .engines.deps import _collect_packages

_PURL_TYPE = {
    "npm": "npm",
    "PyPI": "pypi",
    "Packagist": "composer",
    "Go": "golang",
    "crates.io": "cargo",
    "Pub": "pub",
    "Maven": "maven",
    "NuGet": "nuget",
    "RubyGems": "gem",
}

# ecosystem -> known license statement is not derivable offline; left UNKNOWN
SPDX_NOASSERTION = "NOASSERTION"


def _purl(ecosystem: str, name: str, version: str) -> str:
    ptype = _PURL_TYPE.get(ecosystem, ecosystem.lower())
    if ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{version}"
    if ecosystem == "npm" and name.startswith("@"):
        scope, pkg = name.split("/", 1) if "/" in name else (name, "")
        return f"pkg:npm/{scope}/{pkg}@{version}"
    return f"pkg:{ptype}/{name}@{version}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def collect_components(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    comps: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for eco, name, version in _collect_packages(p):
        key = (eco, name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        comps.append(
            {
                "ecosystem": eco,
                "name": name,
                "version": version,
                "purl": _purl(eco, name, version),
            }
        )
    comps.sort(key=lambda c: (c["ecosystem"], c["name"].lower(), c["version"]))
    return comps


def cyclonedx(path: str, components: list[dict] | None = None) -> dict:
    comps = components if components is not None else collect_components(path)
    from . import __version__

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": [{"vendor": "GRIM", "name": "grim", "version": __version__}],
            "component": {"type": "application", "name": Path(path).name or str(path)},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": c["purl"],
                "name": c["name"],
                "version": c["version"],
                "purl": c["purl"],
                "scope": "required",
            }
            for c in comps
        ],
    }
    return bom


def spdx(path: str, components: list[dict] | None = None) -> dict:
    comps = components if components is not None else collect_components(path)
    from . import __version__

    namespace = "https://grim.local/spdx/" + uuid.uuid4().hex
    packages = []
    for i, c in enumerate(comps, start=1):
        safe = re.sub(r"[^A-Za-z0-9.\-]", "-", c["name"]) or f"pkg{i}"
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{safe}-{i}",
                "name": c["name"],
                "versionInfo": c["version"],
                "downloadLocation": SPDX_NOASSERTION,
                "filesAnalyzed": False,
                "licenseConcluded": SPDX_NOASSERTION,
                "licenseDeclared": SPDX_NOASSERTION,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c["purl"],
                    }
                ],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": Path(path).name or str(path),
        "documentNamespace": namespace,
        "creationInfo": {
            "created": _now(),
            "creators": [f"Tool: grim-{__version__}"],
        },
        "packages": packages,
    }


def render(path: str, fmt: str = "cyclonedx") -> str:
    fmt = (fmt or "cyclonedx").lower()
    if fmt in ("spdx", "spdx-json"):
        return json.dumps(spdx(path), indent=2)
    return json.dumps(cyclonedx(path), indent=2)
