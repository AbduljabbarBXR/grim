"""Exposure and active-compromise scanning for directories and archives.

Single-pass streaming design: archives are read once; content checks read bounded
prefixes from the stream (gzip cannot seek backwards).

Detects: web-executable files in public paths, exposed config/backups, ELF binaries,
polyglot webshells, webshell/stager content indicators.
"""

from __future__ import annotations

import os
import re
import shutil
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..core import limits
from ..core.findings import Finding, make_id

MAX_ENTRIES = 600_000
MAX_CONTENT_READS = 60_000
MAX_FINDINGS = 3_000
READ_LIMIT = 131_072  # 128 KB prefix per file for content checks
MAGIC_LIMIT = 8192
NESTED_MAX_DEPTH = 5
NESTED_MAX_BYTES = 512 * 1024 * 1024
NESTED_MAX_ENTRY_BYTES = 512 * 1024 * 1024
SPILL_CHUNK = 1 << 20  # 1 MB streaming chunk for nested-archive extraction

WEB_SEGMENTS = {
    "public", "public_html", "www", "htdocs", "web", "static", "assets",
    "uploads", "upload", "files", "uploads", "storage", "img", "images", "media",
}
UPLOAD_SEGMENTS = {"uploads", "upload", "uploads", "img", "images", "media", "files", "cache", "tmp"}

SAFE_ROOT_FILES = {
    "index.php", "index.html", "index.htm", ".htaccess", ".user.ini",
    "web.config", "robots.txt", "favicon.ico", "server.php", "404.html",
}
ALLOWED_DOTFILES = {".htaccess", ".user.ini", ".well-known", ".gitkeep"}

EXEC_EXT = {
    ".php": "php", ".phtml": "php", ".phar": "php",
    ".sh": "shell", ".bash": "shell",
    ".pl": "perl", ".py": "python", ".cgi": "cgi", ".rb": "ruby",
}
SKIP_DIRS = {".git", "node_modules", ".cache", ".npm", ".trash", "ea-php-cli"}
SOURCE_SEGMENTS = {
    "vendor", "node_modules", ".git", "resources", "src", "tests", "test",
    "database", "migrations", "routes", "config", "bootstrap",
}

IMAGE_MAGICS = (b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"RIFF", b"BM", b"II*\x00", b"MM\x00*")
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

WEBSHELL_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(rb"\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SESSION)"), "critical",
     "eval on request input", "Webshell-style dynamic execution"),
    (re.compile(rb"(FilesMan|c99shell|r57shell|b374k|indoxploit|alfa\s*shell)", re.I), "critical",
     "Known webshell signature", "Matches a known webshell family"),
    (re.compile(rb"(gzinflate|gzuncompress|str_rot13)\s*\("), "high",
     "Obfuscated payload decode", "Decompression of embedded payload, common in webshells"),
    (re.compile(rb"<form[^>]*>[\s\S]{0,400}?PASSWORD[\s\S]{0,400}?cmd", re.I), "critical",
     "Password-gated command form", "Interactive webshell control panel"),
    (re.compile(rb"\bsetsid\b"), "critical",
     "Detached process execution (stager)", "Downloads/executes payloads detached from the parent process"),
    (re.compile(rb"(uguu\.se|transfer\.sh(?![a-z0-9])|anonfiles|catbox\.moe)"), "high",
     "Payload host reference", "Free file hosts frequently used for malware staging"),
    (re.compile(rb"curl[^\n]{0,160}\|\s*(sudo\s+)?(ba|z)?sh", re.I), "critical",
     "Piped shell download", "curl | sh style remote execution"),
    (re.compile(rb"artifacts of previous malicious infection", re.I), "high",
     "Malware cleaner artifact", "A scanner removed malicious code here previously — treat as compromised"),
    (re.compile(rb"\b(move_uploaded_file|file_put_contents)\s*\([^)]{0,120}\$_(GET|POST|REQUEST|FILES)"), "critical",
     "Attacker-controlled file write", "Writes attacker data to disk — classic webshell dropper"),
]


@dataclass
class Entry:
    path: str
    size: int
    is_dir: bool = False
    is_link: bool = False

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


class Source:
    """Read-only, single-pass source over a directory or archive."""

    label: str = "source"
    error: str | None = None

    def iter_items(self) -> Iterator[tuple[Entry, Callable[[int], bytes]]]:
        """Yield (entry, reader) exactly once per entry, in stream order."""
        raise NotImplementedError

    def iter_entries(self) -> Iterator[Entry]:
        for entry, _reader in self.iter_items():
            yield entry

    def close(self) -> None:
        pass


class DirSource(Source):
    def __init__(self, root: str):
        self.root = Path(root)
        self.label = str(self.root)

    def iter_items(self) -> Iterator[tuple[Entry, Callable[[int], bytes]]]:
        for r, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            relroot = os.path.relpath(r, self.root).replace(os.sep, "/")
            relroot = "" if relroot == "." else relroot
            for d in list(dirs):
                yield Entry(path=f"{relroot}/{d}".lstrip("/"), size=0, is_dir=True), (lambda limit: b"")
            for fn in files:
                fp = Path(r) / fn
                try:
                    st = fp.lstat()
                except OSError:
                    continue
                rel = f"{relroot}/{fn}".lstrip("/")
                if fp.is_symlink():
                    yield Entry(path=rel, size=0, is_link=True), (lambda limit: b"")
                    continue

                def reader(limit: int, _fp: Path = fp) -> bytes:
                    try:
                        with open(_fp, "rb") as fh:
                            return fh.read(limit)
                    except OSError:
                        return b""

                yield Entry(path=rel, size=st.st_size), reader


class ArchiveSource(Source):
    def __init__(self, archive: str):
        self.archive = archive
        self.label = str(archive)
        self._kind = _archive_kind(archive)
        if self._kind is None:
            raise ValueError(f"unsupported archive: {archive}")

    def iter_items(self) -> Iterator[tuple[Entry, Callable[[int], bytes]]]:
        if self._kind == "tar":
            try:
                tf = tarfile.open(self.archive, "r:*")
            except (tarfile.TarError, OSError) as exc:
                self.error = f"unreadable tar archive: {exc}"
                return
            with tf:
                for m in tf:
                    entry = Entry(
                        path=m.name.lstrip("./"),
                        size=m.size,
                        is_dir=m.isdir(),
                        is_link=m.issym() or m.islnk(),
                    )
                    if entry.is_dir or entry.is_link or not m.isfile():
                        yield entry, (lambda limit: b"")
                        continue
                    state = {"f": None, "done": False}

                    def reader(limit: int, _tf: tarfile.TarFile = tf, _m: tarfile.TarInfo = m, _st: dict = state) -> bytes:
                        # Sequential, multi-call reader so consumers can stream in chunks.
                        if _st["done"]:
                            return b""
                        if _st["f"] is None:
                            try:
                                _st["f"] = _tf.extractfile(_m)
                            except (OSError, tarfile.TarError):
                                _st["done"] = True
                                return b""
                            if _st["f"] is None:
                                _st["done"] = True
                                return b""
                        try:
                            data = _st["f"].read(limit)
                        except (OSError, tarfile.TarError):
                            _st["done"] = True
                            return b""
                        if not data:
                            _st["done"] = True
                        return data or b""

                    yield entry, reader
        else:
            try:
                zf = zipfile.ZipFile(self.archive)
            except (zipfile.BadZipFile, OSError) as exc:
                self.error = f"unreadable zip archive: {exc}"
                return
            with zf:
                for info in zf.infolist():
                    entry = Entry(
                        path=info.filename,
                        size=info.file_size,
                        is_dir=info.is_dir(),
                        is_link=False,
                    )
                    if entry.is_dir:
                        yield entry, (lambda limit: b"")
                        continue

                    state = {"f": None, "done": False}

                    def reader(limit: int, _zf: zipfile.ZipFile = zf, _name: str = info.filename, _st: dict = state) -> bytes:
                        if _st["done"]:
                            return b""
                        if _st["f"] is None:
                            try:
                                _st["f"] = _zf.open(_name)
                            except (OSError, zipfile.BadZipFile, KeyError):
                                _st["done"] = True
                                return b""
                        try:
                            data = _st["f"].read(limit)
                        except (OSError, zipfile.BadZipFile):
                            _st["done"] = True
                            return b""
                        if not data:
                            _st["done"] = True
                        return data or b""

                    yield entry, reader


def open_source(
    path: str,
    nested: bool = False,
    max_depth: int | None = None,
    max_bytes: int | None = None,
    max_entry_bytes: int | None = None,
) -> Source:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    if p.is_dir():
        return DirSource(path)
    if _archive_kind(str(path)):
        if nested:
            return DeepArchiveSource(
                path, max_depth=max_depth, max_bytes=max_bytes, max_entry_bytes=max_entry_bytes
            )
        return ArchiveSource(path)
    raise ValueError(f"not a directory or archive: {path}")


def _limit(explicit: int | None, env: str, default: int) -> int:
    if explicit is not None:
        return explicit
    return limits.resolve(env, default)


class _DeepState:
    """Bookkeeping for the nested-archive walk."""

    def __init__(self, tmp_root: Path, max_depth: int, max_bytes: int, max_entry_bytes: int):
        self.tmp_root = tmp_root
        self.max_depth = max_depth
        self.max_bytes = max_bytes
        self.max_entry_bytes = max_entry_bytes
        self.extracted_bytes = 0
        self.nested_archives = 0
        self.depth_capped = 0
        self.budget_capped = 0
        self.oversize_skipped = 0
        self.errors: list[str] = []
        self._spilled: dict[str, Path] = {}

    def remaining(self) -> int | None:
        if limits.is_unlimited(self.max_bytes):
            return None
        return self.max_bytes - self.extracted_bytes

    def stats(self) -> dict:
        return {
            "nested_archives": self.nested_archives,
            "extracted_bytes": self.extracted_bytes,
            "depth_capped": self.depth_capped,
            "budget_capped": self.budget_capped,
            "oversize_skipped": self.oversize_skipped,
            "errors": list(self.errors),
        }


def _file_reader(path: Path) -> Callable[[int], bytes]:
    def reader(limit: int, _p: Path = path) -> bytes:
        try:
            with open(_p, "rb") as fh:
                return fh.read(limit)
        except OSError:
            return b""

    return reader


class DeepArchiveSource(Source):
    """Streams an archive and descends into nested archives without extracting ordinary files.

    The outer archive is read once. Non-archive entries are passed through untouched, so a
    large backup is never truncated by the nested-archive budget. Only inner archives are
    spilled to an isolated temp dir, bounded by a byte budget, a per-archive size cap, and a
    depth limit. Every cap is recorded in ``stats()`` so callers can report truncation.
    """

    def __init__(
        self,
        archive: str,
        max_depth: int | None = None,
        max_bytes: int | None = None,
        max_entry_bytes: int | None = None,
    ):
        self.archive = archive
        self.label = str(archive)
        self._tmp = tempfile.mkdtemp(prefix="grim-arc-")
        self._state = _DeepState(
            Path(self._tmp),
            _limit(max_depth, "GRIM_MAX_ARCHIVE_DEPTH", NESTED_MAX_DEPTH),
            _limit(max_bytes, "GRIM_MAX_ARCHIVE_BYTES", NESTED_MAX_BYTES),
            _limit(max_entry_bytes, "GRIM_MAX_ARCHIVE_ENTRY_BYTES", NESTED_MAX_ENTRY_BYTES),
        )

    def stats(self) -> dict:
        return self._state.stats()

    def iter_items(self) -> Iterator[tuple[Entry, Callable[[int], bytes]]]:
        src = ArchiveSource(self.archive)
        try:
            yield from self._walk(src, "", 0)
        finally:
            if src.error:
                self._state.errors.append(src.error)
            src.close()

    def close(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _walk(
        self, source: Source, prefix: str, depth: int
    ) -> Iterator[tuple[Entry, Callable[[int], bytes]]]:
        for entry, reader in source.iter_items():
            path = f"{prefix}{entry.path}" if prefix else entry.path
            wrapped = Entry(path=path, size=entry.size, is_dir=entry.is_dir, is_link=entry.is_link)
            if entry.is_dir or entry.is_link:
                yield wrapped, reader
                continue
            if _archive_kind(entry.path):
                temp_path = self._spill(entry, reader, path)
                if temp_path is None:
                    # budget/size cap: cannot decode, but still report the file itself
                    yield wrapped, reader
                    continue
                yield Entry(path=path, size=temp_path.stat().st_size), _file_reader(temp_path)
                try:
                    if depth < self._state.max_depth:
                        inner = ArchiveSource(str(temp_path))
                        try:
                            yield from self._walk(inner, path + "/", depth + 1)
                        finally:
                            if inner.error:
                                self._state.errors.append(f"{path}: {inner.error}")
                            inner.close()
                    else:
                        self._state.depth_capped += 1
                finally:
                    # spilled archives stay cached in temp until close(), so a second
                    # traversal (e.g. diff manifest + classify) does not re-extract them
                    pass
                continue
            yield wrapped, reader

    def _spill(self, entry: Entry, reader: Callable[[int], bytes], path: str) -> Path | None:
        """Stream one nested archive to a temp file, bounded by size and byte budgets.

        Memory stays flat regardless of archive size. Results are cached by path so a
        second walk reuses the same temp file instead of consuming the budget twice.
        """
        size = entry.size
        if size <= 0:
            return None
        cached = self._state._spilled.get(path)
        if cached is not None and cached.exists():
            return cached
        if not limits.is_unlimited(self._state.max_entry_bytes) and size > self._state.max_entry_bytes:
            self._state.oversize_skipped += 1
            return None
        remaining = self._state.remaining()
        if remaining is not None and size > remaining:
            self._state.budget_capped += 1
            return None

        target = self._state.tmp_root / f"nested-{len(self._state._spilled)}-{Path(entry.path).name}"
        written = 0
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as out:
                while True:
                    data = reader(SPILL_CHUNK)
                    if not data:
                        break
                    if remaining is not None and written + len(data) > remaining:
                        self._state.budget_capped += 1
                        out.close()
                        target.unlink(missing_ok=True)
                        return None
                    out.write(data)
                    written += len(data)
        except OSError:
            if target.exists():
                target.unlink(missing_ok=True)
            return None
        if written == 0:
            target.unlink(missing_ok=True)
            return None
        self._state.extracted_bytes += written
        self._state.nested_archives += 1
        self._state._spilled[path] = target
        return target


def _safe_rel(name: str) -> str | None:
    """Neutralize path traversal and absolute/drive paths from archive members."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    if not parts:
        return None
    return "/".join(parts)


def audit_exposure(
    path: str,
    deep: bool = False,
    stats: dict | None = None,
    max_findings: int | None = None,
    max_entries: int | None = None,
    max_content_reads: int | None = None,
    max_depth: int | None = None,
    max_archive_bytes: int | None = None,
) -> list[Finding]:
    source = open_source(path, nested=deep, max_depth=max_depth, max_bytes=max_archive_bytes)
    findings: list[Finding] = []
    reasons: list[str] = []
    count = 0
    reads = 0
    read_capped = False
    start = time.monotonic()
    dl = limits.deadline()
    entry_limit = _limit(max_entries, "GRIM_MAX_ENTRIES", MAX_ENTRIES)
    read_limit = _limit(max_content_reads, "GRIM_MAX_CONTENT_READS", MAX_CONTENT_READS)
    finding_limit = _limit(max_findings, "GRIM_MAX_FINDINGS", MAX_FINDINGS)

    try:
        for entry, reader in source.iter_items():
            if limits.expired(dl):
                reasons.append("time budget reached")
                break
            if limits.reached(count, entry_limit):
                reasons.append(f"entry limit reached ({entry_limit})")
                break
            count += 1
            if limits.reached(len(findings), finding_limit):
                reasons.append(f"finding limit reached ({finding_limit})")
                break
            if entry.is_link:
                continue
            if entry.is_dir:
                _check_dir(entry, findings)
                continue
            _check_by_name(entry, findings)
            if entry.size <= 0:
                continue
            if not _in_web_path(entry.path):
                continue
            if limits.reached(reads, read_limit):
                if not read_capped:
                    read_capped = True
                    reasons.append(f"content-read limit reached ({read_limit})")
                continue
            reads += 1
            data = reader(min(READ_LIMIT, entry.size + 1))
            if data:
                _check_content(entry, data, findings)
    finally:
        source.close()

    errors: list[str] = []
    if getattr(source, "error", None):
        errors.append(source.error)
    if deep and isinstance(source, DeepArchiveSource):
        s = source.stats()
        errors.extend(s.get("errors", []))
        if s["depth_capped"]:
            reasons.append("archive nesting depth limit reached")
        if s["budget_capped"]:
            reasons.append("nested-archive byte budget exhausted")
        if s["oversize_skipped"]:
            reasons.append("nested archive exceeded the per-archive size cap")
    for err in errors:
        reasons.append(f"unreadable archive: {err}")

    if stats is not None:
        stats.update(
            {
                "entries": count,
                "content_reads": reads,
                "findings": len(findings),
                "truncated": bool(reasons),
                "reasons": reasons,
                "errors": errors,
                "elapsed_seconds": limits.elapsed_str(start),
            }
        )
        if deep and isinstance(source, DeepArchiveSource):
            stats.update(source.stats())
    return findings


def _in_web_path(path: str) -> bool:
    segs = [s.lower() for s in path.split("/")[:-1]]
    return any(s in WEB_SEGMENTS for s in segs)


# --------------------------------------------------------------------------- rules


def _check_dir(entry: Entry, out: list[Finding]) -> None:
    base = entry.path.rstrip("/").rsplit("/", 1)[-1].lower()
    if base == ".git":
        out.append(
            _mk("critical", "CWE-538", "A05:2021",
                "Exposed .git directory",
                "Version control metadata in a deploy artifact can leak source and credentials (history, remotes).",
                entry.path, f"directory {entry.path}",
                "Remove .git from deploys and block access to it.",
                "grim-exposure", ["exposure", "vcs"])
        )


def _check_by_name(entry: Entry, out: list[Finding]) -> None:
    rel = entry.path
    name = entry.name
    lower = name.lower()
    if not _in_web_path(rel):
        return
    segs = [s.lower() for s in rel.split("/")[:-1]]
    if any(s in SOURCE_SEGMENTS for s in segs):
        return
    in_upload = any(s in UPLOAD_SEGMENTS for s in segs)

    parent_is_web_root = bool(segs) and segs[-1] in WEB_SEGMENTS and name in SAFE_ROOT_FILES
    if parent_is_web_root:
        return

    ext = _ext(lower)
    if ext in EXEC_EXT and entry.size > 0:
        kind = EXEC_EXT[ext]
        if in_upload:
            sev, conf = "critical", 0.95
        elif ext in {".sh", ".bash"}:
            sev, conf = "critical", 0.9
        else:
            return
        out.append(
            _mk(sev, "CWE-434", "A04:2021",
                f"Executable {kind} file in web-served directory",
                "Code files in public paths can be executed or served. Upload folders must never execute scripts.",
                rel, f"{name} ({entry.size} B)",
                "Remove the file; block script execution in this directory; fix upload validation server-side.",
                "grim-exposure", ["exposure", "webshell", kind], confidence=conf)
        )

    if name.startswith(".") and name not in ALLOWED_DOTFILES:
        if lower.startswith(".env"):
            out.append(
                _mk("critical", "CWE-538", "A05:2021",
                    "Environment file inside web path",
                    "Exposes database credentials and API keys if reachable.",
                    rel, name,
                    "Remove from web root; deny access at server level.",
                    "grim-exposure", ["exposure", "secrets"])
            )
        elif lower.endswith((".sql", ".bak", ".old", ".orig", ".save", ".swp", ".tar", ".tar.gz", ".zip", ".7z", ".rar")):
            out.append(
                _mk("high", "CWE-530", "A05:2021",
                    "Backup file in web-served path",
                    "Backups can be downloaded and contain source, credentials, or data.",
                    rel, f"{name} ({entry.size} B)",
                    "Move backups outside web root.",
                    "grim-exposure", ["exposure", "backup"])
            )
    elif lower.endswith((".sql", ".bak", ".old", ".orig", ".save", ".swp", ".dump")):
        out.append(
            _mk("high", "CWE-530", "A05:2021",
                "Backup/dump file in web-served path",
                "Downloadable unless blocked; may contain source or data.",
                rel, f"{name} ({entry.size} B)",
                "Remove/move outside web root.",
                "grim-exposure", ["exposure", "backup"])
        )

    if lower.startswith("error_log") or lower.endswith("error_log"):
        out.append(
            _mk("low", "CWE-532", "A09:2021",
                "Log file in web path",
                "May leak file paths or stack traces to visitors.",
                rel, name,
                "Keep logs outside the web root.",
                "grim-exposure", ["exposure", "logs"])
        )


def _check_content(entry: Entry, data: bytes, out: list[Finding]) -> None:
    head = data[:MAGIC_LIMIT]
    segs = [s.lower() for s in entry.path.split("/")[:-1]]
    in_source = any(s in SOURCE_SEGMENTS for s in segs)

    if not in_source and (head.startswith(ELF_MAGIC) or head.startswith(PE_MAGIC)):
        out.append(
            _mk("critical", "CWE-506", "A08:2021",
                "Native executable in web-served directory",
                "ELF/PE binaries under a web path are almost always malware payloads.",
                entry.path, f"magic: {head[:4]!r} ({entry.size} B)",
                "Quarantine and scan the host for running processes and persistence.",
                "grim-exposure", ["malware", "active-compromise", "elf"])
        )
        return

    images = head.startswith(IMAGE_MAGICS)
    short_tag = re.search(rb"<\?=\s*(\$|eval\b|system\b|assert\b|base64|shell_exec\b|passthru\b|preg_replace\b)", data)
    if images and (b"<?php" in data or short_tag):
        idx = data.find(b"<?php") if b"<?php" in data else short_tag.start()
        out.append(
            _mk("critical", "CWE-506", "A08:2021",
                "Polyglot file: image header with embedded PHP",
                "Disguised webshell: renders as an image but executes as PHP where the server runs scripts.",
                entry.path, f"{head[:10]!r} + php tag at offset {idx}",
                "Quarantine the file; assume prior code execution; clean and rotate credentials.",
                "grim-exposure", ["malware", "active-compromise", "webshell"])
        )
        return

    if not images and b"\x00" not in data[:1024]:
        for pat, sev, title, desc in WEBSHELL_PATTERNS:
            m = pat.search(data)
            if not m:
                continue
            out.append(
                _mk(sev, "CWE-506", "A08:2021",
                    f"Webshell indicator: {title}",
                    desc,
                    entry.path, m.group(0)[:160].decode("utf-8", errors="replace"),
                    "Quarantine the file; investigate access logs around its modification date; rotate credentials.",
                    "grim-exposure", ["malware", "webshell", "active-compromise"])
            )
            break


def _ext(lower_name: str) -> str:
    for ext in EXEC_EXT:
        if lower_name.endswith(ext):
            return ext
    return ""


def _archive_kind(path: str) -> str | None:
    lowered = path.lower()
    if lowered.endswith(".zip"):
        return "zip"
    if lowered.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz")):
        return "tar"
    return None


def _mk(severity: str, category: str, owasp: str, title: str, desc: str,
        path: str, evidence: str, fix: str, engine: str, tags: list[str],
        confidence: float | None = None) -> Finding:
    return Finding(
        id=make_id("EXPOS", title + path, path),
        severity=severity,
        confidence=confidence if confidence is not None else (0.9 if severity == "critical" else 0.8),
        category=category,
        owasp=owasp,
        title=title,
        description=desc,
        location={"file": path},
        evidence=evidence,
        remediation=fix,
        engine=engine,
        tags=tags,
    )
