"""GRIM — security audit orchestrator for code, deps, exposure, and active compromise."""

# Single source of truth: the installed distribution metadata. Falls back to the
# literal below when running from a source checkout with nothing installed, and the
# test suite asserts the two never drift apart.
try:  # pragma: no cover - trivial branch
    from importlib.metadata import PackageNotFoundError, version as _dist_version

    try:
        __version__ = _dist_version("grim-mcp")
    except PackageNotFoundError:
        __version__ = "0.6.4"
except ImportError:  # pragma: no cover - Python < 3.8 only
    __version__ = "0.6.4"

__all__ = ["__version__"]