from __future__ import annotations

from packaging.version import Version, InvalidVersion


SUPPORTED_ECOSYSTEMS = {"pypi", "deb", "maven", "npm", "golang", "generic", "pyPI".lower()}


def _parse_version(v: str) -> Version | str:
    try:
        return Version(v)
    except InvalidVersion:
        return v


def _compare_versions(a: str, b: str) -> int:
    """
    Compare two version strings.
    Returns -1 if a < b, 0 if ==, 1 if >.
    Uses packaging.Version if possible, falls back to lexicographic.
    """
    pa = _parse_version(a)
    pb = _parse_version(b)
    if isinstance(pa, Version) and isinstance(pb, Version):
        if pa < pb:
            return -1
        if pa > pb:
            return 1
        return 0
    # Fallback: string comparison
    if str(pa) < str(pb):
        return -1
    if str(pa) > str(pb):
        return 1
    return 0


def is_version_in_range(version: str, introduced: str | None, fixed: str | None, last_affected: str | None = None) -> bool:
    """
    Determine if version is within OSV range.
    OSV semantics:
    - introduced: first vulnerable version (inclusive)
    - fixed: first fixed version (exclusive)
    - last_affected: last vulnerable version (inclusive)
    If introduced is "0" or None, means from beginning.
    """
    if introduced and introduced != "0":
        if _compare_versions(version, introduced) < 0:
            return False
    if fixed:
        if _compare_versions(version, fixed) >= 0:
            return False
    if last_affected:
        if _compare_versions(version, last_affected) > 0:
            return False
    return True


def supports_ecosystem(ecosystem: str | None) -> bool:
    if not ecosystem:
        return False
    return ecosystem.lower() in SUPPORTED_ECOSYSTEMS


def normalize_ecosystem(ecosystem: str | None) -> str | None:
    if not ecosystem:
        return None
    # OSV uses PyPI, PyPI vs pypi
    lower = ecosystem.lower()
    mapping = {"pypi": "pypi", "pyPI": "pypi", "deb": "deb", "debian": "deb", "maven": "maven", "npm": "npm"}
    return mapping.get(lower, lower)
