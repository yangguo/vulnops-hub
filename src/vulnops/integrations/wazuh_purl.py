"""Best-effort Package URL derivation from Wazuh syscollector package rows.

Wazuh inventory payloads often omit ``purl`` even when ``format``, ``name``,
and ``version`` are present. We derive a purl only for well-known Linux package
managers when the identity is unambiguous; otherwise we skip and leave matching
to the candidate review path.

Skipped (non-exhaustive): missing name/version, unsupported ``format``, RPM
without a recognizable vendor/distro namespace, empty or placeholder versions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

# Wazuh / syscollector placeholder values that must not become purl versions.
_INVALID_VERSIONS = frozenset({"", "-", "(none)", "unknown", "n/a"})

# RPM vendor strings -> purl namespace segment (distro).
_RPM_VENDOR_NAMESPACE: dict[str, str] = {
    "fedora": "fedora",
    "red hat": "redhat",
    "redhat": "redhat",
    "rhel": "redhat",
    "centos": "centos",
    "rocky": "rocky",
    "almalinux": "almalinux",
    "amazon": "amazon",
    "amzn": "amazon",
    "suse": "suse",
    "opensuse": "opensuse",
    "oracle": "oracle",
}


@dataclass(frozen=True)
class PurlDerivationResult:
    status: str  # present | derived | skipped
    purl: str | None = None
    reason: str | None = None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _deb_namespace(vendor: str | None) -> str:
    if vendor:
        lower = vendor.lower()
        if "ubuntu" in lower:
            return "ubuntu"
        if "debian" in lower:
            return "debian"
    return "debian"


def _rpm_namespace(vendor: str | None) -> str | None:
    if not vendor:
        return None
    lower = vendor.lower()
    for needle, namespace in _RPM_VENDOR_NAMESPACE.items():
        if needle in lower:
            return namespace
    return None


def _encode_purl_name(name: str) -> str:
    """Percent-encode characters that are invalid in a purl name segment."""

    return quote(name, safe="._-+")


def derive_purl_from_wazuh_package(package: dict[str, Any]) -> PurlDerivationResult:
    """Return a derivation outcome without mutating ``package``."""

    existing = _clean(package.get("purl"))
    if existing:
        return PurlDerivationResult(status="present", purl=existing)

    name = _clean(package.get("name"))
    version = _clean(package.get("version"))
    if not name or not version:
        return PurlDerivationResult(status="skipped", reason="missing_name_or_version")
    if version.lower() in _INVALID_VERSIONS:
        return PurlDerivationResult(status="skipped", reason="invalid_version")

    fmt = (_clean(package.get("format")) or "").lower()
    arch = _clean(package.get("architecture"))
    vendor = _clean(package.get("vendor"))

    encoded_name = _encode_purl_name(name)
    encoded_version = quote(version, safe="._-+~")

    base: str | None = None
    skip_reason: str | None = None

    if fmt == "deb":
        namespace = _deb_namespace(vendor)
        base = f"pkg:deb/{namespace}/{encoded_name}@{encoded_version}"
    elif fmt == "apk":
        base = f"pkg:apk/alpine/{encoded_name}@{encoded_version}"
    elif fmt == "rpm":
        namespace = _rpm_namespace(vendor)
        if not namespace:
            skip_reason = "rpm_namespace_unknown"
        else:
            base = f"pkg:rpm/{namespace}/{encoded_name}@{encoded_version}"
    elif fmt:
        skip_reason = f"unsupported_format:{fmt}"
    else:
        skip_reason = "missing_format"

    if not base:
        return PurlDerivationResult(status="skipped", reason=skip_reason)

    if arch:
        purl = f"{base}?arch={quote(arch.lower(), safe='')}"
    else:
        purl = base

    return PurlDerivationResult(status="derived", purl=purl, reason=fmt)


def enrich_wazuh_package(package: dict[str, Any]) -> tuple[dict[str, Any], PurlDerivationResult]:
    """Copy ``package`` and attach a derived ``purl`` when reliable."""

    result = derive_purl_from_wazuh_package(package)
    if result.status == "derived" and result.purl:
        merged = {**package, "purl": result.purl}
        return merged, result
    return dict(package), result
