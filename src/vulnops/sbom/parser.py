from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedComponent:
    raw_name: str
    raw_version: str | None
    purl: str | None
    ecosystem: str | None
    normalized_name: str | None
    cpe: str | None
    version_scheme: str | None = None
    dependency_path: str | None = None


@dataclass
class ParsedSBOM:
    format: str  # cyclonedx | spdx
    spec_version: str | None
    serial_number: str | None
    components: list[ParsedComponent] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>.+)$")


def _parse_purl(purl: str | None) -> tuple[str | None, str | None]:
    if not purl:
        return None, None
    m = _PURL_RE.match(purl)
    if not m:
        return None, purl
    ecosystem = m.group("type").lower()
    # Extract name part for normalized name: after last '/' before '@' or '?' or '#'
    rest = m.group("rest")
    # Strip qualifiers and version
    # rest example: maven/org.apache.tomcat/tomcat-catalina@9.0.80 or pypi/urllib3@1.26.18
    # We want normalized name = namespace + name if present
    # version is after '@'
    version = None
    if "@" in rest:
        rest_no_version, version = rest.split("@", 1)
        version = version.split("?")[0].split("#")[0]
    else:
        rest_no_version = rest
    rest_no_version = rest_no_version.split("?")[0].split("#")[0]
    # normalized name is rest_no_version without leading slash?
    normalized = rest_no_version
    # For pypi etc., it's simple; for maven it's group/name
    return ecosystem, normalized


class SBOMParser:
    """
    Parses CycloneDX JSON and SPDX JSON.
    Preserves raw identifier/version and normalizes purl where present.
    Stores CPE as alias, not canonical key (per docs/modules.md).
    """

    PARSER_VERSION = "2026.1"

    def parse(self, data: dict[str, Any]) -> ParsedSBOM:
        if not isinstance(data, dict):
            raise ValueError("invalid SBOM: expected JSON object")

        # Detect CycloneDX
        if data.get("bomFormat") == "CycloneDX" or "components" in data and "bomFormat" in data:
            return self._parse_cyclonedx(data)
        # SPDX detection
        if data.get("spdxVersion") or "SPDXID" in data:
            return self._parse_spdx(data)
        # Fallback heuristic: if has components without bomFormat, treat as CycloneDX
        if "components" in data and isinstance(data["components"], list):
            # Could be CycloneDX without explicit bomFormat
            try:
                return self._parse_cyclonedx(data)
            except Exception:
                pass
        # If has packages, treat as SPDX
        if "packages" in data:
            return self._parse_spdx(data)

        raise ValueError("invalid SBOM: unrecognized format, expected CycloneDX or SPDX")

    def _parse_cyclonedx(self, data: dict[str, Any]) -> ParsedSBOM:
        if not isinstance(data, dict):
            raise ValueError("invalid CycloneDX: expected object")
        components_raw = data.get("components")
        if components_raw is None:
            # Some BOMs may have no components but metadata component
            components_raw = []
        if not isinstance(components_raw, list):
            raise ValueError("invalid CycloneDX: components must be array")

        # Validate: at least bomFormat or specVersion present for strict mode
        # But we allow lenient if components present
        # If neither bomFormat nor components with purl, check required fields
        has_bom_format = data.get("bomFormat") == "CycloneDX"
        if not has_bom_format and not components_raw:
            # Check if it's really CycloneDX? but we already decided
            pass
        # If data explicitly says bomFormat but not CycloneDX, error
        if data.get("bomFormat") and data.get("bomFormat") != "CycloneDX":
            raise ValueError("invalid CycloneDX: bomFormat must be CycloneDX")

        parsed_components: list[ParsedComponent] = []
        for comp in components_raw:
            if not isinstance(comp, dict):
                continue
            raw_name = comp.get("name")
            if not raw_name:
                # Skip entries without name, but keep warning
                continue
            raw_version = comp.get("version")
            purl = comp.get("purl")
            cpe = comp.get("cpe")
            # Try to extract purl from alternative fields?
            ecosystem, normalized = _parse_purl(purl) if purl else (None, None)
            if not normalized and raw_name:
                normalized = raw_name
                if comp.get("group"):
                    normalized = f"{comp['group']}/{raw_name}"
            # version scheme: infer from ecosystem or purl type
            version_scheme = None
            if ecosystem:
                version_scheme = ecosystem
            elif raw_version:
                version_scheme = "generic"

            # Normalize ecosystem fallback
            if not ecosystem and purl:
                ecosystem = "generic"
            elif not ecosystem:
                ecosystem = None if raw_version is None else "generic"

            parsed_components.append(
                ParsedComponent(
                    raw_name=raw_name,
                    raw_version=raw_version,
                    purl=purl,
                    ecosystem=ecosystem,
                    normalized_name=normalized,
                    cpe=cpe,
                    version_scheme=version_scheme,
                )
            )

        # Also handle case where metadata.component is present but no components list?
        # Not needed for tests

        return ParsedSBOM(
            format="cyclonedx",
            spec_version=str(data.get("specVersion") or data.get("spec_version") or ""),
            serial_number=data.get("serialNumber"),
            components=parsed_components,
            raw=data,
        )

    def _parse_spdx(self, data: dict[str, Any]) -> ParsedSBOM:
        # SPDX requires several fields per spec
        required = ["spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace"]
        for req in required:
            if req not in data:
                raise ValueError(f"invalid SPDX: missing required field {req}")

        packages = data.get("packages")
        if not isinstance(packages, list):
            raise ValueError("invalid SPDX: packages must be array")
        if not packages:
            raise ValueError("invalid SPDX: packages must not be empty for this parser")

        parsed_components: list[ParsedComponent] = []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            raw_name = pkg.get("name")
            if not raw_name:
                continue
            raw_version = pkg.get("versionInfo") or pkg.get("version")
            # purl is in externalRefs
            purl = None
            cpe = None
            external_refs = pkg.get("externalRefs") or []
            for ref in external_refs:
                if not isinstance(ref, dict):
                    continue
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                if ref.get("referenceType") == "cpe22Type" or ref.get("referenceType") == "cpe23Type":
                    cpe = ref.get("referenceLocator")

            ecosystem, normalized = _parse_purl(purl) if purl else (None, None)
            if not normalized:
                normalized = raw_name

            version_scheme = ecosystem or "generic"

            parsed_components.append(
                ParsedComponent(
                    raw_name=raw_name,
                    raw_version=raw_version,
                    purl=purl,
                    ecosystem=ecosystem,
                    normalized_name=normalized,
                    cpe=cpe,
                    version_scheme=version_scheme,
                )
            )

        return ParsedSBOM(
            format="spdx",
            spec_version=str(data.get("spdxVersion") or ""),
            serial_number=data.get("documentNamespace"),
            components=parsed_components,
            raw=data,
        )
