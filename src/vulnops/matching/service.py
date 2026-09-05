from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from vulnops.matching.versioning import is_version_in_range, normalize_ecosystem, supports_ecosystem
from vulnops.sbom.parser import ParsedComponent


def _strip_purl_identity(purl: str | None) -> str | None:
    """Return canonical purl identity without version/qualifiers, lowercased.

    e.g. pkg:pypi/urllib3@1.26.18 -> pkg:pypi/urllib3
         pkg:deb/debian/openssl@3.0.2?arch=x86_64 -> pkg:deb/debian/openssl
    """
    if not purl:
        return None
    p = purl.split("?")[0].split("#")[0].split("@")[0]
    return p.lower().rstrip("/")


def _package_identity_matches(component: ParsedComponent, pkg: dict) -> bool:
    """Check advisory package refers to the same component identity.

    Compares purl identity first, then normalized/name fallback.
    Returns False when advisory package carries no usable identity
    to avoid false positives from ecosystem-only matches.
    """
    aff_purl = pkg.get("purl")
    aff_name = pkg.get("name")

    if aff_purl and component.purl:
        comp_id = _strip_purl_identity(component.purl)
        aff_id = _strip_purl_identity(aff_purl)
        if comp_id and aff_id:
            return comp_id == aff_id
        return False

    # If advisory has purl but component does not (or vice versa),
    # fall back to name comparison when both names are available.
    comp_name = (component.normalized_name or component.raw_name or "").lower().strip()
    # Component normalized may be "group/name"; also try last segment.
    comp_names = {comp_name}
    if "/" in comp_name:
        comp_names.add(comp_name.split("/")[-1])

    if aff_name:
        aff_n = str(aff_name).lower().strip()
        aff_names = {aff_n}
        if "/" in aff_n:
            aff_names.add(aff_n.split("/")[-1])
        return bool(comp_names & aff_names)

    # No usable advisory identity (no purl, no name): do not match.
    # Ecosystem-only ranges must not create deterministic exposures.
    return False


@dataclass
class MatchExplanation:
    decision: str
    confidence: float
    matcher_version: str
    component_identity: str | None
    vulnerability: str | None
    rules: list[str]
    evidence_refs: list[str]
    limitations: list[str]


@dataclass
class ExposureResult:
    match_class: str  # confirmed|deterministic|corroborated|candidate|not_affected|unsupported|none
    confidence: float
    should_create_case: bool
    case_id: str | None
    matched_rules: list[str]
    limitations: list[str]
    matcher_version: str
    explanation: MatchExplanation | None = None

    # For compatibility with tests expecting exposure.case_id or should_create_case
    @property
    def case(self):
        return self.case_id


class MatchingService:
    """
    Implements matching pipeline per docs/modules.md:5
    Order: scanner-confirmed, VEX, purl range, distribution range, CPE mapping, human review
    """

    MATCHER_VERSION = "2026.1"

    def evaluate(
        self,
        component: ParsedComponent,
        advisory: dict[str, Any],
        asset_context: dict[str, Any] | None = None,
        scanner_evidence: dict[str, Any] | None = None,
        vex_status: str | None = None,
    ) -> ExposureResult:
        asset_context = asset_context or {}
        advisory_id = advisory.get("id") or advisory.get("vulnerability_id") or "unknown"

        # 1. Scanner-confirmed evidence
        if scanner_evidence and scanner_evidence.get("scanner_confirmed"):
            # Valid scanner result with explicit CVE and asset mapping
            return ExposureResult(
                match_class="confirmed",
                confidence=0.99,
                should_create_case=True,
                case_id=f"case_{uuid.uuid4().hex[:8]}",
                matched_rules=["scanner.confirmed", "asset.service-context"],
                limitations=[],
                matcher_version=self.MATCHER_VERSION,
                explanation=MatchExplanation(
                    decision="confirmed",
                    confidence=0.99,
                    matcher_version=self.MATCHER_VERSION,
                    component_identity=component.purl or component.cpe or component.raw_name,
                    vulnerability=advisory_id,
                    rules=["scanner.confirmed"],
                    evidence_refs=[str(scanner_evidence.get("finding_id", "ev_scanner"))],
                    limitations=[],
                ),
            )

        # 2. VEX disposition
        if vex_status:
            if vex_status == "not_affected":
                return ExposureResult(
                    match_class="not_affected",
                    confidence=0.95,
                    should_create_case=False,
                    case_id=None,
                    matched_rules=["vex.not_affected"],
                    limitations=[],
                    matcher_version=self.MATCHER_VERSION,
                )
            if vex_status == "affected":
                return ExposureResult(
                    match_class="confirmed",
                    confidence=0.98,
                    should_create_case=True,
                    case_id=f"case_{uuid.uuid4().hex[:8]}",
                    matched_rules=["vex.affected"],
                    limitations=[],
                    matcher_version=self.MATCHER_VERSION,
                )

        # 3. purl/ecosystem range - deterministic when supported
        if component.purl and component.raw_version:
            # Check if ecosystem supported
            eco = normalize_ecosystem(component.ecosystem)
            if not supports_ecosystem(eco):
                return ExposureResult(
                    match_class="candidate",
                    confidence=0.4,
                    should_create_case=False,
                    case_id=None,
                    matched_rules=["unsupported.ecosystem"],
                    limitations=[f"unsupported version scheme: {component.ecosystem}"],
                    matcher_version=self.MATCHER_VERSION,
                )

            # Try to match against advisory affected ranges
            # Must match canonical package identity first, then version range.
            matched = False
            identity_matched = False
            for aff in advisory.get("affected", []):
                pkg = aff.get("package", {})
                aff_eco = pkg.get("ecosystem")
                # Normalize aff ecosystem for comparison
                if aff_eco:
                    aff_eco_norm = normalize_ecosystem(aff_eco)
                    # If advisory specifies ecosystem, check compatibility
                    if aff_eco_norm != eco and aff_eco_norm != "generic":
                        # Allow pypi vs PyPI mismatch already normalized
                        continue
                # Identity check: purl/name must refer to the same package
                # before any range or explicit version is evaluated.
                if not _package_identity_matches(component, pkg):
                    continue
                identity_matched = True
                # Check ranges
                for rng in aff.get("ranges", []):
                    events = rng.get("events", [])
                    introduced = None
                    fixed = None
                    last_affected = None
                    for ev in events:
                        if "introduced" in ev:
                            introduced = ev["introduced"]
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                        if "lastAffected" in ev:
                            last_affected = ev["lastAffected"]
                    if is_version_in_range(component.raw_version, introduced, fixed, last_affected):
                        matched = True
                        break
                # Also check explicit versions list
                if not matched and component.raw_version in aff.get("versions", []):
                    matched = True
                if matched:
                    break

            if matched:
                return ExposureResult(
                    match_class="deterministic",
                    confidence=0.93,
                    should_create_case=True,
                    case_id=f"case_{uuid.uuid4().hex[:8]}",
                    matched_rules=["osv.purl-range", "asset.service-context"],
                    limitations=[],
                    matcher_version=self.MATCHER_VERSION,
                    explanation=MatchExplanation(
                        decision="deterministic",
                        confidence=0.93,
                        matcher_version=self.MATCHER_VERSION,
                        component_identity=component.purl,
                        vulnerability=advisory_id,
                        rules=["osv.purl-range"],
                        evidence_refs=[component.purl or ""],
                        limitations=[],
                    ),
                )
            else:
                # No identity matched at all: cannot claim not_affected,
                # fall through to candidate (ecosystem-only ranges must not
                # create false exposures or false negatives).
                if not identity_matched:
                    pass
                else:
                    # Explicit not in range => not_affected for this component
                    has_ranges = any(
                        aff.get("ranges") or aff.get("versions")
                        for aff in advisory.get("affected", [])
                    )
                    if has_ranges:
                        return ExposureResult(
                            match_class="not_affected",
                            confidence=0.85,
                            should_create_case=False,
                            case_id=None,
                            matched_rules=["osv.purl-range.not_affected"],
                            limitations=[],
                            matcher_version=self.MATCHER_VERSION,
                        )

        # 4. Distribution/package range - similar to purl but via Wazuh package name
        # For MVP, treat similarly if component has raw_name matching

        # 5. CPE/product mapping - candidate or corroborated only unless reviewed mapping upgrades
        if component.cpe and not component.purl:
            # Name/CPE heuristic
            if asset_context.get("second_signal"):
                return ExposureResult(
                    match_class="corroborated",
                    confidence=0.65,
                    should_create_case=False,
                    case_id=None,
                    matched_rules=["cpe.corroborated", "inventory.second_signal"],
                    limitations=["CPE mapping requires review"],
                    matcher_version=self.MATCHER_VERSION,
                )
            return ExposureResult(
                match_class="candidate",
                confidence=0.35,
                should_create_case=False,
                case_id=None,
                matched_rules=["cpe.candidate"],
                limitations=["CPE/name heuristic only - review required"],
                matcher_version=self.MATCHER_VERSION,
            )

        # Fallback: if we have no purl and no cpe, candidate
        if not component.purl and not component.cpe:
            return ExposureResult(
                match_class="candidate",
                confidence=0.3,
                should_create_case=False,
                case_id=None,
                matched_rules=["name.candidate"],
                limitations=["incomplete version data"],
                matcher_version=self.MATCHER_VERSION,
            )

        # Default fallback
        return ExposureResult(
            match_class="candidate",
            confidence=0.4,
            should_create_case=False,
            case_id=None,
            matched_rules=["candidate.fallback"],
            limitations=["no deterministic match"],
            matcher_version=self.MATCHER_VERSION,
        )
