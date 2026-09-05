from __future__ import annotations

from typing import Any


def evaluate_coverage(method: str, coverage: dict[str, Any] | None) -> tuple[bool, str]:
    """
    Evaluate verification coverage per docs/modules.md:7
    Returns (can_close, reason)
    """
    if not coverage:
        return False, "coverage missing"

    status = coverage.get("status")
    # Failed, partial, or missing coverage never closes
    if status in ("failed", "partial", "incomplete", "error"):
        return False, f"coverage status {status} cannot prove remediation"
    if status not in ("complete", "success", "ok"):
        # Unknown status
        return False, f"unknown coverage status {status}"

    # For scanner verification, need scope_version and freshness?
    if method == "scanner":
        # If status is complete, allow close only if scope_version present
        if not coverage.get("scope_version") and not coverage.get("scope"):
            # But per spec, complete scanner result can close if same target/service etc.
            # For MVP, require scope_version
            return False, "missing scope_version for scanner verification"

    if method == "wazuh_inventory":
        # Require deterministic version mapping and recent observation
        freshness = coverage.get("freshness_seconds")
        if freshness is not None and freshness > 24 * 3600:
            return False, "stale inventory observation"
        # If scope_version present or not, allow if complete
        return True, "wazuh inventory shows fixed version - recent and complete"

    if method == "manual_attestation":
        # Never auto-close without approval path
        return False, "manual attestation requires approval"

    if method == "vex":
        return False, "vex alone requires review"

    # Generic: if coverage complete, allow
    return True, "coverage complete"
