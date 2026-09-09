"""VEX statement lookup via Vulnerability-Lookup (best-effort enrichment).

VEX statements feed match policy as review evidence: an ``affected``
statement corroborates a match, ``not_affected`` suppresses it. Failures are
reported to the caller (which degrades to no VEX input) and never block
matching. See ADR 0002 and the M2 slices design.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("vulnops.intelligence.vex")

# A wrong "not_affected" hides a real vulnerability, so an "affected"
# statement always wins when both appear.
_STATUS_PRIORITY = ("affected", "not_affected")


class VexClient:
    """Query Vulnerability-Lookup for VEX statements about a CVE."""

    def __init__(self, base_url: str, http_client: Any = None):
        self.base_url = base_url.rstrip("/")
        self.http_client = http_client

    def get_status(self, cve_id: str) -> str | None:
        """Return the governing VEX status for a CVE, or None.

        Raises on network/parsing errors — callers wrap best-effort.
        """
        client = self.http_client or _make_client()
        try:
            resp = client.get(
                f"{self.base_url}/api/vex/{cve_id}", headers={"accept": "application/json"}
            )
            resp.raise_for_status()
            payload = resp.json()
        finally:
            if self.http_client is None:
                client.close()
        statements = payload.get("statements") or []
        found: dict[str, dict] = {}
        for statement in statements:
            status = str(statement.get("status") or "").strip().lower()
            if status in _STATUS_PRIORITY and status not in found:
                found[status] = statement
        for status in _STATUS_PRIORITY:
            if status in found:
                logger.info(
                    "VEX status %s for %s (source=%s)",
                    status,
                    cve_id,
                    found[status].get("source"),
                )
                return status
        return None


def _make_client() -> Any:
    import httpx

    return httpx.Client(timeout=15)
