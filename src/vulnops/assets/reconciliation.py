from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from vulnops.assets.models import AssetAlias


@dataclass
class ReconciliationResult:
    status: Literal["resolved", "ambiguous", "not_found", "candidate"]
    asset_id: str | None
    reason: str


# Namespaces considered strong identity - single alias should resolve
STRONG_NAMESPACES = {
    "arn",
    "cloud_arn",
    "aws_arn",
    "resource_arn",
    "instance_id",
    "uuid",
    "cpe",
    "purl",
}


class AssetService:
    def __init__(self, session: Session):
        self.session = session

    def reconcile_alias(
        self, namespace: str, value: str, organization_id: str | None = None
    ) -> ReconciliationResult:
        """
        Reconcile an alias to a canonical Asset.
        - If no alias found: not_found
        - If exactly one alias: resolved
        - If multiple aliases with same namespace/value: ambiguous (collision requires review)
        Per data-model.md: alias collisions require review rather than last-write-wins.
        IP is treated as observation/alias, not long-lived identity.
        """
        q = self.session.query(AssetAlias).filter(
            AssetAlias.namespace == namespace, AssetAlias.value == value
        )
        if organization_id:
            q = q.filter(AssetAlias.organization_id == organization_id)

        aliases = q.all()

        if not aliases:
            # No match - treat weak namespaces like ip/hostname as candidate/not_found
            if namespace in ("ip", "hostname", "dns"):
                return ReconciliationResult(
                    status="not_found",
                    asset_id=None,
                    reason=f"no asset found for {namespace}={value}",
                )
            return ReconciliationResult(status="not_found", asset_id=None, reason="no alias match")

        if len(aliases) == 1:
            return ReconciliationResult(
                status="resolved",
                asset_id=aliases[0].asset_id,
                reason=f"single match for {namespace}={value}",
            )

        # Multiple matches -> ambiguous collision
        asset_ids = ", ".join(sorted({a.asset_id for a in aliases}))
        return ReconciliationResult(
            status="ambiguous",
            asset_id=None,
            reason=f"ambiguous collision for {namespace}={value} across assets [{asset_ids}]",
        )

    def create_asset(
        self,
        *,
        id: str | None = None,
        name: str,
        type: str = "host",
        organization_id: str,
        criticality: str = "medium",
        environment: str | None = None,
        status: str = "active",
    ):
        from vulnops.assets.models import Asset

        asset = Asset(
            id=id or f"ast_{uuid.uuid4().hex[:8]}",
            name=name,
            type=type,
            status=status,
            organization_id=organization_id,
            criticality=criticality,
            environment=environment,
        )
        self.session.add(asset)
        self.session.commit()
        return asset

    def add_alias(
        self,
        asset_id: str,
        namespace: str,
        value: str,
        organization_id: str,
    ) -> AssetAlias:
        alias = AssetAlias(
            id=f"alias_{uuid.uuid4().hex[:8]}",
            asset_id=asset_id,
            namespace=namespace,
            value=value,
            organization_id=organization_id,
        )
        self.session.add(alias)
        self.session.commit()
        return alias
