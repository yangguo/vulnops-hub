"""add business services and ownership escalation flag

Revision ID: 7f8b6a1c2d3e
Revises: dc7b340e57d8
Create Date: 2026-09-10

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7f8b6a1c2d3e"
down_revision: str | None = "dc7b340e57d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "business_services",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("owner_team", sa.String(length=128), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_business_service_org", "business_services", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_business_service_org_name",
        "business_services",
        ["organization_id", "name"],
        unique=False,
    )
    op.add_column(
        "remediation_cases",
        sa.Column(
            "ownership_escalated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("remediation_cases", "ownership_escalated")
    op.drop_index("ix_business_service_org_name", table_name="business_services")
    op.drop_index("ix_business_service_org", table_name="business_services")
    op.drop_table("business_services")
