"""complete actor provenance trace

Revision ID: dc7b340e57d8
Revises: f32ac08783d4
Create Date: 2026-09-06 16:41:46.206402

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "dc7b340e57d8"
down_revision: str | None = "f32ac08783d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column("request_id", sa.String(length=128), nullable=True),
    )
    # Rows written before the authenticated actor boundary retain their raw
    # actor/requester/approver values; only the additive provenance marker is
    # populated for legacy approvals.
    op.execute(
        sa.text(
            "UPDATE risk_decisions "
            "SET approver_provenance = 'legacy_request' "
            "WHERE approver IS NOT NULL AND approver_provenance IS NULL"
        )
    )


def downgrade() -> None:
    op.drop_column("audit_events", "request_id")
