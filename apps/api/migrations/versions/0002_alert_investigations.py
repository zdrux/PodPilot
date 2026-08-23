"""Add durable alert investigations.

Revision ID: 0002_alert_investigations
Revises: 0001_milestone_one
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_alert_investigations"
down_revision: str | None = "0001_milestone_one"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("alert_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("alert_name", sa.String(length=253), nullable=False),
        sa.Column("alert_snapshot_json", sa.Text(), nullable=False),
        sa.Column("analysis_json", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigations_created_at", "investigations", ["created_at"])
    op.create_index(
        "ix_investigations_alert_fingerprint",
        "investigations",
        ["alert_fingerprint"],
    )


def downgrade() -> None:
    op.drop_index("ix_investigations_alert_fingerprint", table_name="investigations")
    op.drop_index("ix_investigations_created_at", table_name="investigations")
    op.drop_table("investigations")
