"""Add typed remediation action records.

Revision ID: 0004_remediation_actions
Revises: 0003_model_profile
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_remediation_actions"
down_revision: str | None = "0003_model_profile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=253), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("target_namespace", sa.String(length=253), nullable=False),
        sa.Column("target_kind", sa.String(length=64), nullable=False),
        sa.Column("target_name", sa.String(length=253), nullable=False),
        sa.Column("proposal_json", sa.Text(), nullable=False),
        sa.Column("preview_json", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=253), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediation_actions_investigation_id", "remediation_actions", ["investigation_id"])
    op.create_index("ix_remediation_actions_status", "remediation_actions", ["status"])


def downgrade() -> None:
    op.drop_index("ix_remediation_actions_status", table_name="remediation_actions")
    op.drop_index("ix_remediation_actions_investigation_id", table_name="remediation_actions")
    op.drop_table("remediation_actions")
