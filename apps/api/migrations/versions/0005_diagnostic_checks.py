"""Add persisted investigation diagnostic checks.

Revision ID: 0005_diagnostic_checks
Revises: 0004_remediation_actions
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_diagnostic_checks"
down_revision: str | None = "0004_remediation_actions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "diagnostic_checks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by", sa.String(length=253), nullable=True),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=253), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("input_json", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_diagnostic_checks_investigation_id", "diagnostic_checks", ["investigation_id"])
    op.create_index("ix_diagnostic_checks_status", "diagnostic_checks", ["status"])


def downgrade() -> None:
    op.drop_index("ix_diagnostic_checks_status", table_name="diagnostic_checks")
    op.drop_index("ix_diagnostic_checks_investigation_id", table_name="diagnostic_checks")
    op.drop_table("diagnostic_checks")
