"""Add persisted asynchronous Ask PodPilot runs.

Revision ID: 0010_adhoc_runs
Revises: 0009_model_registry
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_adhoc_runs"
down_revision: str | None = "0009_model_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "adhoc_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.String(36),
            sa.ForeignKey("adhoc_conversations.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(253), nullable=False),
        sa.Column("message_text", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("phase", sa.String(64), nullable=False, server_default="queued"),
        sa.Column("progress_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("assistant_message_id", sa.String(36), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
    )
    op.create_index("ix_adhoc_runs_conversation_id", "adhoc_runs", ["conversation_id"])
    op.create_index("ix_adhoc_runs_created_at", "adhoc_runs", ["created_at"])
    op.create_index("ix_adhoc_runs_created_by", "adhoc_runs", ["created_by"])
    op.create_index("ix_adhoc_runs_status", "adhoc_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_adhoc_runs_status", table_name="adhoc_runs")
    op.drop_index("ix_adhoc_runs_created_by", table_name="adhoc_runs")
    op.drop_index("ix_adhoc_runs_created_at", table_name="adhoc_runs")
    op.drop_index("ix_adhoc_runs_conversation_id", table_name="adhoc_runs")
    op.drop_table("adhoc_runs")
