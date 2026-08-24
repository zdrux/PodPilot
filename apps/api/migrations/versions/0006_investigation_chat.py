"""Add durable investigation chat messages.

Revision ID: 0006_investigation_chat
Revises: 0005_diagnostic_checks
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_investigation_chat"
down_revision: str | None = "0005_diagnostic_checks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "chat_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=253), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("answer_mode", sa.String(length=32), nullable=True),
        sa.Column("citations_json", sa.Text(), nullable=False),
        sa.Column("tool_intent_json", sa.Text(), nullable=True),
        sa.Column("provider_status", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_chat_messages_investigation_id", "chat_messages", ["investigation_id"])
    op.create_index("ix_chat_messages_created_at", "chat_messages", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_chat_messages_created_at", table_name="chat_messages")
    op.drop_index("ix_chat_messages_investigation_id", table_name="chat_messages")
    op.drop_table("chat_messages")
