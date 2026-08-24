"""Add standalone ad-hoc cluster conversations.

Revision ID: 0007_adhoc_chat
Revises: 0006_investigation_chat
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_adhoc_chat"
down_revision: str | None = "0006_investigation_chat"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "adhoc_conversations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=253), nullable=False),
        sa.Column("title", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_adhoc_conversations_created_at", "adhoc_conversations", ["created_at"])
    op.create_table(
        "adhoc_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("conversation_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=253), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("answer_mode", sa.String(length=32), nullable=True),
        sa.Column("citations_json", sa.Text(), nullable=False),
        sa.Column("tool_activity_json", sa.Text(), nullable=False),
        sa.Column("provider_status", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(["conversation_id"], ["adhoc_conversations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_adhoc_messages_conversation_id", "adhoc_messages", ["conversation_id"])
    op.create_index("ix_adhoc_messages_created_at", "adhoc_messages", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_adhoc_messages_created_at", table_name="adhoc_messages")
    op.drop_index("ix_adhoc_messages_conversation_id", table_name="adhoc_messages")
    op.drop_table("adhoc_messages")
    op.drop_index("ix_adhoc_conversations_created_at", table_name="adhoc_conversations")
    op.drop_table("adhoc_conversations")
