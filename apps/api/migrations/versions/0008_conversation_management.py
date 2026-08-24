"""Add bounded rolling context for managed ad-hoc conversations.

Revision ID: 0008_conversation_management
Revises: 0007_adhoc_chat
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_conversation_management"
down_revision: str | None = "0007_adhoc_chat"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("adhoc_conversations") as batch_op:
        batch_op.add_column(sa.Column("context_summary", sa.Text(), nullable=False, server_default=""))
        batch_op.add_column(sa.Column(
            "summarized_message_count", sa.Integer(), nullable=False, server_default="0"
        ))


def downgrade() -> None:
    with op.batch_alter_table("adhoc_conversations") as batch_op:
        batch_op.drop_column("summarized_message_count")
        batch_op.drop_column("context_summary")
