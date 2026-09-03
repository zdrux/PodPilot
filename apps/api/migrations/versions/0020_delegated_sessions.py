"""Add delegated execution sessions and per-cluster custom CAs.

Revision ID: 0020_delegated_sessions
Revises: 0019_model_provider_retries
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_delegated_sessions"
down_revision: str | None = "0019_model_provider_retries"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("clusters") as batch:
        batch.add_column(sa.Column("custom_ca_pem", sa.Text(), nullable=True))
    with op.batch_alter_table("adhoc_conversations") as batch:
        batch.add_column(sa.Column(
            "execution_mode", sa.String(length=32), nullable=False,
            server_default="read_only",
        ))
        batch.add_column(sa.Column("delegated_session_id", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("adhoc_conversations") as batch:
        batch.drop_column("delegated_session_id")
        batch.drop_column("execution_mode")
    with op.batch_alter_table("clusters") as batch:
        batch.drop_column("custom_ca_pem")
