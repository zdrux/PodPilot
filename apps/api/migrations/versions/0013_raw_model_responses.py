"""Add opt-in raw model response capture for Ask turns.

Revision ID: 0013_raw_model_responses
Revises: 0012_multi_cluster_ask
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_raw_model_responses"
down_revision: str | None = "0012_multi_cluster_ask"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.add_column(sa.Column(
            "include_raw_response", sa.Boolean(), nullable=False, server_default=sa.false()
        ))
    with op.batch_alter_table("adhoc_messages") as batch:
        batch.add_column(sa.Column(
            "raw_responses_json", sa.Text(), nullable=False, server_default="[]"
        ))


def downgrade() -> None:
    with op.batch_alter_table("adhoc_messages") as batch:
        batch.drop_column("raw_responses_json")
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.drop_column("include_raw_response")
