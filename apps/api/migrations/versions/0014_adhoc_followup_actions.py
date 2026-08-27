"""Add grounded follow-up action metadata to Ask runs.

Revision ID: 0014_adhoc_followup_actions
Revises: 0013_raw_model_responses
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_adhoc_followup_actions"
down_revision: str | None = "0013_raw_model_responses"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.add_column(sa.Column(
            "followup_action_json", sa.Text(), nullable=False, server_default="{}"
        ))


def downgrade() -> None:
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.drop_column("followup_action_json")
