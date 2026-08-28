"""Add optional reasoning effort to model profiles.

Revision ID: 0015_model_reasoning_effort
Revises: 0014_adhoc_followup_actions
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_model_reasoning_effort"
down_revision: str | None = "0014_adhoc_followup_actions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch:
        batch.add_column(sa.Column("reasoning_effort", sa.String(16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch:
        batch.drop_column("reasoning_effort")
