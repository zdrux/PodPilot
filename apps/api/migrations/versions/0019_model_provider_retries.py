"""Add configurable model-provider transient retries.

Revision ID: 0019_model_provider_retries
Revises: 0018_model_temperature
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_model_provider_retries"
down_revision: str | None = "0018_model_temperature"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch:
        batch.add_column(sa.Column(
            "max_retries", sa.Integer(), nullable=False, server_default="3",
        ))


def downgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch:
        batch.drop_column("max_retries")
