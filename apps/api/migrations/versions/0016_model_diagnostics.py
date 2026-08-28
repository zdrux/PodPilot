"""Persist bounded model usage and probe diagnostics.

Revision ID: 0016_model_diagnostics
Revises: 0015_model_reasoning_effort
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_model_diagnostics"
down_revision: str | None = "0015_model_reasoning_effort"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch:
        batch.add_column(sa.Column(
            "last_probe_diagnostics_json", sa.Text(), nullable=False, server_default="{}"
        ))
    with op.batch_alter_table("adhoc_messages") as batch:
        batch.add_column(sa.Column(
            "model_diagnostics_json", sa.Text(), nullable=False, server_default="{}"
        ))


def downgrade() -> None:
    with op.batch_alter_table("adhoc_messages") as batch:
        batch.drop_column("model_diagnostics_json")
    with op.batch_alter_table("model_profiles") as batch:
        batch.drop_column("last_probe_diagnostics_json")
