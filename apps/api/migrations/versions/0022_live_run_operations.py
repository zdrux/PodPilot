"""Persist live Ask operation timeline entries.

Revision ID: 0022_live_run_operations
Revises: 0021_user_delegated_access
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_live_run_operations"
down_revision: str | None = "0021_user_delegated_access"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.add_column(sa.Column(
            "operation_json", sa.Text(), nullable=False, server_default="[]"
        ))


def downgrade() -> None:
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.drop_column("operation_json")
