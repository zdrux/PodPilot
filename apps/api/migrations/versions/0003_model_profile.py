"""Add the singleton model provider profile.

Revision ID: 0003_model_profile
Revises: 0002_alert_investigations
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_model_profile"
down_revision: str | None = "0002_alert_investigations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "model_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("provider_label", sa.String(length=100), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("chat_model", sa.String(length=253), nullable=False),
        sa.Column("embedding_model", sa.String(length=253), nullable=True),
        sa.Column("timeout_seconds", sa.Float(), nullable=False),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("capabilities_json", sa.Text(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_probe_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=253), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("model_profiles")
