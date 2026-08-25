"""Expand the singleton model profile into a multi-model registry.

Revision ID: 0009_model_registry
Revises: 0008_conversation_management
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_model_registry"
down_revision: str | None = "0008_conversation_management"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch_op:
        batch_op.add_column(sa.Column("api_type", sa.String(32), nullable=False, server_default="responses"))
        batch_op.add_column(sa.Column("credential_key", sa.String(253), nullable=False, server_default="api_key"))
        batch_op.add_column(sa.Column("tls_mode", sa.String(32), nullable=False, server_default="system"))
        batch_op.add_column(sa.Column("custom_ca_pem", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("max_input_tokens", sa.Integer(), nullable=False, server_default="128000"))
        batch_op.add_column(sa.Column("tool_calling_hint", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("vision_hint", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.create_index("ix_model_profiles_is_active", ["is_active"])


def downgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch_op:
        batch_op.drop_index("ix_model_profiles_is_active")
        for name in (
            "is_active", "vision_hint", "tool_calling_hint", "max_input_tokens",
            "custom_ca_pem", "tls_mode", "credential_key", "api_type",
        ):
            batch_op.drop_column(name)
