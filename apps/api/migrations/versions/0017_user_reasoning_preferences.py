"""Add per-model reasoning choices and persistent user preferences.

Revision ID: 0017_user_reasoning_preferences
Revises: 0016_model_diagnostics
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_user_reasoning_preferences"
down_revision: str | None = "0016_model_diagnostics"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("model_profiles") as batch:
        batch.add_column(sa.Column(
            "reasoning_efforts_json", sa.Text(), nullable=False, server_default="[]"
        ))
    op.execute(
        "UPDATE model_profiles "
        "SET reasoning_efforts_json = '[\"' || reasoning_effort || '\"]' "
        "WHERE reasoning_effort IS NOT NULL"
    )
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.add_column(sa.Column("reasoning_effort", sa.String(16), nullable=True))
    op.create_table(
        "user_model_preferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(253), nullable=False),
        sa.Column("model_profile_id", sa.Integer(), nullable=False),
        sa.Column("reasoning_effort", sa.String(16), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["model_profile_id"], ["model_profiles.id"]),
        sa.UniqueConstraint(
            "username", "model_profile_id", name="uq_user_model_preference"
        ),
    )
    op.create_index(
        "ix_user_model_preferences_username", "user_model_preferences", ["username"]
    )
    op.create_index(
        "ix_user_model_preferences_model_profile_id",
        "user_model_preferences",
        ["model_profile_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_user_model_preferences_model_profile_id",
        table_name="user_model_preferences",
    )
    op.drop_index(
        "ix_user_model_preferences_username", table_name="user_model_preferences"
    )
    op.drop_table("user_model_preferences")
    with op.batch_alter_table("adhoc_runs") as batch:
        batch.drop_column("reasoning_effort")
    with op.batch_alter_table("model_profiles") as batch:
        batch.drop_column("reasoning_efforts_json")
