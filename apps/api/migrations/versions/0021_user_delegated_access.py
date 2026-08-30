"""Make Ask clusters user-delegated and add private registry ownership.

Revision ID: 0021_user_delegated_access
Revises: 0020_delegated_sessions
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_user_delegated_access"
down_revision: str | None = "0020_delegated_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("clusters") as batch:
        batch.add_column(sa.Column(
            "environment", sa.String(length=64), nullable=False, server_default="default"
        ))
        batch.add_column(sa.Column(
            "visibility", sa.String(length=16), nullable=False, server_default="shared"
        ))
        batch.add_column(sa.Column("owner", sa.String(length=253), nullable=True))
        batch.create_index("ix_clusters_environment", ["environment"])
        batch.create_index("ix_clusters_visibility", ["visibility"])
        batch.create_index("ix_clusters_owner", ["owner"])
    op.execute("UPDATE clusters SET credential_key = NULL")
    op.execute("""
        UPDATE adhoc_conversations
        SET execution_mode = CASE
            WHEN execution_mode = 'delegated_unrestricted' THEN 'action'
            ELSE 'read_only'
        END
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE adhoc_conversations
        SET execution_mode = CASE
            WHEN execution_mode = 'action' THEN 'delegated_unrestricted'
            ELSE 'managed_guarded'
        END
    """)
    with op.batch_alter_table("clusters") as batch:
        batch.drop_index("ix_clusters_owner")
        batch.drop_index("ix_clusters_visibility")
        batch.drop_index("ix_clusters_environment")
        batch.drop_column("owner")
        batch.drop_column("visibility")
        batch.drop_column("environment")
