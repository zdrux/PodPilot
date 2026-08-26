"""Add the Ask PodPilot cluster registry and knowledge targeting.

Revision ID: 0012_multi_cluster_ask
Revises: 0011_cluster_memory
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_multi_cluster_ask"
down_revision: str | None = "0011_cluster_memory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "clusters",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(253), nullable=False),
        sa.Column("api_url", sa.String(2048), nullable=False),
        sa.Column("credential_key", sa.String(253), nullable=True),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("tls_verify", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(32), nullable=False, server_default="not_tested"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(253), nullable=False),
        sa.Column("updated_by", sa.String(253), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="uq_clusters_name"),
        sa.UniqueConstraint("credential_key", name="uq_clusters_credential_key"),
    )
    op.create_index("ix_clusters_name", "clusters", ["name"], unique=True)
    op.create_index("ix_clusters_is_enabled", "clusters", ["is_enabled"])
    with op.batch_alter_table("adhoc_conversations") as batch:
        batch.add_column(sa.Column(
            "cluster_ids_json", sa.Text(), nullable=False, server_default="[]"
        ))
    with op.batch_alter_table("knowledge_documents") as batch:
        batch.add_column(sa.Column(
            "target_cluster_ids_json", sa.Text(), nullable=False, server_default="[]"
        ))
        batch.add_column(sa.Column(
            "target_tags_json", sa.Text(), nullable=False, server_default="{}"
        ))
    op.execute("""
        UPDATE knowledge_documents
        SET target_cluster_ids_json = CASE
            WHEN cluster_id = '*' THEN '[]'
            ELSE '[\"' || replace(cluster_id, '\"', '') || '\"]'
        END
    """)


def downgrade() -> None:
    with op.batch_alter_table("knowledge_documents") as batch:
        batch.drop_column("target_tags_json")
        batch.drop_column("target_cluster_ids_json")
    with op.batch_alter_table("adhoc_conversations") as batch:
        batch.drop_column("cluster_ids_json")
    op.drop_index("ix_clusters_is_enabled", table_name="clusters")
    op.drop_index("ix_clusters_name", table_name="clusters")
    op.drop_table("clusters")
