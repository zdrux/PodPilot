"""Add curated cluster memory and its SQLite FTS5 index.

Revision ID: 0011_cluster_memory
Revises: 0010_adhoc_runs
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_cluster_memory"
down_revision: str | None = "0010_adhoc_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("logical_id", sa.String(36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(253), nullable=False),
        sa.Column("title", sa.String(253), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source", sa.String(512), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("cluster_id", sa.String(253), nullable=False),
        sa.Column("namespace", sa.String(253), nullable=True),
        sa.Column("resource_kind", sa.String(128), nullable=True),
        sa.Column("resource_name", sa.String(253), nullable=True),
        sa.Column("owner", sa.String(253), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("sensitivity", sa.String(32), nullable=False),
        sa.Column("review_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("logical_id", "version", name="uq_knowledge_logical_version"),
    )
    for column in ("logical_id", "created_at", "source_type", "cluster_id", "namespace",
                   "verification_state", "sensitivity", "expires_at", "is_enabled", "is_current"):
        op.create_index(f"ix_knowledge_documents_{column}", "knowledge_documents", [column])
    op.create_table(
        "knowledge_chunks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("document_id", sa.String(36), sa.ForeignKey("knowledge_documents.id"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("heading", sa.String(253), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("token_estimate", sa.Integer(), nullable=False),
    )
    op.create_index("ix_knowledge_chunks_document_id", "knowledge_chunks", ["document_id"])
    op.execute("""
        CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(
            chunk_id UNINDEXED, title, heading, content,
            tokenize = 'porter unicode61'
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS knowledge_chunks_fts")
    op.drop_index("ix_knowledge_chunks_document_id", table_name="knowledge_chunks")
    op.drop_table("knowledge_chunks")
    for column in reversed(("logical_id", "created_at", "source_type", "cluster_id", "namespace",
                            "verification_state", "sensitivity", "expires_at", "is_enabled", "is_current")):
        op.drop_index(f"ix_knowledge_documents_{column}", table_name="knowledge_documents")
    op.drop_table("knowledge_documents")
