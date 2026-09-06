"""Persist idempotent incident-to-Ask handoffs.

Revision ID: 0026_incident_ask_handoff
Revises: 0025_connector_discovery
"""
from alembic import op
import sqlalchemy as sa


revision = "0026_incident_ask_handoff"
down_revision = "0025_connector_discovery"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "adhoc_conversations",
        sa.Column("handoff_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "adhoc_conversations",
        sa.Column("handoff_run_id", sa.String(36), nullable=True),
    )
    op.create_index(
        "ix_adhoc_conversations_handoff_run_id",
        "adhoc_conversations",
        ["handoff_run_id"],
    )


def downgrade():
    op.drop_index("ix_adhoc_conversations_handoff_run_id", table_name="adhoc_conversations")
    op.drop_column("adhoc_conversations", "handoff_run_id")
    op.drop_column("adhoc_conversations", "handoff_json")
