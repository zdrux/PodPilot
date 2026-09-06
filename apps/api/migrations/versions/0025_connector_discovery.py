"""Persist latest bounded connector discovery snapshots.

Revision ID: 0025_connector_discovery
Revises: 0024_incident_activity
"""
from alembic import op
import sqlalchemy as sa


revision = "0025_connector_discovery"
down_revision = "0024_incident_activity"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "connector_discoveries",
        sa.Column("connector_id", sa.String(36), sa.ForeignKey("incident_connections.id"), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_by", sa.String(253), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_connector_discoveries_status", "connector_discoveries", ["status"])
    op.create_index("ix_connector_discoveries_updated_at", "connector_discoveries", ["updated_at"])


def downgrade():
    op.drop_table("connector_discoveries")
