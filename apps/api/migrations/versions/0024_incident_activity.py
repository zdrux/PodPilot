"""Persist bounded incident investigation activity.

Revision ID: 0024_incident_activity
Revises: 0023_fleet_incidents
"""
from alembic import op
import sqlalchemy as sa


revision = "0024_incident_activity"
down_revision = "0023_fleet_incidents"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "incident_runs",
        sa.Column("activity_json", sa.Text(), nullable=False, server_default="{}"),
    )


def downgrade():
    op.drop_column("incident_runs", "activity_json")
