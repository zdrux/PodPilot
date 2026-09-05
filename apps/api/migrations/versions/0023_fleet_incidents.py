"""Fleet incident response PoC.

Revision ID: 0023_fleet_incidents
Revises: 0022_live_run_operations
"""
from alembic import op
import sqlalchemy as sa

revision = "0023_fleet_incidents"
down_revision = "0022_live_run_operations"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("incident_connections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("name", sa.String(253), nullable=False),
        sa.Column("cluster_id", sa.String(36), sa.ForeignKey("clusters.id")),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False),
        sa.Column("credential_key", sa.String(253), nullable=False),
        sa.Column("webhook_key", sa.String(253)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("fleet_incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("cluster_id", sa.String(36), sa.ForeignKey("clusters.id"), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("incident_connections.id"), nullable=False),
        sa.Column("group_key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("alert_state", sa.String(16), nullable=False),
        sa.Column("alerts_json", sa.Text(), nullable=False),
        sa.Column("limitations_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("incident_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("fleet_incidents.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(253), nullable=False),
        sa.Column("alert_snapshot_json", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("briefing_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)))
    for table, columns in {"fleet_incidents": ["cluster_id", "group_key", "updated_at"],
                           "incident_runs": ["incident_id", "status"]}.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    op.drop_table("incident_runs")
    op.drop_table("fleet_incidents")
    op.drop_table("incident_connections")
