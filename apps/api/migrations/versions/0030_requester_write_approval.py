"""Requester approval records; credentials and unredacted bodies remain ephemeral."""
from alembic import op
import sqlalchemy as sa

revision = "0030_requester_write_approval"
down_revision = "0029_model_tool_policy"
branch_labels = None
depends_on = None


def upgrade():
    # Retain historical records, but retire every outstanding legacy preview.
    op.execute("UPDATE remediation_actions SET status='cancelled' WHERE status IN ('preview_ready', 'approved')")
    op.execute("UPDATE investigations SET status='recommendation_ready' WHERE status='awaiting_approval'")
    op.create_table("write_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("adhoc_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("owner", sa.String(253), nullable=False),
        sa.Column("cluster_id", sa.String(36), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("preview_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_write_approvals_run_id", "write_approvals", ["run_id"])


def downgrade():
    op.drop_index("ix_write_approvals_run_id", table_name="write_approvals")
    op.drop_table("write_approvals")
