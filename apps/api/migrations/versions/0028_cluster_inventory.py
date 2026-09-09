"""Delegated technology inventory snapshots."""
from alembic import op
import sqlalchemy as sa

revision = "0028_cluster_inventory"
down_revision = "0027_model_runtime_policy"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("clusters", sa.Column("inventory_json", sa.Text(), nullable=False, server_default="{}"))


def downgrade():
    op.drop_column("clusters", "inventory_json")
