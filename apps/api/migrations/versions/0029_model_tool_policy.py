"""Per-model optional tool availability."""
from alembic import op
import sqlalchemy as sa

revision = "0029_model_tool_policy"
down_revision = "0028_cluster_inventory"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("model_profiles", sa.Column("tool_policy_json", sa.Text(), nullable=False, server_default="{}"))


def downgrade():
    op.drop_column("model_profiles", "tool_policy_json")
