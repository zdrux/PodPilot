"""Global model window and editable incident policy."""
from alembic import op
import sqlalchemy as sa

revision = "0027_model_runtime_policy"
down_revision = "0026_incident_ask_handoff"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("model_profiles", sa.Column("context_window_tokens", sa.Integer(), nullable=False, server_default="64000"))
    op.add_column("model_profiles", sa.Column("protocol_reserve_tokens", sa.Integer(), nullable=False, server_default="2048"))
    op.add_column("model_profiles", sa.Column("incident_policy_json", sa.Text(), nullable=False, server_default="{}"))


def downgrade():
    for name in ("incident_policy_json", "protocol_reserve_tokens", "context_window_tokens"):
        op.drop_column("model_profiles", name)
