"""Personal Copilot conversation selection; credentials remain in volatile memory."""
from alembic import op
import sqlalchemy as sa

revision = "0031_personal_copilot"
down_revision = "0030_requester_write_approval"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("adhoc_conversations", sa.Column("copilot_connection_id", sa.String(128), nullable=True))
    op.add_column("adhoc_conversations", sa.Column("copilot_model", sa.String(253), nullable=True))


def downgrade():
    op.drop_column("adhoc_conversations", "copilot_model")
    op.drop_column("adhoc_conversations", "copilot_connection_id")
