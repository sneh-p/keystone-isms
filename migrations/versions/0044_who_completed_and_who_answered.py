"""who completed and who answered

Revision ID: 0044
Revises: 0043
Create Date: 2026-11-18 03:42:52.299844

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0044'
down_revision: Union[str, Sequence[str], None] = '0043'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. Plain add_column on existing tables (lesson from 0015), and no foreign key, like 0033 and 0035:
    SQLite can't add one to an existing table without rebuilding it. Both columns hold a user id."""
    op.add_column('corrective_actions', sa.Column('completed_by_id', sa.Integer(), nullable=True))
    op.add_column('audit_requests', sa.Column('provided_by_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('audit_requests', schema=None) as batch_op:
        batch_op.drop_column('provided_by_id')
    with op.batch_alter_table('corrective_actions', schema=None) as batch_op:
        batch_op.drop_column('completed_by_id')
