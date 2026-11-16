"""trust center framework status (aligned / certified / hidden)

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-16 08:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0010'
down_revision: Union[str, Sequence[str], None] = '0009'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('trust_settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('framework_status', sa.JSON(), server_default=sa.text("'{}'"), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('trust_settings', schema=None) as batch_op:
        batch_op.drop_column('framework_status')
