"""ai usage: cache write tokens

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-17 09:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0031'
down_revision: Union[str, Sequence[str], None] = '0030'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Plain add_column (no batch rebuild): ai_usage references users.
    op.add_column('ai_usage', sa.Column('cache_write_tokens', sa.Integer(), server_default='0', nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('ai_usage') as batch_op:
        batch_op.drop_column('cache_write_tokens')
