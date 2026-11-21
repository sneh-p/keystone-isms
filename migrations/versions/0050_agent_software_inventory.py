"""agent software inventory

Revision ID: 0050
Revises: 0049
Create Date: 2026-11-21 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0050'
down_revision: Union[str, Sequence[str], None] = '0049'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. Plain added columns."""
    op.add_column('config_targets', sa.Column('software', sa.JSON(), nullable=True))
    op.add_column('config_targets', sa.Column('software_at', sa.DateTime(), nullable=True))
    op.add_column('config_targets', sa.Column('os_release', sa.String(length=60), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('config_targets', 'os_release')
    op.drop_column('config_targets', 'software_at')
    op.drop_column('config_targets', 'software')
