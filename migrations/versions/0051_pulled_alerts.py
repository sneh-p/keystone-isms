"""pulled alerts: alert sources linked to an integration

Revision ID: 0051
Revises: 0050
Create Date: 2026-11-21 15:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0051'
down_revision: Union[str, Sequence[str], None] = '0050'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. A plain added column."""
    op.add_column('alert_sources', sa.Column('integration_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('alert_sources', 'integration_id')
