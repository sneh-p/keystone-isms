"""guided tours

Revision ID: 0043
Revises: 0042
Create Date: 2026-11-17 20:43:09.832970

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0043'
down_revision: Union[str, Sequence[str], None] = '0042'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. A new table only: each user's guided-tour state."""
    op.create_table('tour_states',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('tour', sa.String(length=20), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('outcome', sa.String(length=20), nullable=False),
    sa.Column('at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_tour_states_user_id_users')),
    sa.PrimaryKeyConstraint('user_id', 'tour', name=op.f('pk_tour_states'))
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('tour_states')
