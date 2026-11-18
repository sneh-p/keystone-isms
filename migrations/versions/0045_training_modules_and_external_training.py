"""training modules and external training

Revision ID: 0045
Revises: 0044
Create Date: 2026-11-18 14:45:49.411863

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0045'
down_revision: Union[str, Sequence[str], None] = '0044'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. Two new tables, and a plain add_column on training_assignments (lesson from 0015)."""
    op.create_table('training_modules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=60), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('summary', sa.String(length=300), nullable=False),
    sa.Column('minutes', sa.Integer(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('quiz', sa.JSON(), nullable=False),
    sa.Column('pass_mark', sa.Integer(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('copied_from', sa.String(length=60), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_training_modules')),
    sa.UniqueConstraint('key', name=op.f('uq_training_modules_key'))
    )
    op.create_table('external_trainings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('person_id', sa.Integer(), nullable=False),
    sa.Column('module_key', sa.String(length=60), nullable=True),
    sa.Column('module_version', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('provider', sa.String(length=200), nullable=True),
    sa.Column('completed_on', sa.Date(), nullable=False),
    sa.Column('valid_until', sa.Date(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('attachment_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['attachment_id'], ['attachments.id'], name=op.f('fk_external_trainings_attachment_id_attachments')),
    sa.ForeignKeyConstraint(['person_id'], ['people.id'], name=op.f('fk_external_trainings_person_id_people')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_external_trainings'))
    )
    with op.batch_alter_table('external_trainings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_external_trainings_person_id'), ['person_id'], unique=False)

    op.add_column('training_assignments', sa.Column('active', sa.Boolean(), nullable=True))



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('training_assignments', schema=None) as batch_op:
        batch_op.drop_column('active')

    with op.batch_alter_table('external_trainings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_external_trainings_person_id'))

    op.drop_table('external_trainings')
    op.drop_table('training_modules')
