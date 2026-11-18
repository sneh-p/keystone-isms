"""registers, security reports, access check

Revision ID: 0046
Revises: 0045
Create Date: 2026-11-18 15:58:01.258613

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0046'
down_revision: Union[str, Sequence[str], None] = '0045'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. New tables only."""
    op.create_table('access_check_exemptions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('account', sa.String(length=400), nullable=False),
    sa.Column('note', sa.Text(), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_access_check_exemptions_created_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_access_check_exemptions')),
    sa.UniqueConstraint('account', name=op.f('uq_access_check_exemptions_account'))
    )
    op.create_table('register_entries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('register', sa.String(length=40), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=True),
    sa.Column('person_id', sa.Integer(), nullable=True),
    sa.Column('due_on', sa.Date(), nullable=True),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.Column('decisions', sa.JSON(), nullable=True),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_register_entries_created_by_id_users')),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], name=op.f('fk_register_entries_owner_id_users')),
    sa.ForeignKeyConstraint(['person_id'], ['people.id'], name=op.f('fk_register_entries_person_id_people')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_register_entries')),
    sa.UniqueConstraint('register', 'seq', name=op.f('uq_register_entries_register'))
    )
    with op.batch_alter_table('register_entries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_register_entries_person_id'), ['person_id'], unique=False)
        batch_op.create_index('ix_register_entries_register_status', ['register', 'status'], unique=False)

    op.create_table('security_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('reporter_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('sender', sa.String(length=320), nullable=True),
    sa.Column('subject', sa.String(length=300), nullable=True),
    sa.Column('where', sa.String(length=300), nullable=True),
    sa.Column('clicked', sa.Boolean(), nullable=True),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('outcome', sa.String(length=20), nullable=True),
    sa.Column('reply', sa.Text(), nullable=True),
    sa.Column('triaged_by_id', sa.Integer(), nullable=True),
    sa.Column('triaged_at', sa.DateTime(), nullable=True),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_security_reports_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['reporter_id'], ['users.id'], name=op.f('fk_security_reports_reporter_id_users')),
    sa.ForeignKeyConstraint(['triaged_by_id'], ['users.id'], name=op.f('fk_security_reports_triaged_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_reports'))
    )
    with op.batch_alter_table('security_reports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_security_reports_reporter_id'), ['reporter_id'], unique=False)



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('security_reports', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_security_reports_reporter_id'))

    op.drop_table('security_reports')
    with op.batch_alter_table('register_entries', schema=None) as batch_op:
        batch_op.drop_index('ix_register_entries_register_status')
        batch_op.drop_index(batch_op.f('ix_register_entries_person_id'))

    op.drop_table('register_entries')
    op.drop_table('access_check_exemptions')
