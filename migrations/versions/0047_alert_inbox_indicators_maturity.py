"""alert inbox, indicators, maturity

Revision ID: 0047
Revises: 0046
Create Date: 2026-11-18 16:27:51.226157

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0047'
down_revision: Union[str, Sequence[str], None] = '0046'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. New tables only."""
    op.create_table('alert_sources',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('kind', sa.String(length=30), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('last_received_at', sa.DateTime(), nullable=True),
    sa.Column('received', sa.Integer(), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_alert_sources_created_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_alert_sources')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_alert_sources_token_hash'))
    )
    op.create_table('indicators',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('metric_key', sa.String(length=60), nullable=True),
    sa.Column('unit', sa.String(length=20), nullable=True),
    sa.Column('higher_is_better', sa.Boolean(), nullable=False),
    sa.Column('amber', sa.Float(), nullable=False),
    sa.Column('red', sa.Float(), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('last_value', sa.Float(), nullable=True),
    sa.Column('last_state', sa.String(length=10), nullable=True),
    sa.Column('last_measured_on', sa.Date(), nullable=True),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_indicators_created_by_id_users')),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], name=op.f('fk_indicators_owner_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_indicators'))
    )
    op.create_table('maturity_assessments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('assessed_on', sa.Date(), nullable=False),
    sa.Column('scores', sa.JSON(), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_maturity_assessments_created_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_maturity_assessments'))
    )
    op.create_table('indicator_values',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('indicator_id', sa.Integer(), nullable=False),
    sa.Column('measured_on', sa.Date(), nullable=False),
    sa.Column('value', sa.Float(), nullable=False),
    sa.Column('source', sa.String(length=10), nullable=False),
    sa.Column('note', sa.String(length=500), nullable=True),
    sa.ForeignKeyConstraint(['indicator_id'], ['indicators.id'], name=op.f('fk_indicator_values_indicator_id_indicators'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_indicator_values')),
    sa.UniqueConstraint('indicator_id', 'measured_on', name=op.f('uq_indicator_values_indicator_id'))
    )
    with op.batch_alter_table('indicator_values', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_indicator_values_indicator_id'), ['indicator_id'], unique=False)

    op.create_table('alerts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source_id', sa.Integer(), nullable=False),
    sa.Column('external_id', sa.String(length=200), nullable=True),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('category', sa.String(length=30), nullable=False),
    sa.Column('host', sa.String(length=253), nullable=True),
    sa.Column('account', sa.String(length=320), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('link', sa.String(length=2000), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('count', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=15), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=True),
    sa.Column('owner_id', sa.Integer(), nullable=True),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('close_reason', sa.String(length=20), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('handled_by_id', sa.Integer(), nullable=True),
    sa.Column('handled_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['handled_by_id'], ['users.id'], name=op.f('fk_alerts_handled_by_id_users')),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_alerts_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], name=op.f('fk_alerts_owner_id_users')),
    sa.ForeignKeyConstraint(['source_id'], ['alert_sources.id'], name=op.f('fk_alerts_source_id_alert_sources'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_alerts')),
    sa.UniqueConstraint('source_id', 'external_id', name=op.f('uq_alerts_source_id'))
    )
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.create_index('ix_alerts_fingerprint', ['source_id', 'fingerprint'], unique=False)
        batch_op.create_index('ix_alerts_status', ['status'], unique=False)



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_index('ix_alerts_status')
        batch_op.drop_index('ix_alerts_fingerprint')

    op.drop_table('alerts')
    with op.batch_alter_table('indicator_values', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_indicator_values_indicator_id'))

    op.drop_table('indicator_values')
    op.drop_table('maturity_assessments')
    op.drop_table('indicators')
    op.drop_table('alert_sources')
