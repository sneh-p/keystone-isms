"""phishing, threat intel, on-call, dmarc

Revision ID: 0048
Revises: 0047
Create Date: 2026-11-18 17:06:16.477797

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0048'
down_revision: Union[str, Sequence[str], None] = '0047'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. New tables only."""
    op.create_table('dmarc_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('org_name', sa.String(length=200), nullable=False),
    sa.Column('report_id', sa.String(length=200), nullable=False),
    sa.Column('domain', sa.String(length=253), nullable=False),
    sa.Column('policy', sa.String(length=20), nullable=True),
    sa.Column('begin', sa.DateTime(), nullable=False),
    sa.Column('end', sa.DateTime(), nullable=False),
    sa.Column('messages', sa.Integer(), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_dmarc_reports_created_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_dmarc_reports')),
    sa.UniqueConstraint('org_name', 'report_id', name=op.f('uq_dmarc_reports_org_name'))
    )
    op.create_table('lookalike_domains',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('domain_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=253), nullable=False),
    sa.Column('reason', sa.String(length=200), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('decided_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['decided_by_id'], ['users.id'], name=op.f('fk_lookalike_domains_decided_by_id_users')),
    sa.ForeignKeyConstraint(['domain_id'], ['external_domains.id'], name=op.f('fk_lookalike_domains_domain_id_external_domains'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lookalike_domains')),
    sa.UniqueConstraint('name', name=op.f('uq_lookalike_domains_name'))
    )
    with op.batch_alter_table('lookalike_domains', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_lookalike_domains_domain_id'), ['domain_id'], unique=False)

    op.create_table('oncall_rotas',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('member_ids', sa.JSON(), nullable=False),
    sa.Column('start_on', sa.Date(), nullable=False),
    sa.Column('rotation_days', sa.Integer(), nullable=False),
    sa.Column('escalate_after_minutes', sa.Integer(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_oncall_rotas_created_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_oncall_rotas'))
    )
    op.create_table('phishing_campaigns',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('template', sa.String(length=60), nullable=False),
    sa.Column('audience', sa.JSON(), nullable=True),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('launched_by_id', sa.Integer(), nullable=True),
    sa.Column('launched_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_phishing_campaigns_created_by_id_users')),
    sa.ForeignKeyConstraint(['launched_by_id'], ['users.id'], name=op.f('fk_phishing_campaigns_launched_by_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_phishing_campaigns'))
    )
    op.create_table('dmarc_records',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('report_id', sa.Integer(), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=False),
    sa.Column('count', sa.Integer(), nullable=False),
    sa.Column('disposition', sa.String(length=20), nullable=True),
    sa.Column('dkim', sa.String(length=20), nullable=True),
    sa.Column('spf', sa.String(length=20), nullable=True),
    sa.Column('header_from', sa.String(length=253), nullable=True),
    sa.ForeignKeyConstraint(['report_id'], ['dmarc_reports.id'], name=op.f('fk_dmarc_records_report_id_dmarc_reports'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_dmarc_records'))
    )
    with op.batch_alter_table('dmarc_records', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_dmarc_records_report_id'), ['report_id'], unique=False)

    op.create_table('oncall_pages',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rota_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('level', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('page', sa.String(length=200), nullable=False),
    sa.Column('source', sa.String(length=60), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('emailed', sa.Boolean(), nullable=False),
    sa.Column('acked_at', sa.DateTime(), nullable=True),
    sa.Column('escalated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['rota_id'], ['oncall_rotas.id'], name=op.f('fk_oncall_pages_rota_id_oncall_rotas'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_oncall_pages_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_oncall_pages'))
    )
    with op.batch_alter_table('oncall_pages', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_oncall_pages_rota_id'), ['rota_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_oncall_pages_user_id'), ['user_id'], unique=False)

    op.create_table('phishing_targets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('campaign_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('department', sa.String(length=200), nullable=True),
    sa.Column('token_hash', sa.String(length=64), nullable=True),
    sa.Column('sent_at', sa.DateTime(), nullable=True),
    sa.Column('send_error', sa.String(length=200), nullable=True),
    sa.Column('clicked_at', sa.DateTime(), nullable=True),
    sa.Column('clicks', sa.Integer(), nullable=False),
    sa.Column('reported_at', sa.DateTime(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id'], name=op.f('fk_phishing_targets_campaign_id_phishing_campaigns'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_phishing_targets_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_phishing_targets')),
    sa.UniqueConstraint('campaign_id', 'user_id', name=op.f('uq_phishing_targets_campaign_id'))
    )
    with op.batch_alter_table('phishing_targets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_phishing_targets_campaign_id'), ['campaign_id'], unique=False)
        batch_op.create_index('ix_phishing_targets_token', ['token_hash'], unique=False)

    op.create_table('vendor_breaches',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vendor_id', sa.Integer(), nullable=False),
    sa.Column('breach', sa.String(length=200), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('domain', sa.String(length=253), nullable=False),
    sa.Column('breach_date', sa.Date(), nullable=True),
    sa.Column('added_on', sa.Date(), nullable=True),
    sa.Column('accounts', sa.Integer(), nullable=True),
    sa.Column('data_classes', sa.JSON(), nullable=True),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('decided_by_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['decided_by_id'], ['users.id'], name=op.f('fk_vendor_breaches_decided_by_id_users')),
    sa.ForeignKeyConstraint(['vendor_id'], ['vendors.id'], name=op.f('fk_vendor_breaches_vendor_id_vendors'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vendor_breaches')),
    sa.UniqueConstraint('vendor_id', 'breach', name=op.f('uq_vendor_breaches_vendor_id'))
    )
    with op.batch_alter_table('vendor_breaches', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vendor_breaches_vendor_id'), ['vendor_id'], unique=False)



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('vendor_breaches', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vendor_breaches_vendor_id'))

    op.drop_table('vendor_breaches')
    with op.batch_alter_table('phishing_targets', schema=None) as batch_op:
        batch_op.drop_index('ix_phishing_targets_token')
        batch_op.drop_index(batch_op.f('ix_phishing_targets_campaign_id'))

    op.drop_table('phishing_targets')
    with op.batch_alter_table('oncall_pages', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oncall_pages_user_id'))
        batch_op.drop_index(batch_op.f('ix_oncall_pages_rota_id'))

    op.drop_table('oncall_pages')
    with op.batch_alter_table('dmarc_records', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_dmarc_records_report_id'))

    op.drop_table('dmarc_records')
    op.drop_table('phishing_campaigns')
    op.drop_table('oncall_rotas')
    with op.batch_alter_table('lookalike_domains', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_lookalike_domains_domain_id'))

    op.drop_table('lookalike_domains')
    op.drop_table('dmarc_reports')
