"""attack surface management

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-16 23:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0017'
down_revision: Union[str, Sequence[str], None] = '0016'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'asm_devices',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('serial', sa.String(length=120), nullable=True),
        sa.Column('aad_device_id', sa.String(length=64), nullable=True),
        sa.Column('os', sa.String(length=120), nullable=True),
        sa.Column('os_version', sa.String(length=120), nullable=True),
        sa.Column('device_type', sa.String(length=20), nullable=False),
        sa.Column('owner_email', sa.String(length=320), nullable=True),
        sa.Column('owner_user_id', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('properties', sa.JSON(), nullable=False),
        sa.Column('retired', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['owner_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    for col in ('hostname', 'serial', 'aad_device_id'):
        op.create_index(f'ix_asm_devices_{col}', 'asm_devices', [col])
    op.create_table(
        'asm_source_records',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('integration_id', sa.Integer(), nullable=True),
        sa.Column('category', sa.String(length=20), nullable=False),
        sa.Column('external_id', sa.String(length=200), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('properties', sa.JSON(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('collected_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['asm_devices.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('integration_id', 'external_id'),
    )
    op.create_index('ix_asm_source_records_integration_id', 'asm_source_records', ['integration_id'])
    op.create_index('ix_asm_source_records_device_id', 'asm_source_records', ['device_id'])
    op.create_table(
        'asm_identities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=40), nullable=False),
        sa.Column('integration_id', sa.Integer(), nullable=True),
        sa.Column('upn', sa.String(length=320), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('properties', sa.JSON(), nullable=False),
        sa.Column('collected_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source', 'upn'),
    )
    op.create_index('ix_asm_identities_integration_id', 'asm_identities', ['integration_id'])
    op.create_table(
        'asm_vulnerabilities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('integration_id', sa.Integer(), nullable=True),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('vuln_key', sa.String(length=120), nullable=False),
        sa.Column('cve', sa.String(length=200), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('severity', sa.String(length=10), nullable=False),
        sa.Column('cvss', sa.Float(), nullable=True),
        sa.Column('exploitable', sa.Boolean(), nullable=False),
        sa.Column('first_seen', sa.Date(), nullable=True),
        sa.Column('last_seen', sa.Date(), nullable=True),
        sa.Column('state', sa.String(length=10), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['asm_devices.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('integration_id', 'device_id', 'vuln_key'),
    )
    op.create_index('ix_asm_vulnerabilities_integration_id', 'asm_vulnerabilities', ['integration_id'])
    op.create_index('ix_asm_vuln_open', 'asm_vulnerabilities', ['device_id', 'state'])
    op.create_table(
        'asm_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('integration_id', sa.Integer(), nullable=True),
        sa.Column('key', sa.String(length=200), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('category', sa.String(length=80), nullable=True),
        sa.Column('compliant', sa.Boolean(), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('collected_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('integration_id', 'key'),
    )
    op.create_index('ix_asm_settings_integration_id', 'asm_settings', ['integration_id'])
    op.create_table(
        'asm_baselines',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('entity', sa.String(length=20), nullable=False),
        sa.Column('property', sa.String(length=60), nullable=False),
        sa.Column('operator', sa.String(length=10), nullable=False),
        sa.Column('value', sa.String(length=100), nullable=True),
        sa.Column('scope', sa.JSON(), nullable=False),
        sa.Column('severity', sa.String(length=10), nullable=False),
        sa.Column('controls', sa.JSON(), nullable=False),
        sa.Column('missing', sa.String(length=10), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'asm_findings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('baseline_id', sa.Integer(), nullable=False),
        sa.Column('entity_type', sa.String(length=20), nullable=False),
        sa.Column('entity_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=12), nullable=False),
        sa.Column('no_data', sa.Boolean(), nullable=False),
        sa.Column('detail', sa.String(length=500), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('exception_reason', sa.Text(), nullable=True),
        sa.Column('exception_by_id', sa.Integer(), nullable=True),
        sa.Column('exception_until', sa.Date(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['baseline_id'], ['asm_baselines.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['exception_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('baseline_id', 'entity_type', 'entity_id'),
    )
    op.create_index('ix_asm_findings_baseline_id', 'asm_findings', ['baseline_id'])


def downgrade() -> None:
    for t in ('asm_findings', 'asm_baselines', 'asm_settings', 'asm_vulnerabilities', 'asm_identities', 'asm_source_records', 'asm_devices'):
        op.drop_table(t)
