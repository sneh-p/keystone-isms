"""integration health, agent check-ins and integrity, enrolment key limits

Revision ID: 0049
Revises: 0048
Create Date: 2026-11-21 09:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0049'
down_revision: Union[str, Sequence[str], None] = '0048'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. One new table and plain added columns (with defaults where not nullable)."""
    op.create_table('agent_releases',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('platform', sa.String(length=20), nullable=False),
    sa.Column('version', sa.String(length=20), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('signed', sa.Boolean(), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('platform', 'sha256')
    )
    op.add_column('integrations', sa.Column('consecutive_failures', sa.Integer(), server_default='0', nullable=False))
    op.add_column('integrations', sa.Column('last_success_at', sa.DateTime(), nullable=True))
    op.add_column('integrations', sa.Column('credential_expires_on', sa.Date(), nullable=True))
    op.add_column('config_targets', sa.Column('last_seen_at', sa.DateTime(), nullable=True))
    op.add_column('config_targets', sa.Column('agent_sha256', sa.String(length=64), nullable=True))
    op.add_column('config_targets', sa.Column('device_id', sa.Integer(), nullable=True))
    op.add_column('config_agent_settings', sa.Column('enrollment_expires_at', sa.DateTime(), nullable=True))
    op.add_column('config_agent_settings', sa.Column('enrollment_days', sa.Integer(), nullable=True))
    op.add_column('config_agent_settings', sa.Column('enrollment_max_uses', sa.Integer(), nullable=True))
    op.add_column('config_agent_settings', sa.Column('enrollment_uses', sa.Integer(), server_default='0', nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('config_agent_settings', 'enrollment_uses')
    op.drop_column('config_agent_settings', 'enrollment_max_uses')
    op.drop_column('config_agent_settings', 'enrollment_days')
    op.drop_column('config_agent_settings', 'enrollment_expires_at')
    op.drop_column('config_targets', 'device_id')
    op.drop_column('config_targets', 'agent_sha256')
    op.drop_column('config_targets', 'last_seen_at')
    op.drop_column('integrations', 'credential_expires_on')
    op.drop_column('integrations', 'last_success_at')
    op.drop_column('integrations', 'consecutive_failures')
    op.drop_table('agent_releases')
