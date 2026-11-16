"""notifications inbox, digest preferences and SMTP settings

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-16 16:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0011'
down_revision: Union[str, Sequence[str], None] = '0010'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'notifications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=30), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('page', sa.String(length=200), nullable=False),
        sa.Column('due', sa.Date(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('read_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('emailed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'key'),
    )
    op.create_index('ix_notifications_user_id', 'notifications', ['user_id'])
    op.create_table(
        'notification_prefs',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('email_digest', sa.Boolean(), nullable=False),
        sa.Column('last_digest_on', sa.Date(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('user_id'),
    )
    op.create_table(
        'smtp_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('host', sa.String(length=253), nullable=True),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('security', sa.String(length=10), nullable=False),
        sa.Column('username', sa.String(length=320), nullable=True),
        sa.Column('password_enc', sa.Text(), nullable=True),
        sa.Column('password_host', sa.String(length=253), nullable=True),
        sa.Column('from_address', sa.String(length=320), nullable=True),
        sa.Column('from_name', sa.String(length=100), nullable=False),
        sa.Column('digest_hour_utc', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('smtp_settings')
    op.drop_table('notification_prefs')
    op.drop_index('ix_notifications_user_id', table_name='notifications')
    op.drop_table('notifications')
