"""comments, saved views, SSO-required policy

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-16 21:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0016'
down_revision: Union[str, Sequence[str], None] = '0015'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'comments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('entity_type', sa.String(length=40), nullable=False),
        sa.Column('entity_id', sa.Integer(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_comments_entity', 'comments', ['entity_type', 'entity_id'])
    op.create_table(
        'saved_views',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('page', sa.String(length=40), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('query', sa.String(length=1000), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'page', 'name'),
    )
    op.create_index('ix_saved_views_user_id', 'saved_views', ['user_id'])
    op.create_table(
        'sso_policy',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('required', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('sso_policy')
    op.drop_index('ix_saved_views_user_id', table_name='saved_views')
    op.drop_table('saved_views')
    op.drop_index('ix_comments_entity', table_name='comments')
    op.drop_table('comments')
