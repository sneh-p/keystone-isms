"""single sign-on (OIDC): providers, in-flight logins, user binding

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-16 19:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0015'
down_revision: Union[str, Sequence[str], None] = '0014'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Plain columns plus a unique index: a unique constraint would make SQLite rebuild "users", which fails while
    # other tables hold foreign keys to it.
    op.add_column('users', sa.Column('sso_issuer', sa.String(length=200), nullable=True))
    op.add_column('users', sa.Column('sso_subject', sa.String(length=200), nullable=True))
    op.create_index('uq_users_sso_identity', 'users', ['sso_issuer', 'sso_subject'], unique=True)
    op.create_table(
        'sso_providers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('client_id', sa.String(length=200), nullable=True),
        sa.Column('client_secret_enc', sa.Text(), nullable=True),
        sa.Column('tenant_id', sa.String(length=36), nullable=True),
        sa.Column('allowed_domains', sa.JSON(), nullable=False),
        sa.Column('jit_enabled', sa.Boolean(), nullable=False),
        sa.Column('jit_role', sa.String(length=30), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('kind'),
    )
    op.create_table(
        'oidc_logins',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('provider_kind', sa.String(length=20), nullable=False),
        sa.Column('state_hash', sa.String(length=64), nullable=False),
        sa.Column('browser_hash', sa.String(length=64), nullable=False),
        sa.Column('nonce', sa.String(length=100), nullable=False),
        sa.Column('code_verifier_enc', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state_hash'),
    )


def downgrade() -> None:
    op.drop_table('oidc_logins')
    op.drop_table('sso_providers')
    op.drop_index('uq_users_sso_identity', table_name='users')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('sso_subject')
        batch_op.drop_column('sso_issuer')
