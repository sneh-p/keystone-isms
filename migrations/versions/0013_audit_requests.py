"""audit evidence request list (PBC) with comments

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-16 17:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0013'
down_revision: Union[str, Sequence[str], None] = '0012'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_requests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('audit_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('common_control_id', sa.Integer(), nullable=True),
        sa.Column('due_date', sa.Date(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['audits.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['common_control_id'], ['common_controls.id']),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_requests_audit_id', 'audit_requests', ['audit_id'])
    op.create_table(
        'audit_request_comments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('request_id', sa.Integer(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['request_id'], ['audit_requests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_request_comments_request_id', 'audit_request_comments', ['request_id'])
    op.create_table(
        'audit_request_evidence',
        sa.Column('request_id', sa.Integer(), nullable=False),
        sa.Column('evidence_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['evidence_id'], ['evidence.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['request_id'], ['audit_requests.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('request_id', 'evidence_id'),
    )


def downgrade() -> None:
    op.drop_table('audit_request_evidence')
    op.drop_index('ix_audit_request_comments_request_id', table_name='audit_request_comments')
    op.drop_table('audit_request_comments')
    op.drop_index('ix_audit_requests_audit_id', table_name='audit_requests')
    op.drop_table('audit_requests')
