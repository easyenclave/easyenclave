"""add tcb status fields

Revision ID: 69893640
Revises: d22607323814
Create Date: 2026-02-09

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = '69893640'
down_revision = 'd22607323814'
branch_labels = None
depends_on = None


def upgrade():
    """Add TCB status fields to agents table."""
    # Add tcb_status column
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tcb_status', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('tcb_verified_at', sa.DateTime(), nullable=True))
        batch_op.create_index('ix_agents_tcb_status', ['tcb_status'], unique=False)


def downgrade():
    """Remove TCB status fields from agents table."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_index('ix_agents_tcb_status')
        batch_op.drop_column('tcb_verified_at')
        batch_op.drop_column('tcb_status')
