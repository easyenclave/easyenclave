"""add settings table

Revision ID: a1b2c3d4
Revises: 69893640
Create Date: 2026-02-09

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4'
down_revision = '69893640'
branch_labels = None
depends_on = None


def upgrade():
    """Create settings key-value table."""
    op.create_table(
        'settings',
        sa.Column('key', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=False, server_default=''),
        sa.Column('is_secret', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('key'),
    )


def downgrade():
    """Drop settings table."""
    op.drop_table('settings')
