"""add github owner fields

Revision ID: b3c4d5e6
Revises: a1b2c3d4
Create Date: 2026-02-11

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b3c4d5e6'
down_revision = 'a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    """Add github_owner to agents and github_orgs to admin_sessions."""
    with op.batch_alter_table('agents') as batch_op:
        batch_op.add_column(sa.Column('github_owner', sa.String(), nullable=True))
        batch_op.create_index('ix_agents_github_owner', ['github_owner'])

    with op.batch_alter_table('admin_sessions') as batch_op:
        batch_op.add_column(sa.Column('github_orgs', sa.String(), nullable=True))


def downgrade():
    """Remove github_owner from agents and github_orgs from admin_sessions."""
    with op.batch_alter_table('admin_sessions') as batch_op:
        batch_op.drop_column('github_orgs')

    with op.batch_alter_table('agents') as batch_op:
        batch_op.drop_index('ix_agents_github_owner')
        batch_op.drop_column('github_owner')
