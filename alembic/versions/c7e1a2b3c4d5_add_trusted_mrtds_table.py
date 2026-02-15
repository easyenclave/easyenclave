"""add trusted_mrtds table

Revision ID: c7e1a2b3c4d5
Revises: b3c4d5e6
Create Date: 2026-02-15
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "c7e1a2b3c4d5"
down_revision = "b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trusted_mrtds",
        sa.Column("mrtd", sa.String(), primary_key=True, nullable=False),
        sa.Column("mrtd_type", sa.String(), nullable=False, server_default="agent"),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_trusted_mrtds_mrtd_type", "trusted_mrtds", ["mrtd_type"])


def downgrade() -> None:
    op.drop_index("ix_trusted_mrtds_mrtd_type", table_name="trusted_mrtds")
    op.drop_table("trusted_mrtds")
